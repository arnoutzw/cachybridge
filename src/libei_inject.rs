//! Narrow libei sender wrapper for consented RemoteDesktop sessions.
//!
//! Raw FFI pointers remain private. The public surface validates and bounds
//! relative pointer, keyboard, button, and scroll events and tracks held state
//! for safe release during disconnect or cleanup.

use std::{
    collections::BTreeSet,
    ffi::{c_char, c_int, c_short, c_void, CStr, CString},
    io,
    os::fd::{IntoRawFd, OwnedFd},
    ptr::NonNull,
    time::{Duration, Instant},
};

use crate::libei_capture::{DeviceMetadata, ReceiverMetadata, RegionMetadata, SeatMetadata};

const EI_EVENT_CONNECT: c_int = 1;
const EI_EVENT_DISCONNECT: c_int = 2;
const EI_EVENT_SEAT_ADDED: c_int = 3;
const EI_EVENT_DEVICE_ADDED: c_int = 5;
const EI_EVENT_DEVICE_REMOVED: c_int = 6;
const EI_EVENT_DEVICE_PAUSED: c_int = 7;
const EI_EVENT_DEVICE_RESUMED: c_int = 8;

const CAP_POINTER: c_int = 1 << 0;
const CAP_POINTER_ABSOLUTE: c_int = 1 << 1;
const CAP_KEYBOARD: c_int = 1 << 2;
const CAP_TOUCH: c_int = 1 << 3;
const CAP_SCROLL: c_int = 1 << 4;
const CAP_BUTTON: c_int = 1 << 5;
const CAP_TEXT: c_int = 1 << 6;

const POLLIN: c_short = 0x001;
const POINTER_TEST_DELTA: f64 = 2.0;
const MAX_AXIS_DELTA: f64 = 2048.0;
const EVDEV_KEY_MAX: u16 = 0x2ff;
const EVDEV_BUTTON_MIN: u16 = 0x100;

#[repr(C)]
struct Ei {
    _private: [u8; 0],
}

#[repr(C)]
struct EiEvent {
    _private: [u8; 0],
}

#[repr(C)]
struct EiSeat {
    _private: [u8; 0],
}

#[repr(C)]
struct EiDevice {
    _private: [u8; 0],
}

#[repr(C)]
struct EiRegion {
    _private: [u8; 0],
}

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: c_short,
    revents: c_short,
}

#[link(name = "ei")]
unsafe extern "C" {
    fn ei_new_sender(user_data: *mut c_void) -> *mut Ei;
    fn ei_unref(context: *mut Ei) -> *mut Ei;
    fn ei_configure_name(context: *mut Ei, name: *const c_char);
    fn ei_setup_backend_fd(context: *mut Ei, fd: c_int) -> c_int;
    fn ei_get_fd(context: *mut Ei) -> c_int;
    fn ei_dispatch(context: *mut Ei);
    fn ei_get_event(context: *mut Ei) -> *mut EiEvent;
    fn ei_disconnect(context: *mut Ei);
    fn ei_now(context: *mut Ei) -> u64;

    fn ei_event_get_type(event: *mut EiEvent) -> c_int;
    fn ei_event_type_to_string(event_type: c_int) -> *const c_char;
    fn ei_event_unref(event: *mut EiEvent) -> *mut EiEvent;
    fn ei_event_get_seat(event: *mut EiEvent) -> *mut EiSeat;
    fn ei_event_get_device(event: *mut EiEvent) -> *mut EiDevice;

    fn ei_seat_get_name(seat: *mut EiSeat) -> *const c_char;
    fn ei_seat_has_capability(seat: *mut EiSeat, capability: c_int) -> bool;
    fn ei_seat_bind_capabilities(seat: *mut EiSeat, ...);

    fn ei_device_ref(device: *mut EiDevice) -> *mut EiDevice;
    fn ei_device_unref(device: *mut EiDevice) -> *mut EiDevice;
    fn ei_device_get_name(device: *mut EiDevice) -> *const c_char;
    fn ei_device_get_type(device: *mut EiDevice) -> c_int;
    fn ei_device_has_capability(device: *mut EiDevice, capability: c_int) -> bool;
    fn ei_device_get_region(device: *mut EiDevice, index: usize) -> *mut EiRegion;
    fn ei_device_start_emulating(device: *mut EiDevice, sequence: u32);
    fn ei_device_stop_emulating(device: *mut EiDevice);
    fn ei_device_frame(device: *mut EiDevice, time: u64);
    fn ei_device_pointer_motion(device: *mut EiDevice, x: f64, y: f64);
    fn ei_device_button_button(device: *mut EiDevice, button: u32, is_press: bool);
    fn ei_device_scroll_delta(device: *mut EiDevice, x: f64, y: f64);
    fn ei_device_scroll_stop(device: *mut EiDevice, stop_x: bool, stop_y: bool);
    fn ei_device_keyboard_key(device: *mut EiDevice, keycode: u32, is_press: bool);

    fn ei_region_get_x(region: *mut EiRegion) -> u32;
    fn ei_region_get_y(region: *mut EiRegion) -> u32;
    fn ei_region_get_width(region: *mut EiRegion) -> u32;
    fn ei_region_get_height(region: *mut EiRegion) -> u32;

    fn poll(fds: *mut PollFd, nfds: usize, timeout: c_int) -> c_int;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputState {
    Released,
    Pressed,
}

impl InputState {
    fn is_pressed(self) -> bool {
        self == Self::Pressed
    }
}

pub struct Sender {
    context: NonNull<Ei>,
    pointer: Option<NonNull<EiDevice>>,
    keyboard: Option<NonNull<EiDevice>>,
    button: Option<NonNull<EiDevice>>,
    scroll: Option<NonNull<EiDevice>>,
    resumed: Vec<NonNull<EiDevice>>,
    emulating: Vec<NonNull<EiDevice>>,
    pressed_keys: BTreeSet<u16>,
    pressed_buttons: BTreeSet<u16>,
    sequence: u32,
    metadata: ReceiverMetadata,
}

impl Sender {
    /// Create a sender context. libei takes ownership of `fd`.
    pub fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        let context = NonNull::new(unsafe { ei_new_sender(std::ptr::null_mut()) })
            .ok_or_else(|| io::Error::other("ei_new_sender returned NULL"))?;
        let name =
            CString::new("CachyBridge RemoteDesktop spike").expect("static string has no NUL");
        unsafe { ei_configure_name(context.as_ptr(), name.as_ptr()) };
        let raw_fd = fd.into_raw_fd();
        let result = unsafe { ei_setup_backend_fd(context.as_ptr(), raw_fd) };
        if result < 0 {
            unsafe { ei_unref(context.as_ptr()) };
            return Err(io::Error::from_raw_os_error(-result));
        }
        Ok(Self {
            context,
            pointer: None,
            keyboard: None,
            button: None,
            scroll: None,
            resumed: Vec::new(),
            emulating: Vec::new(),
            pressed_keys: BTreeSet::new(),
            pressed_buttons: BTreeSet::new(),
            sequence: 0,
            metadata: ReceiverMetadata::default(),
        })
    }

    /// Complete the sender handshake and wait for resumed pointer and keyboard devices.
    pub fn handshake(&mut self, timeout: Duration) -> io::Result<&ReceiverMetadata> {
        let deadline = Instant::now() + timeout;
        while !(self.device_ready(self.pointer) && self.device_ready(self.keyboard))
            && !self.metadata.disconnected
        {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            self.dispatch(remaining.min(Duration::from_millis(250)))?;
        }
        if !self.metadata.connected {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "EIS sender did not complete its Connect handshake",
            ));
        }
        if !self.device_ready(self.pointer) || !self.device_ready(self.keyboard) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "EIS sender did not announce and resume both pointer and keyboard devices",
            ));
        }
        Ok(&self.metadata)
    }

    /// Send two opposite 2-logical-pixel frames and return to the origin.
    pub fn bounded_pointer_test(&mut self) -> io::Result<()> {
        self.inject_relative(POINTER_TEST_DELTA, 0.0)?;
        self.inject_relative(-POINTER_TEST_DELTA, 0.0)?;
        // Dispatch once without blocking to flush protocol work and surface an
        // immediate disconnect. No arbitrary event payload is consumed.
        self.dispatch(Duration::ZERO)?;
        if self.metadata.disconnected {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "EIS server disconnected during pointer proof",
            ));
        }
        Ok(())
    }

    /// Inject a finite, bounded relative motion frame.
    pub fn inject_relative(&mut self, dx: f64, dy: f64) -> io::Result<()> {
        validate_axis_pair(dx, dy, "relative pointer")?;
        let device = self.require_ready(self.pointer, "relative-pointer")?;
        self.ensure_emulating(device);
        unsafe {
            ei_device_pointer_motion(device.as_ptr(), dx, dy);
        }
        self.frame(device);
        Ok(())
    }

    /// Inject one validated evdev key transition.
    pub fn inject_key(&mut self, evdev: u16, state: InputState) -> io::Result<()> {
        if evdev > EVDEV_KEY_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("evdev key code {evdev} exceeds KEY_MAX"),
            ));
        }
        let device = self.require_ready(self.keyboard, "keyboard")?;
        update_pressed(&mut self.pressed_keys, evdev, state, "key")?;
        self.ensure_emulating(device);
        unsafe { ei_device_keyboard_key(device.as_ptr(), evdev.into(), state.is_pressed()) };
        self.frame(device);
        Ok(())
    }

    /// Inject one validated evdev button transition.
    pub fn inject_button(&mut self, evdev: u16, state: InputState) -> io::Result<()> {
        if !(EVDEV_BUTTON_MIN..=EVDEV_KEY_MAX).contains(&evdev) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("evdev button code {evdev} is outside the BTN range"),
            ));
        }
        let device = self.require_ready(self.button, "button")?;
        update_pressed(&mut self.pressed_buttons, evdev, state, "button")?;
        self.ensure_emulating(device);
        unsafe { ei_device_button_button(device.as_ptr(), evdev.into(), state.is_pressed()) };
        self.frame(device);
        Ok(())
    }

    /// Inject a finite, bounded smooth-scroll frame.
    pub fn inject_scroll(
        &mut self,
        horizontal: f64,
        vertical: f64,
        finish: bool,
    ) -> io::Result<()> {
        validate_axis_pair(horizontal, vertical, "scroll")?;
        let device = self.require_ready(self.scroll, "scroll")?;
        self.ensure_emulating(device);
        unsafe {
            ei_device_scroll_delta(device.as_ptr(), horizontal, vertical);
            if finish {
                ei_device_scroll_stop(device.as_ptr(), horizontal != 0.0, vertical != 0.0);
            }
        }
        self.frame(device);
        Ok(())
    }

    fn frame(&self, device: NonNull<EiDevice>) {
        unsafe { ei_device_frame(device.as_ptr(), ei_now(self.context.as_ptr())) };
    }

    fn require_ready(
        &self,
        device: Option<NonNull<EiDevice>>,
        capability: &str,
    ) -> io::Result<NonNull<EiDevice>> {
        let device = device.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                format!("no EIS {capability} device"),
            )
        })?;
        if !self.device_ready(Some(device)) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("EIS {capability} device is not resumed"),
            ));
        }
        Ok(device)
    }

    fn device_ready(&self, device: Option<NonNull<EiDevice>>) -> bool {
        device.is_some_and(|device| contains_device(&self.resumed, device))
    }

    fn ensure_emulating(&mut self, device: NonNull<EiDevice>) {
        if contains_device(&self.emulating, device) {
            return;
        }
        self.sequence = self.sequence.wrapping_add(1).max(1);
        unsafe { ei_device_start_emulating(device.as_ptr(), self.sequence) };
        self.emulating.push(device);
    }

    fn dispatch(&mut self, timeout: Duration) -> io::Result<()> {
        let mut poll_fd = PollFd {
            fd: unsafe { ei_get_fd(self.context.as_ptr()) },
            events: POLLIN,
            revents: 0,
        };
        let result = unsafe { poll(&mut poll_fd, 1, duration_to_poll_ms(timeout)) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result == 0 {
            return Ok(());
        }
        unsafe { ei_dispatch(self.context.as_ptr()) };
        while let Some(event) = NonNull::new(unsafe { ei_get_event(self.context.as_ptr()) }) {
            let event_type = unsafe { ei_event_get_type(event.as_ptr()) };
            self.metadata.event_types.push(event_type_name(event_type));
            self.process_event(event.as_ptr(), event_type);
            unsafe { ei_event_unref(event.as_ptr()) };
        }
        Ok(())
    }

    fn process_event(&mut self, event: *mut EiEvent, event_type: c_int) {
        match event_type {
            EI_EVENT_CONNECT => self.metadata.connected = true,
            EI_EVENT_DISCONNECT => self.metadata.disconnected = true,
            EI_EVENT_SEAT_ADDED => {
                let seat = unsafe { ei_event_get_seat(event) };
                if seat.is_null() {
                    return;
                }
                self.metadata.seats.push(SeatMetadata {
                    name: nullable_string(unsafe { ei_seat_get_name(seat) }),
                    capabilities: capabilities(|capability| unsafe {
                        ei_seat_has_capability(seat, capability)
                    }),
                });
                unsafe {
                    ei_seat_bind_capabilities(
                        seat,
                        CAP_POINTER,
                        CAP_KEYBOARD,
                        CAP_BUTTON,
                        CAP_SCROLL,
                        std::ptr::null::<c_void>(),
                    );
                }
            }
            EI_EVENT_DEVICE_ADDED => {
                let device = unsafe { ei_event_get_device(event) };
                if device.is_null() {
                    return;
                }
                self.metadata.devices.push(device_metadata(device));
                if self.pointer.is_none()
                    && unsafe { ei_device_has_capability(device, CAP_POINTER) }
                {
                    self.pointer = NonNull::new(unsafe { ei_device_ref(device) });
                }
                if self.keyboard.is_none()
                    && unsafe { ei_device_has_capability(device, CAP_KEYBOARD) }
                {
                    self.keyboard = NonNull::new(unsafe { ei_device_ref(device) });
                }
                if self.button.is_none() && unsafe { ei_device_has_capability(device, CAP_BUTTON) }
                {
                    self.button = NonNull::new(unsafe { ei_device_ref(device) });
                }
                if self.scroll.is_none() && unsafe { ei_device_has_capability(device, CAP_SCROLL) }
                {
                    self.scroll = NonNull::new(unsafe { ei_device_ref(device) });
                }
            }
            EI_EVENT_DEVICE_REMOVED => {
                let device = unsafe { ei_event_get_device(event) };
                self.resumed
                    .retain(|candidate| candidate.as_ptr() != device);
                self.emulating
                    .retain(|candidate| candidate.as_ptr() != device);
                release_matching(&mut self.pointer, device);
                release_matching(&mut self.keyboard, device);
                release_matching(&mut self.button, device);
                release_matching(&mut self.scroll, device);
                self.pressed_keys.clear();
                self.pressed_buttons.clear();
            }
            EI_EVENT_DEVICE_PAUSED => {
                let device = unsafe { ei_event_get_device(event) };
                self.resumed
                    .retain(|candidate| candidate.as_ptr() != device);
                self.emulating
                    .retain(|candidate| candidate.as_ptr() != device);
                if self.keyboard.is_some_and(|slot| slot.as_ptr() == device) {
                    self.pressed_keys.clear();
                }
                if self.button.is_some_and(|slot| slot.as_ptr() == device) {
                    self.pressed_buttons.clear();
                }
            }
            EI_EVENT_DEVICE_RESUMED => {
                let device = unsafe { ei_event_get_device(event) };
                if [self.pointer, self.keyboard, self.button, self.scroll]
                    .into_iter()
                    .flatten()
                    .any(|slot| slot.as_ptr() == device)
                {
                    let device = NonNull::new(device).expect("event device is non-NULL");
                    if !contains_device(&self.resumed, device) {
                        self.resumed.push(device);
                    }
                }
            }
            _ => {}
        }
    }

    /// Release every held key/button and stop all active emulation sequences.
    ///
    /// This is idempotent and the sender can be used again after devices resume.
    pub fn release_all(&mut self) {
        if let Some(keyboard) = self.keyboard {
            let pressed_keys = std::mem::take(&mut self.pressed_keys);
            let sent_releases = !pressed_keys.is_empty();
            for key in pressed_keys {
                unsafe { ei_device_keyboard_key(keyboard.as_ptr(), key.into(), false) };
            }
            if sent_releases {
                self.frame(keyboard);
            }
        }
        if let Some(button) = self.button {
            let pressed_buttons = std::mem::take(&mut self.pressed_buttons);
            let sent_releases = !pressed_buttons.is_empty();
            for code in pressed_buttons {
                unsafe { ei_device_button_button(button.as_ptr(), code.into(), false) };
            }
            if sent_releases {
                self.frame(button);
            }
        }
        for device in std::mem::take(&mut self.emulating) {
            unsafe { ei_device_stop_emulating(device.as_ptr()) };
        }
    }

    fn release_devices(&mut self) {
        release_slot(&mut self.pointer);
        release_slot(&mut self.keyboard);
        release_slot(&mut self.button);
        release_slot(&mut self.scroll);
        self.resumed.clear();
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        self.release_all();
        self.release_devices();
        unsafe {
            ei_disconnect(self.context.as_ptr());
            ei_unref(self.context.as_ptr());
        }
    }
}

fn device_metadata(device: *mut EiDevice) -> DeviceMetadata {
    let mut regions = Vec::new();
    for index in 0.. {
        let region = unsafe { ei_device_get_region(device, index) };
        if region.is_null() {
            break;
        }
        regions.push(RegionMetadata {
            x: unsafe { ei_region_get_x(region) },
            y: unsafe { ei_region_get_y(region) },
            width: unsafe { ei_region_get_width(region) },
            height: unsafe { ei_region_get_height(region) },
        });
    }
    DeviceMetadata {
        name: nullable_string(unsafe { ei_device_get_name(device) }),
        device_type: match unsafe { ei_device_get_type(device) } {
            1 => "virtual",
            2 => "physical",
            _ => "unknown",
        },
        capabilities: capabilities(|capability| unsafe {
            ei_device_has_capability(device, capability)
        }),
        regions,
    }
}

fn validate_axis_pair(x: f64, y: f64, kind: &str) -> io::Result<()> {
    if !x.is_finite() || !y.is_finite() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{kind} deltas must be finite"),
        ));
    }
    if x.abs() > MAX_AXIS_DELTA || y.abs() > MAX_AXIS_DELTA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{kind} delta exceeds the per-frame limit of {MAX_AXIS_DELTA}"),
        ));
    }
    Ok(())
}

fn update_pressed(
    pressed: &mut BTreeSet<u16>,
    code: u16,
    state: InputState,
    kind: &str,
) -> io::Result<()> {
    let changed = match state {
        InputState::Pressed => pressed.insert(code),
        InputState::Released => pressed.remove(&code),
    };
    if changed {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("duplicate or unmatched {kind} transition for code {code}"),
        ))
    }
}

fn contains_device(devices: &[NonNull<EiDevice>], target: NonNull<EiDevice>) -> bool {
    devices.contains(&target)
}

fn release_matching(slot: &mut Option<NonNull<EiDevice>>, removed: *mut EiDevice) {
    if slot.is_some_and(|device| device.as_ptr() == removed) {
        release_slot(slot);
    }
}

fn release_slot(slot: &mut Option<NonNull<EiDevice>>) {
    if let Some(device) = slot.take() {
        unsafe { ei_device_unref(device.as_ptr()) };
    }
}

fn capabilities(mut has: impl FnMut(c_int) -> bool) -> Vec<&'static str> {
    [
        (CAP_POINTER, "pointer"),
        (CAP_POINTER_ABSOLUTE, "pointer-absolute"),
        (CAP_KEYBOARD, "keyboard"),
        (CAP_TOUCH, "touch"),
        (CAP_SCROLL, "scroll"),
        (CAP_BUTTON, "button"),
        (CAP_TEXT, "text"),
    ]
    .into_iter()
    .filter_map(|(value, name)| has(value).then_some(name))
    .collect()
}

fn nullable_string(value: *const c_char) -> String {
    if value.is_null() {
        "unnamed".to_owned()
    } else {
        unsafe { CStr::from_ptr(value) }
            .to_string_lossy()
            .into_owned()
    }
}

fn event_type_name(event_type: c_int) -> String {
    nullable_string(unsafe { ei_event_type_to_string(event_type) })
}

fn duration_to_poll_ms(duration: Duration) -> c_int {
    if duration.is_zero() {
        0
    } else {
        duration
            .as_millis()
            .clamp(1, c_int::MAX as u128)
            .try_into()
            .unwrap_or(c_int::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_proof_is_small_and_net_zero() {
        let deltas = [POINTER_TEST_DELTA, -POINTER_TEST_DELTA];
        assert!(deltas.iter().all(|delta| delta.abs() <= 2.0));
        assert_eq!(deltas.into_iter().sum::<f64>(), 0.0);
    }

    #[test]
    fn sender_only_binds_requested_keyboard_pointer_capabilities() {
        let bound = [CAP_POINTER, CAP_KEYBOARD, CAP_BUTTON, CAP_SCROLL];
        assert!(!bound.contains(&CAP_POINTER_ABSOLUTE));
        assert!(!bound.contains(&CAP_TOUCH));
        assert!(!bound.contains(&CAP_TEXT));
    }

    #[test]
    fn rejects_nonfinite_and_unbounded_axis_values() {
        assert!(validate_axis_pair(10.0, -10.0, "motion").is_ok());
        assert!(validate_axis_pair(f64::NAN, 0.0, "motion").is_err());
        assert!(validate_axis_pair(MAX_AXIS_DELTA + 1.0, 0.0, "motion").is_err());
    }

    #[test]
    fn pressed_ledger_rejects_duplicate_and_unmatched_transitions() {
        let mut pressed = BTreeSet::new();
        assert!(update_pressed(&mut pressed, 30, InputState::Pressed, "key").is_ok());
        assert!(update_pressed(&mut pressed, 30, InputState::Pressed, "key").is_err());
        assert!(update_pressed(&mut pressed, 30, InputState::Released, "key").is_ok());
        assert!(update_pressed(&mut pressed, 30, InputState::Released, "key").is_err());
    }
}
