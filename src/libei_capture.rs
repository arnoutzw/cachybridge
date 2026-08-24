//! Narrow safe wrapper around the libei receiver API.
//!
//! The raw FFI is contained in this module. It performs the EIS handshake,
//! binds advertised seat capabilities, reports metadata, and extracts a typed
//! subset of keyboard/pointer events without exposing raw libei pointers.

use std::{
    ffi::{c_char, c_int, c_short, c_void, CStr, CString},
    io,
    os::fd::{IntoRawFd, OwnedFd},
    ptr::NonNull,
    time::{Duration, Instant},
};

const EI_EVENT_CONNECT: c_int = 1;
const EI_EVENT_DISCONNECT: c_int = 2;
const EI_EVENT_SEAT_ADDED: c_int = 3;
const EI_EVENT_DEVICE_ADDED: c_int = 5;
const EI_EVENT_DEVICE_START_EMULATING: c_int = 200;
const EI_EVENT_DEVICE_STOP_EMULATING: c_int = 201;
const EI_EVENT_FRAME: c_int = 100;
const EI_EVENT_POINTER_MOTION: c_int = 300;
const EI_EVENT_POINTER_MOTION_ABSOLUTE: c_int = 400;
const EI_EVENT_BUTTON_BUTTON: c_int = 500;
const EI_EVENT_SCROLL_DELTA: c_int = 600;
const EI_EVENT_SCROLL_STOP: c_int = 601;
const EI_EVENT_SCROLL_CANCEL: c_int = 602;
const EI_EVENT_SCROLL_DISCRETE: c_int = 603;
const EI_EVENT_KEYBOARD_KEY: c_int = 700;
const EI_EVENT_TOUCH_DOWN: c_int = 800;
const EI_EVENT_TOUCH_UP: c_int = 801;
const EI_EVENT_TOUCH_MOTION: c_int = 802;

const CAP_POINTER: c_int = 1 << 0;
const CAP_POINTER_ABSOLUTE: c_int = 1 << 1;
const CAP_KEYBOARD: c_int = 1 << 2;
const CAP_TOUCH: c_int = 1 << 3;
const CAP_SCROLL: c_int = 1 << 4;
const CAP_BUTTON: c_int = 1 << 5;
const CAP_TEXT: c_int = 1 << 6;

const POLLIN: c_short = 0x001;

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
    fn ei_new_receiver(user_data: *mut c_void) -> *mut Ei;
    fn ei_unref(context: *mut Ei) -> *mut Ei;
    fn ei_configure_name(context: *mut Ei, name: *const c_char);
    fn ei_setup_backend_fd(context: *mut Ei, fd: c_int) -> c_int;
    fn ei_get_fd(context: *mut Ei) -> c_int;
    fn ei_dispatch(context: *mut Ei);
    fn ei_get_event(context: *mut Ei) -> *mut EiEvent;
    fn ei_disconnect(context: *mut Ei);

    fn ei_event_get_type(event: *mut EiEvent) -> c_int;
    fn ei_event_type_to_string(event_type: c_int) -> *const c_char;
    fn ei_event_unref(event: *mut EiEvent) -> *mut EiEvent;
    fn ei_event_get_seat(event: *mut EiEvent) -> *mut EiSeat;
    fn ei_event_get_device(event: *mut EiEvent) -> *mut EiDevice;
    fn ei_event_emulating_get_sequence(event: *mut EiEvent) -> u32;
    fn ei_event_get_time(event: *mut EiEvent) -> u64;
    fn ei_event_pointer_get_dx(event: *mut EiEvent) -> f64;
    fn ei_event_pointer_get_dy(event: *mut EiEvent) -> f64;
    fn ei_event_pointer_get_absolute_x(event: *mut EiEvent) -> f64;
    fn ei_event_pointer_get_absolute_y(event: *mut EiEvent) -> f64;
    fn ei_event_button_get_button(event: *mut EiEvent) -> u32;
    fn ei_event_button_get_is_press(event: *mut EiEvent) -> bool;
    fn ei_event_scroll_get_dx(event: *mut EiEvent) -> f64;
    fn ei_event_scroll_get_dy(event: *mut EiEvent) -> f64;
    fn ei_event_scroll_get_stop_x(event: *mut EiEvent) -> bool;
    fn ei_event_scroll_get_stop_y(event: *mut EiEvent) -> bool;
    fn ei_event_scroll_get_discrete_dx(event: *mut EiEvent) -> i32;
    fn ei_event_scroll_get_discrete_dy(event: *mut EiEvent) -> i32;
    fn ei_event_keyboard_get_key(event: *mut EiEvent) -> u32;
    fn ei_event_keyboard_get_key_is_press(event: *mut EiEvent) -> bool;
    fn ei_event_touch_get_id(event: *mut EiEvent) -> u32;
    fn ei_event_touch_get_x(event: *mut EiEvent) -> f64;
    fn ei_event_touch_get_y(event: *mut EiEvent) -> f64;
    fn ei_event_touch_get_is_cancel(event: *mut EiEvent) -> bool;

    fn ei_seat_get_name(seat: *mut EiSeat) -> *const c_char;
    fn ei_seat_has_capability(seat: *mut EiSeat, capability: c_int) -> bool;
    fn ei_seat_bind_capabilities(seat: *mut EiSeat, ...);

    fn ei_device_get_name(device: *mut EiDevice) -> *const c_char;
    fn ei_device_get_type(device: *mut EiDevice) -> c_int;
    fn ei_device_has_capability(device: *mut EiDevice, capability: c_int) -> bool;
    fn ei_device_get_region(device: *mut EiDevice, index: usize) -> *mut EiRegion;

    fn ei_region_get_x(region: *mut EiRegion) -> u32;
    fn ei_region_get_y(region: *mut EiRegion) -> u32;
    fn ei_region_get_width(region: *mut EiRegion) -> u32;
    fn ei_region_get_height(region: *mut EiRegion) -> u32;

    fn poll(fds: *mut PollFd, nfds: usize, timeout: c_int) -> c_int;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatMetadata {
    pub name: String,
    pub capabilities: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionMetadata {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceMetadata {
    pub name: String,
    pub device_type: &'static str,
    pub capabilities: Vec<&'static str>,
    pub regions: Vec<RegionMetadata>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReceiverMetadata {
    pub connected: bool,
    pub disconnected: bool,
    pub seats: Vec<SeatMetadata>,
    pub devices: Vec<DeviceMetadata>,
    pub event_types: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CapturedEvent {
    StartEmulating {
        sequence: u32,
    },
    StopEmulating,
    Frame {
        time_micros: u64,
    },
    RelativePointer {
        dx: f64,
        dy: f64,
    },
    /// Logical absolute pointer coordinates from an EIS absolute-pointer
    /// device. The portal adapter converts these to bounded relative deltas;
    /// absolute coordinates are never placed on the existing wire protocol.
    AbsolutePointer {
        x: f64,
        y: f64,
    },
    Button {
        evdev: u16,
        pressed: bool,
    },
    Key {
        evdev: u16,
        pressed: bool,
    },
    ScrollDelta {
        horizontal: f64,
        vertical: f64,
    },
    ScrollDiscrete {
        horizontal: i32,
        vertical: i32,
    },
    ScrollStop {
        horizontal: bool,
        vertical: bool,
    },
    ScrollCancel {
        horizontal: bool,
        vertical: bool,
    },
    /// A physical touch contact normalized to its source EIS device region.
    /// Normalization makes a Magic Trackpad's physical mm surface portable to
    /// a remote desktop's logical touch region.
    TouchDown {
        id: u32,
        x: u16,
        y: u16,
    },
    TouchMotion {
        id: u32,
        x: u16,
        y: u16,
    },
    TouchUp {
        id: u32,
        cancelled: bool,
    },
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct DispatchBatch {
    pub event_types: Vec<String>,
    pub input_events: Vec<CapturedEvent>,
}

pub struct Receiver {
    context: NonNull<Ei>,
    metadata: ReceiverMetadata,
}

impl Receiver {
    /// Create a receiver context. libei takes ownership of `fd`.
    pub fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        let context = NonNull::new(unsafe { ei_new_receiver(std::ptr::null_mut()) })
            .ok_or_else(|| io::Error::other("ei_new_receiver returned NULL"))?;
        let name =
            CString::new("CachyBridge InputCapture spike").expect("static string has no NUL");
        unsafe { ei_configure_name(context.as_ptr(), name.as_ptr()) };
        let raw_fd = fd.into_raw_fd();
        let result = unsafe { ei_setup_backend_fd(context.as_ptr(), raw_fd) };
        if result < 0 {
            unsafe { ei_unref(context.as_ptr()) };
            return Err(io::Error::from_raw_os_error(-result));
        }
        Ok(Self {
            context,
            metadata: ReceiverMetadata::default(),
        })
    }

    /// Complete the initial EIS exchange and collect announced metadata.
    pub fn handshake(&mut self, timeout: Duration) -> io::Result<&ReceiverMetadata> {
        let deadline = Instant::now() + timeout;
        while !self.metadata.connected && !self.metadata.disconnected {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            self.dispatch(remaining.min(Duration::from_millis(250)))?;
        }
        if !self.metadata.connected {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "EIS receiver did not complete its Connect handshake",
            ));
        }

        // Seat capability binding is asynchronous. Give the server a short,
        // bounded opportunity to announce its devices after Connect.
        let metadata_deadline = Instant::now() + Duration::from_millis(750);
        while self.metadata.devices.is_empty() && !self.metadata.disconnected {
            let Some(remaining) = metadata_deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            self.dispatch(remaining.min(Duration::from_millis(100)))?;
        }
        Ok(&self.metadata)
    }

    /// Dispatch available protocol messages into owned metadata and input events.
    pub fn dispatch(&mut self, timeout: Duration) -> io::Result<DispatchBatch> {
        self.dispatch_inner(timeout, true)
    }

    /// Hot-path dispatch for input forwarding. It deliberately avoids
    /// allocating diagnostic event-name strings or retaining an unbounded
    /// event history for every mouse update.
    pub fn dispatch_input(&mut self, timeout: Duration) -> io::Result<DispatchBatch> {
        self.dispatch_inner(timeout, false)
    }

    fn dispatch_inner(
        &mut self,
        timeout: Duration,
        record_event_names: bool,
    ) -> io::Result<DispatchBatch> {
        let timeout_ms = duration_to_poll_ms(timeout);
        let mut poll_fd = PollFd {
            fd: unsafe { ei_get_fd(self.context.as_ptr()) },
            events: POLLIN,
            revents: 0,
        };
        let result = unsafe { poll(&mut poll_fd, 1, timeout_ms) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result == 0 {
            return Ok(DispatchBatch::default());
        }
        unsafe { ei_dispatch(self.context.as_ptr()) };
        let mut batch = DispatchBatch::default();
        while let Some(event) = NonNull::new(unsafe { ei_get_event(self.context.as_ptr()) }) {
            let event_type = unsafe { ei_event_get_type(event.as_ptr()) };
            if record_event_names {
                let event_name = event_type_name(event_type);
                self.metadata.event_types.push(event_name.clone());
                batch.event_types.push(event_name);
            }
            self.process_metadata_event(event.as_ptr(), event_type, record_event_names);
            let decoded = decode_input_event(event.as_ptr(), event_type);
            unsafe { ei_event_unref(event.as_ptr()) };
            if let Some(input) = decoded? {
                batch.input_events.push(input);
            }
        }
        Ok(batch)
    }

    fn process_metadata_event(
        &mut self,
        event: *mut EiEvent,
        event_type: c_int,
        record_event_names: bool,
    ) {
        match event_type {
            EI_EVENT_CONNECT => self.metadata.connected = true,
            EI_EVENT_DISCONNECT => self.metadata.disconnected = true,
            EI_EVENT_SEAT_ADDED => {
                let seat = unsafe { ei_event_get_seat(event) };
                if seat.is_null() {
                    return;
                }
                let metadata = SeatMetadata {
                    name: nullable_string(unsafe { ei_seat_get_name(seat) }),
                    capabilities: capabilities(|capability| unsafe {
                        ei_seat_has_capability(seat, capability)
                    }),
                };
                self.metadata.seats.push(metadata);
                // C variadic API, terminated by a null pointer as required by
                // libei. All capabilities are metadata-only receiver interests.
                unsafe {
                    ei_seat_bind_capabilities(
                        seat,
                        CAP_POINTER,
                        CAP_KEYBOARD,
                        CAP_POINTER_ABSOLUTE,
                        CAP_TOUCH,
                        CAP_BUTTON,
                        CAP_SCROLL,
                        CAP_TEXT,
                        std::ptr::null::<c_void>(),
                    );
                }
            }
            EI_EVENT_DEVICE_ADDED => {
                let device = unsafe { ei_event_get_device(event) };
                if device.is_null() {
                    return;
                }
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
                self.metadata.devices.push(DeviceMetadata {
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
                });
            }
            EI_EVENT_DEVICE_START_EMULATING if record_event_names => {
                let sequence = unsafe { ei_event_emulating_get_sequence(event) };
                if let Some(last) = self.metadata.event_types.last_mut() {
                    last.push_str(&format!("(sequence={sequence})"));
                }
            }
            _ => {}
        }
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        unsafe {
            ei_disconnect(self.context.as_ptr());
            ei_unref(self.context.as_ptr());
        }
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
    let name = unsafe { ei_event_type_to_string(event_type) };
    if name.is_null() {
        format!("EI_EVENT_UNKNOWN({event_type})")
    } else {
        nullable_string(name)
    }
}

fn decode_input_event(event: *mut EiEvent, event_type: c_int) -> io::Result<Option<CapturedEvent>> {
    let decoded = match event_type {
        EI_EVENT_DEVICE_START_EMULATING => Some(CapturedEvent::StartEmulating {
            sequence: unsafe { ei_event_emulating_get_sequence(event) },
        }),
        EI_EVENT_DEVICE_STOP_EMULATING => Some(CapturedEvent::StopEmulating),
        EI_EVENT_FRAME => Some(CapturedEvent::Frame {
            time_micros: unsafe { ei_event_get_time(event) },
        }),
        EI_EVENT_POINTER_MOTION => {
            let dx = unsafe { ei_event_pointer_get_dx(event) };
            let dy = unsafe { ei_event_pointer_get_dy(event) };
            require_finite(dx, dy, "relative pointer")?;
            Some(CapturedEvent::RelativePointer { dx, dy })
        }
        EI_EVENT_POINTER_MOTION_ABSOLUTE => {
            let x = unsafe { ei_event_pointer_get_absolute_x(event) };
            let y = unsafe { ei_event_pointer_get_absolute_y(event) };
            require_finite(x, y, "absolute pointer")?;
            Some(CapturedEvent::AbsolutePointer { x, y })
        }
        EI_EVENT_BUTTON_BUTTON => Some(CapturedEvent::Button {
            evdev: checked_evdev(unsafe { ei_event_button_get_button(event) }, "button")?,
            pressed: unsafe { ei_event_button_get_is_press(event) },
        }),
        EI_EVENT_KEYBOARD_KEY => Some(CapturedEvent::Key {
            evdev: checked_evdev(unsafe { ei_event_keyboard_get_key(event) }, "key")?,
            pressed: unsafe { ei_event_keyboard_get_key_is_press(event) },
        }),
        EI_EVENT_SCROLL_DELTA => {
            let horizontal = unsafe { ei_event_scroll_get_dx(event) };
            let vertical = unsafe { ei_event_scroll_get_dy(event) };
            require_finite(horizontal, vertical, "scroll")?;
            Some(CapturedEvent::ScrollDelta {
                horizontal,
                vertical,
            })
        }
        EI_EVENT_SCROLL_DISCRETE => Some(CapturedEvent::ScrollDiscrete {
            horizontal: unsafe { ei_event_scroll_get_discrete_dx(event) },
            vertical: unsafe { ei_event_scroll_get_discrete_dy(event) },
        }),
        EI_EVENT_SCROLL_STOP => Some(CapturedEvent::ScrollStop {
            horizontal: unsafe { ei_event_scroll_get_stop_x(event) },
            vertical: unsafe { ei_event_scroll_get_stop_y(event) },
        }),
        EI_EVENT_SCROLL_CANCEL => Some(CapturedEvent::ScrollCancel {
            horizontal: unsafe { ei_event_scroll_get_stop_x(event) },
            vertical: unsafe { ei_event_scroll_get_stop_y(event) },
        }),
        EI_EVENT_TOUCH_DOWN | EI_EVENT_TOUCH_MOTION => {
            let (x, y) = normalized_touch_coordinates(event)?;
            let id = unsafe { ei_event_touch_get_id(event) };
            if event_type == EI_EVENT_TOUCH_DOWN {
                Some(CapturedEvent::TouchDown { id, x, y })
            } else {
                Some(CapturedEvent::TouchMotion { id, x, y })
            }
        }
        EI_EVENT_TOUCH_UP => Some(CapturedEvent::TouchUp {
            id: unsafe { ei_event_touch_get_id(event) },
            cancelled: unsafe { ei_event_touch_get_is_cancel(event) },
        }),
        _ => None,
    };
    Ok(decoded)
}

fn normalized_touch_coordinates(event: *mut EiEvent) -> io::Result<(u16, u16)> {
    let x = unsafe { ei_event_touch_get_x(event) };
    let y = unsafe { ei_event_touch_get_y(event) };
    require_finite(x, y, "touch")?;
    let device = unsafe { ei_event_get_device(event) };
    if device.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "touch event has no EIS device",
        ));
    }
    let mut region = unsafe { ei_device_get_region(device, 0) };
    for index in 1.. {
        if region.is_null() {
            break;
        }
        let origin_x = unsafe { ei_region_get_x(region) } as f64;
        let origin_y = unsafe { ei_region_get_y(region) } as f64;
        let width = unsafe { ei_region_get_width(region) } as f64;
        let height = unsafe { ei_region_get_height(region) } as f64;
        if width > 0.0
            && height > 0.0
            && x >= origin_x
            && x <= origin_x + width
            && y >= origin_y
            && y <= origin_y + height
        {
            return normalize_touch_point(x, y, origin_x, origin_y, width, height);
        }
        region = unsafe { ei_device_get_region(device, index) };
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "touch event is outside all valid EIS device regions",
    ))
}

fn normalize_touch_point(
    x: f64,
    y: f64,
    origin_x: f64,
    origin_y: f64,
    width: f64,
    height: f64,
) -> io::Result<(u16, u16)> {
    if !width.is_finite() || !height.is_finite() || width <= 0.0 || height <= 0.0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "touch region has invalid dimensions",
        ));
    }
    let normalize = |value: f64, origin: f64, span: f64| {
        (((value - origin) / span).clamp(0.0, 1.0) * f64::from(u16::MAX)).round() as u16
    };
    Ok((
        normalize(x, origin_x, width),
        normalize(y, origin_y, height),
    ))
}

fn checked_evdev(value: u32, kind: &str) -> io::Result<u16> {
    value.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("EIS {kind} code {value} exceeds the supported u16 range"),
        )
    })
}

fn require_finite(x: f64, y: f64, kind: &str) -> io::Result<()> {
    if x.is_finite() && y.is_finite() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("EIS {kind} values are not finite"),
        ))
    }
}

fn duration_to_poll_ms(duration: Duration) -> c_int {
    if duration.is_zero() {
        return 0;
    }
    duration
        .as_millis()
        .clamp(1, c_int::MAX as u128)
        .try_into()
        .unwrap_or(c_int::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_timeout_rounds_sub_millisecond_up_and_saturates() {
        assert_eq!(duration_to_poll_ms(Duration::ZERO), 0);
        assert_eq!(duration_to_poll_ms(Duration::from_nanos(1)), 1);
        assert_eq!(duration_to_poll_ms(Duration::from_millis(25)), 25);
        assert_eq!(duration_to_poll_ms(Duration::MAX), c_int::MAX);
    }

    #[test]
    fn capability_names_are_stable_and_filtered() {
        let available = CAP_POINTER | CAP_KEYBOARD | CAP_BUTTON;
        assert_eq!(
            capabilities(|capability| available & capability != 0),
            vec!["pointer", "keyboard", "button"]
        );
    }

    #[test]
    fn evdev_and_axis_validation_rejects_invalid_wire_values() {
        assert_eq!(checked_evdev(700, "key").unwrap(), 700);
        assert!(checked_evdev(u32::from(u16::MAX) + 1, "key").is_err());
        assert!(require_finite(1.0, -1.0, "motion").is_ok());
        assert!(require_finite(f64::INFINITY, 0.0, "motion").is_err());
    }

    #[test]
    fn touch_normalization_maps_a_physical_surface_to_the_full_wire_range() {
        assert_eq!(
            normalize_touch_point(10.0, 20.0, 10.0, 20.0, 160.0, 115.0).unwrap(),
            (0, 0)
        );
        assert_eq!(
            normalize_touch_point(170.0, 135.0, 10.0, 20.0, 160.0, 115.0).unwrap(),
            (u16::MAX, u16::MAX)
        );
        assert!(normalize_touch_point(0.0, 0.0, 0.0, 0.0, 0.0, 1.0).is_err());
    }
}
