//! Linux evdev capture and uinput injection for the demo.
//!
//! This module intentionally accepts only ordinary keyboard, mouse-button and
//! relative-pointer events.  Device-management events, LEDs, force feedback,
//! absolute axes and power-management keys never cross the network boundary.

use crate::protocol::WireInputEvent;
use evdev::{
    enumerate,
    uinput::{VirtualDevice, VirtualDeviceBuilder},
    AttributeSet, Device, EventType, InputEvent, Key, RelativeAxisType,
};
use std::{
    collections::BTreeSet,
    fmt, io,
    os::fd::AsRawFd,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{SyncSender, TrySendError},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const EV_SYN: u16 = 0;
const EV_KEY: u16 = 1;
const EV_REL: u16 = 2;
const SYN_REPORT: u16 = 0;

const REL_X: u16 = 0;
const REL_Y: u16 = 1;
const REL_HWHEEL: u16 = 6;
const REL_WHEEL: u16 = 8;
const REL_WHEEL_HI_RES: u16 = 11;
const REL_HWHEEL_HI_RES: u16 = 12;

const BTN_MOUSE_FIRST: u16 = 0x110;
const BTN_MOUSE_LAST: u16 = 0x117;
const BTN_TASK: u16 = 0x117;
const KERNEL_SELF_TEST_TIMEOUT: Duration = Duration::from_secs(2);

// Linux fcntl values are stable ABI constants. evdev 0.12 exposes the device
// fd but does not offer a set_nonblocking helper of its own.
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const O_NONBLOCK: i32 = 0x800;

/// A capture candidate shown by the `devices` CLI command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputDeviceInfo {
    pub path: PathBuf,
    pub name: String,
}

pub fn list_input_devices() -> Vec<InputDeviceInfo> {
    enumerate()
        .map(|(path, device)| InputDeviceInfo {
            path,
            name: device.name().unwrap_or("unnamed input device").to_owned(),
        })
        .collect()
}

unsafe extern "C" {
    fn fcntl(fd: i32, command: i32, ...) -> i32;
}

fn set_nonblocking(device: &Device) -> io::Result<()> {
    let fd = device.as_raw_fd();
    // SAFETY: fd is owned by `device`, remains live for both calls, F_GETFL
    // takes no variadic argument, and F_SETFL takes one integer argument.
    let flags = unsafe { fcntl(fd, F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    let result = unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Evidence returned after a real uinput -> evdev -> uinput -> evdev round trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelSelfTestReport {
    pub source_node: PathBuf,
    pub receiver_node: PathBuf,
    pub observed_events: usize,
}

/// Temporary uinput source used to exercise the real host capture path.
pub struct KernelTestSource {
    device: VirtualDevice,
    event_node: PathBuf,
}

impl KernelTestSource {
    pub fn create() -> io::Result<Self> {
        let mut relative_x = AttributeSet::<RelativeAxisType>::new();
        relative_x.insert(RelativeAxisType::REL_X);
        let mut device = VirtualDeviceBuilder::new()?
            .name("CachyBridge kernel test source")
            .with_relative_axes(&relative_x)?
            .build()?;
        let event_node = first_event_node(&mut device, "test source")?;
        Ok(Self { device, event_node })
    }

    pub fn event_node(&self) -> &std::path::Path {
        &self.event_node
    }

    pub fn emit_net_zero_report(&mut self) -> io::Result<()> {
        self.device.emit(&[
            InputEvent::new(EventType(EV_REL), REL_X, 1),
            InputEvent::new(EventType(EV_REL), REL_X, -1),
        ])
    }
}

impl fmt::Display for KernelSelfTestReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "kernel input self-test passed: source={} receiver={} observed_events={}",
            self.source_node.display(),
            self.receiver_node.display(),
            self.observed_events
        )
    }
}

/// Exercises the complete local kernel path with a net-zero mouse report.
///
/// This diagnostic requires permission to create `/dev/uinput` devices and to
/// read their `/dev/input/event*` nodes. It creates a source that emits +1 and
/// -1 REL_X in one frame, captures and injects that frame through the normal
/// production types, and observes the net-zero report on the receiver node.
pub fn run_kernel_self_test() -> io::Result<KernelSelfTestReport> {
    let mut relative_x = AttributeSet::<RelativeAxisType>::new();
    relative_x.insert(RelativeAxisType::REL_X);
    let mut source = VirtualDeviceBuilder::new()?
        .name("CachyBridge kernel self-test source")
        .with_relative_axes(&relative_x)?
        .build()?;
    let source_event_node = first_event_node(&mut source, "source")?;

    let mut receiver = UInputSink::new()?;
    let receiver_event_node = first_event_node(&mut receiver.device, "receiver")?;
    let mut observer = Device::open(&receiver_event_node)?;
    set_nonblocking(&observer)?;

    let (tx, rx) = std::sync::mpsc::sync_channel(32);
    let capture = start_capture(std::slice::from_ref(&source_event_node), false, tx)?;

    let test_result = (|| {
        // VirtualDevice::emit appends SYN_REPORT. The two deltas cancel within
        // the same report, avoiding any net visible pointer movement.
        source.emit(&[
            InputEvent::new(EventType(EV_REL), REL_X, 1),
            InputEvent::new(EventType(EV_REL), REL_X, -1),
        ])?;

        let capture_deadline = Instant::now() + KERNEL_SELF_TEST_TIMEOUT;
        let mut forwarded_positive_x = false;
        let mut forwarded_negative_x = false;
        let mut forwarded_syn = false;
        while !(forwarded_positive_x && forwarded_negative_x && forwarded_syn) {
            let remaining = capture_deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| timed_out("capturing the source uinput report"))?;
            let event = rx.recv_timeout(remaining).map_err(|error| match error {
                std::sync::mpsc::RecvTimeoutError::Timeout => {
                    timed_out("capturing the source uinput report")
                }
                std::sync::mpsc::RecvTimeoutError::Disconnected => io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "capture worker stopped during kernel self-test",
                ),
            })?;
            forwarded_positive_x |=
                event.event_type == EV_REL && event.code == REL_X && event.value == 1;
            forwarded_negative_x |=
                event.event_type == EV_REL && event.code == REL_X && event.value == -1;
            forwarded_syn |= event.event_type == EV_SYN && event.code == SYN_REPORT;
            receiver.inject(event)?;
        }

        let observe_deadline = Instant::now() + KERNEL_SELF_TEST_TIMEOUT;
        let mut observed_event_count = 0;
        let mut observed_positive_x = false;
        let mut observed_negative_x = false;
        let mut observed_syn = false;
        while !(observed_positive_x && observed_negative_x && observed_syn) {
            match observer.fetch_events() {
                Ok(events) => {
                    for event in events {
                        observed_event_count += 1;
                        observed_positive_x |= event.event_type().0 == EV_REL
                            && event.code() == REL_X
                            && event.value() == 1;
                        observed_negative_x |= event.event_type().0 == EV_REL
                            && event.code() == REL_X
                            && event.value() == -1;
                        observed_syn |= event.event_type().0 == EV_SYN
                            && event.code() == SYN_REPORT
                            && event.value() == 0;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            if observed_positive_x && observed_negative_x && observed_syn {
                break;
            }
            if Instant::now() >= observe_deadline {
                return Err(timed_out("observing the receiver uinput report"));
            }
            thread::sleep(Duration::from_millis(2));
        }

        Ok(KernelSelfTestReport {
            source_node: source_event_node.clone(),
            receiver_node: receiver_event_node.clone(),
            observed_events: observed_event_count,
        })
    })();

    // Cleanup is explicit so optional grabs and all virtual-device state are
    // gone before the diagnostic returns, including every failure path.
    let release_result = receiver.release_all();
    let shutdown_result = capture.shutdown();
    match test_result {
        Err(error) => Err(error),
        Ok(_) if release_result.is_err() => Err(release_result.unwrap_err()),
        Ok(_) if shutdown_result.is_err() => Err(shutdown_result.unwrap_err()),
        Ok(report) => Ok(report),
    }
}

fn first_event_node(device: &mut VirtualDevice, role: &str) -> io::Result<PathBuf> {
    device
        .enumerate_dev_nodes_blocking()?
        .next()
        .transpose()?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("uinput {role} did not expose an event node"),
            )
        })
}

fn timed_out(action: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("timed out while {action}"))
}

/// Owns the capture threads. Dropping the handle requests a prompt stop.
/// `shutdown` additionally waits for every input device to be ungrabbed.
pub struct CaptureHandle {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<io::Result<()>>>,
}

impl CaptureHandle {
    pub fn shutdown(mut self) -> io::Result<()> {
        self.stop.store(true, Ordering::Release);
        let mut first_error = None;
        for worker in self.threads.drain(..) {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) if first_error.is_none() => first_error = Some(error),
                Err(_) if first_error.is_none() => {
                    first_error = Some(io::Error::other("input capture thread panicked"));
                }
                _ => {}
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

/// Opens all requested evdev devices before starting any worker.
///
/// The supplied `SyncSender` is expected to come from a bounded `sync_channel`.
/// If that queue is full, capture stops instead of silently dropping an ordered
/// key/button transition. The receiver's normal disconnect path must then call
/// `InputSink::release_all`.
pub fn start_capture(
    paths: &[PathBuf],
    grab: bool,
    tx: SyncSender<WireInputEvent>,
) -> io::Result<CaptureHandle> {
    if paths.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "at least one /dev/input/event device is required",
        ));
    }

    let mut devices = Vec::with_capacity(paths.len());
    for path in paths {
        let mut device = Device::open(path).map_err(|error| {
            io::Error::new(error.kind(), format!("open {}: {error}", path.display()))
        })?;
        set_nonblocking(&device)?;
        if grab {
            device.grab().map_err(|error| {
                io::Error::new(error.kind(), format!("grab {}: {error}", path.display()))
            })?;
        }
        devices.push((path.clone(), device));
    }

    let stop = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::with_capacity(devices.len());
    for (path, device) in devices {
        let worker_stop = Arc::clone(&stop);
        let worker_tx = tx.clone();
        threads.push(
            thread::Builder::new()
                .name(format!("evdev:{}", path.display()))
                .spawn(move || capture_device(device, worker_stop, worker_tx))?,
        );
    }

    Ok(CaptureHandle { stop, threads })
}

fn capture_device(
    mut device: Device,
    stop: Arc<AtomicBool>,
    tx: SyncSender<WireInputEvent>,
) -> io::Result<()> {
    while !stop.load(Ordering::Acquire) {
        match device.fetch_events() {
            Ok(events) => {
                for event in events {
                    if let Some(event) = to_wire_event(&event) {
                        match tx.try_send(event) {
                            Ok(()) => {}
                            Err(TrySendError::Full(_)) => {
                                stop.store(true, Ordering::Release);
                                return Err(io::Error::new(
                                    io::ErrorKind::WouldBlock,
                                    "bounded input queue is full",
                                ));
                            }
                            Err(TrySendError::Disconnected(_)) => return Ok(()),
                        }
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn to_wire_event(event: &InputEvent) -> Option<WireInputEvent> {
    let event_type = event.event_type().0;
    let code = event.code();
    let value = event.value();
    if !is_allowed_event(event_type, code, value) {
        return None;
    }
    Some(WireInputEvent {
        event_type,
        code,
        value,
    })
}

/// A receiver for already authenticated, decoded wire events.
pub trait InputSink: Send {
    fn inject(&mut self, event: WireInputEvent) -> io::Result<()>;
    fn release_all(&mut self) -> io::Result<()>;
}

/// Creates a real combined keyboard/relative-mouse uinput device, or a sink
/// that performs the same validation/state tracking without touching uinput.
pub fn create_sink(dry_run: bool) -> io::Result<Box<dyn InputSink>> {
    if dry_run {
        return Ok(Box::new(DryRunSink::default()));
    }
    Ok(Box::new(UInputSink::new()?))
}

struct UInputSink {
    device: VirtualDevice,
    state: SinkState,
}

impl UInputSink {
    fn new() -> io::Result<Self> {
        let mut keys = AttributeSet::<Key>::new();
        for code in 0..=0x2ff {
            if is_allowed_key_code(code) {
                keys.insert(Key::new(code));
            }
        }

        let mut relative_axes = AttributeSet::<RelativeAxisType>::new();
        for code in [
            REL_X,
            REL_Y,
            REL_HWHEEL,
            REL_WHEEL,
            REL_WHEEL_HI_RES,
            REL_HWHEEL_HI_RES,
        ] {
            relative_axes.insert(RelativeAxisType(code));
        }

        let device = VirtualDeviceBuilder::new()?
            .name("CachyBridge virtual keyboard and mouse")
            .with_keys(&keys)?
            .with_relative_axes(&relative_axes)?
            .build()?;
        Ok(Self {
            device,
            state: SinkState::default(),
        })
    }

    fn emit_frame(&mut self, frame: &[InputEvent]) -> io::Result<()> {
        self.device.emit(frame)
    }
}

impl InputSink for UInputSink {
    fn inject(&mut self, event: WireInputEvent) -> io::Result<()> {
        let frame = self.state.accept(event)?;
        if let Some(frame) = frame {
            self.emit_frame(&frame.events)?;
            self.state.commit(frame);
        }
        Ok(())
    }

    fn release_all(&mut self) -> io::Result<()> {
        self.state.pending.clear();
        let frame = self.state.release_frame();
        if !frame.is_empty() {
            self.emit_frame(&frame)?;
            self.state.pressed.clear();
        }
        Ok(())
    }
}

#[derive(Default)]
struct DryRunSink {
    state: SinkState,
    #[cfg(test)]
    emitted: Vec<Vec<InputEvent>>,
}

impl InputSink for DryRunSink {
    fn inject(&mut self, event: WireInputEvent) -> io::Result<()> {
        if let Some(frame) = self.state.accept(event)? {
            #[cfg(test)]
            self.emitted.push(frame.events.clone());
            self.state.commit(frame);
        }
        Ok(())
    }

    fn release_all(&mut self) -> io::Result<()> {
        self.state.pending.clear();
        #[cfg(test)]
        {
            let releases = self.state.release_frame();
            if !releases.is_empty() {
                self.emitted.push(releases);
            }
        }
        self.state.pressed.clear();
        Ok(())
    }
}

#[derive(Default)]
struct SinkState {
    pending: Vec<InputEvent>,
    pressed: BTreeSet<u16>,
}

struct PendingFrame {
    events: Vec<InputEvent>,
    next_pressed: BTreeSet<u16>,
}

impl SinkState {
    fn accept(&mut self, event: WireInputEvent) -> io::Result<Option<PendingFrame>> {
        if !is_allowed_event(event.event_type, event.code, event.value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "refusing input event type={} code={} value={}",
                    event.event_type, event.code, event.value
                ),
            ));
        }

        if event.event_type == EV_SYN {
            let events = std::mem::take(&mut self.pending);
            let mut next_pressed = self.pressed.clone();
            for event in &events {
                if event.event_type().0 == EV_KEY {
                    match event.value() {
                        0 => {
                            next_pressed.remove(&event.code());
                        }
                        1 => {
                            next_pressed.insert(event.code());
                        }
                        _ => {}
                    }
                }
            }
            return Ok(Some(PendingFrame {
                events,
                next_pressed,
            }));
        }

        // VirtualDevice::emit appends exactly one SYN_REPORT to this buffered
        // frame, preserving the sender's report boundaries.
        self.pending.push(InputEvent::new(
            EventType(event.event_type),
            event.code,
            event.value,
        ));
        Ok(None)
    }

    fn commit(&mut self, frame: PendingFrame) {
        self.pressed = frame.next_pressed;
    }

    fn release_frame(&self) -> Vec<InputEvent> {
        self.pressed
            .iter()
            .map(|code| InputEvent::new(EventType(EV_KEY), *code, 0))
            .collect()
    }
}

fn is_allowed_event(event_type: u16, code: u16, value: i32) -> bool {
    match event_type {
        EV_SYN => code == SYN_REPORT && value == 0,
        EV_KEY => is_allowed_key_code(code) && matches!(value, 0..=2),
        EV_REL => is_allowed_relative_code(code),
        _ => false,
    }
}

fn is_allowed_relative_code(code: u16) -> bool {
    matches!(
        code,
        REL_X | REL_Y | REL_HWHEEL | REL_WHEEL | REL_WHEEL_HI_RES | REL_HWHEEL_HI_RES
    )
}

fn is_allowed_key_code(code: u16) -> bool {
    // Standard PC keyboard controls, excluding power/sleep/wakeup.
    matches!(code, 1..=115 | 117..=140 | 150..=204 | 206..=246 | 248)
        // Only ordinary mouse buttons; tablet, joystick and gamepad controls
        // are deliberately outside the demo's capability surface.
        || matches!(code, BTN_MOUSE_FIRST..=BTN_MOUSE_LAST)
        || code == BTN_TASK
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(event_type: u16, code: u16, value: i32) -> WireInputEvent {
        WireInputEvent {
            event_type,
            code,
            value,
        }
    }

    #[test]
    fn rejects_non_input_and_power_management_events() {
        assert!(!is_allowed_event(3, 0, 1)); // EV_ABS
        assert!(!is_allowed_event(EV_KEY, 116, 1)); // KEY_POWER
        assert!(!is_allowed_event(EV_KEY, 142, 1)); // KEY_SLEEP
        assert!(!is_allowed_event(EV_SYN, 3, 0)); // SYN_DROPPED
        assert!(is_allowed_event(EV_REL, REL_X, -42));
        assert!(is_allowed_event(EV_KEY, 30, 1)); // KEY_A
        assert!(is_allowed_event(EV_KEY, 272, 1)); // BTN_LEFT
    }

    #[test]
    fn dry_run_preserves_syn_framing() {
        let mut sink = DryRunSink::default();
        sink.inject(wire(EV_KEY, 30, 1)).unwrap();
        sink.inject(wire(EV_REL, REL_X, 7)).unwrap();
        assert!(sink.emitted.is_empty());

        sink.inject(wire(EV_SYN, SYN_REPORT, 0)).unwrap();
        assert_eq!(sink.emitted.len(), 1);
        assert_eq!(sink.emitted[0].len(), 2);
        assert!(sink.state.pressed.contains(&30));
    }

    #[test]
    fn release_all_emits_releases_and_discards_partial_frame() {
        let mut sink = DryRunSink::default();
        sink.inject(wire(EV_KEY, 30, 1)).unwrap();
        sink.inject(wire(EV_KEY, 272, 1)).unwrap();
        sink.inject(wire(EV_SYN, SYN_REPORT, 0)).unwrap();
        sink.inject(wire(EV_KEY, 48, 1)).unwrap(); // no SYN, never applied

        sink.release_all().unwrap();
        assert!(sink.state.pressed.is_empty());
        assert!(sink.state.pending.is_empty());
        let releases = sink.emitted.last().unwrap();
        assert_eq!(releases.len(), 2);
        assert!(releases.iter().all(|event| event.value() == 0));
        assert!(releases.iter().any(|event| event.code() == 30));
        assert!(releases.iter().any(|event| event.code() == 272));
    }

    #[test]
    fn invalid_wire_event_is_rejected_without_mutating_pending_frame() {
        let mut sink = DryRunSink::default();
        sink.inject(wire(EV_KEY, 30, 1)).unwrap();
        let result = sink.inject(wire(0x15, 1, 1));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(sink.state.pending.len(), 1);
    }
}
