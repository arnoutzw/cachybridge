//! Transport/controller orchestration for the portal-backed seamless modes.
//!
//! This module has no portal or libei FFI. The platform layer implements the
//! small traits below, while this code enforces the network ordering invariant:
//! an authenticated `EnterAck` is required before any `Input` is sent or
//! injected, and every close/error path first releases local/remote input.

use std::{
    collections::{BTreeMap, VecDeque},
    io,
    os::fd::AsRawFd,
    path::PathBuf,
    time::{Duration, Instant},
};

use evdev::{enumerate, AbsoluteAxisType, Device};
use thiserror::Error;

use crate::{
    handoff::{HandoffAction, HandoffController, HandoffState, Point},
    protocol::{Message, TouchPhase, WireEdge, WireInputEvent, WireTouchEvent},
    transport::{SecureConnection, TransportError},
};

/// Adapter for the consent-driven RemoteDesktop session. Current portal APIs
/// provide relative virtual pointer injection; the requested entry point is
/// retained for handoff accounting but cannot yet be placed absolutely without
/// a ScreenCast coordinate mapping.
pub struct RemoteDesktopInjector {
    session: crate::remote_spike::RemoteDesktopSession,
    entry: Option<Point>,
    injection_timing: FrameTiming,
}

/// Adapter from the reusable InputCapture session and typed libei receiver to
/// the existing evdev-shaped encrypted protocol. It owns the portal activation
/// ID so every stop path can issue the matching portal `Release` before
/// disabling capture.
pub struct InputCaptureAdapter {
    session: crate::portal_spike::InputCaptureSession,
    local_edge_x: i32,
    active_activation: Option<u32>,
    /// A successful portal `Release` emits `Deactivated` asynchronously. It
    /// is the normal end of a handoff, not a lost capture session; consume
    /// exactly that signal before waiting for the next edge activation.
    pending_release_deactivation: Option<u32>,
    absolute_motion: AbsoluteMotionTracker,
    /// One coalesced relative move per receiver dispatch. Buttons, keys and
    /// scrolling stay ordered and uncoalesced; pointer motion is safe to
    /// batch and avoids a burst of individually framed network packets.
    pending_motion: (i32, i32),
    /// A source compositor may report the same physical scroll both as a
    /// smooth pixel delta and as a 120-unit wheel click before its Frame.
    /// Smooth data is authoritative, so suppress that duplicate click.
    smooth_scroll_axes: (bool, bool),
    pinch_zoom: PinchZoomTracker,
    /// KWin consumes Magic Trackpad contacts as gestures before they reach
    /// InputCapture. Read the trackpad's multitouch stream directly so a
    /// pinch remains available while the pointer is on the paired desktop.
    raw_trackpad_pinch: Option<RawTrackpadPinchCapture>,
    capture_timing: FrameTiming,
    pending: VecDeque<CapturedInput>,
}

/// Rolling frame-time report for the actual input stream. This follows the
/// same convention as game frame diagnostics: cadence, latest, average,
/// percentiles, and two useful jank thresholds are reported once per second.
#[derive(Debug)]
struct FrameTiming {
    label: &'static str,
    window_started: Instant,
    last_sample: Option<Instant>,
    intervals_ms: VecDeque<f64>,
    events: u64,
    idle_gaps: u64,
    series_path: Option<PathBuf>,
    last_series_publish: Instant,
}

impl FrameTiming {
    const HISTORY: usize = 240;

    fn new(label: &'static str) -> Self {
        Self {
            label,
            window_started: Instant::now(),
            last_sample: None,
            intervals_ms: VecDeque::with_capacity(Self::HISTORY),
            events: 0,
            idle_gaps: 0,
            series_path: diagnostics_series_path(label),
            last_series_publish: Instant::now(),
        }
    }

    fn record(&mut self) {
        let now = Instant::now();
        if let Some(previous) = self.last_sample.replace(now) {
            let interval_ms = now.duration_since(previous).as_secs_f64() * 1_000.0;
            // A stopped pointer is not a dropped frame. Keep its return as an
            // explicit idle gap and only percentile contiguous active input.
            if interval_ms <= 250.0 {
                push_timing_sample(&mut self.intervals_ms, interval_ms, Self::HISTORY);
            } else {
                self.idle_gaps += 1;
            }
        }
        self.events += 1;
        if !self.intervals_ms.is_empty()
            && self.last_series_publish.elapsed() >= Duration::from_millis(16)
        {
            self.publish_series();
            self.last_series_publish = now;
        }
        let elapsed = self.window_started.elapsed();
        if elapsed >= Duration::from_secs(1) && !self.intervals_ms.is_empty() {
            let summary = TimingSummary::from_samples(&self.intervals_ms);
            eprintln!(
                "diagnostics {}: rate={:.1}Hz frame_ms latest={:.2} avg={:.2} p50={:.2} p95={:.2} p99={:.2} max={:.2} jank>8.33ms={} jank>16.67ms={} idle_gaps={} samples={}",
                self.label,
                self.events as f64 / elapsed.as_secs_f64(),
                summary.latest,
                summary.average,
                summary.p50,
                summary.p95,
                summary.p99,
                summary.max,
                summary.jank_120,
                summary.jank_60,
                self.idle_gaps,
                self.intervals_ms.len(),
            );
            self.window_started = now;
            self.events = 0;
            self.idle_gaps = 0;
        }
    }

    fn publish_series(&self) {
        let Some(path) = &self.series_path else {
            return;
        };
        let series = self
            .intervals_ms
            .iter()
            .map(|milliseconds| format!("{milliseconds:.3}"))
            .collect::<Vec<_>>()
            .join(",");
        let temporary = path.with_extension("tmp");
        if std::fs::write(&temporary, series)
            .and_then(|()| std::fs::rename(&temporary, path))
            .is_err()
        {
            // Performance telemetry is optional and must never interfere with
            // input forwarding if the runtime directory vanishes mid-session.
        }
    }
}

fn diagnostics_series_path(label: &str) -> Option<PathBuf> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")?;
    let directory = PathBuf::from(runtime).join("cachybridge");
    if std::fs::create_dir_all(&directory).is_err() {
        return None;
    }
    Some(directory.join(format!("frame-times-{label}.csv")))
}

#[derive(Debug, Clone, Copy)]
struct TimingSummary {
    latest: f64,
    average: f64,
    p50: f64,
    p95: f64,
    p99: f64,
    max: f64,
    jank_120: usize,
    jank_60: usize,
}

impl TimingSummary {
    fn from_samples(samples: &VecDeque<f64>) -> Self {
        let mut sorted = samples.iter().copied().collect::<Vec<_>>();
        sorted.sort_by(f64::total_cmp);
        let percentile =
            |percent: f64| sorted[((sorted.len() - 1) as f64 * percent).round() as usize];
        Self {
            latest: *samples.back().expect("non-empty timing history"),
            average: sorted.iter().sum::<f64>() / sorted.len() as f64,
            p50: percentile(0.50),
            p95: percentile(0.95),
            p99: percentile(0.99),
            max: *sorted.last().expect("non-empty timing history"),
            jank_120: sorted.iter().filter(|&&ms| ms > 8.33).count(),
            jank_60: sorted.iter().filter(|&&ms| ms > 16.67).count(),
        }
    }
}

fn push_timing_sample(samples: &mut VecDeque<f64>, sample_ms: f64, limit: usize) {
    if samples.len() == limit {
        samples.pop_front();
    }
    samples.push_back(sample_ms);
}

#[derive(Debug)]
struct LatencyTiming {
    samples_ms: VecDeque<f64>,
    last_report: Instant,
}

impl LatencyTiming {
    fn new() -> Self {
        Self {
            samples_ms: VecDeque::with_capacity(FrameTiming::HISTORY),
            last_report: Instant::now(),
        }
    }

    fn record(&mut self, duration: Duration) {
        push_timing_sample(
            &mut self.samples_ms,
            duration.as_secs_f64() * 1_000.0,
            FrameTiming::HISTORY,
        );
        if self.last_report.elapsed() >= Duration::from_secs(1) {
            let summary = TimingSummary::from_samples(&self.samples_ms);
            eprintln!(
                "diagnostics round_trip: latest={:.2}ms avg={:.2}ms p50={:.2}ms p95={:.2}ms p99={:.2}ms max={:.2}ms samples={}",
                summary.latest,
                summary.average,
                summary.p50,
                summary.p95,
                summary.p99,
                summary.max,
                self.samples_ms.len(),
            );
            self.last_report = Instant::now();
        }
    }
}

/// Typed input leaving the portal capture adapter. Pointer motion has its own
/// paired form so a diagonal source update remains a single remote EIS frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturedInput {
    Motion { dx: i32, dy: i32 },
    Event(WireInputEvent),
    Touch(WireTouchEvent),
}

/// Watches the controlled client's outer InputCapture barrier. It is separate
/// from RemoteDesktop injection because a return request is a local portal
/// activation, not a network input event.
pub struct EdgeReturnWatcher {
    session: crate::portal_spike::InputCaptureSession,
    edge: WireEdge,
    wire_y_offset: i32,
}

impl EdgeReturnWatcher {
    pub fn start(edge: WireEdge, wire_y_offset: i32) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            session: crate::portal_spike::InputCaptureSession::start(
                capture_edge(edge),
                crate::portal_spike::CaptureCapabilities::PointerOnly,
            )?,
            edge,
            wire_y_offset,
        })
    }

    pub fn start_with_persistence(
        edge: WireEdge,
        wire_y_offset: i32,
        persistence: crate::portal_persistence::PortalPersistence,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            session: crate::portal_spike::InputCaptureSession::start_with_persistence(
                capture_edge(edge),
                crate::portal_spike::CaptureCapabilities::PointerOnly,
                persistence,
            )?,
            edge,
            wire_y_offset,
        })
    }

    pub fn take_restore_token(&mut self) -> Option<crate::portal_persistence::RestoreToken> {
        self.session.take_restore_token()
    }

    /// Polls the target's outer barrier. On activation it releases the exact
    /// target capture before handing its edge and y position to transport.
    pub fn poll_exit(&mut self) -> io::Result<Option<(WireEdge, i32)>> {
        match self.session.poll_signal(Duration::ZERO)? {
            Some(crate::portal_spike::CaptureSignal::Activated {
                activation_id,
                cursor_position: Some((x, y)),
                ..
            }) if x.is_finite() && y.is_finite() => {
                self.session
                    .release(activation_id, None)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                Ok(Some((
                    self.edge,
                    rounded_coordinate(y)?
                        .checked_add(self.wire_y_offset)
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "return cursor y overflow")
                        })?,
                )))
            }
            Some(crate::portal_spike::CaptureSignal::Activated { .. }) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "edge activation omitted a finite cursor position",
            )),
            // Release intentionally produces a Deactivated signal. It is the
            // expected completion of a right-edge return, not a reason to
            // tear down a session that is meant to re-arm indefinitely.
            Some(crate::portal_spike::CaptureSignal::Deactivated { .. }) => Ok(None),
            Some(crate::portal_spike::CaptureSignal::Disabled) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "right InputCapture session ended",
            )),
            Some(_) | None => Ok(None),
        }
    }

    pub fn close(&mut self) -> io::Result<()> {
        self.session
            .close()
            .map_err(|error| io::Error::other(error.to_string()))
    }
}

fn capture_edge(edge: WireEdge) -> crate::portal_spike::CaptureEdge {
    match edge {
        WireEdge::Left => crate::portal_spike::CaptureEdge::Left,
        WireEdge::Right => crate::portal_spike::CaptureEdge::Right,
    }
}

const MAX_ABSOLUTE_DELTA: f64 = 2_048.0;

/// Turns an EIS absolute-pointer stream into the relative motion supported by
/// the current encrypted input frame. The first coordinate establishes an
/// origin; it never moves the remote pointer. Deltas are independently bounded
/// to prevent an output-layout reset from jumping across a desktop.
#[derive(Debug, Default)]
struct AbsoluteMotionTracker {
    previous: Option<(f64, f64)>,
    remainder: (f64, f64),
}

impl AbsoluteMotionTracker {
    fn reset(&mut self) {
        self.previous = None;
        self.remainder = (0.0, 0.0);
    }

    fn update(&mut self, x: f64, y: f64) -> io::Result<Option<(i32, i32)>> {
        if !x.is_finite() || !y.is_finite() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "absolute pointer coordinates must be finite",
            ));
        }
        let Some((previous_x, previous_y)) = self.previous.replace((x, y)) else {
            self.remainder = (0.0, 0.0);
            return Ok(None);
        };
        let dx = (x - previous_x + self.remainder.0).clamp(-MAX_ABSOLUTE_DELTA, MAX_ABSOLUTE_DELTA);
        let dy = (y - previous_y + self.remainder.1).clamp(-MAX_ABSOLUTE_DELTA, MAX_ABSOLUTE_DELTA);
        let integer_dx = rounded_delta(dx)?;
        let integer_dy = rounded_delta(dy)?;
        // Retain fractional motion only when it was not safety-clamped.
        self.remainder = (
            if dx.abs() < MAX_ABSOLUTE_DELTA {
                dx - f64::from(integer_dx)
            } else {
                0.0
            },
            if dy.abs() < MAX_ABSOLUTE_DELTA {
                dy - f64::from(integer_dy)
            } else {
                0.0
            },
        );
        Ok(Some((integer_dx, integer_dy)))
    }
}

/// Converts two-finger Magic Trackpad distance changes into Ctrl+scroll zoom
/// input. This is the desktop-native zoom convention used by browsers, Qt,
/// GTK, and most document viewers. The original touch contacts still travel
/// over the encrypted touch path for applications that consume touchscreen
/// input directly.
#[derive(Debug, Default)]
struct PinchZoomTracker {
    contacts: BTreeMap<u32, (u16, u16)>,
    previous_distance: Option<f64>,
    accumulated_distance: f64,
    control_held: bool,
}

impl PinchZoomTracker {
    const STEP_DISTANCE: f64 = 1_200.0;
    const EV_KEY: u16 = 1;
    const EV_REL: u16 = 2;
    const KEY_LEFTCTRL: u16 = 29;
    const REL_WHEEL: u16 = 8;

    fn down(&mut self, id: u32, x: u16, y: u16) -> Vec<WireInputEvent> {
        self.contacts.insert(id, (x, y));
        self.reset_reference_if_needed()
    }

    fn motion(&mut self, id: u32, x: u16, y: u16) -> Vec<WireInputEvent> {
        let Some(contact) = self.contacts.get_mut(&id) else {
            return Vec::new();
        };
        *contact = (x, y);
        let Some(distance) = self.distance() else {
            return self.reset_reference_if_needed();
        };
        let Some(previous) = self.previous_distance.replace(distance) else {
            return Vec::new();
        };
        self.accumulated_distance += distance - previous;
        let steps = (self.accumulated_distance / Self::STEP_DISTANCE).trunc() as i32;
        if steps == 0 {
            return Vec::new();
        }
        self.accumulated_distance -= f64::from(steps) * Self::STEP_DISTANCE;
        let mut events = Vec::with_capacity(2);
        if !self.control_held {
            self.control_held = true;
            events.push(Self::event(Self::EV_KEY, Self::KEY_LEFTCTRL, 1));
        }
        events.push(Self::event(Self::EV_REL, Self::REL_WHEEL, steps * 120));
        events
    }

    fn up(&mut self, id: u32) -> Vec<WireInputEvent> {
        self.contacts.remove(&id);
        let mut events = self.reset_reference_if_needed();
        if self.contacts.len() < 2 && self.control_held {
            self.control_held = false;
            events.push(Self::event(Self::EV_KEY, Self::KEY_LEFTCTRL, 0));
        }
        events
    }

    fn distance(&self) -> Option<f64> {
        if self.contacts.len() != 2 {
            return None;
        }
        let mut contacts = self.contacts.values();
        let (first_x, first_y) = *contacts.next().expect("two contacts are present");
        let (second_x, second_y) = *contacts.next().expect("two contacts are present");
        let dx = f64::from(i32::from(first_x) - i32::from(second_x));
        let dy = f64::from(i32::from(first_y) - i32::from(second_y));
        Some(dx.hypot(dy))
    }

    fn reset_reference_if_needed(&mut self) -> Vec<WireInputEvent> {
        if let Some(distance) = self.distance() {
            self.previous_distance = Some(distance);
            self.accumulated_distance = 0.0;
        } else {
            self.previous_distance = None;
            self.accumulated_distance = 0.0;
        }
        Vec::new()
    }

    const fn event(event_type: u16, code: u16, value: i32) -> WireInputEvent {
        WireInputEvent {
            event_type,
            code,
            value,
        }
    }
}

const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const O_NONBLOCK: i32 = 0x800;
const RAW_TRACKPAD_POLL_INTERVAL: Duration = Duration::from_millis(8);

unsafe extern "C" {
    fn fcntl(fd: i32, command: i32, ...) -> i32;
}

#[derive(Debug, Default)]
struct RawTrackpadContact {
    id: Option<u32>,
    x: Option<i32>,
    y: Option<i32>,
    forwarded: bool,
}

/// Magic Trackpad's raw ABS_MT contacts. This supplements the portal path;
/// it never grabs the device or forwards pointer/button data, so Plasma keeps
/// full local ownership until a normal edge handoff is active.
struct RawTrackpadPinchCapture {
    device: Device,
    current_slot: usize,
    contacts: BTreeMap<usize, RawTrackpadContact>,
    x_range: (i32, i32),
    y_range: (i32, i32),
    pinch: PinchZoomTracker,
}

impl RawTrackpadPinchCapture {
    fn open() -> io::Result<Option<Self>> {
        let Some((path, device)) = enumerate().find(|(_, device)| {
            device
                .name()
                .is_some_and(|name| name.to_ascii_lowercase().contains("magic trackpad"))
        }) else {
            return Ok(None);
        };
        set_nonblocking(&device)?;
        let axes = device.get_abs_state()?;
        let x = axes[usize::from(AbsoluteAxisType::ABS_MT_POSITION_X.0)];
        let y = axes[usize::from(AbsoluteAxisType::ABS_MT_POSITION_Y.0)];
        if x.maximum <= x.minimum || y.maximum <= y.minimum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} has invalid multitouch coordinate ranges",
                    path.display()
                ),
            ));
        }
        eprintln!(
            "pinch zoom: direct Magic Trackpad capture enabled ({})",
            path.display()
        );
        Ok(Some(Self {
            device,
            current_slot: 0,
            contacts: BTreeMap::new(),
            x_range: (x.minimum, x.maximum),
            y_range: (y.minimum, y.maximum),
            pinch: PinchZoomTracker::default(),
        }))
    }

    fn reset(&mut self) -> io::Result<()> {
        // Do not treat fingers that were already down before the edge crossing
        // as a new remote gesture. Empty the non-grabbed kernel ring first.
        loop {
            match self.device.fetch_events() {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        self.current_slot = 0;
        self.contacts.clear();
        self.pinch = PinchZoomTracker::default();
        Ok(())
    }

    fn drain(&mut self) -> io::Result<Vec<WireInputEvent>> {
        let mut output = Vec::new();
        loop {
            let events = match self.device.fetch_events() {
                Ok(events) => events
                    .map(|event| (event.event_type().0, event.code(), event.value()))
                    .collect::<Vec<_>>(),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(output),
                Err(error) => return Err(error),
            };
            for (event_type, code, value) in events {
                // Never mistake a touchpad button/key event for an absolute
                // axis merely because Linux input codes share the same range.
                if event_type == 3 {
                    self.process(code, value, &mut output);
                }
            }
        }
    }

    fn process(&mut self, code: u16, value: i32, output: &mut Vec<WireInputEvent>) {
        const ABS_MT_SLOT: u16 = AbsoluteAxisType::ABS_MT_SLOT.0;
        const ABS_MT_POSITION_X: u16 = AbsoluteAxisType::ABS_MT_POSITION_X.0;
        const ABS_MT_POSITION_Y: u16 = AbsoluteAxisType::ABS_MT_POSITION_Y.0;
        const ABS_MT_TRACKING_ID: u16 = AbsoluteAxisType::ABS_MT_TRACKING_ID.0;

        match code {
            ABS_MT_SLOT if value >= 0 => self.current_slot = value as usize,
            ABS_MT_TRACKING_ID if value < 0 => {
                if let Some(contact) = self.contacts.remove(&self.current_slot) {
                    if contact.forwarded {
                        output.extend(self.pinch.up(contact.id.expect("forwarded contact has id")));
                    }
                }
            }
            ABS_MT_TRACKING_ID => {
                self.contacts.insert(
                    self.current_slot,
                    RawTrackpadContact {
                        id: Some(value as u32),
                        ..Default::default()
                    },
                );
            }
            ABS_MT_POSITION_X | ABS_MT_POSITION_Y => {
                let Some(contact) = self.contacts.get_mut(&self.current_slot) else {
                    return;
                };
                if code == ABS_MT_POSITION_X {
                    contact.x = Some(value);
                } else {
                    contact.y = Some(value);
                }
                let (Some(id), Some(x), Some(y)) = (contact.id, contact.x, contact.y) else {
                    return;
                };
                let x = normalize_trackpad_coordinate(x, self.x_range);
                let y = normalize_trackpad_coordinate(y, self.y_range);
                if contact.forwarded {
                    output.extend(self.pinch.motion(id, x, y));
                } else {
                    contact.forwarded = true;
                    output.extend(self.pinch.down(id, x, y));
                }
            }
            _ => {}
        }
    }
}

fn normalize_trackpad_coordinate(value: i32, range: (i32, i32)) -> u16 {
    let (minimum, maximum) = range;
    let bounded = value.clamp(minimum, maximum);
    let width = i64::from(maximum - minimum);
    let offset = i64::from(bounded - minimum);
    ((offset * i64::from(u16::MAX)) / width) as u16
}

fn set_nonblocking(device: &Device) -> io::Result<()> {
    let fd = device.as_raw_fd();
    // SAFETY: `fd` belongs to `device` for the duration of both calls.
    let flags = unsafe { fcntl(fd, F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_SETFL takes one integer flags argument.
    if unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn is_expected_release_deactivation(expected: Option<u32>, observed: Option<u32>) -> bool {
    expected.is_some_and(|activation_id| observed.is_none_or(|actual| actual == activation_id))
}

impl InputCaptureAdapter {
    pub fn start(
        edge: crate::portal_spike::CaptureEdge,
        local_edge_x: i32,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            session: crate::portal_spike::InputCaptureSession::start(
                edge,
                crate::portal_spike::CaptureCapabilities::KeyboardPointerTouch,
            )?,
            local_edge_x,
            active_activation: None,
            pending_release_deactivation: None,
            absolute_motion: AbsoluteMotionTracker::default(),
            pending_motion: (0, 0),
            smooth_scroll_axes: (false, false),
            pinch_zoom: PinchZoomTracker::default(),
            raw_trackpad_pinch: Self::open_raw_trackpad(),
            capture_timing: FrameTiming::new("capture"),
            pending: VecDeque::new(),
        })
    }

    pub fn start_with_persistence(
        edge: crate::portal_spike::CaptureEdge,
        local_edge_x: i32,
        persistence: crate::portal_persistence::PortalPersistence,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            session: crate::portal_spike::InputCaptureSession::start_with_persistence(
                edge,
                crate::portal_spike::CaptureCapabilities::KeyboardPointerTouch,
                persistence,
            )?,
            local_edge_x,
            active_activation: None,
            pending_release_deactivation: None,
            absolute_motion: AbsoluteMotionTracker::default(),
            pending_motion: (0, 0),
            smooth_scroll_axes: (false, false),
            pinch_zoom: PinchZoomTracker::default(),
            raw_trackpad_pinch: Self::open_raw_trackpad(),
            capture_timing: FrameTiming::new("capture"),
            pending: VecDeque::new(),
        })
    }

    pub fn start_left(local_left_x: i32) -> Result<Self, Box<dyn std::error::Error>> {
        Self::start(crate::portal_spike::CaptureEdge::Left, local_left_x)
    }

    pub fn start_left_with_persistence(
        local_left_x: i32,
        persistence: crate::portal_persistence::PortalPersistence,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_with_persistence(
            crate::portal_spike::CaptureEdge::Left,
            local_left_x,
            persistence,
        )
    }

    pub fn take_restore_token(&mut self) -> Option<crate::portal_persistence::RestoreToken> {
        self.session.take_restore_token()
    }

    fn open_raw_trackpad() -> Option<RawTrackpadPinchCapture> {
        match RawTrackpadPinchCapture::open() {
            Ok(capture) => capture,
            Err(error) => {
                // The portal handoff remains fully usable when a particular
                // trackpad is unavailable or access is denied.
                eprintln!("pinch zoom: direct Magic Trackpad capture unavailable: {error}");
                None
            }
        }
    }

    fn queue_motion(&mut self, dx: i32, dy: i32) {
        self.pending_motion.0 = self.pending_motion.0.saturating_add(dx);
        self.pending_motion.1 = self.pending_motion.1.saturating_add(dy);
    }

    fn flush_motion(&mut self) {
        let (dx, dy) = std::mem::take(&mut self.pending_motion);
        if dx != 0 || dy != 0 {
            self.pending.push_back(CapturedInput::Motion { dx, dy });
        }
    }

    fn take_pending(&mut self) -> Option<CapturedInput> {
        let input = self.pending.pop_front();
        if input.is_some() {
            self.capture_timing.record();
        }
        input
    }

    fn drain_batch(&mut self, batch: crate::libei_capture::DispatchBatch) -> io::Result<()> {
        for event in batch.input_events {
            match event {
                crate::libei_capture::CapturedEvent::AbsolutePointer { x, y } => {
                    if let Some((dx, dy)) = self.absolute_motion.update(x, y)? {
                        self.queue_motion(dx, dy);
                    }
                }
                crate::libei_capture::CapturedEvent::RelativePointer { dx, dy } => {
                    self.queue_motion(rounded_delta(dx)?, rounded_delta(dy)?);
                }
                crate::libei_capture::CapturedEvent::ScrollDelta {
                    horizontal,
                    vertical,
                } => {
                    self.flush_motion();
                    self.smooth_scroll_axes.0 |= horizontal != 0.0;
                    self.smooth_scroll_axes.1 |= vertical != 0.0;
                    self.pending.extend(
                        captured_to_wire(crate::libei_capture::CapturedEvent::ScrollDelta {
                            horizontal,
                            vertical,
                        })?
                        .into_iter()
                        .map(CapturedInput::Event),
                    );
                }
                crate::libei_capture::CapturedEvent::ScrollDiscrete {
                    horizontal,
                    vertical,
                } => {
                    self.flush_motion();
                    // Avoid double injection when the same physical scroll
                    // was also delivered as a smooth pixel update this frame.
                    let horizontal = if self.smooth_scroll_axes.0 {
                        0
                    } else {
                        horizontal
                    };
                    let vertical = if self.smooth_scroll_axes.1 {
                        0
                    } else {
                        vertical
                    };
                    self.pending.extend(
                        captured_to_wire(crate::libei_capture::CapturedEvent::ScrollDiscrete {
                            horizontal,
                            vertical,
                        })?
                        .into_iter()
                        .map(CapturedInput::Event),
                    );
                }
                crate::libei_capture::CapturedEvent::TouchDown { id, x, y } => {
                    self.flush_motion();
                    self.pending.extend(
                        self.pinch_zoom
                            .down(id, x, y)
                            .into_iter()
                            .map(CapturedInput::Event),
                    );
                    self.pending.push_back(CapturedInput::Touch(WireTouchEvent {
                        phase: TouchPhase::Down,
                        id,
                        x,
                        y,
                    }));
                }
                crate::libei_capture::CapturedEvent::TouchMotion { id, x, y } => {
                    self.flush_motion();
                    self.pending.extend(
                        self.pinch_zoom
                            .motion(id, x, y)
                            .into_iter()
                            .map(CapturedInput::Event),
                    );
                    self.pending.push_back(CapturedInput::Touch(WireTouchEvent {
                        phase: TouchPhase::Motion,
                        id,
                        x,
                        y,
                    }));
                }
                crate::libei_capture::CapturedEvent::TouchUp { id, cancelled } => {
                    self.flush_motion();
                    self.pending.push_back(CapturedInput::Touch(WireTouchEvent {
                        phase: if cancelled {
                            TouchPhase::Cancel
                        } else {
                            TouchPhase::Up
                        },
                        id,
                        x: 0,
                        y: 0,
                    }));
                    self.pending
                        .extend(self.pinch_zoom.up(id).into_iter().map(CapturedInput::Event));
                }
                // InputCapture frames delimit a compositor update. Send one
                // coherent move before transitions or this frame boundary.
                crate::libei_capture::CapturedEvent::Frame { .. } => {
                    self.flush_motion();
                    self.smooth_scroll_axes = (false, false);
                }
                event => {
                    self.flush_motion();
                    self.pending.extend(
                        captured_to_wire(event)?
                            .into_iter()
                            .map(CapturedInput::Event),
                    );
                }
            }
        }
        // Some backends may end a dispatch batch without emitting Frame.
        // Keeping this flush makes the latency bounded in that case too.
        self.flush_motion();
        Ok(())
    }

    fn map_portal_error(error: Box<dyn std::error::Error>) -> io::Error {
        io::Error::other(error.to_string())
    }
}

impl CaptureBackend for InputCaptureAdapter {
    fn wait_for_left_activation(&mut self) -> io::Result<Point> {
        loop {
            match self.session.poll_signal(Duration::from_millis(250))? {
                Some(crate::portal_spike::CaptureSignal::Activated {
                    activation_id,
                    cursor_position: Some((x, y)),
                    ..
                }) if x.is_finite() && y.is_finite() => {
                    self.active_activation = Some(activation_id);
                    self.absolute_motion.reset();
                    return Ok(Point {
                        // A left-edge barrier is the capture session's only
                        // activation source; use configured logical edge to
                        // avoid accepting portal overshoot as an interior x.
                        x: self.local_edge_x,
                        y: rounded_coordinate(y)?,
                    });
                }
                Some(crate::portal_spike::CaptureSignal::Activated { .. }) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "left-edge activation omitted a finite cursor position",
                    ));
                }
                Some(crate::portal_spike::CaptureSignal::Deactivated { activation_id })
                    if is_expected_release_deactivation(
                        self.pending_release_deactivation,
                        activation_id,
                    ) =>
                {
                    self.pending_release_deactivation = None;
                }
                Some(crate::portal_spike::CaptureSignal::Disabled)
                | Some(crate::portal_spike::CaptureSignal::Deactivated { .. }) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "InputCapture session stopped before handoff activation",
                    ));
                }
                Some(_) | None => {}
            }
        }
    }

    fn begin_remote_input(&mut self) -> io::Result<()> {
        if self.active_activation.is_some() {
            if let Some(trackpad) = &mut self.raw_trackpad_pinch {
                trackpad.reset()?;
            }
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot begin remote input without an InputCapture activation",
            ))
        }
    }

    fn next_input(&mut self, timeout: Duration) -> io::Result<Option<CapturedInput>> {
        if let Some(event) = self.take_pending() {
            return Ok(Some(event));
        }
        if let Some(trackpad) = &mut self.raw_trackpad_pinch {
            self.pending
                .extend(trackpad.drain()?.into_iter().map(CapturedInput::Event));
            if let Some(event) = self.take_pending() {
                return Ok(Some(event));
            }
        }
        match self.session.poll_signal(Duration::ZERO)? {
            Some(crate::portal_spike::CaptureSignal::Deactivated { .. })
            | Some(crate::portal_spike::CaptureSignal::Disabled) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "InputCapture session ended while remote input was active",
                ));
            }
            Some(_) | None => {}
        }
        // A bounded 125 Hz wake-up also services peer control/RTT replies in
        // the idle case. Heartbeats themselves remain rate-limited, so this
        // does not add wire traffic while the pointer is still.
        let timeout = timeout.min(RAW_TRACKPAD_POLL_INTERVAL);
        let batch = self.session.dispatch_events(timeout)?;
        self.drain_batch(batch)?;
        if let Some(trackpad) = &mut self.raw_trackpad_pinch {
            self.pending
                .extend(trackpad.drain()?.into_iter().map(CapturedInput::Event));
        }
        Ok(self.take_pending())
    }

    fn return_to_local(&mut self, restore: Point) -> io::Result<()> {
        let activation_id = self.active_activation.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot return without an InputCapture activation",
            )
        })?;
        self.absolute_motion.reset();
        self.pending_motion = (0, 0);
        self.session
            .release(
                activation_id,
                Some((f64::from(restore.x), f64::from(restore.y))),
            )
            .map_err(Self::map_portal_error)?;
        self.pending_release_deactivation = Some(activation_id);
        Ok(())
    }

    fn release_local_input(&mut self, restore: Option<Point>) -> io::Result<()> {
        self.absolute_motion.reset();
        self.pending_motion = (0, 0);
        self.pending_release_deactivation = None;
        if let Some(trackpad) = &mut self.raw_trackpad_pinch {
            trackpad.reset()?;
        }
        let release_result = if let Some(activation_id) = self.active_activation.take() {
            self.session
                .release(
                    activation_id,
                    restore.map(|point| (f64::from(point.x), f64::from(point.y))),
                )
                .map_err(Self::map_portal_error)
        } else {
            Ok(())
        };
        let disable_result = self.session.disable().map_err(Self::map_portal_error);
        release_result?;
        disable_result
    }
}

fn captured_to_wire(event: crate::libei_capture::CapturedEvent) -> io::Result<Vec<WireInputEvent>> {
    use crate::libei_capture::CapturedEvent;

    const EV_SYN: u16 = 0;
    const EV_KEY: u16 = 1;
    const EV_REL: u16 = 2;
    const SYN_REPORT: u16 = 0;
    const REL_HWHEEL: u16 = 6;
    const REL_WHEEL: u16 = 8;
    // These remain encrypted application markers; they are never emitted to
    // a Linux input device. Keeping smooth data distinct from wheel clicks
    // lets the client call the matching libei API.
    const REL_WHEEL_HI_RES: u16 = 11;
    const REL_HWHEEL_HI_RES: u16 = 12;

    let wire_event = |event_type, code, value| WireInputEvent {
        event_type,
        code,
        value,
    };
    match event {
        CapturedEvent::RelativePointer { dx, dy } => {
            Ok(relative_wire_events(rounded_delta(dx)?, rounded_delta(dy)?))
        }
        CapturedEvent::AbsolutePointer { .. } => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "absolute pointer events must pass through the motion tracker",
        )),
        CapturedEvent::Button { evdev, pressed } | CapturedEvent::Key { evdev, pressed } => {
            Ok(vec![wire_event(EV_KEY, evdev, i32::from(pressed))])
        }
        CapturedEvent::ScrollDelta {
            horizontal,
            vertical,
        } => {
            let mut output = Vec::with_capacity(2);
            let horizontal = rounded_delta(horizontal)?;
            let vertical = rounded_delta(vertical)?;
            if horizontal != 0 {
                output.push(wire_event(EV_REL, REL_HWHEEL_HI_RES, horizontal));
            }
            if vertical != 0 {
                output.push(wire_event(EV_REL, REL_WHEEL_HI_RES, vertical));
            }
            Ok(output)
        }
        CapturedEvent::ScrollDiscrete {
            horizontal,
            vertical,
        } => {
            let mut output = Vec::with_capacity(2);
            if horizontal != 0 {
                output.push(wire_event(EV_REL, REL_HWHEEL, horizontal));
            }
            if vertical != 0 {
                output.push(wire_event(EV_REL, REL_WHEEL, vertical));
            }
            Ok(output)
        }
        CapturedEvent::Frame { .. } => Ok(vec![wire_event(EV_SYN, SYN_REPORT, 0)]),
        CapturedEvent::ScrollStop { .. }
        | CapturedEvent::ScrollCancel { .. }
        | CapturedEvent::TouchDown { .. }
        | CapturedEvent::TouchMotion { .. }
        | CapturedEvent::TouchUp { .. }
        | CapturedEvent::StartEmulating { .. }
        | CapturedEvent::StopEmulating => Ok(Vec::new()),
    }
}

fn relative_wire_events(dx: i32, dy: i32) -> Vec<WireInputEvent> {
    const EV_REL: u16 = 2;
    const REL_X: u16 = 0;
    const REL_Y: u16 = 1;
    let mut output = Vec::with_capacity(2);
    if dx != 0 {
        output.push(WireInputEvent {
            event_type: EV_REL,
            code: REL_X,
            value: dx,
        });
    }
    if dy != 0 {
        output.push(WireInputEvent {
            event_type: EV_REL,
            code: REL_Y,
            value: dy,
        });
    }
    output
}

fn rounded_coordinate(value: f64) -> io::Result<i32> {
    if !value.is_finite()
        || value.round() < f64::from(i32::MIN)
        || value.round() > f64::from(i32::MAX)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("portal coordinate {value} cannot be represented as i32"),
        ));
    }
    Ok(value.round() as i32)
}

fn rounded_delta(value: f64) -> io::Result<i32> {
    rounded_coordinate(value)
}

impl RemoteDesktopInjector {
    /// Requests the target-side RemoteDesktop portal consent and completes its
    /// EIS sender handshake before the TCP listener is exposed.
    pub fn start() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            session: crate::remote_spike::RemoteDesktopSession::start()?,
            entry: None,
            injection_timing: FrameTiming::new("injection"),
        })
    }

    pub fn start_with_persistence(
        persistence: crate::portal_persistence::PortalPersistence,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            session: crate::remote_spike::RemoteDesktopSession::start_with_persistence(
                persistence,
            )?,
            entry: None,
            injection_timing: FrameTiming::new("injection"),
        })
    }

    pub fn take_restore_token(&mut self) -> Option<crate::portal_persistence::RestoreToken> {
        self.session.take_restore_token()
    }

    fn input_state(value: i32) -> io::Result<crate::libei_inject::InputState> {
        match value {
            0 => Ok(crate::libei_inject::InputState::Released),
            1 => Ok(crate::libei_inject::InputState::Pressed),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported evdev key/button value {value}"),
            )),
        }
    }
}

impl InjectBackend for RemoteDesktopInjector {
    fn prepare_entry(&mut self, entry: Point) -> io::Result<()> {
        // Relative-only RemoteDesktop EIS cannot reliably warp to `entry`.
        // Recording it still keeps the control-plane transaction strict and
        // lets the later absolute/ScreenCast adapter use the same API.
        self.entry = Some(entry);
        Ok(())
    }

    fn inject_motion(&mut self, dx: i32, dy: i32) -> io::Result<()> {
        self.session.inject_relative(f64::from(dx), f64::from(dy))?;
        self.injection_timing.record();
        Ok(())
    }

    fn inject(&mut self, event: WireInputEvent) -> io::Result<()> {
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

        let result = match (event.event_type, event.code) {
            (EV_SYN, SYN_REPORT) => Ok(()),
            (EV_REL, REL_X) => self.session.inject_relative(f64::from(event.value), 0.0),
            (EV_REL, REL_Y) => self.session.inject_relative(0.0, f64::from(event.value)),
            (EV_REL, REL_HWHEEL_HI_RES) => {
                self.session
                    .inject_scroll(f64::from(event.value), 0.0, false)
            }
            (EV_REL, REL_WHEEL_HI_RES) => {
                self.session
                    .inject_scroll(0.0, f64::from(event.value), false)
            }
            (EV_REL, REL_HWHEEL) => self.session.inject_scroll_discrete(event.value, 0, false),
            (EV_REL, REL_WHEEL) => self.session.inject_scroll_discrete(0, event.value, false),
            (EV_KEY, code) if code >= BTN_MOUSE_FIRST => self
                .session
                .inject_button(code, Self::input_state(event.value)?),
            (EV_KEY, code) => self
                .session
                .inject_key(code, Self::input_state(event.value)?),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "unsupported seamless wire event type={} code={}",
                    event.event_type, event.code
                ),
            )),
        };
        if result.is_ok() {
            self.injection_timing.record();
        }
        result
    }

    fn inject_touch(&mut self, event: WireTouchEvent) -> io::Result<()> {
        let result = match event.phase {
            TouchPhase::Down => self.session.inject_touch_down(event.id, event.x, event.y),
            TouchPhase::Motion => self.session.inject_touch_motion(event.id, event.x, event.y),
            TouchPhase::Up => self.session.inject_touch_up(event.id, false),
            TouchPhase::Cancel => self.session.inject_touch_up(event.id, true),
        };
        if result.is_ok() {
            self.injection_timing.record();
        }
        result
    }

    fn release_all(&mut self) -> io::Result<()> {
        self.session.release_all()
    }
}

/// Minimal platform contract for InputCapture + libei receiver integration.
pub trait CaptureBackend {
    /// Waits for a portal activation of the configured left pointer barrier.
    fn wait_for_left_activation(&mut self) -> io::Result<Point>;
    /// Enables forwarding from the already-active portal capture session.
    fn begin_remote_input(&mut self) -> io::Result<()>;
    /// Returns the next safely decoded input event. The implementation may use
    /// `None` for a heartbeat interval with no input.
    fn next_input(&mut self, timeout: Duration) -> io::Result<Option<CapturedInput>>;
    /// Releases the active portal capture at `restore` and leaves the edge
    /// armed for a later handoff.
    fn return_to_local(&mut self, restore: Point) -> io::Result<()>;
    /// Releases the portal activation and stops capture. `restore` is the
    /// host-local position mapped from a peer return edge. Idempotent by design.
    fn release_local_input(&mut self, restore: Option<Point>) -> io::Result<()>;
}

/// Minimal platform contract for RemoteDesktop + libei sender integration.
pub trait InjectBackend {
    /// Prepares virtual pointer/input state for an accepted peer entry.
    fn prepare_entry(&mut self, entry: Point) -> io::Result<()>;
    /// Inject one paired relative motion update in exactly one remote frame.
    fn inject_motion(&mut self, dx: i32, dy: i32) -> io::Result<()>;
    fn inject(&mut self, event: WireInputEvent) -> io::Result<()>;
    fn inject_touch(&mut self, event: WireTouchEvent) -> io::Result<()>;
    /// Synthesizes releases for all pressed keys/buttons and closes the active
    /// injection scope. It must be safe to call more than once.
    fn release_all(&mut self) -> io::Result<()>;
}

/// The narrow transport surface that lets orchestration be unit-tested without
/// a real TCP socket, while the production implementation remains Noise.
pub trait MessageTransport {
    fn send(&mut self, message: Message) -> Result<(), TransportError>;
    fn receive(&mut self) -> Result<Message, TransportError>;
    fn poll_receive(&mut self) -> Result<Option<Message>, TransportError>;
}

impl MessageTransport for SecureConnection {
    fn send(&mut self, message: Message) -> Result<(), TransportError> {
        Self::send(self, message)
    }

    fn receive(&mut self) -> Result<Message, TransportError> {
        Self::receive(self)
    }

    fn poll_receive(&mut self) -> Result<Option<Message>, TransportError> {
        Self::poll_receive(self)
    }
}

#[derive(Debug, Error)]
pub enum SeamlessError {
    #[error("portal/libei backend error: {0}")]
    Backend(#[from] io::Error),
    #[error("encrypted transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("expected EnterAck or EnterRejected, received {0:?}")]
    UnexpectedControl(Message),
    #[error("input was attempted before a peer entry was acknowledged")]
    InputBeforeAcknowledgement,
    #[error("peer sent input before an accepted handoff")]
    InputBeforeEntry,
    #[error("left barrier did not produce a handoff entry request")]
    InvalidActivation,
}

/// Host-side handoff coordinator. The caller supplies a controller configured
/// with its actual local and peer logical rectangles.
pub struct SeamlessHost<C, T> {
    controller: HandoffController,
    capture: C,
    transport: T,
    last_peer_activity: Instant,
    last_latency_probe: Instant,
    next_probe_sequence: u32,
    pending_probe: Option<(u32, Instant)>,
    round_trip_timing: LatencyTiming,
}

impl<C: CaptureBackend, T: MessageTransport> SeamlessHost<C, T> {
    pub fn new(controller: HandoffController, capture: C, transport: T) -> Self {
        Self {
            controller,
            capture,
            transport,
            last_peer_activity: Instant::now(),
            last_latency_probe: Instant::now(),
            next_probe_sequence: 0,
            pending_probe: None,
            round_trip_timing: LatencyTiming::new(),
        }
    }

    pub const fn state(&self) -> HandoffState {
        self.controller.state()
    }

    /// Waits for the real portal activation and establishes remote ownership.
    /// No libei event is read or sent until the peer's encrypted ACK arrives.
    pub fn activate_once(&mut self) -> Result<(), SeamlessError> {
        let point = self.capture.wait_for_left_activation()?;
        let transition = self.controller.local_edge_activated(point);
        let Some(HandoffAction::RequestPeerEntry { entry }) = transition.action else {
            return Err(SeamlessError::InvalidActivation);
        };
        self.transport.send(Message::Enter {
            x: entry.x,
            y: entry.y,
        })?;

        match self.transport.receive()? {
            Message::EnterAck => match self.controller.peer_entry_acknowledged().action {
                Some(HandoffAction::BeginRemoteInput) => self.capture.begin_remote_input()?,
                _ => return Err(SeamlessError::UnexpectedControl(Message::EnterAck)),
            },
            Message::EnterRejected => {
                let Some(HandoffAction::WarpLocalPointer { at }) =
                    self.controller.peer_entry_rejected().action
                else {
                    return Err(SeamlessError::UnexpectedControl(Message::EnterRejected));
                };
                self.capture.return_to_local(at)?;
            }
            message => {
                let _ = self.close();
                return Err(SeamlessError::UnexpectedControl(message));
            }
        }
        Ok(())
    }

    /// Forwards one event only while the controller owns a remote-active
    /// handoff. Call this repeatedly from the portal/libei dispatch loop.
    pub fn forward(&mut self, input: CapturedInput) -> Result<(), SeamlessError> {
        if !matches!(self.controller.state(), HandoffState::RemoteActive { .. }) {
            return Err(SeamlessError::InputBeforeAcknowledgement);
        }
        match input {
            CapturedInput::Motion { dx, dy } => {
                self.transport.send(Message::PointerMotion { dx, dy })?
            }
            CapturedInput::Event(event) => self.transport.send(Message::Input(event))?,
            CapturedInput::Touch(event) => self.transport.send(Message::Touch(event))?,
        }
        self.last_peer_activity = Instant::now();
        Ok(())
    }

    /// Reads and forwards one capture event, emitting a heartbeat for an idle
    /// interval. Transport failure is handled by the caller via [`Self::close`]
    /// so local portal input is always released first.
    pub fn forward_next(&mut self, timeout: Duration) -> Result<(), SeamlessError> {
        self.poll_control()?;
        if !matches!(self.controller.state(), HandoffState::RemoteActive { .. }) {
            return Ok(());
        }
        self.maybe_send_latency_probe()?;
        match self.capture.next_input(timeout)? {
            Some(input) => {
                // An ExitRequest may have arrived while EIS dispatch waited.
                // Check again before emitting another remote input event.
                self.poll_control()?;
                if matches!(self.controller.state(), HandoffState::RemoteActive { .. }) {
                    self.forward(input)
                } else {
                    Ok(())
                }
            }
            None => {
                if matches!(self.controller.state(), HandoffState::RemoteActive { .. })
                    && self.last_peer_activity.elapsed()
                        >= Duration::from_millis(crate::protocol::HEARTBEAT_INTERVAL_MS)
                {
                    self.transport.send(Message::Heartbeat)?;
                    self.last_peer_activity = Instant::now();
                }
                Ok(())
            }
        }
    }

    /// Safety cleanup for normal exit, portal close, heartbeat timeout, and
    /// transport disconnect. Local release is attempted first; the network
    /// release remains best-effort because the peer may already be gone.
    pub fn close(&mut self) -> Result<(), SeamlessError> {
        let local_result = self.capture.release_local_input(None);
        let message = match self.controller.disconnect_or_cancel().action {
            Some(HandoffAction::ReleaseRemoteInput) => Some(Message::HandoffRelease),
            _ => None,
        };
        if let Some(message) = message {
            let _ = self.transport.send(message);
        }
        local_result.map_err(Into::into)
    }

    fn poll_control(&mut self) -> Result<(), SeamlessError> {
        let Some(message) = self.transport.poll_receive()? else {
            return Ok(());
        };
        match message {
            Message::Heartbeat => Ok(()),
            Message::DiagnosticPong { sequence } => {
                if let Some((expected, sent_at)) = self.pending_probe.take() {
                    if sequence == expected {
                        self.round_trip_timing.record(sent_at.elapsed());
                    }
                }
                Ok(())
            }
            Message::ExitRequest { edge, x, y } => {
                let edge = match edge {
                    WireEdge::Left => crate::handoff::Edge::Left,
                    WireEdge::Right => crate::handoff::Edge::Right,
                };
                let transition = self.controller.peer_exit_activated(edge, Point { x, y });
                let Some(HandoffAction::ReturnToLocal { at }) = transition.action else {
                    let _ = self.close();
                    return Err(SeamlessError::UnexpectedControl(Message::ExitRequest {
                        edge: match edge {
                            crate::handoff::Edge::Left => WireEdge::Left,
                            crate::handoff::Edge::Right => WireEdge::Right,
                        },
                        x,
                        y,
                    }));
                };
                self.capture.return_to_local(at)?;
                // This is idempotent with the client-side release and covers a
                // disconnect racing immediately after the exit request.
                let _ = self.transport.send(Message::HandoffRelease);
                Ok(())
            }
            Message::HandoffRelease | Message::ReleaseAll | Message::Goodbye => self.close(),
            message => {
                let _ = self.close();
                Err(SeamlessError::UnexpectedControl(message))
            }
        }
    }

    fn maybe_send_latency_probe(&mut self) -> Result<(), SeamlessError> {
        if self.pending_probe.is_some()
            || self.last_latency_probe.elapsed() < Duration::from_secs(1)
        {
            return Ok(());
        }
        self.next_probe_sequence = self.next_probe_sequence.wrapping_add(1);
        let sequence = self.next_probe_sequence;
        self.transport.send(Message::DiagnosticPing { sequence })?;
        let now = Instant::now();
        self.pending_probe = Some((sequence, now));
        self.last_latency_probe = now;
        Ok(())
    }

    pub fn into_parts(self) -> (C, T) {
        (self.capture, self.transport)
    }
}

/// Client-side coordinator. It arms virtual input only after it has prepared
/// the requested entry coordinate and returned an encrypted ACK.
pub struct SeamlessClient<I, T> {
    injector: I,
    transport: T,
    remote_active: bool,
    entry: Option<Point>,
    /// Set after the controlled-side barrier has asked the host to return
    /// input. A final host motion record can already be in flight; it is
    /// stale rather than a protocol violation and must be discarded.
    return_pending: bool,
}

impl<I: InjectBackend, T: MessageTransport> SeamlessClient<I, T> {
    pub fn new(injector: I, transport: T) -> Self {
        Self {
            injector,
            transport,
            remote_active: false,
            entry: None,
            return_pending: false,
        }
    }

    pub const fn remote_active(&self) -> bool {
        self.remote_active
    }

    /// The last authenticated host entry.  A left-side client needs its x
    /// coordinate when it returns across its left barrier because that is the
    /// adjoining host's right boundary in the shared topology.
    pub const fn entry(&self) -> Option<Point> {
        self.entry
    }

    /// Receives one encrypted frame. Keeping this narrow wrapper avoids
    /// exposing the transport implementation to the CLI composition layer.
    pub fn receive_next(&mut self) -> Result<Message, TransportError> {
        self.transport.receive()
    }

    /// Polls a complete already-buffered frame so the composition loop can
    /// service a local right-edge portal signal between remote input frames.
    pub fn poll_next(&mut self) -> Result<Option<Message>, TransportError> {
        self.transport.poll_receive()
    }

    /// Handles one decrypted message. The enclosing receive loop must call
    /// [`Self::close`] on any transport error before it returns to its caller.
    pub fn handle(&mut self, message: Message) -> Result<(), SeamlessError> {
        match message {
            Message::Enter { x, y } if !self.remote_active => {
                if let Err(error) = self.injector.prepare_entry(Point { x, y }) {
                    let _ = self.transport.send(Message::EnterRejected);
                    let _ = self.injector.release_all();
                    return Err(error.into());
                }
                self.transport.send(Message::EnterAck)?;
                self.remote_active = true;
                self.return_pending = false;
                self.entry = Some(Point { x, y });
                Ok(())
            }
            Message::Enter { .. } => {
                self.transport.send(Message::EnterRejected)?;
                Ok(())
            }
            Message::Input(event) if self.remote_active => {
                self.injector.inject(event)?;
                Ok(())
            }
            Message::PointerMotion { dx, dy } if self.remote_active => {
                self.injector.inject_motion(dx, dy)?;
                Ok(())
            }
            Message::Touch(event) if self.remote_active => {
                self.injector.inject_touch(event)?;
                Ok(())
            }
            Message::Input(_) => {
                if self.return_pending {
                    // The host may have selected this input before receiving
                    // our ExitRequest. Never inject it after releasing the
                    // client side, but keep the encrypted session alive for
                    // the HandoffRelease acknowledgement and next entry.
                    return Ok(());
                }
                let _ = self.close();
                Err(SeamlessError::InputBeforeEntry)
            }
            Message::PointerMotion { .. } => {
                if self.return_pending {
                    Ok(())
                } else {
                    let _ = self.close();
                    Err(SeamlessError::InputBeforeEntry)
                }
            }
            Message::Touch(_) => {
                if self.return_pending {
                    Ok(())
                } else {
                    let _ = self.close();
                    Err(SeamlessError::InputBeforeEntry)
                }
            }
            Message::Heartbeat => Ok(()),
            Message::DiagnosticPing { sequence } => {
                self.transport.send(Message::DiagnosticPong { sequence })?;
                Ok(())
            }
            Message::HandoffRelease => {
                self.close()?;
                self.return_pending = false;
                Ok(())
            }
            Message::ReleaseAll | Message::Goodbye => self.close(),
            message => {
                let _ = self.close();
                Err(SeamlessError::UnexpectedControl(message))
            }
        }
    }

    /// Requests a return only for an active, authenticated entry. A future
    /// target pointer-tracking backend calls this when its right barrier is
    /// crossed; it never accepts arbitrary caller input while local.
    pub fn request_exit(&mut self, edge: WireEdge, position: Point) -> Result<(), SeamlessError> {
        if !self.remote_active {
            return Err(SeamlessError::InputBeforeEntry);
        }
        self.transport.send(Message::ExitRequest {
            edge,
            x: position.x,
            y: position.y,
        })?;
        self.return_pending = true;
        self.close()
    }

    /// Releases virtual pressed state even after an error/disconnect.
    pub fn close(&mut self) -> Result<(), SeamlessError> {
        self.remote_active = false;
        self.entry = None;
        self.injector.release_all().map_err(Into::into)
    }

    pub fn into_parts(self) -> (I, T) {
        (self.injector, self.transport)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, io::ErrorKind};

    use super::*;
    use crate::handoff::{Edge, Rect};

    #[derive(Default)]
    struct FakeCapture {
        activation: Option<Point>,
        began: bool,
        released: usize,
        restores: Vec<Option<Point>>,
        inputs: VecDeque<Option<CapturedInput>>,
    }

    impl CaptureBackend for FakeCapture {
        fn wait_for_left_activation(&mut self) -> io::Result<Point> {
            self.activation
                .take()
                .ok_or_else(|| io::Error::new(ErrorKind::WouldBlock, "no activation"))
        }

        fn begin_remote_input(&mut self) -> io::Result<()> {
            self.began = true;
            Ok(())
        }

        fn next_input(&mut self, _: Duration) -> io::Result<Option<CapturedInput>> {
            Ok(self.inputs.pop_front().flatten())
        }

        fn return_to_local(&mut self, restore: Point) -> io::Result<()> {
            self.released += 1;
            self.restores.push(Some(restore));
            Ok(())
        }

        fn release_local_input(&mut self, restore: Option<Point>) -> io::Result<()> {
            self.released += 1;
            self.restores.push(restore);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeInject {
        prepared: Vec<Point>,
        motions: Vec<(i32, i32)>,
        inputs: Vec<WireInputEvent>,
        touches: Vec<WireTouchEvent>,
        releases: usize,
    }

    impl InjectBackend for FakeInject {
        fn prepare_entry(&mut self, entry: Point) -> io::Result<()> {
            self.prepared.push(entry);
            Ok(())
        }

        fn inject_motion(&mut self, dx: i32, dy: i32) -> io::Result<()> {
            self.motions.push((dx, dy));
            Ok(())
        }

        fn inject(&mut self, event: WireInputEvent) -> io::Result<()> {
            self.inputs.push(event);
            Ok(())
        }

        fn inject_touch(&mut self, event: WireTouchEvent) -> io::Result<()> {
            self.touches.push(event);
            Ok(())
        }

        fn release_all(&mut self) -> io::Result<()> {
            self.releases += 1;
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeTransport {
        sent: Vec<Message>,
        received: VecDeque<Message>,
    }

    impl MessageTransport for FakeTransport {
        fn send(&mut self, message: Message) -> Result<(), TransportError> {
            self.sent.push(message);
            Ok(())
        }

        fn receive(&mut self) -> Result<Message, TransportError> {
            self.received.pop_front().ok_or_else(|| {
                TransportError::Io(io::Error::new(ErrorKind::UnexpectedEof, "test end"))
            })
        }

        fn poll_receive(&mut self) -> Result<Option<Message>, TransportError> {
            Ok(self.received.pop_front())
        }
    }

    fn controller() -> HandoffController {
        HandoffController::new(
            Rect::new(0, 0, 1_920, 1_080).unwrap(),
            Rect::new(-1_920, 0, 1_920, 1_080).unwrap(),
            Edge::Left,
        )
    }

    #[test]
    fn absolute_motion_uses_first_event_as_origin_then_emits_relative_deltas() {
        let mut tracker = AbsoluteMotionTracker::default();
        assert_eq!(tracker.update(100.25, 200.25).unwrap(), None);
        assert_eq!(tracker.update(103.25, 198.25).unwrap(), Some((3, -2)));
        assert_eq!(
            relative_wire_events(3, -2),
            vec![
                WireInputEvent {
                    event_type: 2,
                    code: 0,
                    value: 3,
                },
                WireInputEvent {
                    event_type: 2,
                    code: 1,
                    value: -2,
                },
            ]
        );
    }

    #[test]
    fn normal_portal_deactivation_after_release_is_distinguished_from_loss() {
        assert!(is_expected_release_deactivation(Some(7), Some(7)));
        // Some portal backends omit activation_id on Deactivated. There can
        // be only one active capture, so it still safely acknowledges it.
        assert!(is_expected_release_deactivation(Some(7), None));
        assert!(!is_expected_release_deactivation(Some(7), Some(8)));
        assert!(!is_expected_release_deactivation(None, Some(7)));
    }

    #[test]
    fn absolute_motion_resets_and_bounds_layout_jumps() {
        let mut tracker = AbsoluteMotionTracker::default();
        tracker.update(0.0, 0.0).unwrap();
        assert_eq!(
            tracker.update(100_000.0, -100_000.0).unwrap(),
            Some((2_048, -2_048))
        );
        tracker.reset();
        assert_eq!(tracker.update(50_000.0, 50_000.0).unwrap(), None);
        assert_eq!(tracker.update(50_001.0, 49_999.0).unwrap(), Some((1, -1)));
    }

    #[test]
    fn absolute_motion_preserves_fractional_deltas_across_events() {
        let mut tracker = AbsoluteMotionTracker::default();
        tracker.update(0.0, 0.0).unwrap();
        assert_eq!(tracker.update(0.4, 0.0).unwrap(), Some((0, 0)));
        // The retained 0.4 plus this 0.4 crosses the rounding threshold.
        assert_eq!(tracker.update(0.8, 0.0).unwrap(), Some((1, 0)));
    }

    #[test]
    fn host_waits_for_ack_before_reading_or_sending_input() {
        let capture = FakeCapture {
            activation: Some(Point { x: 0, y: 540 }),
            ..Default::default()
        };
        let transport = FakeTransport {
            received: VecDeque::from([Message::EnterAck]),
            ..Default::default()
        };
        let mut host = SeamlessHost::new(controller(), capture, transport);
        host.activate_once().unwrap();
        assert_eq!(
            host.state(),
            HandoffState::RemoteActive {
                exit_edge: Edge::Left
            }
        );
        let (capture, transport) = host.into_parts();
        assert!(capture.began);
        assert_eq!(transport.sent, vec![Message::Enter { x: -1, y: 540 }]);
    }

    #[test]
    fn two_finger_pinch_emits_ctrl_scroll_and_releases_control() {
        let mut pinch = PinchZoomTracker::default();
        assert!(pinch.down(1, 10_000, 10_000).is_empty());
        assert!(pinch.down(2, 12_000, 10_000).is_empty());
        assert_eq!(
            pinch.motion(2, 15_000, 10_000),
            vec![
                WireInputEvent {
                    event_type: 1,
                    code: 29,
                    value: 1,
                },
                WireInputEvent {
                    event_type: 2,
                    code: 8,
                    value: 240,
                },
            ]
        );
        assert_eq!(
            pinch.up(2),
            vec![WireInputEvent {
                event_type: 1,
                code: 29,
                value: 0,
            }]
        );
    }

    #[test]
    fn host_reject_does_not_activate_or_forward() {
        let capture = FakeCapture {
            activation: Some(Point { x: 0, y: 10 }),
            ..Default::default()
        };
        let transport = FakeTransport {
            received: VecDeque::from([Message::EnterRejected]),
            ..Default::default()
        };
        let mut host = SeamlessHost::new(controller(), capture, transport);
        host.activate_once().unwrap();
        assert_eq!(host.state(), HandoffState::Local);
        assert!(matches!(
            host.forward(CapturedInput::Event(WireInputEvent {
                event_type: 1,
                code: 30,
                value: 1
            })),
            Err(SeamlessError::InputBeforeAcknowledgement)
        ));
        let (capture, _) = host.into_parts();
        assert!(!capture.began);
        assert_eq!(capture.released, 1);
    }

    #[test]
    fn host_close_releases_local_before_best_effort_remote_release() {
        let capture = FakeCapture {
            activation: Some(Point { x: 0, y: 10 }),
            ..Default::default()
        };
        let transport = FakeTransport {
            received: VecDeque::from([Message::EnterAck]),
            ..Default::default()
        };
        let mut host = SeamlessHost::new(controller(), capture, transport);
        host.activate_once().unwrap();
        host.close().unwrap();
        let (capture, transport) = host.into_parts();
        assert_eq!(capture.released, 1);
        assert_eq!(transport.sent.last(), Some(&Message::HandoffRelease));
    }

    #[test]
    fn host_processes_authenticated_right_exit_and_restores_mapped_position() {
        let capture = FakeCapture {
            activation: Some(Point { x: 0, y: 10 }),
            ..Default::default()
        };
        let transport = FakeTransport {
            received: VecDeque::from([
                Message::EnterAck,
                Message::ExitRequest {
                    edge: WireEdge::Right,
                    x: -1,
                    y: 500,
                },
            ]),
            ..Default::default()
        };
        let mut host = SeamlessHost::new(controller(), capture, transport);
        host.activate_once().unwrap();
        host.forward_next(Duration::ZERO).unwrap();
        assert_eq!(host.state(), HandoffState::Local);
        let (capture, transport) = host.into_parts();
        assert_eq!(capture.restores, vec![Some(Point { x: 1, y: 500 })]);
        assert_eq!(transport.sent.last(), Some(&Message::HandoffRelease));
    }

    #[test]
    fn client_acknowledges_before_it_accepts_input_and_releases_on_close() {
        let injector = FakeInject::default();
        let transport = FakeTransport::default();
        let mut client = SeamlessClient::new(injector, transport);
        client.handle(Message::Enter { x: -1, y: 500 }).unwrap();
        assert!(client.remote_active());
        client
            .handle(Message::Input(WireInputEvent {
                event_type: 1,
                code: 30,
                value: 1,
            }))
            .unwrap();
        client
            .handle(Message::PointerMotion { dx: 7, dy: -4 })
            .unwrap();
        client
            .handle(Message::Touch(WireTouchEvent {
                phase: TouchPhase::Down,
                id: 17,
                x: 12_000,
                y: 34_000,
            }))
            .unwrap();
        client.handle(Message::HandoffRelease).unwrap();
        let (injector, transport) = client.into_parts();
        assert_eq!(injector.prepared, vec![Point { x: -1, y: 500 }]);
        assert_eq!(injector.motions, vec![(7, -4)]);
        assert_eq!(injector.inputs.len(), 1);
        assert_eq!(injector.touches.len(), 1);
        assert_eq!(injector.releases, 1);
        assert_eq!(transport.sent, vec![Message::EnterAck]);
    }

    #[test]
    fn client_releases_if_input_arrives_without_enter() {
        let mut client = SeamlessClient::new(FakeInject::default(), FakeTransport::default());
        assert!(matches!(
            client.handle(Message::Input(WireInputEvent {
                event_type: 1,
                code: 30,
                value: 1
            })),
            Err(SeamlessError::InputBeforeEntry)
        ));
        let (injector, _) = client.into_parts();
        assert_eq!(injector.releases, 1);
    }

    #[test]
    fn client_only_requests_exit_after_active_entry() {
        let mut client = SeamlessClient::new(FakeInject::default(), FakeTransport::default());
        assert!(matches!(
            client.request_exit(WireEdge::Right, Point { x: -1, y: 500 }),
            Err(SeamlessError::InputBeforeEntry)
        ));
        client.handle(Message::Enter { x: -1, y: 500 }).unwrap();
        client
            .request_exit(WireEdge::Right, Point { x: -1, y: 500 })
            .unwrap();
        assert!(!client.remote_active());
        let (injector, transport) = client.into_parts();
        assert_eq!(injector.releases, 1);
        assert_eq!(
            transport.sent,
            vec![
                Message::EnterAck,
                Message::ExitRequest {
                    edge: WireEdge::Right,
                    x: -1,
                    y: 500,
                },
            ]
        );
    }

    #[test]
    fn client_discards_an_in_flight_motion_after_requesting_return() {
        let mut client = SeamlessClient::new(FakeInject::default(), FakeTransport::default());
        client.handle(Message::Enter { x: -1, y: 500 }).unwrap();
        client
            .request_exit(WireEdge::Right, Point { x: -1, y: 500 })
            .unwrap();
        client
            .handle(Message::Input(WireInputEvent {
                event_type: 2,
                code: 0,
                value: 4,
            }))
            .unwrap();
        client.handle(Message::HandoffRelease).unwrap();
        client.handle(Message::Enter { x: -1, y: 600 }).unwrap();
        let (injector, transport) = client.into_parts();
        assert!(injector.inputs.is_empty());
        assert_eq!(injector.releases, 2);
        assert_eq!(
            transport.sent,
            vec![
                Message::EnterAck,
                Message::ExitRequest {
                    edge: WireEdge::Right,
                    x: -1,
                    y: 500,
                },
                Message::EnterAck,
            ]
        );
    }

    #[test]
    fn scroll_wire_preserves_smooth_and_discrete_units() {
        use crate::libei_capture::CapturedEvent;

        assert_eq!(
            captured_to_wire(CapturedEvent::ScrollDelta {
                horizontal: 2.0,
                vertical: -7.0,
            })
            .unwrap(),
            vec![
                WireInputEvent {
                    event_type: 2,
                    code: 12,
                    value: 2,
                },
                WireInputEvent {
                    event_type: 2,
                    code: 11,
                    value: -7,
                },
            ]
        );
        assert_eq!(
            captured_to_wire(CapturedEvent::ScrollDiscrete {
                horizontal: 120,
                vertical: -120,
            })
            .unwrap(),
            vec![
                WireInputEvent {
                    event_type: 2,
                    code: 6,
                    value: 120,
                },
                WireInputEvent {
                    event_type: 2,
                    code: 8,
                    value: -120,
                },
            ]
        );
    }
}
