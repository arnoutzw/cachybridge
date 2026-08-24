//! Transport/controller orchestration for the portal-backed seamless modes.
//!
//! This module has no portal or libei FFI. The platform layer implements the
//! small traits below, while this code enforces the network ordering invariant:
//! an authenticated `EnterAck` is required before any `Input` is sent or
//! injected, and every close/error path first releases local/remote input.

use std::{collections::VecDeque, io, time::Duration};

use thiserror::Error;

use crate::{
    handoff::{HandoffAction, HandoffController, HandoffState, Point},
    protocol::{Message, WireEdge, WireInputEvent},
    transport::{SecureConnection, TransportError},
};

/// Adapter for the consent-driven RemoteDesktop session. Current portal APIs
/// provide relative virtual pointer injection; the requested entry point is
/// retained for handoff accounting but cannot yet be placed absolutely without
/// a ScreenCast coordinate mapping.
pub struct RemoteDesktopInjector {
    session: crate::remote_spike::RemoteDesktopSession,
    entry: Option<Point>,
}

/// Adapter from the reusable InputCapture session and typed libei receiver to
/// the existing evdev-shaped encrypted protocol. It owns the portal activation
/// ID so every stop path can issue the matching portal `Release` before
/// disabling capture.
pub struct InputCaptureAdapter {
    session: crate::portal_spike::InputCaptureSession,
    local_left_x: i32,
    active_activation: Option<u32>,
    absolute_motion: AbsoluteMotionTracker,
    /// One coalesced relative move per receiver dispatch. Buttons, keys and
    /// scrolling stay ordered and uncoalesced; pointer motion is safe to
    /// batch and avoids a burst of individually framed network packets.
    pending_motion: (i32, i32),
    pending: VecDeque<WireInputEvent>,
}

/// Watches the controlled client's right InputCapture barrier. It is separate
/// from RemoteDesktop injection because a return request is a local portal
/// activation, not a network input event.
pub struct RightEdgeReturnWatcher {
    session: crate::portal_spike::InputCaptureSession,
    wire_right_x: i32,
    wire_y_offset: i32,
}

impl RightEdgeReturnWatcher {
    pub fn start(
        wire_right_x: i32,
        wire_y_offset: i32,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            session: crate::portal_spike::InputCaptureSession::start_right()?,
            wire_right_x,
            wire_y_offset,
        })
    }

    pub fn start_with_persistence(
        wire_right_x: i32,
        wire_y_offset: i32,
        persistence: crate::portal_persistence::PortalPersistence,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            session: crate::portal_spike::InputCaptureSession::start_right_with_persistence(
                persistence,
            )?,
            wire_right_x,
            wire_y_offset,
        })
    }

    pub fn take_restore_token(&mut self) -> Option<crate::portal_persistence::RestoreToken> {
        self.session.take_restore_token()
    }

    /// Polls the target's outer right barrier. On activation it releases the
    /// exact target capture before handing the position to the transport layer.
    pub fn poll_exit(&mut self) -> io::Result<Option<Point>> {
        match self.session.poll_signal(Duration::ZERO)? {
            Some(crate::portal_spike::CaptureSignal::Activated {
                activation_id,
                cursor_position: Some((x, y)),
                ..
            }) if x.is_finite() && y.is_finite() => {
                self.session
                    .release(activation_id, None)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                Ok(Some(Point {
                    x: self.wire_right_x,
                    y: rounded_coordinate(y)?
                        .checked_add(self.wire_y_offset)
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "return cursor y overflow")
                        })?,
                }))
            }
            Some(crate::portal_spike::CaptureSignal::Activated { .. }) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "right-edge activation omitted a finite cursor position",
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

impl InputCaptureAdapter {
    pub fn start_left(local_left_x: i32) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            session: crate::portal_spike::InputCaptureSession::start_left()?,
            local_left_x,
            active_activation: None,
            absolute_motion: AbsoluteMotionTracker::default(),
            pending_motion: (0, 0),
            pending: VecDeque::new(),
        })
    }

    pub fn start_left_with_persistence(
        local_left_x: i32,
        persistence: crate::portal_persistence::PortalPersistence,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            session: crate::portal_spike::InputCaptureSession::start_left_with_persistence(
                persistence,
            )?,
            local_left_x,
            active_activation: None,
            absolute_motion: AbsoluteMotionTracker::default(),
            pending_motion: (0, 0),
            pending: VecDeque::new(),
        })
    }

    pub fn take_restore_token(&mut self) -> Option<crate::portal_persistence::RestoreToken> {
        self.session.take_restore_token()
    }

    fn queue_motion(&mut self, dx: i32, dy: i32) {
        self.pending_motion.0 = self.pending_motion.0.saturating_add(dx);
        self.pending_motion.1 = self.pending_motion.1.saturating_add(dy);
    }

    fn flush_motion(&mut self) {
        let (dx, dy) = std::mem::take(&mut self.pending_motion);
        self.pending.extend(relative_wire_events(dx, dy));
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
                // InputCapture frames delimit a compositor update. Send one
                // coherent move before transitions or this frame boundary.
                crate::libei_capture::CapturedEvent::Frame { .. } => {
                    self.flush_motion();
                }
                event => {
                    self.flush_motion();
                    self.pending.extend(captured_to_wire(event)?);
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
                        x: self.local_left_x,
                        y: rounded_coordinate(y)?,
                    });
                }
                Some(crate::portal_spike::CaptureSignal::Activated { .. }) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "left-edge activation omitted a finite cursor position",
                    ));
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
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot begin remote input without an InputCapture activation",
            ))
        }
    }

    fn next_input(&mut self, timeout: Duration) -> io::Result<Option<WireInputEvent>> {
        if let Some(event) = self.pending.pop_front() {
            return Ok(Some(event));
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
        let batch = self.session.dispatch_events(timeout)?;
        self.drain_batch(batch)?;
        Ok(self.pending.pop_front())
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
            .map_err(Self::map_portal_error)
    }

    fn release_local_input(&mut self, restore: Option<Point>) -> io::Result<()> {
        self.absolute_motion.reset();
        self.pending_motion = (0, 0);
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

    let wire_event = |event_type, code, value| WireInputEvent {
        event_type,
        code,
        value,
    };
    let axes = |horizontal: f64, vertical: f64| -> io::Result<Vec<WireInputEvent>> {
        let mut output = Vec::with_capacity(2);
        let horizontal = rounded_delta(horizontal)?;
        let vertical = rounded_delta(vertical)?;
        if horizontal != 0 {
            output.push(wire_event(EV_REL, REL_HWHEEL, horizontal));
        }
        if vertical != 0 {
            output.push(wire_event(EV_REL, REL_WHEEL, vertical));
        }
        Ok(output)
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
        } => axes(horizontal, vertical),
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

    fn inject(&mut self, event: WireInputEvent) -> io::Result<()> {
        const EV_SYN: u16 = 0;
        const EV_KEY: u16 = 1;
        const EV_REL: u16 = 2;
        const SYN_REPORT: u16 = 0;
        const REL_X: u16 = 0;
        const REL_Y: u16 = 1;
        const REL_HWHEEL: u16 = 6;
        const REL_WHEEL: u16 = 8;
        const BTN_MOUSE_FIRST: u16 = 0x110;

        match (event.event_type, event.code) {
            (EV_SYN, SYN_REPORT) => Ok(()),
            (EV_REL, REL_X) => self.session.inject_relative(f64::from(event.value), 0.0),
            (EV_REL, REL_Y) => self.session.inject_relative(0.0, f64::from(event.value)),
            (EV_REL, REL_HWHEEL) => self
                .session
                .inject_scroll(f64::from(event.value), 0.0, false),
            (EV_REL, REL_WHEEL) => self
                .session
                .inject_scroll(0.0, f64::from(event.value), false),
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
        }
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
    fn next_input(&mut self, timeout: Duration) -> io::Result<Option<WireInputEvent>>;
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
    fn inject(&mut self, event: WireInputEvent) -> io::Result<()>;
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
}

impl<C: CaptureBackend, T: MessageTransport> SeamlessHost<C, T> {
    pub fn new(controller: HandoffController, capture: C, transport: T) -> Self {
        Self {
            controller,
            capture,
            transport,
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
                let _ = self.controller.peer_entry_rejected();
                self.capture.release_local_input(None)?;
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
    pub fn forward(&mut self, event: WireInputEvent) -> Result<(), SeamlessError> {
        if !matches!(self.controller.state(), HandoffState::RemoteActive { .. }) {
            return Err(SeamlessError::InputBeforeAcknowledgement);
        }
        self.transport.send(Message::Input(event))?;
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
        match self.capture.next_input(timeout)? {
            Some(event) => {
                // An ExitRequest may have arrived while EIS dispatch waited.
                // Check again before emitting another remote input event.
                self.poll_control()?;
                if matches!(self.controller.state(), HandoffState::RemoteActive { .. }) {
                    self.forward(event)
                } else {
                    Ok(())
                }
            }
            None => {
                if matches!(self.controller.state(), HandoffState::RemoteActive { .. }) {
                    self.transport.send(Message::Heartbeat)?;
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
            return_pending: false,
        }
    }

    pub const fn remote_active(&self) -> bool {
        self.remote_active
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
            Message::Heartbeat => Ok(()),
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
        inputs: VecDeque<Option<WireInputEvent>>,
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

        fn next_input(&mut self, _: Duration) -> io::Result<Option<WireInputEvent>> {
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
        inputs: Vec<WireInputEvent>,
        releases: usize,
    }

    impl InjectBackend for FakeInject {
        fn prepare_entry(&mut self, entry: Point) -> io::Result<()> {
            self.prepared.push(entry);
            Ok(())
        }

        fn inject(&mut self, event: WireInputEvent) -> io::Result<()> {
            self.inputs.push(event);
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
            host.forward(WireInputEvent {
                event_type: 1,
                code: 30,
                value: 1
            }),
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
        assert_eq!(capture.restores, vec![Some(Point { x: 0, y: 500 })]);
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
        client.handle(Message::HandoffRelease).unwrap();
        let (injector, transport) = client.into_parts();
        assert_eq!(injector.prepared, vec![Point { x: -1, y: 500 }]);
        assert_eq!(injector.inputs.len(), 1);
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
}
