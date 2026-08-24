//! Explicit, consent-driven controller-side InputCapture portal spike.
//!
//! Nothing in this module runs unless the `portal-spike` CLI command is
//! invoked. The reusable session API is likewise opt-in and exposes typed EIS
//! events only after portal consent and activation.

use std::{
    collections::HashMap,
    error::Error,
    io,
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use rand::RngCore;
use zbus::{
    blocking::{Connection, MessageIterator, Proxy},
    message::Type,
    zvariant::{OwnedObjectPath, OwnedValue, Str, Value},
    MatchRule,
};

use crate::{
    libei_capture::{DispatchBatch, Receiver, ReceiverMetadata},
    portal_persistence::{PortalPersistence, RestoreToken},
};

const PORTAL_NAME: &str = "org.freedesktop.portal.Desktop";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const INPUT_CAPTURE: &str = "org.freedesktop.portal.InputCapture";
const REQUEST: &str = "org.freedesktop.portal.Request";
const SESSION: &str = "org.freedesktop.portal.Session";
const CAP_KEYBOARD: u32 = 1;
const CAP_POINTER: u32 = 2;
const BARRIER_ID: u32 = 1;

type Options<'a> = HashMap<&'a str, Value<'a>>;
type Results = HashMap<String, OwnedValue>;
pub type CaptureResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Zone {
    pub width: u32,
    pub height: u32,
    pub x: i32,
    pub y: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Barrier {
    pub id: u32,
    pub x1: i32,
    pub y1: i32,
    pub x2: i32,
    pub y2: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureEdge {
    Left,
    Right,
}

impl CaptureEdge {
    fn name(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Right => "right",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureCapabilities {
    PointerOnly,
    KeyboardPointer,
}

impl CaptureCapabilities {
    fn bits(self) -> u32 {
        match self {
            Self::PointerOnly => CAP_POINTER,
            Self::KeyboardPointer => CAP_KEYBOARD | CAP_POINTER,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::PointerOnly => "pointer",
            Self::KeyboardPointer => "keyboard+pointer",
        }
    }
}

/// A lifecycle notification belonging to this InputCapture session.
#[derive(Debug, Clone, PartialEq)]
pub enum CaptureSignal {
    Activated {
        activation_id: u32,
        barrier_id: Option<u32>,
        cursor_position: Option<(f64, f64)>,
    },
    Deactivated {
        activation_id: Option<u32>,
    },
    Disabled,
    ZonesChanged {
        zone_set: Option<u32>,
    },
    Other {
        member: String,
    },
}

#[derive(Debug)]
struct PortalResponse {
    code: u32,
    results: Results,
}

#[derive(Debug)]
struct SessionGuard {
    connection: Connection,
    path: OwnedObjectPath,
    closed: bool,
}

impl SessionGuard {
    fn close(&mut self) -> CaptureResult<()> {
        if self.closed {
            return Ok(());
        }
        let input = input_proxy(&self.connection)?;
        let empty = Options::new();
        if let Err(error) = input.call::<_, _, ()>("Disable", &(&self.path, &empty)) {
            eprintln!("portal-spike: cleanup Disable failed: {error}");
        }
        let session = Proxy::new(&self.connection, PORTAL_NAME, &self.path, SESSION)?;
        session.call::<_, _, ()>("Close", &())?;
        self.closed = true;
        println!("cleanup: capture disabled and portal session closed");
        Ok(())
    }
}

/// A consented, enabled edge InputCapture session and its passive EIS receiver.
///
/// Construction is explicit and may display the desktop portal consent dialog.
/// Dropping the value disables capture and closes the portal session.
pub struct InputCaptureSession {
    receiver: Receiver,
    metadata: ReceiverMetadata,
    portal: SessionGuard,
    signals: mpsc::Receiver<CaptureSignal>,
    enabled: bool,
    edge: CaptureEdge,
    capabilities: CaptureCapabilities,
    restore_token: Option<RestoreToken>,
}

impl InputCaptureSession {
    /// Request keyboard/pointer capture and arm the left edge.
    pub fn start_left() -> CaptureResult<Self> {
        Self::start(CaptureEdge::Left, CaptureCapabilities::KeyboardPointer)
    }

    pub fn start_left_with_persistence(persistence: PortalPersistence) -> CaptureResult<Self> {
        Self::start_with_persistence(
            CaptureEdge::Left,
            CaptureCapabilities::KeyboardPointer,
            persistence,
        )
    }

    /// Request pointer-only capture and arm the right edge.
    ///
    /// This is intended to coexist with a RemoteDesktop injection session on
    /// a controlled peer so its right edge can trigger the return handoff.
    pub fn start_right() -> CaptureResult<Self> {
        Self::start_right_pointer()
    }

    /// Explicitly named alias for the pointer-only right-edge profile.
    pub fn start_right_pointer() -> CaptureResult<Self> {
        Self::start(CaptureEdge::Right, CaptureCapabilities::PointerOnly)
    }

    pub fn start_right_with_persistence(persistence: PortalPersistence) -> CaptureResult<Self> {
        Self::start_with_persistence(
            CaptureEdge::Right,
            CaptureCapabilities::PointerOnly,
            persistence,
        )
    }

    /// Request an explicit edge/capability combination.
    pub fn start(edge: CaptureEdge, capabilities: CaptureCapabilities) -> CaptureResult<Self> {
        Self::start_with_persistence(edge, capabilities, PortalPersistence::disabled())
    }

    pub fn start_with_persistence(
        edge: CaptureEdge,
        capabilities: CaptureCapabilities,
        persistence: PortalPersistence,
    ) -> CaptureResult<Self> {
        start_capture_session(edge, capabilities, persistence)
    }

    pub fn edge(&self) -> CaptureEdge {
        self.edge
    }

    pub fn capabilities(&self) -> CaptureCapabilities {
        self.capabilities
    }

    /// Replacement for the supplied single-use token, if persistence was granted.
    pub fn restore_token(&self) -> Option<&RestoreToken> {
        self.restore_token.as_ref()
    }

    pub fn take_restore_token(&mut self) -> Option<RestoreToken> {
        self.restore_token.take()
    }

    pub fn metadata(&self) -> &ReceiverMetadata {
        &self.metadata
    }

    /// Poll portal lifecycle state without reading EIS input payloads.
    pub fn poll_signal(&self, timeout: Duration) -> io::Result<Option<CaptureSignal>> {
        match self.signals.recv_timeout(timeout) {
            Ok(signal) => Ok(Some(signal)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "InputCapture signal observer disconnected",
            )),
        }
    }

    /// Read a bounded batch of typed libei input events.
    pub fn dispatch_events(&mut self, timeout: Duration) -> io::Result<DispatchBatch> {
        self.receiver.dispatch(timeout)
    }

    pub fn receiver_mut(&mut self) -> &mut Receiver {
        &mut self.receiver
    }

    /// Release one active capture and optionally suggest the host cursor position.
    pub fn release(
        &mut self,
        activation_id: u32,
        cursor_position: Option<(f64, f64)>,
    ) -> CaptureResult<()> {
        let input = input_proxy(&self.portal.connection)?;
        let mut options = Options::new();
        options.insert("activation_id", Value::from(activation_id));
        if let Some(position) = cursor_position {
            if !position.0.is_finite() || !position.1.is_finite() {
                return Err(actionable("release cursor position must be finite"));
            }
            options.insert("cursor_position", Value::from(position));
        }
        input.call::<_, _, ()>("Release", &(&self.portal.path, &options))?;
        Ok(())
    }

    pub fn disable(&mut self) -> CaptureResult<()> {
        if !self.enabled {
            return Ok(());
        }
        let input = input_proxy(&self.portal.connection)?;
        let empty = Options::new();
        input.call::<_, _, ()>("Disable", &(&self.portal.path, &empty))?;
        self.enabled = false;
        Ok(())
    }

    pub fn enable(&mut self) -> CaptureResult<()> {
        if self.enabled {
            return Ok(());
        }
        let input = input_proxy(&self.portal.connection)?;
        let empty = Options::new();
        input.call::<_, _, ()>("Enable", &(&self.portal.path, &empty))?;
        self.enabled = true;
        Ok(())
    }

    pub fn close(&mut self) -> CaptureResult<()> {
        self.enabled = false;
        self.portal.close()
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("portal-spike: best-effort session cleanup failed: {error}");
        }
    }
}

pub fn run_left(observe_seconds: u64) -> CaptureResult<()> {
    let mut capture = InputCaptureSession::start_left()?;
    println!(
        "Enable: left barrier armed for {observe_seconds}s; any activation is immediately safety-disabled"
    );
    let deadline = Instant::now() + Duration::from_secs(observe_seconds);
    let mut observed = 0_u32;
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match capture.poll_signal(remaining.min(Duration::from_millis(50)))? {
            Some(signal) => {
                observed += 1;
                println!("signal: {signal:?}");
                if matches!(signal, CaptureSignal::Activated { .. }) {
                    capture.disable()?;
                    println!("safety Disable succeeded");
                    report_eis_events(capture.receiver_mut())?;
                    break;
                }
            }
            None => report_eis_events(capture.receiver_mut())?,
        }
    }
    if observed == 0 {
        println!("signals: none observed during the armed window");
    }
    capture.close()
}

fn start_capture_session(
    edge: CaptureEdge,
    capabilities: CaptureCapabilities,
    persistence: PortalPersistence,
) -> CaptureResult<InputCaptureSession> {
    if std::env::var("XDG_SESSION_TYPE").as_deref() != Ok("wayland") {
        return Err(actionable(
            "this process is not in a Wayland session; run the command from a terminal on the graphical host",
        ));
    }

    let connection = Connection::session()
        .map_err(|error| actionable(format!("connect to the user session D-Bus: {error}")))?;
    let input = input_proxy(&connection)?;
    let version: u32 = input
        .get_property("version")
        .map_err(|error| actionable(format!("read InputCapture.version: {error}")))?;
    let supported: u32 = input
        .get_property("SupportedCapabilities")
        .map_err(|error| actionable(format!("read SupportedCapabilities: {error}")))?;
    let required_capabilities = capabilities.bits();
    if version < 2 || supported & required_capabilities != required_capabilities {
        return Err(actionable(format!(
            "InputCapture v2 with {} is required; found version={version}, capabilities={supported}",
            capabilities.name()
        )));
    }
    println!(
        "portal: InputCapture v{version}, capabilities={supported} ({} available)",
        capabilities.name()
    );

    let session_token = new_token("cachybridge_session");
    let mut create_options = Options::new();
    create_options.insert(
        "session_handle_token",
        Value::from(Str::from(session_token.clone())),
    );
    let create_results: Results = input
        .call("CreateSession2", &create_options)
        .map_err(|error| actionable(format!("CreateSession2 failed: {error}")))?;
    let session_path = required_object_path(&create_results, "session_handle")?;
    println!("CreateSession2: session={session_path}");
    let session = SessionGuard {
        connection: connection.clone(),
        path: session_path,
        closed: false,
    };

    let start_token = new_token("cachybridge_start");
    let (expected_start_path, mut start_signals) = request_listener(&connection, &start_token)?;
    let mut start_options = Options::new();
    start_options.insert("handle_token", Value::from(Str::from(start_token.clone())));
    start_options.insert("capabilities", Value::from(required_capabilities));
    if persistence.is_enabled() {
        start_options.insert("persist_mode", Value::from(persistence.persist_mode()));
        if let Some(token) = persistence.restore_token() {
            start_options.insert(
                "restore_token",
                Value::from(Str::from(token.expose_secret())),
            );
        }
    }
    println!("Start: waiting for the desktop portal consent decision...");
    let returned_start_path: OwnedObjectPath = input
        .call("Start", &(&session.path, "", &start_options))
        .map_err(|error| actionable(format!("Start call failed: {error}")))?;
    verify_request_path(&expected_start_path, &returned_start_path)?;
    let start_response = wait_for_response(&mut start_signals, "Start")?;
    require_success("Start", start_response.code)?;
    let granted = optional_u32(&start_response.results, "capabilities")?.unwrap_or(0);
    println!("Start response: success, granted capabilities={granted}");
    if granted & required_capabilities != required_capabilities {
        return Err(actionable(format!(
            "portal consent did not grant {}; granted capabilities={granted}",
            capabilities.name()
        )));
    }
    let restore_token = if persistence.is_enabled() {
        optional_restore_token(&start_response.results)?
    } else {
        None
    };

    let zones_response = request_call(
        &connection,
        &input,
        "GetZones",
        &session.path,
        Options::new(),
        |input, path, options| input.call("GetZones", &(path, &options)),
    )?;
    require_success("GetZones", zones_response.code)?;
    let zones = required_zones(&zones_response.results)?;
    let zone_set = required_u32(&zones_response.results, "zone_set")?;
    println!("GetZones response: zone_set={zone_set}, zones={zones:?}");
    let barrier = choose_barrier(edge, &zones)?;
    println!(
        "{} barrier candidate: id={} position=({}, {})..({}, {})",
        edge.name(),
        barrier.id,
        barrier.x1,
        barrier.y1,
        barrier.x2,
        barrier.y2
    );

    let barrier_token = new_token("cachybridge_barrier");
    let (expected_barrier_path, mut barrier_signals) =
        request_listener(&connection, &barrier_token)?;
    let mut barrier_options = Options::new();
    barrier_options.insert(
        "handle_token",
        Value::from(Str::from(barrier_token.clone())),
    );
    let mut barrier_description = Options::new();
    barrier_description.insert("barrier_id", Value::from(barrier.id));
    barrier_description.insert(
        "position",
        Value::from((barrier.x1, barrier.y1, barrier.x2, barrier.y2)),
    );
    let barriers = vec![barrier_description];
    let returned_barrier_path: OwnedObjectPath = input
        .call(
            "SetPointerBarriers",
            &(&session.path, &barrier_options, &barriers, zone_set),
        )
        .map_err(|error| actionable(format!("SetPointerBarriers call failed: {error}")))?;
    verify_request_path(&expected_barrier_path, &returned_barrier_path)?;
    let barrier_response = wait_for_response(&mut barrier_signals, "SetPointerBarriers")?;
    require_success("SetPointerBarriers", barrier_response.code)?;
    let failed =
        optional_u32_vec(&barrier_response.results, "failed_barriers")?.unwrap_or_default();
    println!("SetPointerBarriers response: failed_barriers={failed:?}");
    if failed.contains(&barrier.id) {
        return Err(actionable(format!(
            "KWin denied the computed {}-edge barrier; inspect the reported zones and desktop topology",
            edge.name()
        )));
    }

    // The portal requires ConnectToEIS before Enable. The narrow receiver only
    // completes the handshake and reports metadata; it exposes no input data.
    let empty = Options::new();
    let eis_fd: zbus::zvariant::OwnedFd = input
        .call("ConnectToEIS", &(&session.path, &empty))
        .map_err(|error| actionable(format!("ConnectToEIS failed before Enable: {error}")))?;
    let system_fd: std::os::fd::OwnedFd = eis_fd.into();
    let mut eis = Receiver::from_fd(system_fd)
        .map_err(|error| actionable(format!("initialize libei receiver: {error}")))?;
    let metadata = eis
        .handshake(Duration::from_secs(3))
        .map_err(|error| actionable(format!("complete EIS receiver handshake: {error}")))?
        .clone();
    print_eis_metadata(&metadata);

    let (events_tx, events_rx) = mpsc::channel();
    start_signal_observer(connection.clone(), session.path.clone(), events_tx)?;
    input
        .call::<_, _, ()>("Enable", &(&session.path, &empty))
        .map_err(|error| actionable(format!("Enable failed: {error}")))?;
    Ok(InputCaptureSession {
        receiver: eis,
        metadata,
        portal: session,
        signals: events_rx,
        enabled: true,
        edge,
        capabilities,
        restore_token,
    })
}

fn print_eis_metadata(metadata: &ReceiverMetadata) {
    println!(
        "EIS handshake: connected={} seats={} devices={}",
        metadata.connected,
        metadata.seats.len(),
        metadata.devices.len()
    );
    for seat in &metadata.seats {
        println!(
            "EIS seat: name={:?} capabilities={:?}",
            seat.name, seat.capabilities
        );
    }
    for device in &metadata.devices {
        println!(
            "EIS device: name={:?} type={} capabilities={:?} regions={:?}",
            device.name, device.device_type, device.capabilities, device.regions
        );
    }
    if metadata.devices.is_empty() {
        println!("EIS devices: none announced during the bounded metadata window");
    }
}

fn report_eis_events(eis: &mut Receiver) -> CaptureResult<()> {
    let batch = eis
        .dispatch(Duration::ZERO)
        .map_err(|error| actionable(format!("dispatch EIS metadata events: {error}")))?;
    for event in batch.event_types {
        println!("EIS event: {event}");
    }
    Ok(())
}

fn input_proxy(connection: &Connection) -> zbus::Result<Proxy<'_>> {
    Proxy::new(connection, PORTAL_NAME, PORTAL_PATH, INPUT_CAPTURE)
}

fn request_call<F>(
    connection: &Connection,
    input: &Proxy<'_>,
    stage: &str,
    session: &OwnedObjectPath,
    mut options: Options<'_>,
    call: F,
) -> CaptureResult<PortalResponse>
where
    F: FnOnce(&Proxy<'_>, &OwnedObjectPath, Options<'_>) -> zbus::Result<OwnedObjectPath>,
{
    let token = new_token("cachybridge_request");
    options.insert("handle_token", Value::from(Str::from(token.clone())));
    let (expected, mut signals) = request_listener(connection, &token)?;
    let returned = call(input, session, options)
        .map_err(|error| actionable(format!("{stage} call failed: {error}")))?;
    verify_request_path(&expected, &returned)?;
    wait_for_response(&mut signals, stage)
}

fn request_listener(
    connection: &Connection,
    token: &str,
) -> CaptureResult<(OwnedObjectPath, MessageIterator)> {
    let unique = connection
        .unique_name()
        .ok_or_else(|| actionable("session D-Bus did not assign a unique name"))?;
    let sender = unique.as_str().trim_start_matches(':').replace('.', "_");
    let path: OwnedObjectPath =
        format!("/org/freedesktop/portal/desktop/request/{sender}/{token}").try_into()?;
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .sender(PORTAL_NAME)?
        .path(path.clone())?
        .interface(REQUEST)?
        .member("Response")?
        .build();
    let iterator = MessageIterator::for_match_rule(rule, connection, Some(1))?;
    Ok((path, iterator))
}

fn wait_for_response(signals: &mut MessageIterator, stage: &str) -> CaptureResult<PortalResponse> {
    let message = signals
        .next()
        .ok_or_else(|| actionable(format!("{stage} request signal stream ended")))??;
    let (code, results): (u32, Results) = message
        .body()
        .deserialize()
        .map_err(|error| actionable(format!("decode {stage} Response: {error}")))?;
    Ok(PortalResponse { code, results })
}

fn verify_request_path(
    expected: &OwnedObjectPath,
    returned: &OwnedObjectPath,
) -> CaptureResult<()> {
    if expected == returned {
        Ok(())
    } else {
        Err(actionable(format!(
            "portal returned unexpected request path {returned}; expected {expected}"
        )))
    }
}

fn require_success(stage: &str, response: u32) -> CaptureResult<()> {
    match response {
        0 => Ok(()),
        1 => Err(actionable(format!("{stage} was cancelled by the user"))),
        2 => Err(actionable(format!(
            "{stage} was ended by the portal; inspect the desktop portal service logs"
        ))),
        other => Err(actionable(format!(
            "{stage} returned unknown response code {other}"
        ))),
    }
}

fn required_object_path(results: &Results, key: &str) -> CaptureResult<OwnedObjectPath> {
    let value = results
        .get(key)
        .ok_or_else(|| actionable(format!("portal result omitted required `{key}`")))?;
    OwnedObjectPath::try_from(value.try_clone()?)
        .map_err(|error| actionable(format!("portal result `{key}` has wrong type: {error}")))
}

fn required_u32(results: &Results, key: &str) -> CaptureResult<u32> {
    optional_u32(results, key)?
        .ok_or_else(|| actionable(format!("portal result omitted required `{key}`")))
}

fn optional_u32(results: &Results, key: &str) -> CaptureResult<Option<u32>> {
    results
        .get(key)
        .map(|value| {
            u32::try_from(value).map_err(|error| {
                actionable(format!("portal result `{key}` has wrong type: {error}"))
            })
        })
        .transpose()
}

fn optional_u32_vec(results: &Results, key: &str) -> CaptureResult<Option<Vec<u32>>> {
    results
        .get(key)
        .map(|value| {
            Vec::<u32>::try_from(value.try_clone()?).map_err(|error| {
                actionable(format!("portal result `{key}` has wrong type: {error}"))
            })
        })
        .transpose()
}

fn optional_f64_pair(results: &Results, key: &str) -> CaptureResult<Option<(f64, f64)>> {
    results
        .get(key)
        .map(|value| {
            <(f64, f64)>::try_from(value.try_clone()?).map_err(|error| {
                actionable(format!("portal result `{key}` has wrong type: {error}"))
            })
        })
        .transpose()
}

fn optional_restore_token(results: &Results) -> CaptureResult<Option<RestoreToken>> {
    results
        .get("restore_token")
        .map(|value| {
            let token = String::try_from(value.try_clone()?).map_err(|error| {
                actionable(format!(
                    "portal result `restore_token` has wrong type: {error}"
                ))
            })?;
            RestoreToken::new(token).map_err(|error| actionable(error.to_string()))
        })
        .transpose()
}

fn required_zones(results: &Results) -> CaptureResult<Vec<Zone>> {
    let value = results
        .get("zones")
        .ok_or_else(|| actionable("portal result omitted required `zones`"))?;
    let tuples = Vec::<(u32, u32, i32, i32)>::try_from(value.try_clone()?)
        .map_err(|error| actionable(format!("portal result `zones` has wrong type: {error}")))?;
    Ok(tuples
        .into_iter()
        .map(|(width, height, x, y)| Zone {
            width,
            height,
            x,
            y,
        })
        .collect())
}

pub fn choose_left_barrier(zones: &[Zone]) -> CaptureResult<Barrier> {
    let minimum_x = zones
        .iter()
        .filter(|zone| zone.width > 0 && zone.height > 0)
        .map(|zone| zone.x)
        .min()
        .ok_or_else(|| actionable("portal returned no non-empty zones for a left barrier"))?;
    let zone = zones
        .iter()
        .filter(|zone| zone.width > 0 && zone.height > 0 && zone.x == minimum_x)
        .max_by_key(|zone| zone.height)
        .ok_or_else(|| actionable("portal returned no usable leftmost zone"))?;
    let y2 = zone
        .y
        .checked_add(i32::try_from(zone.height - 1).map_err(|_| {
            actionable("leftmost zone height cannot be represented in portal coordinates")
        })?)
        .ok_or_else(|| actionable("leftmost zone coordinates overflow i32"))?;
    Ok(Barrier {
        id: BARRIER_ID,
        x1: zone.x,
        y1: zone.y,
        x2: zone.x,
        y2,
    })
}

pub fn choose_right_barrier(zones: &[Zone]) -> CaptureResult<Barrier> {
    let mut rightmost: Option<(i32, &Zone)> = None;
    for zone in zones
        .iter()
        .filter(|zone| zone.width > 0 && zone.height > 0)
    {
        let right = zone
            .x
            .checked_add(i32::try_from(zone.width).map_err(|_| {
                actionable("zone width cannot be represented in portal coordinates")
            })?)
            .ok_or_else(|| actionable("rightmost zone coordinates overflow i32"))?;
        let replace = rightmost.is_none_or(|(candidate_right, candidate)| {
            right > candidate_right || (right == candidate_right && zone.height > candidate.height)
        });
        if replace {
            rightmost = Some((right, zone));
        }
    }
    let (right, zone) = rightmost
        .ok_or_else(|| actionable("portal returned no non-empty zones for a right barrier"))?;
    let y2 = zone
        .y
        .checked_add(i32::try_from(zone.height - 1).map_err(|_| {
            actionable("rightmost zone height cannot be represented in portal coordinates")
        })?)
        .ok_or_else(|| actionable("rightmost zone coordinates overflow i32"))?;
    Ok(Barrier {
        id: BARRIER_ID,
        x1: right,
        y1: zone.y,
        x2: right,
        y2,
    })
}

pub fn choose_barrier(edge: CaptureEdge, zones: &[Zone]) -> CaptureResult<Barrier> {
    match edge {
        CaptureEdge::Left => choose_left_barrier(zones),
        CaptureEdge::Right => choose_right_barrier(zones),
    }
}

fn start_signal_observer(
    connection: Connection,
    session: OwnedObjectPath,
    sender: mpsc::Sender<CaptureSignal>,
) -> CaptureResult<()> {
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .sender(PORTAL_NAME)?
        .path(PORTAL_PATH)?
        .interface(INPUT_CAPTURE)?
        .build();
    let signals = MessageIterator::for_match_rule(rule, &connection, Some(16))?;
    thread::spawn(move || {
        for message in signals {
            let Ok(message) = message else {
                break;
            };
            let member = message
                .header()
                .member()
                .map(|member| member.as_str().to_owned())
                .unwrap_or_else(|| "unknown".to_owned());
            let decoded: zbus::Result<(OwnedObjectPath, Results)> = message.body().deserialize();
            let Ok((signal_session, options)) = decoded else {
                let _ = sender.send(CaptureSignal::Other {
                    member: format!("{member}: could not decode signal payload"),
                });
                continue;
            };
            if signal_session != session {
                continue;
            }
            let activation_id = optional_u32(&options, "activation_id").ok().flatten();
            let barrier_id = optional_u32(&options, "barrier_id").ok().flatten();
            let zone_set = optional_u32(&options, "zone_set").ok().flatten();
            let signal = match member.as_str() {
                "Activated" => match activation_id {
                    Some(activation_id) => CaptureSignal::Activated {
                        activation_id,
                        barrier_id,
                        cursor_position: optional_f64_pair(&options, "cursor_position")
                            .ok()
                            .flatten(),
                    },
                    None => CaptureSignal::Other {
                        member: "Activated: missing activation_id".to_owned(),
                    },
                },
                "Deactivated" => CaptureSignal::Deactivated { activation_id },
                "Disabled" => CaptureSignal::Disabled,
                "ZonesChanged" => CaptureSignal::ZonesChanged { zone_set },
                _ => CaptureSignal::Other { member },
            };
            if sender.send(signal).is_err() {
                break;
            }
        }
    });
    Ok(())
}

fn new_token(prefix: &str) -> String {
    let mut random = [0_u8; 12];
    rand::thread_rng().fill_bytes(&mut random);
    format!("{prefix}_{}", hex::encode(random))
}

fn actionable(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chooses_full_left_edge_of_leftmost_zone() {
        let barrier = choose_left_barrier(&[
            Zone {
                width: 1920,
                height: 1080,
                x: 0,
                y: 0,
            },
            Zone {
                width: 2560,
                height: 1440,
                x: -2560,
                y: -200,
            },
        ])
        .unwrap();
        assert_eq!(
            barrier,
            Barrier {
                id: 1,
                x1: -2560,
                y1: -200,
                x2: -2560,
                y2: 1239,
            }
        );
    }

    #[test]
    fn picks_tallest_zone_when_multiple_share_leftmost_edge() {
        let barrier = choose_left_barrier(&[
            Zone {
                width: 100,
                height: 50,
                x: -100,
                y: 0,
            },
            Zone {
                width: 100,
                height: 80,
                x: -100,
                y: 50,
            },
        ])
        .unwrap();
        assert_eq!((barrier.y1, barrier.y2), (50, 129));
    }

    #[test]
    fn chooses_full_right_edge_of_rightmost_zone() {
        let barrier = choose_right_barrier(&[
            Zone {
                width: 1920,
                height: 1080,
                x: 0,
                y: 0,
            },
            Zone {
                width: 1920,
                height: 1200,
                x: 1920,
                y: -100,
            },
        ])
        .unwrap();
        assert_eq!(
            barrier,
            Barrier {
                id: 1,
                x1: 3840,
                y1: -100,
                x2: 3840,
                y2: 1099,
            }
        );
    }

    #[test]
    fn picks_tallest_zone_when_multiple_share_rightmost_edge() {
        let barrier = choose_right_barrier(&[
            Zone {
                width: 100,
                height: 50,
                x: 0,
                y: 0,
            },
            Zone {
                width: 50,
                height: 80,
                x: 50,
                y: 50,
            },
        ])
        .unwrap();
        assert_eq!((barrier.x1, barrier.y1, barrier.y2), (100, 50, 129));
    }

    #[test]
    fn rejects_empty_and_overflowing_zone_geometry() {
        assert!(choose_left_barrier(&[]).is_err());
        assert!(choose_right_barrier(&[]).is_err());
        assert!(choose_left_barrier(&[Zone {
            width: 100,
            height: 2,
            x: 0,
            y: i32::MAX,
        }])
        .is_err());
        assert!(choose_right_barrier(&[Zone {
            width: 1,
            height: 1,
            x: i32::MAX,
            y: 0,
        }])
        .is_err());
    }

    #[test]
    fn capture_profiles_request_expected_portal_bits() {
        assert_eq!(CaptureCapabilities::PointerOnly.bits(), CAP_POINTER);
        assert_eq!(
            CaptureCapabilities::KeyboardPointer.bits(),
            CAP_KEYBOARD | CAP_POINTER
        );
        assert_eq!(CaptureEdge::Left.name(), "left");
        assert_eq!(CaptureEdge::Right.name(), "right");
    }

    #[test]
    fn response_codes_have_actionable_meaning() {
        assert!(require_success("Start", 0).is_ok());
        assert!(require_success("Start", 1)
            .unwrap_err()
            .to_string()
            .contains("cancelled"));
        assert!(require_success("Start", 2)
            .unwrap_err()
            .to_string()
            .contains("portal"));
        assert!(require_success("Start", 99)
            .unwrap_err()
            .to_string()
            .contains("unknown"));
    }

    #[test]
    fn parses_portal_zone_tuple_array() {
        let raw = vec![(5120_u32, 2880_u32, -5120_i32, 0_i32)];
        let mut results = Results::new();
        results.insert(
            "zones".to_owned(),
            OwnedValue::try_from(Value::from(raw)).unwrap(),
        );
        assert_eq!(
            required_zones(&results).unwrap(),
            vec![Zone {
                width: 5120,
                height: 2880,
                x: -5120,
                y: 0,
            }]
        );
    }

    #[test]
    fn parses_optional_cursor_position() {
        let mut results = Results::new();
        results.insert(
            "cursor_position".to_owned(),
            OwnedValue::try_from(Value::from((-0.5_f64, 1440.0_f64))).unwrap(),
        );
        assert_eq!(
            optional_f64_pair(&results, "cursor_position").unwrap(),
            Some((-0.5, 1440.0))
        );
        assert_eq!(optional_f64_pair(&results, "missing").unwrap(), None);
    }

    #[test]
    fn parses_replacement_restore_token_without_logging_it() {
        let mut results = Results::new();
        results.insert(
            "restore_token".to_owned(),
            OwnedValue::from(Str::from("replacement-secret")),
        );
        let token = optional_restore_token(&results).unwrap().unwrap();
        assert_eq!(token.expose_secret(), "replacement-secret");
        assert!(!format!("{token:?}").contains("replacement-secret"));
        assert!(optional_restore_token(&Results::new()).unwrap().is_none());
    }
}
