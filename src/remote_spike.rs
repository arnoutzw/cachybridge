//! Explicit, consent-driven follower-side RemoteDesktop portal spike.

use std::{collections::HashMap, error::Error, io, time::Duration};

use rand::RngCore;
use zbus::{
    blocking::{Connection, MessageIterator, Proxy},
    message::Type,
    zvariant::{OwnedObjectPath, OwnedValue, Str, Value},
    MatchRule,
};

use crate::{
    libei_capture::ReceiverMetadata,
    libei_inject::{InputState, Sender},
    portal_persistence::{PortalPersistence, RestoreToken},
};

const PORTAL_NAME: &str = "org.freedesktop.portal.Desktop";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const REMOTE_DESKTOP: &str = "org.freedesktop.portal.RemoteDesktop";
const REQUEST: &str = "org.freedesktop.portal.Request";
const SESSION: &str = "org.freedesktop.portal.Session";
const REQUIRED_DEVICE_TYPES: u32 = 1 | 2; // keyboard | pointer

type Options<'a> = HashMap<&'a str, Value<'a>>;
type Results = HashMap<String, OwnedValue>;
pub type RemoteResult<T> = Result<T, Box<dyn Error>>;

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
    fn close(&mut self) -> RemoteResult<()> {
        if self.closed {
            return Ok(());
        }
        let session = Proxy::new(&self.connection, PORTAL_NAME, &self.path, SESSION)?;
        session.call::<_, _, ()>("Close", &())?;
        self.closed = true;
        println!("cleanup: RemoteDesktop session closed");
        Ok(())
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("remote-spike: best-effort session cleanup failed: {error}");
        }
    }
}

pub struct RemoteDesktopSession {
    // EIS must disconnect before the owning portal session closes.
    sender: Option<Sender>,
    portal: SessionGuard,
    metadata: ReceiverMetadata,
    restore_token: Option<RestoreToken>,
}

impl RemoteDesktopSession {
    pub fn start() -> RemoteResult<Self> {
        Self::start_with_persistence(PortalPersistence::disabled())
    }

    pub fn start_with_persistence(persistence: PortalPersistence) -> RemoteResult<Self> {
        start_session(persistence)
    }

    pub fn metadata(&self) -> &ReceiverMetadata {
        &self.metadata
    }

    /// Replacement for the supplied single-use token, if persistence was granted.
    pub fn restore_token(&self) -> Option<&RestoreToken> {
        self.restore_token.as_ref()
    }

    pub fn take_restore_token(&mut self) -> Option<RestoreToken> {
        self.restore_token.take()
    }

    pub fn inject_relative(&mut self, dx: f64, dy: f64) -> io::Result<()> {
        self.sender_mut()?.inject_relative(dx, dy)
    }

    pub fn inject_key(&mut self, evdev: u16, state: InputState) -> io::Result<()> {
        self.sender_mut()?.inject_key(evdev, state)
    }

    pub fn inject_button(&mut self, evdev: u16, state: InputState) -> io::Result<()> {
        self.sender_mut()?.inject_button(evdev, state)
    }

    pub fn inject_scroll(
        &mut self,
        horizontal: f64,
        vertical: f64,
        finish: bool,
    ) -> io::Result<()> {
        self.sender_mut()?
            .inject_scroll(horizontal, vertical, finish)
    }

    pub fn bounded_pointer_test(&mut self) -> io::Result<()> {
        self.sender_mut()?.bounded_pointer_test()
    }

    /// Release all held input state without closing the consented portal session.
    pub fn release_all(&mut self) -> io::Result<()> {
        self.sender_mut()?.release_all();
        Ok(())
    }

    pub fn close(&mut self) -> RemoteResult<()> {
        drop(self.sender.take());
        self.portal.close()
    }

    fn sender_mut(&mut self) -> io::Result<&mut Sender> {
        self.sender
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "EIS sender is closed"))
    }
}

pub fn run(pointer_test: bool) -> RemoteResult<()> {
    let mut session = RemoteDesktopSession::start()?;
    if pointer_test {
        session
            .bounded_pointer_test()
            .map_err(|error| actionable(format!("bounded pointer test failed: {error}")))?;
        println!("pointer test: sent +2 then -2 logical pixels; net displacement zero");
    } else {
        println!("pointer test: skipped (pass --pointer-test to opt in)");
    }
    session.close()
}

fn start_session(persistence: PortalPersistence) -> RemoteResult<RemoteDesktopSession> {
    let connection = Connection::session()
        .map_err(|error| actionable(format!("connect to the user session D-Bus: {error}")))?;
    let remote = remote_proxy(&connection)?;
    let version: u32 = remote
        .get_property("version")
        .map_err(|error| actionable(format!("read RemoteDesktop.version: {error}")))?;
    let available: u32 = remote
        .get_property("AvailableDeviceTypes")
        .map_err(|error| actionable(format!("read AvailableDeviceTypes: {error}")))?;
    if version < 2 || available & REQUIRED_DEVICE_TYPES != REQUIRED_DEVICE_TYPES {
        return Err(actionable(format!(
            "RemoteDesktop v2 with keyboard+pointer is required; found version={version}, device_types={available}"
        )));
    }
    println!(
        "portal: RemoteDesktop v{version}, device_types={available} (keyboard+pointer available)"
    );

    let create_token = new_token("cachybridge_remote_create");
    let session_token = new_token("cachybridge_remote_session");
    let (expected_create_path, mut create_signals) = request_listener(&connection, &create_token)?;
    let mut create_options = Options::new();
    create_options.insert("handle_token", Value::from(Str::from(create_token.clone())));
    create_options.insert(
        "session_handle_token",
        Value::from(Str::from(session_token)),
    );
    let returned_create_path: OwnedObjectPath = remote
        .call("CreateSession", &create_options)
        .map_err(|error| actionable(format!("CreateSession call failed: {error}")))?;
    verify_request_path(&expected_create_path, &returned_create_path)?;
    let create_response = wait_for_response(&mut create_signals, "CreateSession")?;
    require_success("CreateSession", create_response.code)?;
    let session_path = required_session_path(&create_response.results)?;
    println!("CreateSession response: session={session_path}");
    let session = SessionGuard {
        connection: connection.clone(),
        path: session_path,
        closed: false,
    };

    let select_token = new_token("cachybridge_remote_select");
    let (expected_select_path, mut select_signals) = request_listener(&connection, &select_token)?;
    let mut select_options = Options::new();
    select_options.insert("handle_token", Value::from(Str::from(select_token.clone())));
    select_options.insert("types", Value::from(REQUIRED_DEVICE_TYPES));
    if persistence.is_enabled() {
        select_options.insert("persist_mode", Value::from(persistence.persist_mode()));
        if let Some(token) = persistence.restore_token() {
            select_options.insert(
                "restore_token",
                Value::from(Str::from(token.expose_secret())),
            );
        }
    }
    let returned_select_path: OwnedObjectPath = remote
        .call("SelectDevices", &(&session.path, &select_options))
        .map_err(|error| actionable(format!("SelectDevices call failed: {error}")))?;
    verify_request_path(&expected_select_path, &returned_select_path)?;
    let select_response = wait_for_response(&mut select_signals, "SelectDevices")?;
    require_success("SelectDevices", select_response.code)?;
    println!(
        "SelectDevices response: keyboard+pointer requested, persistence {}",
        if persistence.is_enabled() {
            "enabled"
        } else {
            "disabled"
        }
    );

    let start_token = new_token("cachybridge_remote_start");
    let (expected_start_path, mut start_signals) = request_listener(&connection, &start_token)?;
    let mut start_options = Options::new();
    start_options.insert("handle_token", Value::from(Str::from(start_token.clone())));
    println!("Start: waiting for the desktop portal consent decision...");
    let returned_start_path: OwnedObjectPath = remote
        .call("Start", &(&session.path, "", &start_options))
        .map_err(|error| actionable(format!("Start call failed: {error}")))?;
    verify_request_path(&expected_start_path, &returned_start_path)?;
    let start_response = wait_for_response(&mut start_signals, "Start")?;
    require_success("Start", start_response.code)?;
    let granted = required_u32(&start_response.results, "devices")?;
    println!("Start response: success, granted device_types={granted}");
    if granted & REQUIRED_DEVICE_TYPES != REQUIRED_DEVICE_TYPES {
        return Err(actionable(format!(
            "portal consent did not grant keyboard+pointer; granted device_types={granted}"
        )));
    }
    let restore_token = if persistence.is_enabled() {
        optional_restore_token(&start_response.results)?
    } else {
        None
    };

    let empty = Options::new();
    let eis_fd: zbus::zvariant::OwnedFd = remote
        .call("ConnectToEIS", &(&session.path, &empty))
        .map_err(|error| actionable(format!("ConnectToEIS failed after Start: {error}")))?;
    let system_fd: std::os::fd::OwnedFd = eis_fd.into();
    let mut sender = Sender::from_fd(system_fd)
        .map_err(|error| actionable(format!("initialize libei sender: {error}")))?;
    let metadata = sender
        .handshake(Duration::from_secs(3))
        .map_err(|error| actionable(format!("complete EIS sender handshake: {error}")))?
        .clone();
    print_eis_metadata(&metadata);

    Ok(RemoteDesktopSession {
        sender: Some(sender),
        portal: session,
        metadata,
        restore_token,
    })
}

fn remote_proxy(connection: &Connection) -> zbus::Result<Proxy<'_>> {
    Proxy::new(connection, PORTAL_NAME, PORTAL_PATH, REMOTE_DESKTOP)
}

fn request_listener(
    connection: &Connection,
    token: &str,
) -> RemoteResult<(OwnedObjectPath, MessageIterator)> {
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

fn wait_for_response(signals: &mut MessageIterator, stage: &str) -> RemoteResult<PortalResponse> {
    let message = signals
        .next()
        .ok_or_else(|| actionable(format!("{stage} request signal stream ended")))??;
    let (code, results): (u32, Results) = message
        .body()
        .deserialize()
        .map_err(|error| actionable(format!("decode {stage} Response: {error}")))?;
    Ok(PortalResponse { code, results })
}

fn verify_request_path(expected: &OwnedObjectPath, returned: &OwnedObjectPath) -> RemoteResult<()> {
    if expected == returned {
        Ok(())
    } else {
        Err(actionable(format!(
            "portal returned unexpected request path {returned}; expected {expected}"
        )))
    }
}

fn require_success(stage: &str, response: u32) -> RemoteResult<()> {
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

fn required_session_path(results: &Results) -> RemoteResult<OwnedObjectPath> {
    let value = results
        .get("session_handle")
        .ok_or_else(|| actionable("portal result omitted required `session_handle`"))?;
    if let Ok(path) = OwnedObjectPath::try_from(value.try_clone()?) {
        return Ok(path);
    }
    let path = String::try_from(value.try_clone()?)
        .map_err(|error| actionable(format!("session_handle has wrong type: {error}")))?;
    path.try_into()
        .map_err(|error| actionable(format!("session_handle is not an object path: {error}")))
}

fn required_u32(results: &Results, key: &str) -> RemoteResult<u32> {
    let value = results
        .get(key)
        .ok_or_else(|| actionable(format!("portal result omitted required `{key}`")))?;
    u32::try_from(value)
        .map_err(|error| actionable(format!("portal result `{key}` has wrong type: {error}")))
}

fn optional_restore_token(results: &Results) -> RemoteResult<Option<RestoreToken>> {
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

fn print_eis_metadata(metadata: &ReceiverMetadata) {
    println!(
        "EIS sender handshake: connected={} seats={} devices={}",
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
    fn parses_spec_compatible_string_session_handle() {
        let expected = "/org/freedesktop/portal/desktop/session/1_5/test";
        let mut results = Results::new();
        results.insert(
            "session_handle".to_owned(),
            OwnedValue::from(Str::from(expected.to_owned())),
        );
        assert_eq!(required_session_path(&results).unwrap().as_str(), expected);
    }

    #[test]
    fn remote_response_codes_are_actionable() {
        assert!(require_success("Start", 0).is_ok());
        assert!(require_success("Start", 1)
            .unwrap_err()
            .to_string()
            .contains("cancelled"));
        assert!(require_success("Start", 2)
            .unwrap_err()
            .to_string()
            .contains("portal"));
    }

    #[test]
    fn parses_replacement_restore_token_as_a_secret() {
        let mut results = Results::new();
        results.insert(
            "restore_token".to_owned(),
            OwnedValue::from(Str::from("next-token")),
        );
        let token = optional_restore_token(&results).unwrap().unwrap();
        assert_eq!(token.expose_secret(), "next-token");
        assert_eq!(format!("{token:?}"), "RestoreToken([REDACTED])");
        assert!(optional_restore_token(&Results::new()).unwrap().is_none());
    }
}
