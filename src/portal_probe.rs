//! Read-only runtime capability probing for the Wayland portal input path.
//!
//! The spike intentionally shells out to the system `gdbus` and `pkg-config`
//! tools. This keeps the existing demo dependency graph and input path
//! untouched while still querying the live D-Bus portal implementation.

use std::{env, fmt::Write as _, process::Command};

const PORTAL_NAME: &str = "org.freedesktop.portal.Desktop";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const INPUT_CAPTURE: &str = "org.freedesktop.portal.InputCapture";
const REMOTE_DESKTOP: &str = "org.freedesktop.portal.RemoteDesktop";
const KEYBOARD: u32 = 1;
const POINTER: u32 = 2;
const TOUCHSCREEN: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceProbe {
    pub available: bool,
    pub version: Option<u32>,
    pub capabilities: Option<u32>,
    pub error: Option<String>,
}

impl InterfaceProbe {
    fn supports_shared_input(&self) -> bool {
        self.capabilities.is_some_and(|value| {
            value & (KEYBOARD | POINTER | TOUCHSCREEN) == KEYBOARD | POINTER | TOUCHSCREEN
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphicalSession {
    pub id: String,
    pub session_type: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    pub process_session_type: Option<String>,
    pub wayland_display: Option<String>,
    pub display: Option<String>,
    pub session_bus_configured: bool,
    pub active_graphical_session: Option<GraphicalSession>,
    pub portal_available: bool,
    pub portal_error: Option<String>,
    pub input_capture: InterfaceProbe,
    pub remote_desktop: InterfaceProbe,
    pub libei_version: Option<String>,
}

impl DoctorReport {
    pub fn controller_ready(&self) -> bool {
        self.portal_available
            && self
                .input_capture
                .version
                .is_some_and(|version| version >= 2)
            && self.input_capture.supports_shared_input()
            && self.libei_version.is_some()
            && self.has_wayland_session()
    }

    pub fn follower_ready(&self) -> bool {
        self.portal_available
            && self
                .remote_desktop
                .version
                .is_some_and(|version| version >= 2)
            && self.remote_desktop.supports_shared_input()
            && self.libei_version.is_some()
            && self.has_wayland_session()
    }

    fn has_wayland_session(&self) -> bool {
        self.process_session_type.as_deref() == Some("wayland")
            || self
                .active_graphical_session
                .as_ref()
                .is_some_and(|session| session.session_type == "wayland")
    }

    pub fn print_human(&self) {
        println!("CachyBridge Wayland capability probe");
        println!(
            "process session: {} (WAYLAND_DISPLAY={}, DISPLAY={})",
            display_option(self.process_session_type.as_deref()),
            display_option(self.wayland_display.as_deref()),
            display_option(self.display.as_deref())
        );
        if let Some(session) = &self.active_graphical_session {
            println!(
                "active graphical session: {} (id={}, state={})",
                session.session_type, session.id, session.state
            );
        } else {
            println!("active graphical session: not detected");
        }
        println!(
            "session bus: {}",
            if self.session_bus_configured {
                "configured"
            } else {
                "not configured"
            }
        );
        println!(
            "desktop portal: {}{}",
            yes_no(self.portal_available),
            format_error(self.portal_error.as_deref())
        );
        print_interface("InputCapture", &self.input_capture, "SupportedCapabilities");
        print_interface(
            "RemoteDesktop",
            &self.remote_desktop,
            "AvailableDeviceTypes",
        );
        println!(
            "libei: {}",
            self.libei_version.as_deref().unwrap_or("not detected")
        );
        println!("controller role ready: {}", yes_no(self.controller_ready()));
        println!("follower role ready: {}", yes_no(self.follower_ready()));
        println!(
            "scope: read-only capability check; portal consent, sessions, barriers, and EIS handshakes were not attempted"
        );
    }

    pub fn to_json(&self) -> String {
        let mut json = String::new();
        writeln!(&mut json, "{{").unwrap();
        writeln!(
            &mut json,
            "  \"process_session_type\": {},",
            json_option(self.process_session_type.as_deref())
        )
        .unwrap();
        writeln!(
            &mut json,
            "  \"wayland_display\": {},",
            json_option(self.wayland_display.as_deref())
        )
        .unwrap();
        writeln!(
            &mut json,
            "  \"display\": {},",
            json_option(self.display.as_deref())
        )
        .unwrap();
        writeln!(
            &mut json,
            "  \"session_bus_configured\": {},",
            self.session_bus_configured
        )
        .unwrap();
        if let Some(session) = &self.active_graphical_session {
            writeln!(
                &mut json,
                "  \"active_graphical_session\": {{\"id\": {}, \"type\": {}, \"state\": {}}},",
                json_string(&session.id),
                json_string(&session.session_type),
                json_string(&session.state)
            )
            .unwrap();
        } else {
            writeln!(&mut json, "  \"active_graphical_session\": null,").unwrap();
        }
        writeln!(
            &mut json,
            "  \"portal_available\": {},",
            self.portal_available
        )
        .unwrap();
        writeln!(
            &mut json,
            "  \"portal_error\": {},",
            json_option(self.portal_error.as_deref())
        )
        .unwrap();
        write_interface_json(&mut json, "input_capture", &self.input_capture);
        write_interface_json(&mut json, "remote_desktop", &self.remote_desktop);
        writeln!(
            &mut json,
            "  \"libei_version\": {},",
            json_option(self.libei_version.as_deref())
        )
        .unwrap();
        writeln!(
            &mut json,
            "  \"controller_ready\": {},",
            self.controller_ready()
        )
        .unwrap();
        writeln!(
            &mut json,
            "  \"follower_ready\": {},",
            self.follower_ready()
        )
        .unwrap();
        writeln!(
            &mut json,
            "  \"probe_scope\": \"read-only; no portal sessions or consent prompts\""
        )
        .unwrap();
        write!(&mut json, "}}").unwrap();
        json
    }
}

pub fn probe() -> DoctorReport {
    let (portal_available, portal_error) = portal_has_owner();
    DoctorReport {
        process_session_type: nonempty_env("XDG_SESSION_TYPE"),
        wayland_display: nonempty_env("WAYLAND_DISPLAY"),
        display: nonempty_env("DISPLAY"),
        session_bus_configured: nonempty_env("DBUS_SESSION_BUS_ADDRESS").is_some(),
        active_graphical_session: find_active_graphical_session(),
        portal_available,
        portal_error,
        input_capture: probe_interface(INPUT_CAPTURE, "SupportedCapabilities"),
        remote_desktop: probe_interface(REMOTE_DESKTOP, "AvailableDeviceTypes"),
        libei_version: command_output("pkg-config", &["--modversion", "libei-1.0"])
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty()),
    }
}

fn portal_has_owner() -> (bool, Option<String>) {
    match gdbus_call(&[
        "--dest",
        "org.freedesktop.DBus",
        "--object-path",
        "/org/freedesktop/DBus",
        "--method",
        "org.freedesktop.DBus.NameHasOwner",
        PORTAL_NAME,
    ]) {
        Ok(output) => (output.contains("true"), None),
        Err(error) => (false, Some(error)),
    }
}

fn probe_interface(interface: &str, capabilities_property: &str) -> InterfaceProbe {
    let version = portal_property(interface, "version");
    let capabilities = portal_property(interface, capabilities_property);
    match (version, capabilities) {
        (Ok(version), Ok(capabilities)) => InterfaceProbe {
            available: true,
            version: Some(version),
            capabilities: Some(capabilities),
            error: None,
        },
        (version, capabilities) => {
            let error = version
                .err()
                .or_else(|| capabilities.err())
                .unwrap_or_else(|| "unknown portal query failure".to_owned());
            InterfaceProbe {
                available: false,
                version: None,
                capabilities: None,
                error: Some(error),
            }
        }
    }
}

fn portal_property(interface: &str, property: &str) -> Result<u32, String> {
    let output = gdbus_call(&[
        "--dest",
        PORTAL_NAME,
        "--object-path",
        PORTAL_PATH,
        "--method",
        "org.freedesktop.DBus.Properties.Get",
        interface,
        property,
    ])?;
    parse_uint32(&output).ok_or_else(|| format!("unexpected gdbus reply: {}", output.trim()))
}

fn gdbus_call(arguments: &[&str]) -> Result<String, String> {
    let mut args = vec!["call", "--session"];
    args.extend_from_slice(arguments);
    command_output("gdbus", &args)
}

fn command_output(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("could not run {program}: {error}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        Err(if stderr.is_empty() {
            format!("{program} exited with {}", output.status)
        } else {
            stderr
        })
    }
}

fn find_active_graphical_session() -> Option<GraphicalSession> {
    let uid = command_output("id", &["-u"]).ok()?;
    let sessions =
        command_output("loginctl", &["list-sessions", "--no-legend", "--no-pager"]).ok()?;
    for line in sessions.lines() {
        let columns: Vec<_> = line.split_whitespace().collect();
        if columns.len() < 2 || columns[1] != uid.trim() {
            continue;
        }
        let id = columns[0];
        let properties = command_output(
            "loginctl",
            &[
                "show-session",
                id,
                "--property=Type",
                "--property=State",
                "--property=Remote",
            ],
        )
        .ok()?;
        let session_type = property_value(&properties, "Type")?;
        let state = property_value(&properties, "State")?;
        let remote = property_value(&properties, "Remote")?;
        if remote == "no"
            && matches!(session_type.as_str(), "wayland" | "x11")
            && matches!(state.as_str(), "active" | "online")
        {
            return Some(GraphicalSession {
                id: id.to_owned(),
                session_type,
                state,
            });
        }
    }
    None
}

fn property_value(properties: &str, name: &str) -> Option<String> {
    properties
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .map(str::to_owned)
}

fn parse_uint32(text: &str) -> Option<u32> {
    let marker = "uint32 ";
    let start = text.find(marker)? + marker.len();
    let digits: String = text[start..]
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

fn nonempty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn display_option(value: Option<&str>) -> &str {
    value.unwrap_or("not set")
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn format_error(error: Option<&str>) -> String {
    error.map_or_else(String::new, |error| format!(" ({error})"))
}

fn print_interface(name: &str, probe: &InterfaceProbe, capability_name: &str) {
    println!(
        "{name}: {} version={} {capability_name}={} keyboard={} pointer={} touchscreen={}{}",
        yes_no(probe.available),
        probe
            .version
            .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
        probe
            .capabilities
            .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
        yes_no(probe.capabilities.unwrap_or(0) & KEYBOARD != 0),
        yes_no(probe.capabilities.unwrap_or(0) & POINTER != 0),
        yes_no(probe.capabilities.unwrap_or(0) & TOUCHSCREEN != 0),
        format_error(probe.error.as_deref())
    );
}

fn write_interface_json(json: &mut String, name: &str, probe: &InterfaceProbe) {
    writeln!(json, "  \"{name}\": {{").unwrap();
    writeln!(json, "    \"available\": {},", probe.available).unwrap();
    writeln!(json, "    \"version\": {},", json_number(probe.version)).unwrap();
    writeln!(
        json,
        "    \"capabilities\": {},",
        json_number(probe.capabilities)
    )
    .unwrap();
    writeln!(
        json,
        "    \"keyboard\": {},",
        probe
            .capabilities
            .is_some_and(|value| value & KEYBOARD != 0)
    )
    .unwrap();
    writeln!(
        json,
        "    \"pointer\": {},",
        probe.capabilities.is_some_and(|value| value & POINTER != 0)
    )
    .unwrap();
    writeln!(
        json,
        "    \"touchscreen\": {},",
        probe
            .capabilities
            .is_some_and(|value| value & TOUCHSCREEN != 0)
    )
    .unwrap();
    writeln!(
        json,
        "    \"error\": {}",
        json_option(probe.error.as_deref())
    )
    .unwrap();
    writeln!(json, "  }},").unwrap();
}

fn json_number(value: Option<u32>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| value.to_string())
}

fn json_option(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), json_string)
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                write!(&mut escaped, "\\u{:04x}", character as u32).unwrap();
            }
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gdbus_uint32_variant() {
        assert_eq!(parse_uint32("(<uint32 7>,)\n"), Some(7));
        assert_eq!(parse_uint32("unexpected"), None);
    }

    #[test]
    fn readiness_requires_version_capabilities_libei_and_wayland() {
        let ready_interface = InterfaceProbe {
            available: true,
            version: Some(2),
            capabilities: Some(KEYBOARD | POINTER | TOUCHSCREEN),
            error: None,
        };
        let report = DoctorReport {
            process_session_type: Some("tty".to_owned()),
            wayland_display: None,
            display: None,
            session_bus_configured: true,
            active_graphical_session: Some(GraphicalSession {
                id: "4".to_owned(),
                session_type: "wayland".to_owned(),
                state: "active".to_owned(),
            }),
            portal_available: true,
            portal_error: None,
            input_capture: ready_interface.clone(),
            remote_desktop: ready_interface,
            libei_version: Some("1.6.0".to_owned()),
        };
        assert!(report.controller_ready());
        assert!(report.follower_ready());
        let without_touch = InterfaceProbe {
            capabilities: Some(KEYBOARD | POINTER),
            ..report.input_capture.clone()
        };
        assert!(!without_touch.supports_shared_input());
    }

    #[test]
    fn json_escapes_external_error_text() {
        assert_eq!(
            json_string("bad \\\"value\"\n"),
            "\"bad \\\\\\\"value\\\"\\n\""
        );
    }
}
