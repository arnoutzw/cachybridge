//! Versioned, user-owned pairing and topology configuration.
//!
//! The format is intentionally narrow and dependency-free. It is a stable
//! line-oriented format rather than a general config language, which makes
//! validation deterministic and avoids accidentally accepting unknown secret
//! fields. The file contains PSKs and is always written mode 0600.

use std::{
    fmt,
    fs::{self, OpenOptions},
    io::{self, Write},
    net::SocketAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use rand::RngCore;
use thiserror::Error;

pub const CONFIG_VERSION: u32 = 4;
const CONFIG_FILE: &str = "config.v4";
const MAX_RESTORE_TOKEN_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelativePlacement {
    Left,
    Right,
    Above,
    Below,
}

impl RelativePlacement {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Right => "right",
            Self::Above => "above",
            Self::Below => "below",
        }
    }

    fn parse(value: &str) -> Result<Self, ConfigError> {
        match value {
            "left" => Ok(Self::Left),
            "right" => Ok(Self::Right),
            "above" => Ok(Self::Above),
            "below" => Ok(Self::Below),
            _ => Err(ConfigError::InvalidField {
                field: "placement",
                reason: "must be left, right, above, or below".to_owned(),
            }),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PeerConfig {
    pub id: String,
    pub name: String,
    /// Address used when this machine takes the host/input-owner role.
    pub host_endpoint: SocketAddr,
    /// Address used when this machine takes the controlled/client role.
    pub client_endpoint: SocketAddr,
    pub placement: RelativePlacement,
    /// User opt-in for persistent portal permissions for this specific peer.
    pub persistent_permissions: bool,
    psk: [u8; 32],
    capture_restore_token: Option<String>,
    remote_restore_token: Option<String>,
}

impl fmt::Debug for PeerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerConfig")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("host_endpoint", &self.host_endpoint)
            .field("client_endpoint", &self.client_endpoint)
            .field("placement", &self.placement)
            .field("persistent_permissions", &self.persistent_permissions)
            .field("psk", &"<redacted>")
            .field(
                "capture_restore_token",
                &self.capture_restore_token.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "remote_restore_token",
                &self.remote_restore_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl PeerConfig {
    pub fn new(
        id: String,
        name: String,
        host_endpoint: SocketAddr,
        client_endpoint: SocketAddr,
        placement: RelativePlacement,
        psk: [u8; 32],
    ) -> Result<Self, ConfigError> {
        let peer = Self {
            id,
            name,
            host_endpoint,
            client_endpoint,
            placement,
            persistent_permissions: false,
            psk,
            capture_restore_token: None,
            remote_restore_token: None,
        };
        peer.validate()?;
        Ok(peer)
    }

    /// Provides the secret only to the transport composition layer. It is
    /// intentionally not exposed in Debug/Display or CLI list output.
    pub const fn psk(&self) -> &[u8; 32] {
        &self.psk
    }

    /// Restore token used by the controller-side InputCapture portal. This is
    /// opaque to the config layer and intentionally omitted from Debug output.
    pub fn capture_restore_token(&self) -> Option<&str> {
        self.capture_restore_token.as_deref()
    }

    /// Restore token used by the controlled-side RemoteDesktop portal. This is
    /// opaque to the config layer and intentionally omitted from Debug output.
    pub fn remote_restore_token(&self) -> Option<&str> {
        self.remote_restore_token.as_deref()
    }

    /// Replace the single-use controller portal token after a portal start.
    /// Passing `None` explicitly clears an old token.
    pub fn replace_capture_restore_token(
        &mut self,
        token: Option<String>,
    ) -> Result<(), ConfigError> {
        validate_restore_token(token.as_deref())?;
        self.capture_restore_token = token;
        Ok(())
    }

    /// Replace the single-use controlled-side portal token after a portal
    /// start. Passing `None` explicitly clears an old token.
    pub fn replace_remote_restore_token(
        &mut self,
        token: Option<String>,
    ) -> Result<(), ConfigError> {
        validate_restore_token(token.as_deref())?;
        self.remote_restore_token = token;
        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.id.len() != 32 || !self.id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ConfigError::InvalidField {
                field: "id",
                reason: "must be 32 hexadecimal characters".to_owned(),
            });
        }
        validate_display_name("name", &self.name)?;
        for (field, endpoint) in [
            ("host_endpoint", self.host_endpoint),
            ("client_endpoint", self.client_endpoint),
        ] {
            if endpoint.ip().is_unspecified() {
                return Err(ConfigError::InvalidField {
                    field,
                    reason: "must not use an unspecified address".to_owned(),
                });
            }
        }
        validate_restore_token(self.capture_restore_token.as_deref())?;
        validate_restore_token(self.remote_restore_token.as_deref())?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeConfig {
    pub schema_version: u32,
    /// Friendly name for this local machine, shown by setup/UI layers.
    pub local_name: String,
    pub peers: Vec<PeerConfig>,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_VERSION,
            local_name: "This computer".to_owned(),
            peers: Vec::new(),
        }
    }
}

impl BridgeConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != CONFIG_VERSION {
            return Err(ConfigError::UnsupportedVersion(self.schema_version));
        }
        validate_display_name("local_name", &self.local_name)?;
        for peer in &self.peers {
            peer.validate()?;
        }
        for (index, peer) in self.peers.iter().enumerate() {
            if self.peers[..index]
                .iter()
                .any(|existing| existing.id.eq_ignore_ascii_case(&peer.id))
            {
                return Err(ConfigError::DuplicatePeerId(peer.id.clone()));
            }
        }
        Ok(())
    }

    pub fn add_peer(&mut self, peer: PeerConfig) -> Result<(), ConfigError> {
        peer.validate()?;
        if self
            .peers
            .iter()
            .any(|existing| existing.id.eq_ignore_ascii_case(&peer.id))
        {
            return Err(ConfigError::DuplicatePeerId(peer.id));
        }
        // A one-time pairing creates a fresh PSK by design. Re-pairing the
        // same controlled desktop must therefore supersede its old record,
        // otherwise setup leaves a growing list of indistinguishable stale
        // peers and a later GUI action can select a key the client no longer
        // accepts. CachyBridge currently supports one host and one client, so
        // the controlled endpoint is the stable identity for this purpose.
        self.peers
            .retain(|existing| existing.client_endpoint != peer.client_endpoint);
        self.peers.push(peer);
        self.validate()
    }

    pub fn peer(&self, id: &str) -> Result<&PeerConfig, ConfigError> {
        self.peers
            .iter()
            .find(|peer| peer.id.eq_ignore_ascii_case(id))
            .ok_or_else(|| ConfigError::PeerNotFound(id.to_owned()))
    }

    /// Changes the stored position for an existing trusted peer.  Callers
    /// persist the complete config with [`save`] so a topology change is one
    /// private, atomic rewrite rather than a partially edited file.
    pub fn set_peer_placement(
        &mut self,
        id: &str,
        placement: RelativePlacement,
    ) -> Result<(), ConfigError> {
        self.peer_mut(id)?.placement = placement;
        self.validate()
    }

    fn peer_mut(&mut self, id: &str) -> Result<&mut PeerConfig, ConfigError> {
        self.peers
            .iter_mut()
            .find(|peer| peer.id.eq_ignore_ascii_case(id))
            .ok_or_else(|| ConfigError::PeerNotFound(id.to_owned()))
    }

    /// Applies returned single-use portal tokens in memory. The caller should
    /// save the config once after all portal sessions have started so their
    /// replacement is atomic at the config-file level.
    pub fn apply_restore_token_updates(
        &mut self,
        id: &str,
        updates: RestoreTokenUpdates,
    ) -> Result<(), ConfigError> {
        let peer = self.peer_mut(id)?;
        if let RestoreTokenUpdate::Replace(token) = updates.capture {
            peer.replace_capture_restore_token(token)?;
        }
        if let RestoreTokenUpdate::Replace(token) = updates.remote {
            peer.replace_remote_restore_token(token)?;
        }
        self.validate()
    }

    pub fn render(&self) -> Result<String, ConfigError> {
        self.validate()?;
        let mut output = format!(
            "schema_version={CONFIG_VERSION}\nlocal_name={}\n",
            self.local_name
        );
        for peer in &self.peers {
            output.push_str("\n[[peer]]\n");
            output.push_str(&format!("id={}\n", peer.id));
            output.push_str(&format!("name={}\n", peer.name));
            output.push_str(&format!("host_endpoint={}\n", peer.host_endpoint));
            output.push_str(&format!("client_endpoint={}\n", peer.client_endpoint));
            output.push_str(&format!("placement={}\n", peer.placement.as_str()));
            output.push_str(&format!(
                "persistent_permissions={}\n",
                peer.persistent_permissions
            ));
            output.push_str(&format!("psk={}\n", hex::encode(peer.psk)));
            if let Some(token) = peer.capture_restore_token() {
                output.push_str(&format!("capture_restore_token={}\n", hex::encode(token)));
            }
            if let Some(token) = peer.remote_restore_token() {
                output.push_str(&format!("remote_restore_token={}\n", hex::encode(token)));
            }
        }
        Ok(output)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut schema_version = None;
        let mut local_name = None;
        let mut peers = Vec::new();
        let mut current: Option<UnvalidatedPeer> = None;
        for (line_number, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line == "[[peer]]" {
                if let Some(peer) = current.take() {
                    peers.push(peer.finish()?);
                }
                current = Some(UnvalidatedPeer::default());
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| ConfigError::Parse {
                line: line_number + 1,
                reason: "expected key=value".to_owned(),
            })?;
            if let Some(peer) = current.as_mut() {
                peer.set(key, value, line_number + 1)?;
            } else {
                match key {
                    "schema_version" => {
                        if schema_version.is_some() {
                            return Err(ConfigError::Parse {
                                line: line_number + 1,
                                reason: "schema_version appears more than once".to_owned(),
                            });
                        }
                        schema_version =
                            Some(value.parse::<u32>().map_err(|_| ConfigError::Parse {
                                line: line_number + 1,
                                reason: "schema_version must be an unsigned integer".to_owned(),
                            })?);
                    }
                    "local_name" => {
                        if local_name.is_some() {
                            return Err(ConfigError::Parse {
                                line: line_number + 1,
                                reason: "local_name appears more than once".to_owned(),
                            });
                        }
                        local_name = Some(value.to_owned());
                    }
                    _ => {
                        return Err(ConfigError::Parse {
                            line: line_number + 1,
                            reason: "only schema_version and local_name may appear before [[peer]]"
                                .to_owned(),
                        });
                    }
                }
            }
        }
        if let Some(peer) = current {
            peers.push(peer.finish()?);
        }
        let config = Self {
            schema_version: schema_version.ok_or(ConfigError::MissingField("schema_version"))?,
            // Early v4 preview files did not yet contain the local label.
            // Keep them loadable with a clear, non-identifying safe default.
            local_name: local_name.unwrap_or_else(|| "This computer".to_owned()),
            peers,
        };
        config.validate()?;
        Ok(config)
    }
}

#[derive(Default)]
struct UnvalidatedPeer {
    id: Option<String>,
    name: Option<String>,
    host_endpoint: Option<SocketAddr>,
    client_endpoint: Option<SocketAddr>,
    placement: Option<RelativePlacement>,
    persistent_permissions: Option<bool>,
    psk: Option<[u8; 32]>,
    capture_restore_token: Option<String>,
    remote_restore_token: Option<String>,
}

impl UnvalidatedPeer {
    fn set(&mut self, key: &str, value: &str, line: usize) -> Result<(), ConfigError> {
        let duplicate = |set: bool| {
            if set {
                Err(ConfigError::Parse {
                    line,
                    reason: format!("{key} appears more than once in a peer"),
                })
            } else {
                Ok(())
            }
        };
        match key {
            "id" => {
                duplicate(self.id.is_some())?;
                self.id = Some(value.to_owned());
            }
            "name" => {
                duplicate(self.name.is_some())?;
                self.name = Some(value.to_owned());
            }
            "host_endpoint" => {
                duplicate(self.host_endpoint.is_some())?;
                self.host_endpoint = Some(value.parse().map_err(|_| ConfigError::Parse {
                    line,
                    reason: "host_endpoint must be an IP address and port".to_owned(),
                })?);
            }
            "client_endpoint" => {
                duplicate(self.client_endpoint.is_some())?;
                self.client_endpoint = Some(value.parse().map_err(|_| ConfigError::Parse {
                    line,
                    reason: "client_endpoint must be an IP address and port".to_owned(),
                })?);
            }
            "placement" => {
                duplicate(self.placement.is_some())?;
                self.placement = Some(RelativePlacement::parse(value)?);
            }
            "persistent_permissions" => {
                duplicate(self.persistent_permissions.is_some())?;
                self.persistent_permissions =
                    Some(value.parse::<bool>().map_err(|_| ConfigError::Parse {
                        line,
                        reason: "persistent_permissions must be true or false".to_owned(),
                    })?);
            }
            "psk" => {
                duplicate(self.psk.is_some())?;
                self.psk = Some(parse_psk(value)?);
            }
            "capture_restore_token" => {
                duplicate(self.capture_restore_token.is_some())?;
                self.capture_restore_token = Some(parse_restore_token(value, line)?);
            }
            "remote_restore_token" => {
                duplicate(self.remote_restore_token.is_some())?;
                self.remote_restore_token = Some(parse_restore_token(value, line)?);
            }
            _ => {
                return Err(ConfigError::Parse {
                    line,
                    reason: format!("unknown peer field {key}"),
                });
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<PeerConfig, ConfigError> {
        let mut peer = PeerConfig::new(
            self.id.ok_or(ConfigError::MissingField("peer.id"))?,
            self.name.ok_or(ConfigError::MissingField("peer.name"))?,
            self.host_endpoint
                .ok_or(ConfigError::MissingField("peer.host_endpoint"))?,
            self.client_endpoint
                .ok_or(ConfigError::MissingField("peer.client_endpoint"))?,
            self.placement
                .ok_or(ConfigError::MissingField("peer.placement"))?,
            self.psk.ok_or(ConfigError::MissingField("peer.psk"))?,
        )?;
        // The opt-in was absent in the initial v4 preview, so preserve a
        // conservative false default for those files.
        peer.persistent_permissions = self.persistent_permissions.unwrap_or(false);
        peer.replace_capture_restore_token(self.capture_restore_token)?;
        peer.replace_remote_restore_token(self.remote_restore_token)?;
        Ok(peer)
    }
}

fn validate_display_name(field: &'static str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 80
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, ' ' | '-' | '_' | '.')
        })
    {
        return Err(ConfigError::InvalidField {
            field,
            reason: "must be 1-80 ASCII letters, digits, spaces, '.', '_' or '-'".to_owned(),
        });
    }
    Ok(())
}

fn validate_restore_token(token: Option<&str>) -> Result<(), ConfigError> {
    if let Some(token) = token {
        if token.is_empty()
            || token.len() > MAX_RESTORE_TOKEN_BYTES
            || token.contains(['\n', '\r', '\0'])
        {
            return Err(ConfigError::InvalidField {
                field: "restore_token",
                reason: "must be non-empty, at most 16384 bytes, and contain no newline or NUL"
                    .to_owned(),
            });
        }
    }
    Ok(())
}

fn parse_restore_token(value: &str, line: usize) -> Result<String, ConfigError> {
    let bytes = hex::decode(value).map_err(|_| ConfigError::Parse {
        line,
        reason: "restore token must be hexadecimal UTF-8".to_owned(),
    })?;
    let token = String::from_utf8(bytes).map_err(|_| ConfigError::Parse {
        line,
        reason: "restore token must be hexadecimal UTF-8".to_owned(),
    })?;
    validate_restore_token(Some(&token)).map_err(|error| ConfigError::Parse {
        line,
        reason: error.to_string(),
    })?;
    Ok(token)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("unsupported config schema version {0}")]
    UnsupportedVersion(u32),
    #[error("missing required field {0}")]
    MissingField(&'static str),
    #[error("invalid {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("invalid config at line {line}: {reason}")]
    Parse { line: usize, reason: String },
    #[error("duplicate peer id {0}")]
    DuplicatePeerId(String),
    #[error("no configured peer with id {0}")]
    PeerNotFound(String),
    #[error("config file permissions are too broad (expected 0600)")]
    InsecurePermissions,
}

/// A portal session either leaves a stored token untouched or replaces it with
/// the returned token. `Replace(None)` explicitly clears a consumed token.
#[derive(Clone, PartialEq, Eq)]
pub enum RestoreTokenUpdate {
    Unchanged,
    Replace(Option<String>),
}

impl fmt::Debug for RestoreTokenUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unchanged => formatter.write_str("Unchanged"),
            Self::Replace(None) => formatter.write_str("Replace(None)"),
            Self::Replace(Some(_)) => formatter.write_str("Replace(Some(<redacted>))"),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RestoreTokenUpdates {
    pub capture: RestoreTokenUpdate,
    pub remote: RestoreTokenUpdate,
}

impl fmt::Debug for RestoreTokenUpdates {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestoreTokenUpdates")
            .field("capture", &self.capture)
            .field("remote", &self.remote)
            .finish()
    }
}

impl RestoreTokenUpdates {
    pub const fn capture(token: Option<String>) -> Self {
        Self {
            capture: RestoreTokenUpdate::Replace(token),
            remote: RestoreTokenUpdate::Unchanged,
        }
    }

    pub const fn remote(token: Option<String>) -> Self {
        Self {
            capture: RestoreTokenUpdate::Unchanged,
            remote: RestoreTokenUpdate::Replace(token),
        }
    }

    pub const fn both(capture: Option<String>, remote: Option<String>) -> Self {
        Self {
            capture: RestoreTokenUpdate::Replace(capture),
            remote: RestoreTokenUpdate::Replace(remote),
        }
    }
}

impl From<io::Error> for ConfigError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

pub fn default_config_path() -> Result<PathBuf, ConfigError> {
    let root = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or_else(|| ConfigError::Io("XDG_CONFIG_HOME and HOME are both unset".to_owned()))?;
    Ok(root.join("cachybridge").join(CONFIG_FILE))
}

pub fn load_or_default(path: &Path) -> Result<BridgeConfig, ConfigError> {
    match fs::read_to_string(path) {
        Ok(text) => {
            ensure_private(path)?;
            BridgeConfig::parse(&text)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(BridgeConfig::default()),
        Err(error) => Err(error.into()),
    }
}

pub fn save(path: &Path, config: &BridgeConfig) -> Result<(), ConfigError> {
    let contents = config.render()?;
    let parent = path
        .parent()
        .ok_or_else(|| ConfigError::Io("config path has no parent directory".to_owned()))?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn generate_pairing_psk() -> [u8; 32] {
    let mut psk = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut psk);
    psk
}

pub fn generate_peer_id() -> String {
    let mut id = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    hex::encode(id)
}

pub fn write_pairing_token(path: &Path, psk: &[u8; 32]) -> Result<(), ConfigError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    writeln!(file, "{}", hex::encode(psk))?;
    file.sync_all()?;
    Ok(())
}

pub fn read_pairing_token(path: &Path) -> Result<[u8; 32], ConfigError> {
    ensure_private(path)?;
    parse_psk(fs::read_to_string(path)?.trim())
}

fn parse_psk(value: &str) -> Result<[u8; 32], ConfigError> {
    let bytes = hex::decode(value).map_err(|_| ConfigError::InvalidField {
        field: "psk",
        reason: "must be 64 hexadecimal characters".to_owned(),
    })?;
    bytes.try_into().map_err(|_| ConfigError::InvalidField {
        field: "psk",
        reason: "must be 64 hexadecimal characters".to_owned(),
    })
}

fn ensure_private(path: &Path) -> Result<(), ConfigError> {
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(ConfigError::InsecurePermissions);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn test_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("cachybridge-config-{name}-{nonce}"))
    }

    fn peer() -> PeerConfig {
        PeerConfig::new(
            "0123456789abcdef0123456789abcdef".to_owned(),
            "Left iMac".to_owned(),
            "192.168.2.10:45231".parse().unwrap(),
            "192.168.2.24:45231".parse().unwrap(),
            RelativePlacement::Left,
            [7_u8; 32],
        )
        .unwrap()
    }

    #[test]
    fn config_round_trip_preserves_secret_without_rendering_it_in_peer_debug() {
        let mut peer = peer();
        peer.persistent_permissions = true;
        peer.replace_capture_restore_token(Some("capture token value".to_owned()))
            .unwrap();
        peer.replace_remote_restore_token(Some("remote token value".to_owned()))
            .unwrap();
        let config = BridgeConfig {
            schema_version: CONFIG_VERSION,
            local_name: "Primary iMac".to_owned(),
            peers: vec![peer],
        };
        let parsed = BridgeConfig::parse(&config.render().unwrap()).unwrap();
        assert_eq!(parsed, config);
        let debug = format!("{:?}", parsed.peers[0]);
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("7, 7"));
        assert!(!debug.contains("capture token value"));
        assert!(!debug.contains("remote token value"));
    }

    #[test]
    fn rejects_invalid_topology_and_unknown_fields() {
        assert!(PeerConfig::new(
            "bad".to_owned(),
            "peer".to_owned(),
            "192.168.2.10:1".parse().unwrap(),
            "192.168.2.24:1".parse().unwrap(),
            RelativePlacement::Above,
            [1; 32],
        )
        .is_err());
        assert!(BridgeConfig::parse("schema_version=4\n\n[[peer]]\nunknown=x\n").is_err());
    }

    #[test]
    fn re_pairing_a_controlled_endpoint_replaces_the_stale_key() {
        let first = peer();
        let mut replacement = peer();
        replacement.id = "fedcba9876543210fedcba9876543210".to_owned();
        replacement.name = "Re-paired left iMac".to_owned();
        replacement.psk = [8; 32];
        let mut config = BridgeConfig::default();
        config.add_peer(first).unwrap();
        config.add_peer(replacement.clone()).unwrap();
        assert_eq!(config.peers, vec![replacement]);
    }

    #[test]
    fn save_load_enforces_private_permissions_and_token_file_is_private() {
        let dir = test_path("private");
        let config_path = dir.join("config.v4");
        let config = BridgeConfig {
            schema_version: CONFIG_VERSION,
            local_name: "Primary iMac".to_owned(),
            peers: vec![peer()],
        };
        save(&config_path, &config).unwrap();
        assert_eq!(load_or_default(&config_path).unwrap(), config);
        assert_eq!(
            fs::metadata(&config_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let token_path = dir.join("pairing.token");
        write_pairing_token(&token_path, &[9; 32]).unwrap();
        assert_eq!(read_pairing_token(&token_path).unwrap(), [9; 32]);
        assert_eq!(
            fs::metadata(&token_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_insecure_secret_file() {
        let path = test_path("insecure");
        fs::write(&path, "schema_version=4\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            load_or_default(&path),
            Err(ConfigError::InsecurePermissions)
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn per_peer_persistent_permission_and_opaque_restore_tokens_round_trip() {
        let text = concat!(
            "schema_version=4\n",
            "local_name=Primary iMac\n\n",
            "[[peer]]\n",
            "id=0123456789abcdef0123456789abcdef\n",
            "name=Left iMac\n",
            "host_endpoint=192.168.2.10:45231\n",
            "client_endpoint=192.168.2.24:45231\n",
            "placement=left\n",
            "persistent_permissions=true\n",
            "psk=0707070707070707070707070707070707070707070707070707070707070707\n",
            "capture_restore_token=63617074757265\n",
            "remote_restore_token=72656d6f7465\n"
        );
        let config = BridgeConfig::parse(text).unwrap();
        assert_eq!(config.local_name, "Primary iMac");
        assert!(config.peers[0].persistent_permissions);
        assert_eq!(config.peers[0].capture_restore_token(), Some("capture"));
        assert_eq!(config.peers[0].remote_restore_token(), Some("remote"));
        assert_eq!(
            BridgeConfig::parse(&config.render().unwrap()).unwrap(),
            config
        );
    }

    #[test]
    fn rejects_invalid_local_name_and_restore_token() {
        let config = BridgeConfig {
            local_name: "contains/slash".to_owned(),
            ..BridgeConfig::default()
        };
        assert!(config.validate().is_err());
        assert!(PeerConfig::new(
            "0123456789abcdef0123456789abcdef".to_owned(),
            "peer".to_owned(),
            "192.168.2.10:1".parse().unwrap(),
            "192.168.2.24:1".parse().unwrap(),
            RelativePlacement::Right,
            [1; 32],
        )
        .unwrap()
        .replace_capture_restore_token(Some("bad\ntoken".to_owned()))
        .is_err());
    }

    #[test]
    fn portal_token_updates_are_targeted_and_can_explicitly_clear() {
        let mut first = peer();
        first
            .replace_capture_restore_token(Some("old-capture".to_owned()))
            .unwrap();
        first
            .replace_remote_restore_token(Some("old-remote".to_owned()))
            .unwrap();
        let second = PeerConfig::new(
            "fedcba9876543210fedcba9876543210".to_owned(),
            "Other iMac".to_owned(),
            "192.168.2.30:45231".parse().unwrap(),
            "192.168.2.31:45231".parse().unwrap(),
            RelativePlacement::Right,
            [3; 32],
        )
        .unwrap();
        let mut config = BridgeConfig {
            schema_version: CONFIG_VERSION,
            local_name: "Primary iMac".to_owned(),
            peers: vec![first, second],
        };
        config
            .apply_restore_token_updates(
                "0123456789abcdef0123456789abcdef",
                RestoreTokenUpdates::both(None, Some("new-remote".to_owned())),
            )
            .unwrap();
        assert_eq!(config.peers[0].capture_restore_token(), None);
        assert_eq!(config.peers[0].remote_restore_token(), Some("new-remote"));
        assert_eq!(config.peers[1].capture_restore_token(), None);
        assert_eq!(
            config.peer("does-not-exist"),
            Err(ConfigError::PeerNotFound("does-not-exist".to_owned()))
        );
        let updates = RestoreTokenUpdates::remote(Some("do-not-log-me".to_owned()));
        assert!(!format!("{updates:?}").contains("do-not-log-me"));
    }
}
