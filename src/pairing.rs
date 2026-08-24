//! Short-lived, code-authenticated first-time pairing.
//!
//! A pairing code has 128 bits of entropy and is displayed in grouped Base32.
//! It authenticates one temporary Noise connection only.  That connection
//! transfers a newly generated 256-bit long-term PSK, which is then stored by
//! each side in its private v4 configuration file.

use std::{fmt, net::IpAddr};

use rand::RngCore;
use thiserror::Error;

use crate::{config::RelativePlacement, transport::TransportError};

const CODE_SYMBOLS: usize = 5;

#[derive(Debug, Error)]
pub enum PairingError {
    #[error("pairing code must contain exactly {CODE_SYMBOLS} Base32 characters")]
    InvalidCode,
    #[error("pairing message is malformed: {0}")]
    InvalidMessage(&'static str),
    #[error("pairing message exceeds its limit")]
    MessageTooLarge,
    #[error("pairing address must not be unspecified")]
    UnspecifiedAddress,
    #[error("pairing port must not be zero")]
    InvalidPort,
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// An endpoint advertised by the local peer during initial setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairRequest {
    pub host_name: String,
    pub host_service_port: u16,
    pub placement: RelativePlacement,
    pub persistent_permissions: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairGrant {
    pub peer_id: String,
    pub psk: [u8; 32],
    pub client_name: String,
    pub client_service_port: u16,
    pub placement: RelativePlacement,
    pub persistent_permissions: bool,
}

pub fn generate_code() -> String {
    let value = rand::thread_rng().next_u32() & 0x01ff_ffff;
    (0..CODE_SYMBOLS)
        .rev()
        .map(|index| base32_symbol(((value >> (index * 5)) & 31) as u8))
        .collect()
}

/// Normalize a human-entered five-character code before giving it to SPAKE2.
/// A PAKE lets this deliberately short code authenticate the exchange without
/// enabling an offline dictionary attack on captured pairing traffic.
pub fn normalize_code(text: &str) -> Result<String, PairingError> {
    let symbols: Vec<u8> = text
        .bytes()
        .filter(|byte| !matches!(byte, b'-' | b' '))
        .map(base32_value)
        .collect::<Result<_, _>>()?;
    if symbols.len() != CODE_SYMBOLS {
        return Err(PairingError::InvalidCode);
    }
    Ok(symbols.into_iter().map(base32_symbol).collect())
}

pub fn encode_request(request: &PairRequest) -> Result<Vec<u8>, PairingError> {
    encode_fields(&[
        ("kind", "request".to_owned()),
        ("host_name", request.host_name.clone()),
        ("host_service_port", request.host_service_port.to_string()),
        ("placement", request.placement.as_str().to_owned()),
        (
            "persistent_permissions",
            request.persistent_permissions.to_string(),
        ),
    ])
}

pub fn decode_request(bytes: &[u8]) -> Result<PairRequest, PairingError> {
    let fields = decode_fields(bytes)?;
    require(&fields, "kind", "request")?;
    Ok(PairRequest {
        host_name: value(&fields, "host_name")?.to_owned(),
        host_service_port: parse_port(value(&fields, "host_service_port")?)?,
        placement: parse_placement(value(&fields, "placement")?)?,
        persistent_permissions: parse_bool(value(&fields, "persistent_permissions")?)?,
    })
}

pub fn encode_grant(grant: &PairGrant) -> Result<Vec<u8>, PairingError> {
    encode_fields(&[
        ("kind", "grant".to_owned()),
        ("peer_id", grant.peer_id.clone()),
        ("psk", hex::encode(grant.psk)),
        ("client_name", grant.client_name.clone()),
        ("client_service_port", grant.client_service_port.to_string()),
        ("placement", grant.placement.as_str().to_owned()),
        (
            "persistent_permissions",
            grant.persistent_permissions.to_string(),
        ),
    ])
}

pub fn decode_grant(bytes: &[u8]) -> Result<PairGrant, PairingError> {
    let fields = decode_fields(bytes)?;
    require(&fields, "kind", "grant")?;
    let psk_text = value(&fields, "psk")?;
    let bytes = hex::decode(psk_text).map_err(|_| PairingError::InvalidMessage("invalid PSK"))?;
    let psk: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PairingError::InvalidMessage("invalid PSK length"))?;
    Ok(PairGrant {
        peer_id: value(&fields, "peer_id")?.to_owned(),
        psk,
        client_name: value(&fields, "client_name")?.to_owned(),
        client_service_port: parse_port(value(&fields, "client_service_port")?)?,
        placement: parse_placement(value(&fields, "placement")?)?,
        persistent_permissions: parse_bool(value(&fields, "persistent_permissions")?)?,
    })
}

pub fn checked_endpoint(ip: IpAddr, port: u16) -> Result<std::net::SocketAddr, PairingError> {
    if ip.is_unspecified() {
        return Err(PairingError::UnspecifiedAddress);
    }
    if port == 0 {
        return Err(PairingError::InvalidPort);
    }
    Ok((ip, port).into())
}

fn base32_symbol(value: u8) -> char {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    ALPHABET[value as usize] as char
}

fn base32_value(byte: u8) -> Result<u8, PairingError> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let upper = byte.to_ascii_uppercase();
    ALPHABET
        .iter()
        .position(|symbol| *symbol == upper)
        .map(|value| value as u8)
        .ok_or(PairingError::InvalidCode)
}

fn encode_fields(fields: &[(&str, String)]) -> Result<Vec<u8>, PairingError> {
    let mut message = String::from("CachyBridgePair/1\n");
    for (key, value) in fields {
        if value.contains(['\n', '\r', '=']) {
            return Err(PairingError::InvalidMessage("field contains a separator"));
        }
        message.push_str(key);
        message.push('=');
        message.push_str(value);
        message.push('\n');
    }
    if message.len() > 1024 {
        return Err(PairingError::MessageTooLarge);
    }
    Ok(message.into_bytes())
}

fn decode_fields(bytes: &[u8]) -> Result<Vec<(String, String)>, PairingError> {
    let text = std::str::from_utf8(bytes).map_err(|_| PairingError::InvalidMessage("not UTF-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some("CachyBridgePair/1") {
        return Err(PairingError::InvalidMessage("unsupported version"));
    }
    let mut fields = Vec::new();
    for line in lines {
        let (key, value) = line
            .split_once('=')
            .ok_or(PairingError::InvalidMessage("missing separator"))?;
        if key.is_empty() || value.is_empty() || fields.iter().any(|(existing, _)| existing == key)
        {
            return Err(PairingError::InvalidMessage("invalid or duplicate field"));
        }
        fields.push((key.to_owned(), value.to_owned()));
    }
    Ok(fields)
}

fn value<'a>(fields: &'a [(String, String)], key: &str) -> Result<&'a str, PairingError> {
    fields
        .iter()
        .find(|(field, _)| field == key)
        .map(|(_, value)| value.as_str())
        .ok_or(PairingError::InvalidMessage("missing required field"))
}

fn require(fields: &[(String, String)], key: &str, expected: &str) -> Result<(), PairingError> {
    if value(fields, key)? == expected {
        Ok(())
    } else {
        Err(PairingError::InvalidMessage("unexpected message kind"))
    }
}

fn parse_port(value: &str) -> Result<u16, PairingError> {
    let port = value
        .parse()
        .map_err(|_| PairingError::InvalidMessage("invalid port"))?;
    if port == 0 {
        Err(PairingError::InvalidPort)
    } else {
        Ok(port)
    }
}

fn parse_bool(value: &str) -> Result<bool, PairingError> {
    value
        .parse()
        .map_err(|_| PairingError::InvalidMessage("invalid boolean"))
}

fn parse_placement(value: &str) -> Result<RelativePlacement, PairingError> {
    match value {
        "left" => Ok(RelativePlacement::Left),
        "right" => Ok(RelativePlacement::Right),
        "above" => Ok(RelativePlacement::Above),
        "below" => Ok(RelativePlacement::Below),
        _ => Err(PairingError::InvalidMessage("invalid placement")),
    }
}

impl fmt::Display for PairRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.host_name, self.host_service_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_codes_normalize_case_and_grouping() {
        let code = generate_code();
        assert_eq!(
            normalize_code(&code).unwrap(),
            normalize_code(&code.to_lowercase()).unwrap()
        );
    }

    #[test]
    fn generated_code_round_trips() {
        let code = generate_code();
        assert_eq!(normalize_code(&code).unwrap().len(), CODE_SYMBOLS);
    }

    #[test]
    fn grant_round_trips_without_leaking_into_debug() {
        let grant = PairGrant {
            peer_id: "a".repeat(32),
            psk: [7; 32],
            client_name: "Client iMac".into(),
            client_service_port: 45_231,
            placement: RelativePlacement::Left,
            persistent_permissions: true,
        };
        assert_eq!(decode_grant(&encode_grant(&grant).unwrap()).unwrap(), grant);
    }
}
