//! Clipboard synchronization over an already authenticated CachyBridge transport.
//! Contents never touch discovery, logs, or configuration files. It supports
//! normal text and common image data, but deliberately excludes file/URI data.

use std::{
    io::{self, Write},
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use rand::RngCore;
use thiserror::Error;

use crate::transport::{SecureConnection, TransportError};

const RECORD_PREFIX: &[u8] = b"CBCL2";
const START_KIND: u8 = 1;
const CHUNK_KIND: u8 = 2;
const START_HEADER_BYTES: usize = RECORD_PREFIX.len() + 1 + 8 + 1 + 4;
const CHUNK_HEADER_BYTES: usize = RECORD_PREFIX.len() + 1 + 8 + 4;
// `poll_receive_payload` intentionally waits until a complete encrypted record
// is buffered before consuming it.  A near-64 KiB application record can be
// larger than an OS's effective TCP receive window, leaving the receiver a few
// KiB short forever while the sender waits for that window to open.  Keep
// clipboard records comfortably below the smallest normal socket window so
// image transfers cannot deadlock at a partial frame boundary.
const MAX_CHUNK_BYTES: usize = 16 * 1024;
const MAX_CLIPBOARD_BYTES: usize = 8 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const IDLE_INTERVAL: Duration = Duration::from_millis(10);

const SUPPORTED_MIME_TYPES: &[&str] = &[
    "text/plain",
    "text/plain;charset=utf-8",
    "image/png",
    "image/jpeg",
    "image/webp",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClipboardContent {
    mime_type: String,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct IncomingTransfer {
    id: u64,
    mime_type: String,
    total_bytes: usize,
    bytes: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum ClipboardError {
    #[error("clipboard synchronization requires wl-clipboard (install the wl-clipboard package)")]
    MissingTool,
    #[error("clipboard command failed: {0}")]
    Command(String),
    #[error("clipboard item exceeds {MAX_CLIPBOARD_BYTES} bytes")]
    TooLarge,
    #[error("clipboard MIME type is not supported")]
    UnsupportedMime,
    #[error("clipboard data is not valid UTF-8 text")]
    NonText,
    #[error("invalid encrypted clipboard record")]
    InvalidRecord,
    #[error("clipboard transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("clipboard I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Continuously mirrors text and image content. Each received value becomes
/// the local baseline before polling again, preventing A→B→A echo loops.
pub fn run(mut connection: SecureConnection) -> Result<(), ClipboardError> {
    let mut last_value: Option<ClipboardContent> = None;
    let mut incoming: Option<IncomingTransfer> = None;
    // Keep ownership of the provider we started.  A foreground wl-copy
    // process can otherwise keep a stale Wayland selection alive after the
    // user copies a newer value, making a just-received image flip back to an
    // earlier text selection a few seconds later.
    let mut provider = None;
    let mut next_poll = Instant::now();
    loop {
        if let Some(record) = connection.poll_receive_payload()? {
            if let Some(content) = receive_record(&record, &mut incoming)? {
                write_content(&content, &mut provider)?;
                eprintln!(
                    "clipboard received {} ({} bytes)",
                    content.mime_type,
                    content.bytes.len()
                );
                last_value = Some(content);
            }
        }
        if Instant::now() >= next_poll {
            if let Some(content) = read_content()? {
                if last_value.as_ref() != Some(&content) {
                    // A user-originated replacement must retire our previous
                    // provider before it can reassert the stale selection.
                    stop_provider(&mut provider);
                    send_content(&mut connection, &content)?;
                    eprintln!(
                        "clipboard sent {} ({} bytes)",
                        content.mime_type,
                        content.bytes.len()
                    );
                    last_value = Some(content);
                }
            }
            next_poll = Instant::now() + POLL_INTERVAL;
        }
        thread::sleep(IDLE_INTERVAL);
    }
}

fn send_content(
    connection: &mut SecureConnection,
    content: &ClipboardContent,
) -> Result<(), ClipboardError> {
    validate_content(content)?;
    let mut id_bytes = [0_u8; 8];
    rand::thread_rng().fill_bytes(&mut id_bytes);
    let id = u64::from_be_bytes(id_bytes);
    connection.send_payload(&encode_start(id, content)?)?;
    for (part, chunk) in content.bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
        let offset = part
            .checked_mul(MAX_CHUNK_BYTES)
            .ok_or(ClipboardError::TooLarge)?;
        connection.send_payload(&encode_chunk(id, offset, chunk)?)?;
    }
    Ok(())
}

fn receive_record(
    record: &[u8],
    incoming: &mut Option<IncomingTransfer>,
) -> Result<Option<ClipboardContent>, ClipboardError> {
    let body = record
        .strip_prefix(RECORD_PREFIX)
        .ok_or(ClipboardError::InvalidRecord)?;
    let Some((&kind, rest)) = body.split_first() else {
        return Err(ClipboardError::InvalidRecord);
    };
    match kind {
        START_KIND => {
            let transfer = decode_start(rest)?;
            if transfer.total_bytes == 0 {
                return Ok(Some(ClipboardContent {
                    mime_type: transfer.mime_type,
                    bytes: Vec::new(),
                }));
            }
            *incoming = Some(transfer);
            Ok(None)
        }
        CHUNK_KIND => {
            let (id, offset, bytes) = decode_chunk(rest)?;
            let transfer = incoming.as_mut().ok_or(ClipboardError::InvalidRecord)?;
            if transfer.id != id || offset != transfer.bytes.len() || bytes.is_empty() {
                return Err(ClipboardError::InvalidRecord);
            }
            let remaining = transfer.total_bytes - transfer.bytes.len();
            if bytes.len() > remaining {
                return Err(ClipboardError::InvalidRecord);
            }
            transfer.bytes.extend_from_slice(bytes);
            if transfer.bytes.len() == transfer.total_bytes {
                let complete = incoming.take().expect("transfer was checked");
                Ok(Some(ClipboardContent {
                    mime_type: complete.mime_type,
                    bytes: complete.bytes,
                }))
            } else {
                Ok(None)
            }
        }
        _ => Err(ClipboardError::InvalidRecord),
    }
}

fn encode_start(id: u64, content: &ClipboardContent) -> Result<Vec<u8>, ClipboardError> {
    validate_content(content)?;
    let mime = content.mime_type.as_bytes();
    if mime.len() > u8::MAX as usize {
        return Err(ClipboardError::UnsupportedMime);
    }
    let length = u32::try_from(content.bytes.len()).map_err(|_| ClipboardError::TooLarge)?;
    let mut record = Vec::with_capacity(START_HEADER_BYTES + mime.len());
    record.extend_from_slice(RECORD_PREFIX);
    record.push(START_KIND);
    record.extend_from_slice(&id.to_be_bytes());
    record.push(mime.len() as u8);
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(mime);
    Ok(record)
}

fn decode_start(record: &[u8]) -> Result<IncomingTransfer, ClipboardError> {
    if record.len() < 13 {
        return Err(ClipboardError::InvalidRecord);
    }
    let id = u64::from_be_bytes(record[..8].try_into().expect("fixed width"));
    let mime_length = record[8] as usize;
    if record.len() != 13 + mime_length {
        return Err(ClipboardError::InvalidRecord);
    }
    let total_bytes = u32::from_be_bytes(record[9..13].try_into().expect("fixed width")) as usize;
    if total_bytes > MAX_CLIPBOARD_BYTES {
        return Err(ClipboardError::TooLarge);
    }
    let mime_type = std::str::from_utf8(&record[13..])
        .map_err(|_| ClipboardError::UnsupportedMime)?
        .to_owned();
    validate_mime(&mime_type)?;
    Ok(IncomingTransfer {
        id,
        mime_type,
        total_bytes,
        bytes: Vec::with_capacity(total_bytes),
    })
}

fn encode_chunk(id: u64, offset: usize, bytes: &[u8]) -> Result<Vec<u8>, ClipboardError> {
    if bytes.is_empty() || bytes.len() > MAX_CHUNK_BYTES {
        return Err(ClipboardError::InvalidRecord);
    }
    let offset = u32::try_from(offset).map_err(|_| ClipboardError::TooLarge)?;
    let mut record = Vec::with_capacity(CHUNK_HEADER_BYTES + bytes.len());
    record.extend_from_slice(RECORD_PREFIX);
    record.push(CHUNK_KIND);
    record.extend_from_slice(&id.to_be_bytes());
    record.extend_from_slice(&offset.to_be_bytes());
    record.extend_from_slice(bytes);
    Ok(record)
}

fn decode_chunk(record: &[u8]) -> Result<(u64, usize, &[u8]), ClipboardError> {
    if record.len() <= 12 {
        return Err(ClipboardError::InvalidRecord);
    }
    let id = u64::from_be_bytes(record[..8].try_into().expect("fixed width"));
    let offset = u32::from_be_bytes(record[8..12].try_into().expect("fixed width")) as usize;
    let bytes = &record[12..];
    if bytes.len() > MAX_CHUNK_BYTES {
        return Err(ClipboardError::InvalidRecord);
    }
    Ok((id, offset, bytes))
}

fn read_content() -> Result<Option<ClipboardContent>, ClipboardError> {
    let types = Command::new(clipboard_tool("wl-paste"))
        .arg("--list-types")
        .output()
        .map_err(map_command_start)?;
    if !types.status.success() {
        return Ok(None);
    }
    let type_list = String::from_utf8(types.stdout).map_err(|_| ClipboardError::InvalidRecord)?;
    let Some(mime_type) = SUPPORTED_MIME_TYPES
        .iter()
        .find(|candidate| type_list.lines().any(|available| available == **candidate))
    else {
        return Ok(None);
    };
    let output = Command::new(clipboard_tool("wl-paste"))
        .args(["--no-newline", "--type", mime_type])
        .output()
        .map_err(map_command_start)?;
    if !output.status.success() {
        return Ok(None);
    }
    let content = ClipboardContent {
        // Advertise the broadly interoperable text target. Some clients offer
        // the charset-qualified alias but only request `text/plain` when
        // pasting, so forwarding that alias unchanged makes the clipboard
        // appear empty despite a successful transfer.
        mime_type: if mime_type.starts_with("text/") {
            "text/plain".to_owned()
        } else {
            (*mime_type).to_owned()
        },
        bytes: output.stdout,
    };
    validate_content(&content)?;
    Ok(Some(content))
}

fn write_content(
    content: &ClipboardContent,
    provider: &mut Option<std::process::Child>,
) -> Result<(), ClipboardError> {
    validate_content(content)?;
    stop_provider(provider);
    let mut child = Command::new(clipboard_tool("wl-copy"))
        // wl-copy normally forks into a clipboard-provider daemon. Waiting for
        // the initial process can therefore block forever under systemd's
        // subreaper, which froze our receive loop after its first update. Keep
        // it in the foreground and return to the sync loop immediately. Its
        // child handle is retained so the next replacement can retire it.
        .args(["--foreground", "--type", &content.mime_type])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(map_command_start)?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| ClipboardError::Command("wl-copy did not accept stdin".to_owned()))?;
    stdin.write_all(&content.bytes)?;
    // Closing stdin tells wl-copy that it has received the complete item.
    drop(stdin);
    *provider = Some(child);
    Ok(())
}

fn stop_provider(provider: &mut Option<std::process::Child>) {
    let Some(mut child) = provider.take() else {
        return;
    };
    match child.try_wait() {
        Ok(Some(_)) => {}
        Ok(None) => {
            // Replacing a local selection is an expected shutdown path, so a
            // best-effort kill plus reap prevents stale providers and zombies
            // without delaying the synchronization loop on normal operation.
            let _ = child.kill();
            let _ = child.wait();
        }
        Err(error) => eprintln!("clipboard provider status check failed: {error}"),
    }
}

fn validate_content(content: &ClipboardContent) -> Result<(), ClipboardError> {
    validate_mime(&content.mime_type)?;
    if content.bytes.len() > MAX_CLIPBOARD_BYTES {
        return Err(ClipboardError::TooLarge);
    }
    if content.mime_type.starts_with("text/") {
        std::str::from_utf8(&content.bytes).map_err(|_| ClipboardError::NonText)?;
    }
    Ok(())
}

fn validate_mime(mime_type: &str) -> Result<(), ClipboardError> {
    if SUPPORTED_MIME_TYPES.contains(&mime_type) {
        Ok(())
    } else {
        Err(ClipboardError::UnsupportedMime)
    }
}

fn map_command_start(error: io::Error) -> ClipboardError {
    if error.kind() == io::ErrorKind::NotFound {
        ClipboardError::MissingTool
    } else {
        ClipboardError::Io(error)
    }
}

/// A portable CachyBridge deployment can place the tiny wl-clipboard helpers
/// next to its CLI. Prefer those when present, then fall back to the system
/// package for normal distro installations.
fn clipboard_tool(name: &str) -> PathBuf {
    if let Ok(executable) = std::env::current_exe() {
        let bundled = executable.with_file_name(name);
        if bundled.is_file() {
            return bundled;
        }
    }
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn content(mime_type: &str, bytes: &[u8]) -> ClipboardContent {
        ClipboardContent {
            mime_type: mime_type.to_owned(),
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn text_record_round_trips() {
        let source = content("text/plain;charset=utf-8", b"copy me");
        let mut incoming = None;
        assert_eq!(
            receive_record(&encode_start(7, &source).unwrap(), &mut incoming).unwrap(),
            None
        );
        assert_eq!(
            receive_record(&encode_chunk(7, 0, &source.bytes).unwrap(), &mut incoming).unwrap(),
            Some(source)
        );
    }

    #[test]
    fn png_transfer_reassembles_across_records() {
        let source = content("image/png", &vec![7_u8; MAX_CHUNK_BYTES + 11]);
        let mut incoming = None;
        assert_eq!(
            receive_record(&encode_start(4, &source).unwrap(), &mut incoming).unwrap(),
            None
        );
        assert_eq!(
            receive_record(
                &encode_chunk(4, 0, &source.bytes[..MAX_CHUNK_BYTES]).unwrap(),
                &mut incoming
            )
            .unwrap(),
            None
        );
        assert_eq!(
            receive_record(
                &encode_chunk(4, MAX_CHUNK_BYTES, &source.bytes[MAX_CHUNK_BYTES..]).unwrap(),
                &mut incoming
            )
            .unwrap(),
            Some(source)
        );
    }

    #[test]
    fn unsafe_types_and_malformed_chunks_fail_closed() {
        assert!(matches!(
            encode_start(1, &content("text/uri-list", b"file:///private")),
            Err(ClipboardError::UnsupportedMime)
        ));
        assert!(matches!(
            encode_start(1, &content("text/plain", &[0xff])),
            Err(ClipboardError::NonText)
        ));
        assert!(matches!(
            decode_chunk(&[0_u8; 12]),
            Err(ClipboardError::InvalidRecord)
        ));
    }
}
