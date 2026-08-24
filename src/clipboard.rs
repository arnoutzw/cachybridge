//! Clipboard synchronization over an already authenticated CachyBridge transport.
//! Contents never touch discovery, logs, or configuration files. It supports
//! normal text, common image data, and bounded regular-file transfers.

use std::{
    collections::HashSet,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
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
/// Maximum aggregate size of one regular-file clipboard transfer. File data is
/// transmitted in-memory, so this is intentionally bounded separately from
/// image/text clipboard content.
const MAX_FILE_TRANSFER_BYTES: usize = 64 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const IDLE_INTERVAL: Duration = Duration::from_millis(10);
const FILE_TRANSFER_MIME: &str = "application/x-cachybridge-file-list";
const FILE_BUNDLE_PREFIX: &[u8] = b"CBFL1";

const SUPPORTED_MIME_TYPES: &[&str] = &[
    "text/plain",
    "text/plain;charset=utf-8",
    "image/png",
    "image/jpeg",
    "image/webp",
    FILE_TRANSFER_MIME,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileEntry {
    name: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum ClipboardError {
    #[error("clipboard synchronization requires wl-clipboard (install the wl-clipboard package)")]
    MissingTool,
    #[error("clipboard command failed: {0}")]
    Command(String),
    #[error("clipboard item exceeds its supported size limit")]
    TooLarge,
    #[error("clipboard MIME type is not supported")]
    UnsupportedMime,
    #[error("clipboard data is not valid UTF-8 text")]
    NonText,
    #[error("clipboard file list contains no supported regular files")]
    NoRegularFiles,
    #[error("clipboard file transfer has an invalid bundle")]
    InvalidFileBundle,
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
    let mime_type = std::str::from_utf8(&record[13..])
        .map_err(|_| ClipboardError::UnsupportedMime)?
        .to_owned();
    validate_mime(&mime_type)?;
    if total_bytes > content_size_limit(&mime_type) {
        return Err(ClipboardError::TooLarge);
    }
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
    if type_list
        .lines()
        .any(|available| available == "text/uri-list")
    {
        let output = Command::new(clipboard_tool("wl-paste"))
            .args(["--no-newline", "--type", "text/uri-list"])
            .output()
            .map_err(map_command_start)?;
        if output.status.success() {
            match pack_local_files(&output.stdout) {
                Ok(content) => return Ok(Some(content)),
                // A URI list can also be a browser URL drag or a directory.
                // Leave those local rather than ending the whole clipboard
                // session because they are not safe portable file copies.
                Err(ClipboardError::NoRegularFiles) => return Ok(None),
                Err(error) => return Err(error),
            }
        }
    }
    let Some(mime_type) = SUPPORTED_MIME_TYPES
        .iter()
        .filter(|candidate| **candidate != FILE_TRANSFER_MIME)
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
    let (mime_type, bytes) = if content.mime_type == FILE_TRANSFER_MIME {
        (
            "text/uri-list".to_owned(),
            materialize_files(&content.bytes)?,
        )
    } else {
        (content.mime_type.clone(), content.bytes.clone())
    };
    let mut child = Command::new(clipboard_tool("wl-copy"))
        // wl-copy normally forks into a clipboard-provider daemon. Waiting for
        // the initial process can therefore block forever under systemd's
        // subreaper, which froze our receive loop after its first update. Keep
        // it in the foreground and return to the sync loop immediately. Its
        // child handle is retained so the next replacement can retire it.
        .args(["--foreground", "--type", &mime_type])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(map_command_start)?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| ClipboardError::Command("wl-copy did not accept stdin".to_owned()))?;
    stdin.write_all(&bytes)?;
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

fn pack_local_files(uri_list: &[u8]) -> Result<ClipboardContent, ClipboardError> {
    let uri_list = std::str::from_utf8(uri_list).map_err(|_| ClipboardError::InvalidFileBundle)?;
    let mut files = Vec::new();
    let mut names = HashSet::new();
    let mut total_bytes = 0_usize;
    for line in uri_list
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let path = file_uri_to_path(line)?;
        let metadata = match fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => metadata,
            _ => continue,
        };
        let size = usize::try_from(metadata.len()).map_err(|_| ClipboardError::TooLarge)?;
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or(ClipboardError::TooLarge)?;
        if total_bytes > MAX_FILE_TRANSFER_BYTES {
            return Err(ClipboardError::TooLarge);
        }
        let name = safe_file_name(&path)?;
        if !names.insert(name.clone()) {
            // A URI list can contain files named alike from different folders.
            // Refuse that ambiguity instead of silently overwriting one peer's
            // file on the other iMac.
            return Err(ClipboardError::InvalidFileBundle);
        }
        files.push(FileEntry {
            name,
            bytes: fs::read(path)?,
        });
    }
    if files.is_empty() {
        return Err(ClipboardError::NoRegularFiles);
    }
    let content = ClipboardContent {
        mime_type: FILE_TRANSFER_MIME.to_owned(),
        bytes: encode_file_bundle(&files)?,
    };
    validate_content(&content)?;
    Ok(content)
}

fn file_uri_to_path(uri: &str) -> Result<PathBuf, ClipboardError> {
    let Some(remainder) = uri.strip_prefix("file://") else {
        return Err(ClipboardError::NoRegularFiles);
    };
    let path = if remainder.starts_with('/') {
        remainder.to_owned()
    } else if let Some(path) = remainder.strip_prefix("localhost/") {
        format!("/{path}")
    } else {
        return Err(ClipboardError::NoRegularFiles);
    };
    let decoded = percent_decode(&path)?;
    if !decoded.starts_with('/') || decoded.contains('\0') {
        return Err(ClipboardError::InvalidFileBundle);
    }
    Ok(PathBuf::from(decoded))
}

fn percent_decode(value: &str) -> Result<String, ClipboardError> {
    let mut bytes = Vec::with_capacity(value.len());
    let source = value.as_bytes();
    let mut index = 0;
    while index < source.len() {
        if source[index] == b'%' {
            if index + 2 >= source.len() {
                return Err(ClipboardError::InvalidFileBundle);
            }
            let nibble = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            let high = nibble(source[index + 1]).ok_or(ClipboardError::InvalidFileBundle)?;
            let low = nibble(source[index + 2]).ok_or(ClipboardError::InvalidFileBundle)?;
            bytes.push((high << 4) | low);
            index += 3;
        } else {
            bytes.push(source[index]);
            index += 1;
        }
    }
    String::from_utf8(bytes).map_err(|_| ClipboardError::InvalidFileBundle)
}

fn safe_file_name(path: &Path) -> Result<String, ClipboardError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .ok_or(ClipboardError::InvalidFileBundle)?;
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(ClipboardError::InvalidFileBundle);
    }
    Ok(name.to_owned())
}

fn encode_file_bundle(files: &[FileEntry]) -> Result<Vec<u8>, ClipboardError> {
    if files.is_empty() || files.len() > u16::MAX as usize {
        return Err(ClipboardError::InvalidFileBundle);
    }
    let mut total_bytes = 0_usize;
    let mut output = Vec::from(FILE_BUNDLE_PREFIX);
    output.extend_from_slice(&(files.len() as u16).to_be_bytes());
    for file in files {
        if file.name.is_empty()
            || file.name.len() > u16::MAX as usize
            || file.name.contains('/')
            || file.name.contains('\\')
            || file.name == "."
            || file.name == ".."
        {
            return Err(ClipboardError::InvalidFileBundle);
        }
        total_bytes = total_bytes
            .checked_add(file.bytes.len())
            .ok_or(ClipboardError::TooLarge)?;
        if total_bytes > MAX_FILE_TRANSFER_BYTES {
            return Err(ClipboardError::TooLarge);
        }
        output.extend_from_slice(&(file.name.len() as u16).to_be_bytes());
        output.extend_from_slice(&(file.bytes.len() as u64).to_be_bytes());
        output.extend_from_slice(file.name.as_bytes());
        output.extend_from_slice(&file.bytes);
    }
    Ok(output)
}

fn decode_file_bundle(bundle: &[u8]) -> Result<Vec<FileEntry>, ClipboardError> {
    let mut input = bundle
        .strip_prefix(FILE_BUNDLE_PREFIX)
        .ok_or(ClipboardError::InvalidFileBundle)?;
    if input.len() < 2 {
        return Err(ClipboardError::InvalidFileBundle);
    }
    let count = u16::from_be_bytes(input[..2].try_into().expect("fixed width")) as usize;
    input = &input[2..];
    if count == 0 {
        return Err(ClipboardError::InvalidFileBundle);
    }
    let mut files = Vec::with_capacity(count);
    let mut names = HashSet::new();
    let mut total_bytes = 0_usize;
    for _ in 0..count {
        if input.len() < 10 {
            return Err(ClipboardError::InvalidFileBundle);
        }
        let name_len = u16::from_be_bytes(input[..2].try_into().expect("fixed width")) as usize;
        let size = u64::from_be_bytes(input[2..10].try_into().expect("fixed width"));
        let size = usize::try_from(size).map_err(|_| ClipboardError::TooLarge)?;
        input = &input[10..];
        if name_len == 0 || input.len() < name_len || input.len() - name_len < size {
            return Err(ClipboardError::InvalidFileBundle);
        }
        let name = std::str::from_utf8(&input[..name_len])
            .map_err(|_| ClipboardError::InvalidFileBundle)?
            .to_owned();
        if name.contains('/')
            || name.contains('\\')
            || name == "."
            || name == ".."
            || !names.insert(name.clone())
        {
            return Err(ClipboardError::InvalidFileBundle);
        }
        input = &input[name_len..];
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or(ClipboardError::TooLarge)?;
        if total_bytes > MAX_FILE_TRANSFER_BYTES {
            return Err(ClipboardError::TooLarge);
        }
        files.push(FileEntry {
            name,
            bytes: input[..size].to_vec(),
        });
        input = &input[size..];
    }
    if !input.is_empty() {
        return Err(ClipboardError::InvalidFileBundle);
    }
    Ok(files)
}

fn materialize_files(bundle: &[u8]) -> Result<Vec<u8>, ClipboardError> {
    let files = decode_file_bundle(bundle)?;
    let parent = received_files_root()?;
    let mut random = [0_u8; 12];
    rand::thread_rng().fill_bytes(&mut random);
    let directory = parent.join(hex::encode(random));
    fs::create_dir(&directory)?;
    set_private_directory(&directory)?;
    let mut uris = String::new();
    for file in files {
        let path = directory.join(&file.name);
        write_private_file(&path, &file.bytes)?;
        uris.push_str("file://");
        uris.push_str(&percent_encode_path(&path)?);
        uris.push('\n');
    }
    Ok(uris.into_bytes())
}

fn received_files_root() -> Result<PathBuf, ClipboardError> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .ok_or_else(|| {
            ClipboardError::Command("could not determine a private data directory".to_owned())
        })?;
    let directory = base.join("cachybridge").join("received-files");
    fs::create_dir_all(&directory)?;
    set_private_directory(&directory)?;
    Ok(directory)
}

fn percent_encode_path(path: &Path) -> Result<String, ClipboardError> {
    let value = path.to_str().ok_or(ClipboardError::InvalidFileBundle)?;
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' | b'~')
        {
            encoded.push(*byte as char);
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    Ok(encoded)
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<(), ClipboardError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory(_: &Path) -> Result<(), ClipboardError> {
    Ok(())
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), ClipboardError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), ClipboardError> {
    fs::write(path, bytes)?;
    Ok(())
}

fn validate_content(content: &ClipboardContent) -> Result<(), ClipboardError> {
    validate_mime(&content.mime_type)?;
    if content.bytes.len() > content_size_limit(&content.mime_type) {
        return Err(ClipboardError::TooLarge);
    }
    if content.mime_type.starts_with("text/") {
        std::str::from_utf8(&content.bytes).map_err(|_| ClipboardError::NonText)?;
    }
    Ok(())
}

fn content_size_limit(mime_type: &str) -> usize {
    if mime_type == FILE_TRANSFER_MIME {
        MAX_FILE_TRANSFER_BYTES
    } else {
        MAX_CLIPBOARD_BYTES
    }
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

    #[test]
    fn file_bundle_round_trips_multiple_regular_files() {
        let files = vec![
            FileEntry {
                name: "notes.txt".to_owned(),
                bytes: b"hello".to_vec(),
            },
            FileEntry {
                name: "diagram.png".to_owned(),
                bytes: vec![1, 2, 3, 4],
            },
        ];
        let bundle = encode_file_bundle(&files).unwrap();
        assert_eq!(decode_file_bundle(&bundle).unwrap(), files);
    }

    #[test]
    fn file_transfer_start_allows_the_separate_file_size_limit() {
        let source = ClipboardContent {
            mime_type: FILE_TRANSFER_MIME.to_owned(),
            bytes: vec![0_u8; MAX_CLIPBOARD_BYTES + 1],
        };
        let start = encode_start(9, &source).unwrap();
        let transfer = decode_start(&start[RECORD_PREFIX.len() + 1..]).unwrap();
        assert_eq!(transfer.total_bytes, MAX_CLIPBOARD_BYTES + 1);
        assert_eq!(transfer.mime_type, FILE_TRANSFER_MIME);
    }

    #[test]
    fn file_bundle_rejects_path_traversal_and_duplicate_names() {
        assert!(matches!(
            encode_file_bundle(&[FileEntry {
                name: "../escape".to_owned(),
                bytes: vec![1],
            }]),
            Err(ClipboardError::InvalidFileBundle)
        ));
        let mut malformed = Vec::from(FILE_BUNDLE_PREFIX);
        malformed.extend_from_slice(&2_u16.to_be_bytes());
        for bytes in [b"first".as_slice(), b"second".as_slice()] {
            malformed.extend_from_slice(&8_u16.to_be_bytes());
            malformed.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            malformed.extend_from_slice(b"same.txt");
            malformed.extend_from_slice(bytes);
        }
        assert!(matches!(
            decode_file_bundle(&malformed),
            Err(ClipboardError::InvalidFileBundle)
        ));
    }

    #[test]
    fn file_uris_decode_only_local_paths() {
        assert_eq!(
            file_uri_to_path("file:///tmp/a%20file.txt").unwrap(),
            PathBuf::from("/tmp/a file.txt")
        );
        assert!(matches!(
            file_uri_to_path("https://example.com/file.txt"),
            Err(ClipboardError::NoRegularFiles)
        ));
    }
}
