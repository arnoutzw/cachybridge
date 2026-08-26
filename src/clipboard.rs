//! Clipboard synchronization over an already authenticated CachyBridge transport.
//! Contents never touch discovery, logs, or configuration files. It supports
//! normal text, common image data, and bounded regular-file transfers.

use std::{
    collections::HashSet,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, UNIX_EPOCH},
};

use rand::RngCore;
use thiserror::Error;

use crate::transport::{SecureConnection, TransportError};

const RECORD_PREFIX: &[u8] = b"CBCL2";
const START_KIND: u8 = 1;
const CHUNK_KIND: u8 = 2;
// File payloads deliberately use a separate streaming format.  The original
// clipboard format is retained for text and images, whose whole value is small
// enough to validate and hold in memory.
const FILE_START_KIND: u8 = 3;
const FILE_CHUNK_KIND: u8 = 4;
const FILE_FINISH_KIND: u8 = 5;
const FILE_ACCEPT_KIND: u8 = 6;
const FILE_REJECT_KIND: u8 = 7;
const DIRECT_FILE_START_KIND: u8 = 8;
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
/// A disk-safety ceiling, not an in-memory ceiling.  Files are streamed into a
/// private staging directory and published only once every byte is present.
const MAX_FILE_TRANSFER_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_FILE_COUNT: usize = 256;
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const IDLE_INTERVAL: Duration = Duration::from_millis(10);
const FILE_APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalFile {
    name: String,
    path: PathBuf,
    size: u64,
    modified_nanos: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSelection {
    files: Vec<LocalFile>,
    total_bytes: u64,
}

type FileManifest = Vec<(String, u64)>;

#[derive(Debug)]
struct IncomingFile {
    name: String,
    size: u64,
    received: u64,
    staging_path: PathBuf,
    file: fs::File,
}

#[derive(Debug)]
struct IncomingFileTransfer {
    id: u64,
    files: Vec<IncomingFile>,
    file_index: usize,
    total_bytes: u64,
    received_bytes: u64,
    staging_directory: PathBuf,
    started: Instant,
    last_status: Instant,
}

enum ReceivedClipboard {
    Content(ClipboardContent),
    Files(FileSelection),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTransferOutcome {
    Completed,
    Declined,
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
pub fn run(connection: SecureConnection) -> Result<(), ClipboardError> {
    run_with_initial_payload(connection, None)
}

pub fn run_with_initial_payload(
    mut connection: SecureConnection,
    mut initial_record: Option<Vec<u8>>,
) -> Result<(), ClipboardError> {
    let mut last_value: Option<ClipboardContent> = None;
    let mut incoming: Option<IncomingTransfer> = None;
    let mut incoming_files: Option<IncomingFileTransfer> = None;
    let mut last_file_selection: Option<FileSelection> = None;
    let mut oversized_selection_reported = false;
    // Keep ownership of the provider we started.  A foreground wl-copy
    // process can otherwise keep a stale Wayland selection alive after the
    // user copies a newer value, making a just-received image flip back to an
    // earlier text selection a few seconds later.
    let mut provider = None;
    let mut next_poll = Instant::now();
    loop {
        // Drain a bounded batch.  The former one-record-per-10ms loop capped
        // transfers at about 1.6 MiB/s regardless of network capacity.
        for _ in 0..64 {
            let record = if let Some(record) = initial_record.take() {
                record
            } else if let Some(record) = connection.poll_receive_payload()? {
                record
            } else {
                break;
            };
            if let Some(received) = process_received_record(
                &mut connection,
                &record,
                &mut incoming,
                &mut incoming_files,
                &mut provider,
            )? {
                update_received_baseline(received, &mut last_value, &mut last_file_selection);
            }
        }
        if Instant::now() >= next_poll {
            match read_file_selection() {
                Ok(Some(selection)) => {
                    oversized_selection_reported = false;
                    // A received item is deliberately published under our
                    // managed Downloads folder. Treat it as a terminal
                    // clipboard value, even after a service restart, so it
                    // cannot boomerang back to the sender indefinitely.
                    if is_received_file_selection(&selection) {
                        last_file_selection = Some(selection);
                        next_poll = Instant::now() + POLL_INTERVAL;
                        thread::sleep(IDLE_INTERVAL);
                        continue;
                    }
                    // File transfers are intentionally explicit: Dolphin's
                    // CachyBridge service-menu action invokes `send-files`.
                    // This preserves normal copy/paste semantics and avoids
                    // offering an accidental file clipboard selection.
                    last_file_selection = Some(selection);
                }
                Ok(None) => {
                    match read_content() {
                        Ok(Some(content)) => {
                            oversized_selection_reported = false;
                            // A confirmed non-file replacement means a later
                            // copy of the same file is intentional. Do not
                            // clear this baseline merely because wl-paste
                            // observes a brief empty selection while a
                            // foreground provider is being replaced.
                            last_file_selection = None;
                            if last_value.as_ref() != Some(&content) {
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
                        Ok(None) => oversized_selection_reported = false,
                        Err(ClipboardError::TooLarge) => {
                            if !oversized_selection_reported {
                                eprintln!(
                                    "clipboard selection exceeds the {} GiB transfer limit; leaving it local",
                                    MAX_FILE_TRANSFER_BYTES / (1024 * 1024 * 1024)
                                );
                                oversized_selection_reported = true;
                            }
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(ClipboardError::TooLarge) => {
                    if !oversized_selection_reported {
                        eprintln!(
                            "clipboard selection exceeds the {} GiB transfer limit; leaving it local",
                            MAX_FILE_TRANSFER_BYTES / (1024 * 1024 * 1024)
                        );
                        oversized_selection_reported = true;
                    }
                }
                Err(error) => return Err(error),
            }
            next_poll = Instant::now() + POLL_INTERVAL;
        }
        thread::sleep(IDLE_INTERVAL);
    }
}

fn record_kind(record: &[u8]) -> Option<u8> {
    record.strip_prefix(RECORD_PREFIX)?.first().copied()
}

pub fn is_direct_file_offer(record: &[u8]) -> bool {
    record_kind(record) == Some(DIRECT_FILE_START_KIND)
}

pub fn send_files(
    mut connection: SecureConnection,
    paths: &[PathBuf],
) -> Result<FileTransferOutcome, ClipboardError> {
    let selection = file_selection_from_paths(paths)?;
    let mut incoming = None;
    let mut incoming_files = None;
    let mut provider = None;
    let mut last_value = None;
    let mut last_file_selection = None;
    send_file_transfer(
        &mut connection,
        &selection,
        &mut incoming,
        &mut incoming_files,
        &mut provider,
        &mut last_value,
        &mut last_file_selection,
        DIRECT_FILE_START_KIND,
    )
}

pub fn receive_direct_file_offer(
    mut connection: SecureConnection,
    first_record: Vec<u8>,
) -> Result<(), ClipboardError> {
    let mut incoming = None;
    let mut provider = None;
    if let Some(selection) = receive_file_record(&mut connection, &first_record, &mut incoming)? {
        write_uri_list(&selection, &mut provider)?;
        return Ok(());
    }
    // A declined offer has no receiver state and no payload will follow.
    if incoming.is_none() {
        return Ok(());
    }
    loop {
        let record = connection.receive_payload()?;
        if let Some(selection) = receive_file_record(&mut connection, &record, &mut incoming)? {
            write_uri_list(&selection, &mut provider)?;
            eprintln!(
                "received explicit file offer: {} file(s) into Downloads/CachyBridge",
                selection.files.len()
            );
            return Ok(());
        }
    }
}

fn is_received_file_selection(selection: &FileSelection) -> bool {
    let Ok(root) = received_airdrop_root() else {
        return false;
    };
    selection
        .files
        .iter()
        .all(|file| file.path.starts_with(&root))
}

fn process_received_record(
    connection: &mut SecureConnection,
    record: &[u8],
    incoming: &mut Option<IncomingTransfer>,
    incoming_files: &mut Option<IncomingFileTransfer>,
    provider: &mut Option<std::process::Child>,
) -> Result<Option<ReceivedClipboard>, ClipboardError> {
    if matches!(
        record_kind(record),
        Some(FILE_START_KIND | FILE_CHUNK_KIND | FILE_FINISH_KIND)
    ) {
        if let Some(selection) = receive_file_record(connection, record, incoming_files)? {
            stop_provider(provider);
            write_uri_list(&selection, provider)?;
            eprintln!(
                "clipboard received {} file(s) ({} bytes) into Downloads/CachyBridge",
                selection.files.len(),
                selection.total_bytes
            );
            return Ok(Some(ReceivedClipboard::Files(selection)));
        }
    } else if matches!(
        record_kind(record),
        Some(FILE_ACCEPT_KIND | FILE_REJECT_KIND)
    ) {
        // Approval records are consumed by the sender while it waits for the
        // receiving iMac's explicit choice. A late duplicate is harmless.
    } else if let Some(content) = receive_record(record, incoming)? {
        write_content(&content, provider)?;
        eprintln!(
            "clipboard received {} ({} bytes)",
            content.mime_type,
            content.bytes.len()
        );
        return Ok(Some(ReceivedClipboard::Content(content)));
    }
    Ok(None)
}

fn update_received_baseline(
    received: ReceivedClipboard,
    last_value: &mut Option<ClipboardContent>,
    last_file_selection: &mut Option<FileSelection>,
) {
    match received {
        ReceivedClipboard::Content(content) => {
            *last_value = Some(content);
            *last_file_selection = None;
        }
        ReceivedClipboard::Files(selection) => {
            *last_file_selection = Some(selection);
            *last_value = None;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn send_file_transfer(
    connection: &mut SecureConnection,
    selection: &FileSelection,
    incoming: &mut Option<IncomingTransfer>,
    incoming_files: &mut Option<IncomingFileTransfer>,
    provider: &mut Option<std::process::Child>,
    last_value: &mut Option<ClipboardContent>,
    last_file_selection: &mut Option<FileSelection>,
    start_kind: u8,
) -> Result<FileTransferOutcome, ClipboardError> {
    if selection.files.is_empty()
        || selection.files.len() > MAX_FILE_COUNT
        || selection.total_bytes > MAX_FILE_TRANSFER_BYTES
    {
        return Err(ClipboardError::TooLarge);
    }
    let id = random_transfer_id();
    let started = Instant::now();
    update_transfer_status(
        "sending",
        "awaiting approval",
        selection
            .files
            .first()
            .map(|file| file.name.as_str())
            .unwrap_or("files"),
        0,
        selection.total_bytes,
        started,
        None,
    )?;
    connection.send_payload(&encode_file_start_with_kind(id, selection, start_kind)?)?;
    if !wait_for_file_approval(
        connection,
        id,
        incoming,
        incoming_files,
        provider,
        last_value,
        last_file_selection,
        selection,
        started,
    )? {
        return Ok(FileTransferOutcome::Declined);
    }
    let mut last_status = started;
    let mut transferred = 0_u64;
    let mut buffer = [0_u8; MAX_CHUNK_BYTES];
    for (index, entry) in selection.files.iter().enumerate() {
        let mut file = fs::File::open(&entry.path)?;
        let mut offset = 0_u64;
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            connection.send_payload(&encode_file_chunk(id, index, offset, &buffer[..count])?)?;
            // A copy in the opposite direction may start at the same time.
            // Reading a bounded batch here prevents both peers from filling
            // their TCP send buffers and waiting forever.
            drain_records_while_sending(
                connection,
                incoming,
                incoming_files,
                provider,
                last_value,
                last_file_selection,
            )?;
            let count = count as u64;
            offset += count;
            transferred += count;
            if last_status.elapsed() >= POLL_INTERVAL {
                update_transfer_status(
                    "sending",
                    "transferring",
                    &entry.name,
                    transferred,
                    selection.total_bytes,
                    started,
                    None,
                )?;
                last_status = Instant::now();
            }
        }
        if offset != entry.size {
            return Err(ClipboardError::Command(format!(
                "{} changed while it was being transferred",
                entry.name
            )));
        }
    }
    connection.send_payload(&encode_file_finish(id))?;
    drain_records_while_sending(
        connection,
        incoming,
        incoming_files,
        provider,
        last_value,
        last_file_selection,
    )?;
    update_transfer_status(
        "sending",
        "completed",
        selection
            .files
            .last()
            .map(|file| file.name.as_str())
            .unwrap_or("files"),
        transferred,
        selection.total_bytes,
        started,
        None,
    )?;
    Ok(FileTransferOutcome::Completed)
}

fn drain_records_while_sending(
    connection: &mut SecureConnection,
    incoming: &mut Option<IncomingTransfer>,
    incoming_files: &mut Option<IncomingFileTransfer>,
    provider: &mut Option<std::process::Child>,
    last_value: &mut Option<ClipboardContent>,
    last_file_selection: &mut Option<FileSelection>,
) -> Result<(), ClipboardError> {
    for _ in 0..8 {
        let Some(record) = connection.poll_receive_payload()? else {
            break;
        };
        if let Some(received) =
            process_received_record(connection, &record, incoming, incoming_files, provider)?
        {
            update_received_baseline(received, last_value, last_file_selection);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn wait_for_file_approval(
    connection: &mut SecureConnection,
    id: u64,
    incoming: &mut Option<IncomingTransfer>,
    incoming_files: &mut Option<IncomingFileTransfer>,
    provider: &mut Option<std::process::Child>,
    last_value: &mut Option<ClipboardContent>,
    last_file_selection: &mut Option<FileSelection>,
    selection: &FileSelection,
    started: Instant,
) -> Result<bool, ClipboardError> {
    let name = selection
        .files
        .first()
        .map(|file| file.name.as_str())
        .unwrap_or("files");
    loop {
        if let Some(record) = connection.poll_receive_payload()? {
            if let Some(approved) = decode_file_decision(&record, id)? {
                update_transfer_status(
                    "sending",
                    if approved { "transferring" } else { "declined" },
                    name,
                    0,
                    selection.total_bytes,
                    started,
                    None,
                )?;
                return Ok(approved);
            }
            if let Some(received) =
                process_received_record(connection, &record, incoming, incoming_files, provider)?
            {
                update_received_baseline(received, last_value, last_file_selection);
            }
        } else if started.elapsed() >= FILE_APPROVAL_TIMEOUT {
            update_transfer_status(
                "sending",
                "timed out",
                name,
                0,
                selection.total_bytes,
                started,
                None,
            )?;
            return Err(ClipboardError::Command(
                "the receiving iMac did not respond to the file-transfer offer".to_owned(),
            ));
        } else {
            thread::sleep(IDLE_INTERVAL);
        }
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

fn random_transfer_id() -> u64 {
    let mut id_bytes = [0_u8; 8];
    rand::thread_rng().fill_bytes(&mut id_bytes);
    u64::from_be_bytes(id_bytes)
}

#[cfg(test)]
fn encode_file_start(id: u64, selection: &FileSelection) -> Result<Vec<u8>, ClipboardError> {
    encode_file_start_with_kind(id, selection, FILE_START_KIND)
}

fn encode_file_start_with_kind(
    id: u64,
    selection: &FileSelection,
    kind: u8,
) -> Result<Vec<u8>, ClipboardError> {
    if !matches!(kind, FILE_START_KIND | DIRECT_FILE_START_KIND) {
        return Err(ClipboardError::InvalidRecord);
    }
    if selection.files.is_empty() || selection.files.len() > MAX_FILE_COUNT {
        return Err(ClipboardError::InvalidFileBundle);
    }
    let mut total = 0_u64;
    let mut record = Vec::with_capacity(32 + selection.files.len() * 32);
    record.extend_from_slice(RECORD_PREFIX);
    record.push(kind);
    record.extend_from_slice(&id.to_be_bytes());
    record.extend_from_slice(&(selection.files.len() as u16).to_be_bytes());
    record.extend_from_slice(&selection.total_bytes.to_be_bytes());
    for file in &selection.files {
        validate_file_name(&file.name)?;
        total = total
            .checked_add(file.size)
            .ok_or(ClipboardError::TooLarge)?;
        let name = file.name.as_bytes();
        if name.len() > u16::MAX as usize {
            return Err(ClipboardError::InvalidFileBundle);
        }
        record.extend_from_slice(&(name.len() as u16).to_be_bytes());
        record.extend_from_slice(&file.size.to_be_bytes());
        record.extend_from_slice(name);
    }
    if total != selection.total_bytes || total > MAX_FILE_TRANSFER_BYTES {
        return Err(ClipboardError::TooLarge);
    }
    Ok(record)
}

fn decode_file_start(record: &[u8]) -> Result<(u64, FileManifest, u64), ClipboardError> {
    if record.len() < 18 {
        return Err(ClipboardError::InvalidRecord);
    }
    let id = u64::from_be_bytes(record[..8].try_into().expect("fixed width"));
    let count = u16::from_be_bytes(record[8..10].try_into().expect("fixed width")) as usize;
    let total_bytes = u64::from_be_bytes(record[10..18].try_into().expect("fixed width"));
    if count == 0 || count > MAX_FILE_COUNT || total_bytes > MAX_FILE_TRANSFER_BYTES {
        return Err(ClipboardError::TooLarge);
    }
    let mut remaining = &record[18..];
    let mut files = Vec::with_capacity(count);
    let mut names = HashSet::new();
    let mut computed_total = 0_u64;
    for _ in 0..count {
        if remaining.len() < 10 {
            return Err(ClipboardError::InvalidRecord);
        }
        let name_length =
            u16::from_be_bytes(remaining[..2].try_into().expect("fixed width")) as usize;
        let size = u64::from_be_bytes(remaining[2..10].try_into().expect("fixed width"));
        remaining = &remaining[10..];
        if name_length == 0 || remaining.len() < name_length {
            return Err(ClipboardError::InvalidRecord);
        }
        let name = std::str::from_utf8(&remaining[..name_length])
            .map_err(|_| ClipboardError::InvalidFileBundle)?
            .to_owned();
        validate_file_name(&name)?;
        if !names.insert(name.clone()) {
            return Err(ClipboardError::InvalidFileBundle);
        }
        computed_total = computed_total
            .checked_add(size)
            .ok_or(ClipboardError::TooLarge)?;
        remaining = &remaining[name_length..];
        files.push((name, size));
    }
    if !remaining.is_empty() || computed_total != total_bytes {
        return Err(ClipboardError::InvalidRecord);
    }
    Ok((id, files, total_bytes))
}

fn encode_file_chunk(
    id: u64,
    index: usize,
    offset: u64,
    bytes: &[u8],
) -> Result<Vec<u8>, ClipboardError> {
    if bytes.is_empty() || bytes.len() > MAX_CHUNK_BYTES || index > u16::MAX as usize {
        return Err(ClipboardError::InvalidRecord);
    }
    let mut record = Vec::with_capacity(RECORD_PREFIX.len() + 1 + 18 + bytes.len());
    record.extend_from_slice(RECORD_PREFIX);
    record.push(FILE_CHUNK_KIND);
    record.extend_from_slice(&id.to_be_bytes());
    record.extend_from_slice(&(index as u16).to_be_bytes());
    record.extend_from_slice(&offset.to_be_bytes());
    record.extend_from_slice(bytes);
    Ok(record)
}

fn decode_file_chunk(record: &[u8]) -> Result<(u64, usize, u64, &[u8]), ClipboardError> {
    if record.len() <= 18 {
        return Err(ClipboardError::InvalidRecord);
    }
    let id = u64::from_be_bytes(record[..8].try_into().expect("fixed width"));
    let index = u16::from_be_bytes(record[8..10].try_into().expect("fixed width")) as usize;
    let offset = u64::from_be_bytes(record[10..18].try_into().expect("fixed width"));
    let bytes = &record[18..];
    if bytes.len() > MAX_CHUNK_BYTES {
        return Err(ClipboardError::InvalidRecord);
    }
    Ok((id, index, offset, bytes))
}

fn encode_file_finish(id: u64) -> Vec<u8> {
    let mut record = Vec::with_capacity(RECORD_PREFIX.len() + 1 + 8);
    record.extend_from_slice(RECORD_PREFIX);
    record.push(FILE_FINISH_KIND);
    record.extend_from_slice(&id.to_be_bytes());
    record
}

fn encode_file_decision(id: u64, approved: bool) -> Vec<u8> {
    let mut record = Vec::with_capacity(RECORD_PREFIX.len() + 1 + 8);
    record.extend_from_slice(RECORD_PREFIX);
    record.push(if approved {
        FILE_ACCEPT_KIND
    } else {
        FILE_REJECT_KIND
    });
    record.extend_from_slice(&id.to_be_bytes());
    record
}

fn decode_file_decision(record: &[u8], expected_id: u64) -> Result<Option<bool>, ClipboardError> {
    let Some(body) = record.strip_prefix(RECORD_PREFIX) else {
        return Ok(None);
    };
    let Some((&kind, rest)) = body.split_first() else {
        return Err(ClipboardError::InvalidRecord);
    };
    if !matches!(kind, FILE_ACCEPT_KIND | FILE_REJECT_KIND) {
        return Ok(None);
    }
    if rest.len() != 8 {
        return Err(ClipboardError::InvalidRecord);
    }
    let id = u64::from_be_bytes(rest.try_into().expect("fixed width"));
    if id != expected_id {
        return Err(ClipboardError::InvalidRecord);
    }
    Ok(Some(kind == FILE_ACCEPT_KIND))
}

fn request_file_transfer_approval(manifest: &FileManifest, total_bytes: u64) -> bool {
    let file_summary = if manifest.len() == 1 {
        manifest[0].0.clone()
    } else {
        format!("{} files (starting with {})", manifest.len(), manifest[0].0)
    };
    let message = format!(
        "A paired CachyBridge iMac wants to send:\n\n{file_summary}\n{}\n\nAccept and save it in Downloads/CachyBridge?",
        human_size(total_bytes)
    );
    match Command::new("kdialog")
        .args([
            "--title",
            "CachyBridge file transfer",
            "--yes-label",
            "Accept",
            "--no-label",
            "Decline",
            "--yesno",
            &message,
        ])
        .status()
    {
        Ok(status) => status.success(),
        Err(error) => {
            eprintln!("could not show file-transfer approval dialog: {error}");
            false
        }
    }
}

fn human_size(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else {
        format!("{bytes} bytes")
    }
}

fn receive_file_record(
    connection: &mut SecureConnection,
    record: &[u8],
    incoming: &mut Option<IncomingFileTransfer>,
) -> Result<Option<FileSelection>, ClipboardError> {
    let body = record
        .strip_prefix(RECORD_PREFIX)
        .ok_or(ClipboardError::InvalidRecord)?;
    let Some((&kind, rest)) = body.split_first() else {
        return Err(ClipboardError::InvalidRecord);
    };
    match kind {
        FILE_START_KIND | DIRECT_FILE_START_KIND => {
            if incoming.is_some() {
                return Err(ClipboardError::InvalidRecord);
            }
            let (id, manifest, total_bytes) = decode_file_start(rest)?;
            let offer_started = Instant::now();
            let name = manifest
                .first()
                .map(|(name, _)| name.as_str())
                .unwrap_or("files");
            update_transfer_status(
                "receiving",
                "awaiting approval",
                name,
                0,
                total_bytes,
                offer_started,
                Some(&received_airdrop_root()?),
            )?;
            let approved = request_file_transfer_approval(&manifest, total_bytes);
            if !approved {
                connection.send_payload(&encode_file_decision(id, false))?;
                update_transfer_status(
                    "receiving",
                    "declined",
                    name,
                    0,
                    total_bytes,
                    offer_started,
                    Some(&received_airdrop_root()?),
                )?;
                return Ok(None);
            }
            let root = received_airdrop_root()?;
            let staging_directory = create_staging_directory(&root)?;
            let mut files = Vec::with_capacity(manifest.len());
            for (index, (name, size)) in manifest.into_iter().enumerate() {
                let staging_path = staging_directory.join(format!("{index:04}"));
                files.push(IncomingFile {
                    name,
                    size,
                    received: 0,
                    file: create_private_file(&staging_path)?,
                    staging_path,
                });
            }
            let started = Instant::now();
            connection.send_payload(&encode_file_decision(id, true))?;
            update_transfer_status(
                "receiving",
                "transferring",
                &files[0].name,
                0,
                total_bytes,
                started,
                Some(&root),
            )?;
            *incoming = Some(IncomingFileTransfer {
                id,
                files,
                file_index: 0,
                total_bytes,
                received_bytes: 0,
                staging_directory,
                started,
                last_status: started,
            });
            Ok(None)
        }
        FILE_CHUNK_KIND => {
            let (id, index, offset, bytes) = decode_file_chunk(rest)?;
            let transfer = incoming.as_mut().ok_or(ClipboardError::InvalidRecord)?;
            if id != transfer.id || index != transfer.file_index || bytes.is_empty() {
                return Err(ClipboardError::InvalidRecord);
            }
            let current = transfer
                .files
                .get_mut(index)
                .ok_or(ClipboardError::InvalidRecord)?;
            if offset != current.received || bytes.len() as u64 > current.size - current.received {
                return Err(ClipboardError::InvalidRecord);
            }
            current.file.write_all(bytes)?;
            current.received += bytes.len() as u64;
            transfer.received_bytes += bytes.len() as u64;
            if current.received == current.size {
                current.file.sync_data()?;
                transfer.file_index += 1;
            }
            if transfer.last_status.elapsed() >= POLL_INTERVAL {
                let name = transfer
                    .files
                    .get(transfer.file_index)
                    .or_else(|| transfer.files.last())
                    .map(|file| file.name.as_str())
                    .unwrap_or("files");
                update_transfer_status(
                    "receiving",
                    "transferring",
                    name,
                    transfer.received_bytes,
                    transfer.total_bytes,
                    transfer.started,
                    Some(&received_airdrop_root()?),
                )?;
                transfer.last_status = Instant::now();
            }
            Ok(None)
        }
        FILE_FINISH_KIND => {
            if rest.len() != 8 {
                return Err(ClipboardError::InvalidRecord);
            }
            let id = u64::from_be_bytes(rest.try_into().expect("fixed width"));
            let transfer = incoming.take().ok_or(ClipboardError::InvalidRecord)?;
            if id != transfer.id
                || transfer.file_index != transfer.files.len()
                || transfer.received_bytes != transfer.total_bytes
            {
                return Err(ClipboardError::InvalidRecord);
            }
            finish_received_files(transfer).map(Some)
        }
        _ => Err(ClipboardError::InvalidRecord),
    }
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
    // URI lists are handled by `read_file_selection` and use the streaming
    // path.  Never fall back to copying their textual representation.
    if type_list
        .lines()
        .any(|available| available == "text/uri-list")
    {
        return Ok(None);
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

fn read_file_selection() -> Result<Option<FileSelection>, ClipboardError> {
    let types = Command::new(clipboard_tool("wl-paste"))
        .arg("--list-types")
        .output()
        .map_err(map_command_start)?;
    if !types.status.success()
        || !String::from_utf8_lossy(&types.stdout)
            .lines()
            .any(|available| available == "text/uri-list")
    {
        return Ok(None);
    }
    let output = Command::new(clipboard_tool("wl-paste"))
        .args(["--no-newline", "--type", "text/uri-list"])
        .output()
        .map_err(map_command_start)?;
    if !output.status.success() {
        return Ok(None);
    }
    match file_selection_from_uri_list(&output.stdout) {
        Ok(selection) => Ok(Some(selection)),
        // A URI list can also be a browser URL drag or a directory. Leave it
        // local rather than treating it as an unsafe portable file copy.
        Err(ClipboardError::NoRegularFiles) => Ok(None),
        Err(error) => Err(error),
    }
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

fn file_selection_from_uri_list(uri_list: &[u8]) -> Result<FileSelection, ClipboardError> {
    let uri_list = std::str::from_utf8(uri_list).map_err(|_| ClipboardError::InvalidFileBundle)?;
    let mut paths = Vec::new();
    for line in uri_list
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        paths.push(file_uri_to_path(line)?);
    }
    file_selection_from_paths(&paths)
}

fn file_selection_from_paths(paths: &[PathBuf]) -> Result<FileSelection, ClipboardError> {
    let mut files = Vec::new();
    let mut names = HashSet::new();
    let mut total_bytes = 0_u64;
    for path in paths {
        let metadata = match fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => metadata,
            _ => continue,
        };
        let size = metadata.len();
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or(ClipboardError::TooLarge)?;
        if total_bytes > MAX_FILE_TRANSFER_BYTES || files.len() == MAX_FILE_COUNT {
            return Err(ClipboardError::TooLarge);
        }
        let name = safe_file_name(path)?;
        if !names.insert(name.clone()) {
            return Err(ClipboardError::InvalidFileBundle);
        }
        let modified_nanos = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        files.push(LocalFile {
            name,
            path: path.clone(),
            size,
            modified_nanos,
        });
    }
    if files.is_empty() {
        return Err(ClipboardError::NoRegularFiles);
    }
    Ok(FileSelection { files, total_bytes })
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
    let name = name.to_owned();
    validate_file_name(&name)?;
    Ok(name)
}

fn validate_file_name(name: &str) -> Result<(), ClipboardError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        Err(ClipboardError::InvalidFileBundle)
    } else {
        Ok(())
    }
}

#[cfg(test)]
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
        if total_bytes > MAX_FILE_TRANSFER_BYTES as usize {
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
        if total_bytes > MAX_FILE_TRANSFER_BYTES as usize {
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

fn write_uri_list(
    selection: &FileSelection,
    provider: &mut Option<std::process::Child>,
) -> Result<(), ClipboardError> {
    let mut uris = String::new();
    for file in &selection.files {
        uris.push_str("file://");
        uris.push_str(&percent_encode_path(&file.path)?);
        uris.push('\n');
    }
    let content = ClipboardContent {
        mime_type: "text/plain".to_owned(),
        bytes: uris.into_bytes(),
    };
    // `wl-copy` needs the actual URI-list target; keep the process lifecycle
    // identical to ordinary clipboard writes while avoiding the legacy bundle.
    stop_provider(provider);
    let mut child = Command::new(clipboard_tool("wl-copy"))
        .args(["--foreground", "--type", "text/uri-list"])
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
    drop(stdin);
    *provider = Some(child);
    Ok(())
}

fn received_airdrop_root() -> Result<PathBuf, ClipboardError> {
    let download = Command::new("xdg-user-dir")
        .arg("DOWNLOAD")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| value.starts_with('/'))
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join("Downloads")))
        .ok_or_else(|| {
            ClipboardError::Command("could not determine a downloads directory".to_owned())
        })?;
    let directory = download.join("CachyBridge");
    fs::create_dir_all(&directory)?;
    set_private_directory(&directory)?;
    Ok(directory)
}

fn create_staging_directory(root: &Path) -> Result<PathBuf, ClipboardError> {
    for _ in 0..16 {
        let mut random = [0_u8; 12];
        rand::thread_rng().fill_bytes(&mut random);
        let directory = root.join(format!(".cachybridge-{}.part", hex::encode(random)));
        match fs::create_dir(&directory) {
            Ok(()) => {
                set_private_directory(&directory)?;
                return Ok(directory);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(ClipboardError::Io(error)),
        }
    }
    Err(ClipboardError::Command(
        "could not create a transfer staging directory".to_owned(),
    ))
}

fn create_private_file(path: &Path) -> Result<fs::File, ClipboardError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(ClipboardError::Io)
    }
    #[cfg(not(unix))]
    {
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(ClipboardError::Io)
    }
}

fn finish_received_files(transfer: IncomingFileTransfer) -> Result<FileSelection, ClipboardError> {
    let root = received_airdrop_root()?;
    let mut files = Vec::with_capacity(transfer.files.len());
    for incoming in transfer.files {
        incoming.file.sync_all()?;
        drop(incoming.file);
        let path = unique_destination_path(&root, &incoming.name)?;
        fs::rename(&incoming.staging_path, &path)?;
        let metadata = fs::metadata(&path)?;
        files.push(LocalFile {
            name: incoming.name,
            path,
            size: metadata.len(),
            modified_nanos: metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_nanos())
                .unwrap_or(0),
        });
    }
    let _ = fs::remove_dir(&transfer.staging_directory);
    update_transfer_status(
        "receiving",
        "completed",
        files
            .last()
            .map(|file| file.name.as_str())
            .unwrap_or("files"),
        transfer.received_bytes,
        transfer.total_bytes,
        transfer.started,
        Some(&root),
    )?;
    Ok(FileSelection {
        files,
        total_bytes: transfer.total_bytes,
    })
}

fn unique_destination_path(root: &Path, name: &str) -> Result<PathBuf, ClipboardError> {
    validate_file_name(name)?;
    let original = root.join(name);
    if !original.exists() {
        return Ok(original);
    }
    let source = Path::new(name);
    let stem = source
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(name);
    let extension = source
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!(".{value}"))
        .unwrap_or_default();
    for index in 2..10_000 {
        let candidate = root.join(format!("{stem} ({index}){extension}"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(ClipboardError::Command(
        "could not choose a non-conflicting file name".to_owned(),
    ))
}

fn update_transfer_status(
    direction: &str,
    state: &str,
    name: &str,
    completed: u64,
    total: u64,
    started: Instant,
    destination: Option<&Path>,
) -> Result<(), ClipboardError> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| {
            ClipboardError::Command("could not determine the runtime directory".to_owned())
        })?;
    let directory = runtime.join("cachybridge");
    fs::create_dir_all(&directory)?;
    let elapsed = started.elapsed().as_secs_f64().max(0.001);
    let status = format!(
        "direction={direction}\nstate={state}\nname={}\ncompleted={completed}\ntotal={total}\nspeed_bps={}\ndestination={}\n",
        name.replace(['\n', '\r', '='], " "),
        (completed as f64 / elapsed) as u64,
        destination.and_then(Path::to_str).unwrap_or("").replace(['\n', '\r', '='], " "),
    );
    let temporary = directory.join("file-transfer-status.tmp");
    fs::write(&temporary, status)?;
    fs::rename(temporary, directory.join("file-transfer-status"))?;
    Ok(())
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
        MAX_FILE_TRANSFER_BYTES as usize
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
    fn streaming_file_manifest_and_chunks_round_trip() {
        let selection = FileSelection {
            files: vec![LocalFile {
                name: "movie.mkv".to_owned(),
                path: PathBuf::from("/tmp/movie.mkv"),
                size: 32_768,
                modified_nanos: 1,
            }],
            total_bytes: 32_768,
        };
        let start = encode_file_start(42, &selection).unwrap();
        assert_eq!(
            decode_file_start(&start[RECORD_PREFIX.len() + 1..]).unwrap(),
            (42, vec![("movie.mkv".to_owned(), 32_768)], 32_768)
        );
        let chunk = encode_file_chunk(42, 0, 16_384, &[7; 64]).unwrap();
        assert_eq!(
            decode_file_chunk(&chunk[RECORD_PREFIX.len() + 1..]).unwrap(),
            (42, 0, 16_384, &[7; 64][..])
        );
    }

    #[test]
    fn file_transfer_approval_is_bound_to_its_offer() {
        let accepted = encode_file_decision(42, true);
        let rejected = encode_file_decision(42, false);
        assert_eq!(decode_file_decision(&accepted, 42).unwrap(), Some(true));
        assert_eq!(decode_file_decision(&rejected, 42).unwrap(), Some(false));
        assert!(matches!(
            decode_file_decision(&accepted, 7),
            Err(ClipboardError::InvalidRecord)
        ));
    }

    #[test]
    fn direct_file_offer_is_distinct_from_clipboard_sync() {
        let selection = FileSelection {
            files: vec![LocalFile {
                name: "report.pdf".to_owned(),
                path: PathBuf::from("/tmp/report.pdf"),
                size: 1,
                modified_nanos: 0,
            }],
            total_bytes: 1,
        };
        let direct = encode_file_start_with_kind(9, &selection, DIRECT_FILE_START_KIND).unwrap();
        let regular = encode_file_start(9, &selection).unwrap();
        assert!(is_direct_file_offer(&direct));
        assert!(!is_direct_file_offer(&regular));
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
