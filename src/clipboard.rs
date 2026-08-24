//! Small, text-only clipboard synchronization over an already authenticated
//! CachyBridge transport. Clipboard contents never touch discovery, logs, or
//! configuration files.

use std::{
    io::{self, Write},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use thiserror::Error;

use crate::transport::{SecureConnection, TransportError, MAX_APPLICATION_PAYLOAD};

const RECORD_PREFIX: &[u8] = b"CBCL1";
const MAX_TEXT_BYTES: usize = 64 * 1024 - RECORD_PREFIX.len();
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const IDLE_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Error)]
pub enum ClipboardError {
    #[error("clipboard synchronization requires wl-clipboard (install the wl-clipboard package)")]
    MissingTool,
    #[error("clipboard command failed: {0}")]
    Command(String),
    #[error("clipboard text exceeds {MAX_TEXT_BYTES} bytes")]
    TooLarge,
    #[error("clipboard data is not valid UTF-8 text")]
    NonText,
    #[error("invalid encrypted clipboard record")]
    InvalidRecord,
    #[error("clipboard transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("clipboard I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Continuously mirrors `text/plain;charset=utf-8` only. Each received value
/// becomes the local baseline before polling again, preventing the familiar
/// A→B→A clipboard echo loop.
pub fn run(mut connection: SecureConnection) -> Result<(), ClipboardError> {
    let mut last_value: Option<Vec<u8>> = None;
    let mut next_poll = Instant::now();
    loop {
        if let Some(record) = connection.poll_receive_payload()? {
            let text = decode_record(&record)?;
            write_text(&text)?;
            last_value = Some(text);
        }

        if Instant::now() >= next_poll {
            if let Some(text) = read_text()? {
                if last_value.as_ref() != Some(&text) {
                    connection.send_payload(&encode_record(&text)?)?;
                    last_value = Some(text);
                }
            }
            next_poll = Instant::now() + POLL_INTERVAL;
        }
        thread::sleep(IDLE_INTERVAL);
    }
}

fn encode_record(text: &[u8]) -> Result<Vec<u8>, ClipboardError> {
    validate_text(text)?;
    let mut record = Vec::with_capacity(RECORD_PREFIX.len() + text.len());
    record.extend_from_slice(RECORD_PREFIX);
    record.extend_from_slice(text);
    Ok(record)
}

fn decode_record(record: &[u8]) -> Result<Vec<u8>, ClipboardError> {
    let Some(text) = record.strip_prefix(RECORD_PREFIX) else {
        return Err(ClipboardError::InvalidRecord);
    };
    validate_text(text)?;
    Ok(text.to_vec())
}

fn validate_text(text: &[u8]) -> Result<(), ClipboardError> {
    if text.len() > MAX_TEXT_BYTES || text.len() + RECORD_PREFIX.len() > MAX_APPLICATION_PAYLOAD {
        return Err(ClipboardError::TooLarge);
    }
    std::str::from_utf8(text).map_err(|_| ClipboardError::NonText)?;
    Ok(())
}

fn read_text() -> Result<Option<Vec<u8>>, ClipboardError> {
    let output = Command::new("wl-paste")
        .args(["--no-newline", "--type", "text/plain;charset=utf-8"])
        .output()
        .map_err(map_command_start)?;
    // wl-paste returns non-zero when this selection does not contain plain
    // text. That is normal (e.g. an image copy), and we simply leave it alone.
    if !output.status.success() {
        return Ok(None);
    }
    validate_text(&output.stdout)?;
    Ok(Some(output.stdout))
}

fn write_text(text: &[u8]) -> Result<(), ClipboardError> {
    validate_text(text)?;
    let mut child = Command::new("wl-copy")
        .args(["--type", "text/plain;charset=utf-8"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(map_command_start)?;
    child
        .stdin
        .take()
        .ok_or_else(|| ClipboardError::Command("wl-copy did not accept stdin".to_owned()))?
        .write_all(text)?;
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(ClipboardError::Command(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ))
    }
}

fn map_command_start(error: io::Error) -> ClipboardError {
    if error.kind() == io::ErrorKind::NotFound {
        ClipboardError::MissingTool
    } else {
        ClipboardError::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_record_round_trips_without_exposing_a_second_format() {
        let record = encode_record("copy me".as_bytes()).unwrap();
        assert_eq!(decode_record(&record).unwrap(), b"copy me");
    }

    #[test]
    fn non_text_and_oversized_records_fail_closed() {
        assert!(matches!(
            encode_record(&[0xff]),
            Err(ClipboardError::NonText)
        ));
        assert!(matches!(
            encode_record(&vec![b'x'; MAX_TEXT_BYTES + 1]),
            Err(ClipboardError::TooLarge)
        ));
        assert!(matches!(
            decode_record(b"other"),
            Err(ClipboardError::InvalidRecord)
        ));
    }
}
