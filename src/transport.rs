//! Bounded blocking TCP transport secured by Noise `NNpsk0`.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use snow::{params::NoiseParams, Builder, TransportState};
use thiserror::Error;

use crate::protocol::{decode_frame, encode_frame, Message, ProtocolError};

const NOISE_PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const MAX_HANDSHAKE_PACKET: usize = 1024;
const NOISE_TAG_BYTES: usize = 16;
/// The input protocol itself remains limited to its small fixed-size frames.
/// Pairing needs one bounded configuration exchange, so the secure transport
/// has a deliberately separate, modest application-record limit.
const MAX_APPLICATION_PAYLOAD: usize = 1024;
const MAX_CIPHERTEXT_FRAME: usize = MAX_APPLICATION_PAYLOAD + NOISE_TAG_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Host,
    Client,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Noise error: {0}")]
    Noise(#[from] snow::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("PSK must be exactly 64 hexadecimal characters")]
    InvalidPsk,
    #[error("network record size {0} exceeds its limit")]
    RecordTooLarge(usize),
    #[error("Noise packet has an invalid size")]
    InvalidNoisePacket,
}

pub fn parse_psk(text: &str) -> Result<[u8; 32], TransportError> {
    if text.len() != 64 {
        return Err(TransportError::InvalidPsk);
    }
    let bytes = hex::decode(text).map_err(|_| TransportError::InvalidPsk)?;
    bytes.try_into().map_err(|_| TransportError::InvalidPsk)
}

pub struct SecureConnection {
    stream: TcpStream,
    noise: TransportState,
}

impl SecureConnection {
    pub fn connect(stream: TcpStream, role: Role, psk: &[u8; 32]) -> Result<Self, TransportError> {
        // Input records are tiny and latency-sensitive. Nagle's algorithm can
        // hold a pointer update while it waits for an ACK from the preceding
        // update, adding an avoidable delayed-ACK-sized jitter burst on LANs.
        // Reliability still comes from TCP; this only disables aggregation.
        stream.set_nodelay(true)?;
        let params: NoiseParams = NOISE_PATTERN.parse().expect("valid static pattern");
        let builder = Builder::new(params).psk(0, psk);
        let mut handshake = match role {
            Role::Host => builder.build_initiator()?,
            Role::Client => builder.build_responder()?,
        };
        let mut stream = stream;
        let mut output = [0_u8; MAX_HANDSHAKE_PACKET];
        let mut input = [0_u8; MAX_HANDSHAKE_PACKET];
        match role {
            Role::Host => {
                let len = handshake.write_message(&[], &mut output)?;
                write_record(&mut stream, &output[..len], MAX_HANDSHAKE_PACKET)?;
                let len = read_record(&mut stream, &mut input, MAX_HANDSHAKE_PACKET)?;
                handshake.read_message(&input[..len], &mut output)?;
            }
            Role::Client => {
                let len = read_record(&mut stream, &mut input, MAX_HANDSHAKE_PACKET)?;
                handshake.read_message(&input[..len], &mut output)?;
                let len = handshake.write_message(&[], &mut output)?;
                write_record(&mut stream, &output[..len], MAX_HANDSHAKE_PACKET)?;
            }
        }
        Ok(Self {
            stream,
            noise: handshake.into_transport_mode()?,
        })
    }

    pub fn send(&mut self, message: Message) -> Result<(), TransportError> {
        let plaintext = encode_frame(message);
        self.send_payload(&plaintext)
    }

    pub fn receive(&mut self) -> Result<Message, TransportError> {
        let plaintext = self.receive_payload()?;
        decode_frame(&plaintext).map_err(Into::into)
    }

    /// Sends a bounded authenticated application record.  This is reserved for
    /// setup-time exchanges; the live input path uses [`Self::send`] so its
    /// stricter protocol limit stays intact.
    pub fn send_payload(&mut self, plaintext: &[u8]) -> Result<(), TransportError> {
        if plaintext.len() > MAX_APPLICATION_PAYLOAD {
            return Err(TransportError::RecordTooLarge(plaintext.len()));
        }
        let mut encrypted = [0_u8; MAX_CIPHERTEXT_FRAME];
        let len = self.noise.write_message(plaintext, &mut encrypted)?;
        write_record(&mut self.stream, &encrypted[..len], MAX_CIPHERTEXT_FRAME)
    }

    /// Receives one bounded authenticated application record.
    pub fn receive_payload(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut encrypted = [0_u8; MAX_CIPHERTEXT_FRAME];
        let len = read_record(&mut self.stream, &mut encrypted, MAX_CIPHERTEXT_FRAME)?;
        if len < NOISE_TAG_BYTES {
            return Err(TransportError::InvalidNoisePacket);
        }
        let mut plaintext = [0_u8; MAX_APPLICATION_PAYLOAD];
        let len = self.noise.read_message(&encrypted[..len], &mut plaintext)?;
        Ok(plaintext[..len].to_vec())
    }

    /// Returns one complete already-buffered encrypted record without blocking.
    ///
    /// The `peek` preflight is essential: changing a blocking stream to
    /// nonblocking and calling `read_exact` on a partial frame would lose the
    /// framing progress. We read only after the full length-prefixed record is
    /// present in the kernel socket buffer.
    pub fn poll_receive(&mut self) -> Result<Option<Message>, TransportError> {
        self.stream.set_nonblocking(true)?;
        let result = (|| {
            let mut header = [0_u8; 2];
            let received = match self.stream.peek(&mut header) {
                Ok(0) => return self.receive().map(Some),
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(TransportError::Io(error)),
            };
            if received < header.len() {
                return Ok(None);
            }
            let encrypted_len = u16::from_be_bytes(header) as usize;
            if encrypted_len > MAX_CIPHERTEXT_FRAME {
                return Err(TransportError::RecordTooLarge(encrypted_len));
            }
            let total_len = header.len() + encrypted_len;
            let mut record = [0_u8; MAX_CIPHERTEXT_FRAME + 2];
            let received = match self.stream.peek(&mut record[..total_len]) {
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(TransportError::Io(error)),
            };
            if received < total_len {
                return Ok(None);
            }
            self.receive().map(Some)
        })();
        let restore_result = self.stream.set_nonblocking(false);
        match (result, restore_result) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(TransportError::Io(error)),
            (Ok(message), Ok(())) => Ok(message),
        }
    }

    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }
}

fn write_record<W: Write>(
    writer: &mut W,
    packet: &[u8],
    limit: usize,
) -> Result<(), TransportError> {
    if packet.len() > limit || packet.len() > u16::MAX as usize {
        return Err(TransportError::RecordTooLarge(packet.len()));
    }
    writer.write_all(&(packet.len() as u16).to_be_bytes())?;
    writer.write_all(packet)?;
    writer.flush()?;
    Ok(())
}

fn read_record<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    limit: usize,
) -> Result<usize, TransportError> {
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header)?;
    let len = u16::from_be_bytes(header) as usize;
    if len > limit || len > buffer.len() {
        return Err(TransportError::RecordTooLarge(len));
    }
    reader.read_exact(&mut buffer[..len])?;
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn matching_psks_can_exchange_encrypted_frames() {
        // Some locked-down build sandboxes prohibit all socket binding. The
        // in-memory Noise test below still covers encryption there; this test
        // remains a real TCP integration test everywhere else.
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind loopback TCP listener: {error}"),
        };
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut conn = SecureConnection::connect(stream, Role::Client, &[7_u8; 32]).unwrap();
            assert_eq!(conn.receive().unwrap(), Message::Heartbeat);
            conn.send(Message::ReleaseAll).unwrap();
        });
        let mut conn =
            SecureConnection::connect(TcpStream::connect(addr).unwrap(), Role::Host, &[7_u8; 32])
                .unwrap();
        conn.send(Message::Heartbeat).unwrap();
        assert_eq!(conn.receive().unwrap(), Message::ReleaseAll);
        server.join().unwrap();
    }

    #[test]
    fn encrypted_connection_disables_nagle_for_small_input_records() {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind loopback TCP listener: {error}"),
        };
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let connection = SecureConnection::connect(stream, Role::Client, &[3_u8; 32]).unwrap();
            assert!(connection.stream.nodelay().unwrap());
        });
        let connection = SecureConnection::connect(
            TcpStream::connect(address).unwrap(),
            Role::Host,
            &[3_u8; 32],
        )
        .unwrap();
        assert!(connection.stream.nodelay().unwrap());
        server.join().unwrap();
    }

    #[test]
    fn psk_parser_rejects_invalid_text() {
        assert!(parse_psk("ff").is_err());
        assert!(parse_psk(&"z".repeat(64)).is_err());
        assert_eq!(parse_psk(&"ab".repeat(32)).unwrap(), [0xab; 32]);
    }

    #[test]
    fn noise_psk_authenticates_and_encrypts_a_frame() {
        let params: NoiseParams = NOISE_PATTERN.parse().unwrap();
        let psk = [9_u8; 32];
        let mut initiator = Builder::new(params.clone())
            .psk(0, &psk)
            .build_initiator()
            .unwrap();
        let mut responder = Builder::new(params).psk(0, &psk).build_responder().unwrap();
        let mut first = [0_u8; MAX_HANDSHAKE_PACKET];
        let first_len = initiator.write_message(&[], &mut first).unwrap();
        let mut ignored = [0_u8; MAX_HANDSHAKE_PACKET];
        responder
            .read_message(&first[..first_len], &mut ignored)
            .unwrap();
        let second_len = responder.write_message(&[], &mut first).unwrap();
        initiator
            .read_message(&first[..second_len], &mut ignored)
            .unwrap();

        let mut sender = initiator.into_transport_mode().unwrap();
        let mut receiver = responder.into_transport_mode().unwrap();
        let plaintext = encode_frame(Message::Heartbeat);
        let mut encrypted = [0_u8; MAX_CIPHERTEXT_FRAME];
        let encrypted_len = sender.write_message(&plaintext, &mut encrypted).unwrap();
        assert_ne!(&encrypted[..encrypted_len], plaintext.as_slice());
        let mut decoded = [0_u8; MAX_APPLICATION_PAYLOAD];
        let decoded_len = receiver
            .read_message(&encrypted[..encrypted_len], &mut decoded)
            .unwrap();
        assert_eq!(
            decode_frame(&decoded[..decoded_len]).unwrap(),
            Message::Heartbeat
        );
    }
}
