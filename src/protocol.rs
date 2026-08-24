//! Small, strict, versioned messages carried inside Noise packets.

use thiserror::Error;

/// Version 5 adds normalized multi-touch contacts. Normalization lets a
/// physical touch surface such as Magic Trackpad map safely to the remote
/// compositor's touch region without assuming matching dimensions.
/// Older handoff implementations fail closed during decoding.
pub const PROTOCOL_VERSION: u8 = 5;
pub const MAX_FRAME_PAYLOAD: usize = 64;
pub const HEARTBEAT_INTERVAL_MS: u64 = 1_000;
pub const PEER_TIMEOUT_MS: u64 = 5_000;

const KIND_INPUT: u8 = 1;
const KIND_HEARTBEAT: u8 = 2;
const KIND_RELEASE_ALL: u8 = 3;
const KIND_GOODBYE: u8 = 4;
const KIND_ENTER: u8 = 5;
const KIND_ENTER_ACK: u8 = 6;
const KIND_ENTER_REJECTED: u8 = 7;
const KIND_HANDOFF_RELEASE: u8 = 8;
const KIND_EXIT_REQUEST: u8 = 9;
const KIND_POINTER_MOTION: u8 = 10;
const KIND_TOUCH: u8 = 11;
const INPUT_PAYLOAD_LEN: usize = 8;
const ENTER_PAYLOAD_LEN: usize = 8;
const EXIT_REQUEST_PAYLOAD_LEN: usize = 9;
const TOUCH_PAYLOAD_LEN: usize = 9;

/// An evdev-style event using Linux kernel type/code/value values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireInputEvent {
    pub event_type: u16,
    pub code: u16,
    pub value: i32,
}

/// A phase in one independently tracked touch contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchPhase {
    Down,
    Motion,
    Up,
    Cancel,
}

/// Coordinates are normalized to the inclusive u16 range. This retains fine
/// trackpad precision while allowing the client to map contacts to its own
/// advertised touch region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireTouchEvent {
    pub phase: TouchPhase,
    pub id: u32,
    pub x: u16,
    pub y: u16,
}

/// A horizontal logical display edge represented independently of compositor
/// types so malformed control frames can be rejected at the wire boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireEdge {
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message {
    Input(WireInputEvent),
    Heartbeat,
    /// Receiver must release all controls previously injected by this session.
    ReleaseAll,
    /// Cleanly finishes a demo session after all controls have been released.
    Goodbye,
    /// An authenticated peer requests an edge handoff at a logical pointer
    /// coordinate. It must not forward input until it receives `EnterAck`.
    Enter {
        x: i32,
        y: i32,
    },
    /// Accepts the immediately preceding `Enter` request.
    EnterAck,
    /// Rejects the immediately preceding `Enter` request.
    EnterRejected,
    /// End the edge-handoff session and release all remotely injected state.
    /// `ReleaseAll` remains available for the original manual host/client
    /// session, while this marker identifies the handoff control path.
    HandoffRelease,
    /// The active client crossed `edge` at logical `x, y` and requests return
    /// to the host. Only an active entry may issue this control frame.
    ExitRequest {
        edge: WireEdge,
        x: i32,
        y: i32,
    },
    /// A coalesced relative pointer sample. Unlike evdev REL_X/REL_Y records,
    /// the two axes are injected in one EIS frame on the controlled desktop.
    PointerMotion {
        dx: i32,
        dy: i32,
    },
    Touch(WireTouchEvent),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("frame is too short")]
    TooShort,
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown message kind {0}")]
    UnknownKind(u8),
    #[error("declared payload length {declared} does not match actual length {actual}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("payload is larger than {MAX_FRAME_PAYLOAD} bytes")]
    PayloadTooLarge,
    #[error("message kind {kind} has invalid payload length {actual}")]
    InvalidPayloadLength { kind: u8, actual: usize },
    #[error("invalid horizontal edge value {0}")]
    InvalidEdge(u8),
    #[error("invalid touch phase value {0}")]
    InvalidTouchPhase(u8),
}

pub fn encode_frame(message: Message) -> Vec<u8> {
    let (kind, payload) = match message {
        Message::Input(event) => {
            let mut payload = [0_u8; INPUT_PAYLOAD_LEN];
            payload[..2].copy_from_slice(&event.event_type.to_be_bytes());
            payload[2..4].copy_from_slice(&event.code.to_be_bytes());
            payload[4..8].copy_from_slice(&event.value.to_be_bytes());
            (KIND_INPUT, payload.to_vec())
        }
        Message::Heartbeat => (KIND_HEARTBEAT, Vec::new()),
        Message::ReleaseAll => (KIND_RELEASE_ALL, Vec::new()),
        Message::Goodbye => (KIND_GOODBYE, Vec::new()),
        Message::Enter { x, y } => {
            let mut payload = [0_u8; ENTER_PAYLOAD_LEN];
            payload[..4].copy_from_slice(&x.to_be_bytes());
            payload[4..].copy_from_slice(&y.to_be_bytes());
            (KIND_ENTER, payload.to_vec())
        }
        Message::EnterAck => (KIND_ENTER_ACK, Vec::new()),
        Message::EnterRejected => (KIND_ENTER_REJECTED, Vec::new()),
        Message::HandoffRelease => (KIND_HANDOFF_RELEASE, Vec::new()),
        Message::ExitRequest { edge, x, y } => {
            let mut payload = [0_u8; EXIT_REQUEST_PAYLOAD_LEN];
            payload[0] = match edge {
                WireEdge::Left => 0,
                WireEdge::Right => 1,
            };
            payload[1..5].copy_from_slice(&x.to_be_bytes());
            payload[5..].copy_from_slice(&y.to_be_bytes());
            (KIND_EXIT_REQUEST, payload.to_vec())
        }
        Message::PointerMotion { dx, dy } => {
            let mut payload = [0_u8; 8];
            payload[..4].copy_from_slice(&dx.to_be_bytes());
            payload[4..].copy_from_slice(&dy.to_be_bytes());
            (KIND_POINTER_MOTION, payload.to_vec())
        }
        Message::Touch(event) => {
            let mut payload = [0_u8; TOUCH_PAYLOAD_LEN];
            payload[0] = match event.phase {
                TouchPhase::Down => 0,
                TouchPhase::Motion => 1,
                TouchPhase::Up => 2,
                TouchPhase::Cancel => 3,
            };
            payload[1..5].copy_from_slice(&event.id.to_be_bytes());
            payload[5..7].copy_from_slice(&event.x.to_be_bytes());
            payload[7..9].copy_from_slice(&event.y.to_be_bytes());
            (KIND_TOUCH, payload.to_vec())
        }
    };
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&[PROTOCOL_VERSION, kind]);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

pub fn decode_frame(frame: &[u8]) -> Result<Message, ProtocolError> {
    if frame.len() < 4 {
        return Err(ProtocolError::TooShort);
    }
    if frame[0] != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(frame[0]));
    }
    let kind = frame[1];
    let declared = u16::from_be_bytes([frame[2], frame[3]]) as usize;
    let actual = frame.len() - 4;
    if declared > MAX_FRAME_PAYLOAD {
        return Err(ProtocolError::PayloadTooLarge);
    }
    if declared != actual {
        return Err(ProtocolError::LengthMismatch { declared, actual });
    }
    let payload = &frame[4..];
    match kind {
        KIND_INPUT if payload.len() == INPUT_PAYLOAD_LEN => Ok(Message::Input(WireInputEvent {
            event_type: u16::from_be_bytes([payload[0], payload[1]]),
            code: u16::from_be_bytes([payload[2], payload[3]]),
            value: i32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
        })),
        KIND_HEARTBEAT | KIND_RELEASE_ALL | KIND_GOODBYE if payload.is_empty() => Ok(match kind {
            KIND_HEARTBEAT => Message::Heartbeat,
            KIND_RELEASE_ALL => Message::ReleaseAll,
            _ => Message::Goodbye,
        }),
        KIND_ENTER if payload.len() == ENTER_PAYLOAD_LEN => Ok(Message::Enter {
            x: i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]),
            y: i32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
        }),
        KIND_ENTER_ACK | KIND_ENTER_REJECTED | KIND_HANDOFF_RELEASE if payload.is_empty() => {
            Ok(match kind {
                KIND_ENTER_ACK => Message::EnterAck,
                KIND_ENTER_REJECTED => Message::EnterRejected,
                _ => Message::HandoffRelease,
            })
        }
        KIND_EXIT_REQUEST if payload.len() == EXIT_REQUEST_PAYLOAD_LEN => {
            let edge = match payload[0] {
                0 => WireEdge::Left,
                1 => WireEdge::Right,
                value => return Err(ProtocolError::InvalidEdge(value)),
            };
            Ok(Message::ExitRequest {
                edge,
                x: i32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]),
                y: i32::from_be_bytes([payload[5], payload[6], payload[7], payload[8]]),
            })
        }
        KIND_POINTER_MOTION if payload.len() == 8 => Ok(Message::PointerMotion {
            dx: i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]),
            dy: i32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
        }),
        KIND_TOUCH if payload.len() == TOUCH_PAYLOAD_LEN => {
            let phase = match payload[0] {
                0 => TouchPhase::Down,
                1 => TouchPhase::Motion,
                2 => TouchPhase::Up,
                3 => TouchPhase::Cancel,
                value => return Err(ProtocolError::InvalidTouchPhase(value)),
            };
            Ok(Message::Touch(WireTouchEvent {
                phase,
                id: u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]),
                x: u16::from_be_bytes([payload[5], payload[6]]),
                y: u16::from_be_bytes([payload[7], payload[8]]),
            }))
        }
        KIND_INPUT | KIND_HEARTBEAT | KIND_RELEASE_ALL | KIND_GOODBYE | KIND_ENTER
        | KIND_ENTER_ACK | KIND_ENTER_REJECTED | KIND_HANDOFF_RELEASE | KIND_EXIT_REQUEST
        | KIND_POINTER_MOTION | KIND_TOUCH => Err(ProtocolError::InvalidPayloadLength {
            kind,
            actual: payload.len(),
        }),
        _ => Err(ProtocolError::UnknownKind(kind)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_round_trip() {
        let message = Message::Input(WireInputEvent {
            event_type: 1,
            code: 272,
            value: -1,
        });
        assert_eq!(decode_frame(&encode_frame(message)), Ok(message));
    }

    #[test]
    fn rejects_future_version() {
        assert_eq!(
            decode_frame(&[PROTOCOL_VERSION + 1, KIND_HEARTBEAT, 0, 0]),
            Err(ProtocolError::UnsupportedVersion(PROTOCOL_VERSION + 1))
        );
    }

    #[test]
    fn goodbye_round_trip() {
        assert_eq!(
            decode_frame(&encode_frame(Message::Goodbye)),
            Ok(Message::Goodbye)
        );
    }

    #[test]
    fn edge_handoff_messages_round_trip() {
        for message in [
            Message::Enter { x: -1_440, y: 612 },
            Message::EnterAck,
            Message::EnterRejected,
            Message::HandoffRelease,
            Message::ExitRequest {
                edge: WireEdge::Right,
                x: -1,
                y: 612,
            },
            Message::PointerMotion { dx: 8, dy: -5 },
            Message::Touch(WireTouchEvent {
                phase: TouchPhase::Motion,
                id: 42,
                x: 32_000,
                y: 16_000,
            }),
        ] {
            assert_eq!(decode_frame(&encode_frame(message)), Ok(message));
        }
    }

    #[test]
    fn enter_requires_an_exact_coordinate_payload() {
        assert_eq!(
            decode_frame(&[PROTOCOL_VERSION, KIND_ENTER, 0, 0]),
            Err(ProtocolError::InvalidPayloadLength {
                kind: KIND_ENTER,
                actual: 0,
            })
        );
    }

    #[test]
    fn touch_rejects_unknown_phase_before_injection() {
        assert_eq!(
            decode_frame(&[
                PROTOCOL_VERSION,
                KIND_TOUCH,
                0,
                TOUCH_PAYLOAD_LEN as u8,
                9,
                0,
                0,
                0,
                1,
                0,
                0,
                0,
                0,
            ]),
            Err(ProtocolError::InvalidTouchPhase(9))
        );
    }

    #[test]
    fn exit_request_rejects_an_unknown_edge() {
        assert_eq!(
            decode_frame(&[
                PROTOCOL_VERSION,
                KIND_EXIT_REQUEST,
                0,
                9,
                7,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ]),
            Err(ProtocolError::InvalidEdge(7))
        );
    }
}
