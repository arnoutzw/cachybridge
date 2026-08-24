//! Encrypted left-edge handoff demonstration glue.
//!
//! This is intentionally not a Wayland input backend. It accepts a simulated
//! pointer-barrier observation, performs the authenticated `Enter`/`EnterAck`
//! exchange, and translates it through the pure [`crate::handoff`] state
//! machine. A future portal/libei adapter can feed the same methods.

use thiserror::Error;

use crate::{
    handoff::{Edge, HandoffAction, HandoffController, HandoffState, LayoutError, Point, Rect},
    protocol::Message,
};

/// A testable adapter for an iMac with a peer positioned at its left edge.
#[derive(Debug, Clone)]
pub struct LeftEdgeDemo {
    controller: HandoffController,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DemoError {
    #[error("invalid logical display geometry: {0:?}")]
    Layout(LayoutError),
    #[error("left-edge event at y={0} is outside the local display")]
    InvalidEdgeCoordinate(i32),
    #[error("unexpected handoff control message while state is {state:?}: {message:?}")]
    UnexpectedMessage {
        state: HandoffState,
        message: Message,
    },
    #[error("unexpected controller action while state is {state:?}: {action:?}")]
    UnexpectedAction {
        state: HandoffState,
        action: HandoffAction,
    },
}

impl LeftEdgeDemo {
    pub fn new(local: Rect, peer: Rect) -> Self {
        Self {
            controller: HandoffController::new(local, peer, Edge::Left),
        }
    }

    /// Creates the common side-by-side layout. The local iMac starts at
    /// `(0, 0)`; the peer occupies the left side and may have a different size
    /// or vertical offset.
    pub fn side_by_side(
        local_width: u32,
        local_height: u32,
        peer_x: i32,
        peer_y: i32,
        peer_width: u32,
        peer_height: u32,
    ) -> Result<Self, DemoError> {
        let local = Rect::new(0, 0, local_width, local_height).map_err(DemoError::Layout)?;
        let peer = Rect::new(peer_x, peer_y, peer_width, peer_height).map_err(DemoError::Layout)?;
        Ok(Self::new(local, peer))
    }

    pub const fn state(&self) -> HandoffState {
        self.controller.state()
    }

    /// Translates a left pointer-barrier activation into the encrypted message
    /// to send to the peer. No input is remotely active at this point.
    pub fn left_barrier_activated(&mut self, y: i32) -> Result<Message, DemoError> {
        let transition = self.controller.local_edge_activated(Point { x: 0, y });
        match transition.action {
            Some(HandoffAction::RequestPeerEntry { entry }) => Ok(Message::Enter {
                x: entry.x,
                y: entry.y,
            }),
            None => Err(DemoError::InvalidEdgeCoordinate(y)),
            Some(action) => Err(DemoError::UnexpectedAction {
                state: transition.state,
                action,
            }),
        }
    }

    /// Feeds an authenticated control message from the peer into the state
    /// machine. `Ok(true)` means input forwarding may begin; `Ok(false)` means
    /// the peer declined entry and the local pointer was recovered.
    pub fn receive_peer_message(&mut self, message: Message) -> Result<bool, DemoError> {
        match message {
            Message::EnterAck => match self.controller.peer_entry_acknowledged().action {
                Some(HandoffAction::BeginRemoteInput) => Ok(true),
                _ => Err(self.unexpected(Message::EnterAck)),
            },
            Message::EnterRejected => match self.controller.peer_entry_rejected().action {
                Some(HandoffAction::WarpLocalPointer { .. }) => Ok(false),
                _ => Err(self.unexpected(Message::EnterRejected)),
            },
            Message::HandoffRelease => {
                self.controller.disconnect_or_cancel();
                Ok(false)
            }
            message => Err(self.unexpected(message)),
        }
    }

    /// Converts an orderly stop, disconnect, or emergency release into the
    /// dedicated handoff release frame. It is idempotent: callers send a frame
    /// only when a pending or active handoff actually existed.
    pub fn release(&mut self) -> Option<Message> {
        match self.controller.disconnect_or_cancel().action {
            Some(HandoffAction::ReleaseRemoteInput) => Some(Message::HandoffRelease),
            _ => None,
        }
    }

    fn unexpected(&self, message: Message) -> DemoError {
        DemoError::UnexpectedMessage {
            state: self.controller.state(),
            message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo() -> LeftEdgeDemo {
        LeftEdgeDemo::side_by_side(1_920, 1_080, -1_440, 200, 1_440, 900).unwrap()
    }

    #[test]
    fn left_barrier_maps_to_an_authenticated_enter_request() {
        let mut demo = demo();
        assert_eq!(
            demo.left_barrier_activated(0),
            Ok(Message::Enter { x: -1, y: 200 })
        );
        assert!(matches!(demo.state(), HandoffState::EntryPending { .. }));
    }

    #[test]
    fn input_is_not_active_until_the_peer_acknowledges() {
        let mut demo = demo();
        demo.left_barrier_activated(540).unwrap();
        assert_eq!(demo.receive_peer_message(Message::EnterAck), Ok(true));
        assert_eq!(
            demo.state(),
            HandoffState::RemoteActive {
                exit_edge: Edge::Left
            }
        );
    }

    #[test]
    fn rejected_or_malformed_control_does_not_activate_remote_input() {
        let mut demo = demo();
        demo.left_barrier_activated(540).unwrap();
        assert_eq!(demo.receive_peer_message(Message::EnterRejected), Ok(false));
        assert_eq!(demo.state(), HandoffState::Local);
        assert!(matches!(
            demo.receive_peer_message(Message::EnterAck),
            Err(DemoError::UnexpectedMessage { .. })
        ));
    }

    #[test]
    fn release_is_sent_once_for_pending_or_active_handoffs() {
        let mut demo = demo();
        assert_eq!(demo.release(), None);
        demo.left_barrier_activated(540).unwrap();
        assert_eq!(demo.release(), Some(Message::HandoffRelease));
        assert_eq!(demo.release(), None);

        demo.left_barrier_activated(540).unwrap();
        demo.receive_peer_message(Message::EnterAck).unwrap();
        assert_eq!(demo.release(), Some(Message::HandoffRelease));
    }

    #[test]
    fn invalid_barrier_coordinate_is_rejected_before_network_activity() {
        let mut demo = demo();
        assert_eq!(
            demo.left_barrier_activated(1_080),
            Err(DemoError::InvalidEdgeCoordinate(1_080))
        );
        assert_eq!(demo.state(), HandoffState::Local);
    }
}
