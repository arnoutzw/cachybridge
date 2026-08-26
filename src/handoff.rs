//! Pure state machine for a future Wayland/libei edge-handoff backend.
//!
//! The input backend owns pointer barriers and the network backend owns the
//! enter/ack messages.  This module deliberately owns neither: it turns those
//! observations into explicit actions, making the security-sensitive transfer
//! boundary deterministic and independently testable.

/// One horizontal edge of a logical display rectangle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    Left,
    Right,
}

impl Edge {
    /// The edge used to leave a display after entering through `self`.
    pub const fn opposite(self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }
}

/// A pixel coordinate in a logical desktop coordinate space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

/// A non-empty logical display rectangle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    /// Creates a rectangle, rejecting empty displays and coordinates that
    /// would overflow when their inclusive right/bottom edge is calculated.
    pub fn new(x: i32, y: i32, width: u32, height: u32) -> Result<Self, LayoutError> {
        if width == 0 || height == 0 {
            return Err(LayoutError::EmptyRectangle);
        }
        let rectangle = Self {
            x,
            y,
            width,
            height,
        };
        rectangle.right().ok_or(LayoutError::CoordinateOverflow)?;
        rectangle.bottom().ok_or(LayoutError::CoordinateOverflow)?;
        Ok(rectangle)
    }

    pub fn contains(self, point: Point) -> bool {
        self.right()
            .zip(self.bottom())
            .is_some_and(|(right, bottom)| {
                (self.x..=right).contains(&point.x) && (self.y..=bottom).contains(&point.y)
            })
    }

    pub fn edge_x(self, edge: Edge) -> i32 {
        match edge {
            Edge::Left => self.x,
            Edge::Right => self
                .right()
                .expect("validated rectangles have a right edge"),
        }
    }

    fn right(self) -> Option<i32> {
        self.x
            .checked_add(i32::try_from(self.width).ok()?.checked_sub(1)?)
    }

    fn bottom(self) -> Option<i32> {
        self.y
            .checked_add(i32::try_from(self.height).ok()?.checked_sub(1)?)
    }
}

/// Invalid logical display geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    EmptyRectangle,
    CoordinateOverflow,
}

/// The current ownership of keyboard/mouse input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffState {
    /// The local compositor owns input.
    Local,
    /// An authenticated peer has been asked to accept a handoff. Input stays
    /// local until the peer acknowledges it.
    EntryPending {
        exit_edge: Edge,
        entry: Point,
        local_entry: Point,
    },
    /// Input belongs to the peer until its opposite edge is crossed, the peer
    /// disconnects, or the user cancels the handoff.
    RemoteActive { exit_edge: Edge },
}

/// An instruction for the compositor/network adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffAction {
    /// Ask the peer to place its pointer at `entry`, then wait for an ACK.
    RequestPeerEntry { entry: Point },
    /// The peer has acknowledged the entry; forwarding may now begin.
    BeginRemoteInput,
    /// Stop forwarding and release all keys/buttons on the peer. This must be
    /// best-effort even when the transport is already disconnected.
    ReleaseRemoteInput,
    /// Move the local compositor pointer back onto this display.
    WarpLocalPointer { at: Point },
    /// Stop remote input, release all remote controls, then warp the local
    /// pointer back to `at`. The adapter must preserve that order.
    ReturnToLocal { at: Point },
}

/// Result of feeding one external observation to [`HandoffController`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub state: HandoffState,
    pub action: Option<HandoffAction>,
}

impl Transition {
    fn unchanged(state: HandoffState) -> Self {
        Self {
            state,
            action: None,
        }
    }

    fn changed(state: HandoffState, action: HandoffAction) -> Self {
        Self {
            state,
            action: Some(action),
        }
    }
}

/// Maps two independent logical screens and controls one horizontal handoff.
///
/// `peer_edge` is the edge of the *local* display adjoining the peer. For a
/// client positioned left of this iMac, use [`Edge::Left`]. Rectangles do not
/// need to be adjacent; their vertical ranges are scaled proportionally.
#[derive(Debug, Clone)]
pub struct HandoffController {
    local: Rect,
    peer: Rect,
    peer_edge: Edge,
    state: HandoffState,
}

impl HandoffController {
    pub fn new(local: Rect, peer: Rect, peer_edge: Edge) -> Self {
        Self {
            local,
            peer,
            peer_edge,
            state: HandoffState::Local,
        }
    }

    pub const fn state(&self) -> HandoffState {
        self.state
    }

    /// Processes a local pointer position. Only a point on the configured
    /// edge can begin a transfer; callers should feed this after a Wayland
    /// pointer-barrier activation, not for ordinary motion.
    pub fn local_edge_activated(&mut self, point: Point) -> Transition {
        if self.state != HandoffState::Local
            || !self.local.contains(point)
            || point.x != self.local.edge_x(self.peer_edge)
        {
            return Transition::unchanged(self.state);
        }

        let entry = Point {
            x: self.peer.edge_x(self.peer_edge.opposite()),
            y: map_coordinate(
                point.y,
                self.local.y,
                self.local.height,
                self.peer.y,
                self.peer.height,
            ),
        };
        self.state = HandoffState::EntryPending {
            exit_edge: self.peer_edge,
            entry,
            local_entry: point,
        };
        Transition::changed(self.state, HandoffAction::RequestPeerEntry { entry })
    }

    /// Completes a pending transfer only after a matching authenticated peer
    /// acknowledgement. Duplicate/out-of-order ACKs are harmless no-ops.
    pub fn peer_entry_acknowledged(&mut self) -> Transition {
        let HandoffState::EntryPending { exit_edge, .. } = self.state else {
            return Transition::unchanged(self.state);
        };
        self.state = HandoffState::RemoteActive { exit_edge };
        Transition::changed(self.state, HandoffAction::BeginRemoteInput)
    }

    /// Recovers locally when the peer rejects or times out a pending entry.
    pub fn peer_entry_rejected(&mut self) -> Transition {
        let HandoffState::EntryPending { local_entry, .. } = self.state else {
            return Transition::unchanged(self.state);
        };
        self.state = HandoffState::Local;
        Transition::changed(
            self.state,
            HandoffAction::WarpLocalPointer {
                at: self.local_interior(local_entry),
            },
        )
    }

    /// Handles a pointer barrier reported by the peer. A remote session may
    /// return only through the edge opposite the original departure edge.
    pub fn peer_exit_activated(&mut self, edge: Edge, point: Point) -> Transition {
        let HandoffState::RemoteActive { exit_edge } = self.state else {
            return Transition::unchanged(self.state);
        };
        if edge != exit_edge.opposite()
            || point.x != self.peer.edge_x(edge)
            || !(self.peer.y..=self.peer.bottom().unwrap()).contains(&point.y)
        {
            return Transition::unchanged(self.state);
        }

        self.state = HandoffState::Local;
        let local_y = map_coordinate(
            point.y,
            self.peer.y,
            self.peer.height,
            self.local.y,
            self.local.height,
        );
        Transition::changed(
            self.state,
            HandoffAction::ReturnToLocal {
                at: self.local_interior(Point {
                    x: self.local.edge_x(exit_edge),
                    y: local_y,
                }),
            },
        )
    }

    /// Cancels a handoff on transport loss or an explicit emergency release.
    /// Remote input is released for both pending and active sessions; doing so
    /// is idempotent and protects against a peer that accepted just before a
    /// disconnect was detected.
    pub fn disconnect_or_cancel(&mut self) -> Transition {
        if self.state == HandoffState::Local {
            return Transition::unchanged(self.state);
        }
        self.state = HandoffState::Local;
        Transition::changed(self.state, HandoffAction::ReleaseRemoteInput)
    }

    /// A portal release at the exact barrier coordinate can immediately
    /// activate the same barrier again. Restore one logical pixel inside the
    /// local display instead, leaving the physical pointer in normal local
    /// compositor ownership. A one-pixel-wide display has no interior, so it
    /// necessarily falls back to its only coordinate.
    fn local_interior(&self, boundary: Point) -> Point {
        Point {
            x: match self.peer_edge {
                Edge::Left if self.local.width > 1 => self.local.x + 1,
                Edge::Right if self.local.width > 1 => {
                    self.local
                        .right()
                        .expect("validated rectangles have a right edge")
                        - 1
                }
                _ => boundary.x,
            },
            y: boundary.y,
        }
    }
}

fn map_coordinate(
    value: i32,
    source_start: i32,
    source_len: u32,
    destination_start: i32,
    destination_len: u32,
) -> i32 {
    debug_assert!(source_len > 0 && destination_len > 0);
    if source_len == 1 || destination_len == 1 {
        return destination_start;
    }
    let source_span = i64::from(source_len - 1);
    let destination_span = i64::from(destination_len - 1);
    let offset = i64::from(value - source_start).clamp(0, source_span);
    let mapped_offset = (offset * destination_span + source_span / 2) / source_span;
    let result = i64::from(destination_start) + mapped_offset;
    i32::try_from(result).expect("validated rectangle coordinate cannot overflow")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x: i32, y: i32, width: u32, height: u32) -> Rect {
        Rect::new(x, y, width, height).unwrap()
    }

    fn controller(edge: Edge) -> HandoffController {
        HandoffController::new(
            rect(0, 0, 1_920, 1_080),
            rect(-1_440, 200, 1_440, 900),
            edge,
        )
    }

    #[test]
    fn rejects_empty_and_overflowing_rectangles() {
        assert_eq!(Rect::new(0, 0, 0, 1), Err(LayoutError::EmptyRectangle));
        assert_eq!(
            Rect::new(i32::MAX, 0, 2, 1),
            Err(LayoutError::CoordinateOverflow)
        );
    }

    #[test]
    fn left_edge_requests_entry_at_peers_right_edge_with_scaled_y() {
        let mut handoff = controller(Edge::Left);
        let transition = handoff.local_edge_activated(Point { x: 0, y: 0 });
        assert_eq!(
            transition,
            Transition::changed(
                HandoffState::EntryPending {
                    exit_edge: Edge::Left,
                    entry: Point { x: -1, y: 200 },
                    local_entry: Point { x: 0, y: 0 },
                },
                HandoffAction::RequestPeerEntry {
                    entry: Point { x: -1, y: 200 },
                },
            )
        );

        let mut handoff = controller(Edge::Left);
        let transition = handoff.local_edge_activated(Point { x: 0, y: 1_079 });
        assert_eq!(
            transition.action,
            Some(HandoffAction::RequestPeerEntry {
                entry: Point { x: -1, y: 1_099 },
            })
        );
    }

    #[test]
    fn right_edge_maps_to_peers_left_edge() {
        let mut handoff = controller(Edge::Right);
        let transition = handoff.local_edge_activated(Point { x: 1_919, y: 540 });
        assert_eq!(
            transition.action,
            Some(HandoffAction::RequestPeerEntry {
                entry: Point { x: -1_440, y: 650 },
            })
        );
    }

    #[test]
    fn ordinary_motion_and_wrong_edge_do_not_start_transfer() {
        let mut handoff = controller(Edge::Left);
        assert_eq!(
            handoff.local_edge_activated(Point { x: 1, y: 400 }),
            Transition::unchanged(HandoffState::Local)
        );
        assert_eq!(
            handoff.local_edge_activated(Point { x: 0, y: 1_080 }),
            Transition::unchanged(HandoffState::Local)
        );
    }

    #[test]
    fn remote_input_starts_only_after_acknowledgement() {
        let mut handoff = controller(Edge::Left);
        handoff.local_edge_activated(Point { x: 0, y: 400 });
        assert_eq!(
            handoff.state(),
            HandoffState::EntryPending {
                exit_edge: Edge::Left,
                entry: Point { x: -1, y: 533 },
                local_entry: Point { x: 0, y: 400 },
            }
        );
        assert_eq!(
            handoff.peer_entry_acknowledged(),
            Transition::changed(
                HandoffState::RemoteActive {
                    exit_edge: Edge::Left
                },
                HandoffAction::BeginRemoteInput,
            )
        );
        assert_eq!(
            handoff.peer_entry_acknowledged(),
            Transition::unchanged(HandoffState::RemoteActive {
                exit_edge: Edge::Left
            })
        );
    }

    #[test]
    fn rejected_entry_warps_local_pointer_without_forwarding() {
        let mut handoff = controller(Edge::Left);
        handoff.local_edge_activated(Point { x: 0, y: 400 });
        assert_eq!(
            handoff.peer_entry_rejected(),
            Transition::changed(
                HandoffState::Local,
                HandoffAction::WarpLocalPointer {
                    at: Point { x: 1, y: 400 }
                },
            )
        );
    }

    #[test]
    fn remote_exit_requires_opposite_edge_then_releases_input() {
        let mut handoff = controller(Edge::Left);
        handoff.local_edge_activated(Point { x: 0, y: 539 });
        handoff.peer_entry_acknowledged();
        assert_eq!(
            handoff.peer_exit_activated(Edge::Left, Point { x: -1_440, y: 600 }),
            Transition::unchanged(HandoffState::RemoteActive {
                exit_edge: Edge::Left
            })
        );
        assert_eq!(
            handoff.peer_exit_activated(Edge::Right, Point { x: -1, y: 600 }),
            Transition::changed(
                HandoffState::Local,
                HandoffAction::ReturnToLocal {
                    at: Point { x: 1, y: 480 },
                },
            )
        );
        assert_eq!(handoff.state(), HandoffState::Local);
    }

    #[test]
    fn disconnect_releases_pending_or_active_input_idempotently() {
        let mut handoff = controller(Edge::Left);
        handoff.local_edge_activated(Point { x: 0, y: 400 });
        assert_eq!(
            handoff.disconnect_or_cancel(),
            Transition::changed(HandoffState::Local, HandoffAction::ReleaseRemoteInput)
        );
        assert_eq!(
            handoff.disconnect_or_cancel(),
            Transition::unchanged(HandoffState::Local)
        );

        handoff.local_edge_activated(Point { x: 0, y: 400 });
        handoff.peer_entry_acknowledged();
        assert_eq!(
            handoff.disconnect_or_cancel(),
            Transition::changed(HandoffState::Local, HandoffAction::ReleaseRemoteInput)
        );
    }
}
