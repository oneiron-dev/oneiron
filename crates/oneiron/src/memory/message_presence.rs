//! Scope and wire bytes of a live MESSAGE partial.

/// Whose message a live partial is (FIX 9537), from its stream's own seed:
/// the conversation its MESSAGE lands in and the stream's generation. A
/// host judges where the partial may go by this, never by the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessagePresenceScope {
    pub message: crate::EntityId,
    pub conversation: crate::EntityId,
    pub generation: crate::EntityId,
    /// The stream ended: the frame deletes its partial.
    pub cleared: bool,
}

/// An all-devices partial's presence frame, with its scope.
#[derive(Debug, Clone)]
pub struct ScopedPresenceFrame {
    /// The frame, `TAG_EPHEMERAL` first, as the device lane carries it.
    pub frame: Vec<u8>,
    pub scope: MessagePresenceScope,
}
