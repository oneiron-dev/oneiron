//! Result vocabulary for a fingerprint-pinned conversation span read.

/// What the Dreamer's read of a declared span found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationSpanRead {
    /// Each declared turn's exact projected text, in the declared order.
    Ready(Vec<String>),
    /// A turn reads other words, rows, authors or stream generations than
    /// its pin.
    Drifted,
    /// A turn or a child it depends on is gone, has no text, or is not the
    /// Dreamer's to read.
    Unreadable,
    /// A turn's tagged MESSAGE is away from this replica for now: the read
    /// waits for it.
    Deferred,
}
