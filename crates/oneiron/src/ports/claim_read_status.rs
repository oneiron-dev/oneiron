//! Status modes carried by an actor-keyed read lane.

/// Which claim statuses a scoped read lane admits.
///
/// The status half of claim admission, and nothing else: every other check
/// (reader, credential, ceiling, audience, relationship and grant) applies in
/// both modes. Actor-owned exact-store claims are never admitted in either.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ClaimReadStatus {
    /// Retrieval channels: `auto`/`approved`, active, and not stale unless
    /// the resolved filter includes stale claims (the D19 read-path gate).
    #[default]
    Surfaceable,
    /// The record verbs (get, list, history): proposed and closed claims are
    /// part of those verbs' contract, so the status half admits every status.
    Recorded,
}
