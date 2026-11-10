//! Status modes carried by an actor-keyed read lane.

/// Which claim statuses a scoped read lane admits.
///
/// The status half of claim admission, and nothing else: every other check
/// (reader, credential, ceiling, audience, relationship and grant) applies in
/// every mode. Actor-owned exact-store claims are admitted only in
/// [`Self::ExactStore`], which admits nothing else.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ClaimReadStatus {
    /// Retrieval channels: `auto`/`approved`, active, and not stale unless
    /// the resolved filter includes stale claims (the D19 read-path gate).
    #[default]
    Surfaceable,
    /// The record verbs (get, list, history): proposed and closed claims are
    /// part of those verbs' contract, so the status half admits every status.
    Recorded,
    /// The keyed store's own reader (`Memory::key_value_*` under a read
    /// credential, OF-172 D2): actor-owned exact-store claims, at the
    /// Surfaceable status, and no other claim. Generic retrieval, hydration
    /// and history never open this mode ([E2E-KV-GET-PREFILTER]).
    ExactStore,
}
