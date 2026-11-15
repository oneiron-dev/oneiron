//! Moved from `crates/oneiron/src/memory/people_verbs.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::memory::people_verbs::GrantAskRequest;
pub use oneiron_verb_wire::memory::people_verbs::GrantAskScope;
pub use oneiron_verb_wire::memory::people_verbs::GrantAskedRequest;
pub use oneiron_verb_wire::memory::people_verbs::GrantRequestedScope;
pub use oneiron_verb_wire::memory::people_verbs::MessagePersonRequest;
pub use oneiron_verb_wire::memory::people_verbs::PeopleListRequest;
pub use oneiron_verb_wire::memory::people_verbs::PersonRequest;
use serde::Deserialize;
use serde::Serialize;

/// The pending access request. Asking grants nothing; the vault owner, or
/// the person asked, answers it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantAskReceipt {
    pub request: String,
    pub asked: String,
    pub status: String,
}

/// One pending access request that asks the caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantAskedRow {
    /// 32-hex request id, as `self.grants.answer` takes it.
    pub request: String,
    /// 32-hex id of the actor who asked; the grant would be theirs.
    pub asker: String,
    pub capability: String,
    pub scope: GrantRequestedScope,
    /// When the request was filed, in unix seconds.
    pub created_at: u64,
    /// When the requested grant would end, in unix seconds; none when it
    /// would not.
    pub expires_at: Option<u64>,
}

/// One page of the pending access requests that ask the caller, in request
/// id order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantAskedPage {
    pub requests: Vec<GrantAskedRow>,
    /// The cursor of the next page; none when no more requests ask the
    /// caller.
    pub next_after: Option<String>,
}
