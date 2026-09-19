//! Door inputs and snapshot results.

use crate::{EntityId, TimeRange, WriteActor};

/// Which chain or retained sub-session a scope addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopePath {
    /// The ancestor path ending at the current HEAD.
    Canonical,
    /// The ancestor path ending at this record, even after a HEAD move.
    Branch(EntityId),
    /// Exactly the records admitted into this sub-session.
    SubSession(EntityId),
}

/// A precise scope over one conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSelector {
    /// Conversation containing every selected record.
    pub conversation: EntityId,
    /// Optional recorded session-membership restriction.
    pub session: Option<EntityId>,
    /// Chain or sub-session selection.
    pub path: ScopePath,
    /// Include descendants branching off the selected chain. Sub-sessions
    /// stay isolated; this flag never broadens a SubSession selection.
    pub include_forks: bool,
}

/// Exact record set in deterministic root-first order (not an LMDB id page).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedScope {
    /// Original selector.
    pub scope: ScopeSelector,
    /// Complete result, or an error if the safety cap would truncate it.
    pub records: Vec<EntityId>,
}

/// Input to the append-only conversation record door.
#[derive(Debug, Clone)]
pub struct AppendRecord {
    /// Conversation owner.
    pub conversation: EntityId,
    /// Record continued by the append; absent only for the first root.
    pub parent: Option<EntityId>,
    /// Advance HEAD; requires parent == HEAD and a non-sub-session record.
    pub advance: bool,
    /// Record type. This revision admits TURN only; MESSAGE has its own door.
    pub kind: u8,
    /// Valid-time span.
    pub occurred: TimeRange,
    /// Learned-at time.
    pub learned_at: u64,
    /// MessagePack record payload. It must be a map; actor is host-stamped.
    pub body: Vec<u8>,
    /// Explicit text-index fields, stored atomically with the record.
    pub text: Vec<(String, String)>,
    /// Optional sitting / sub-session membership.
    pub session: Option<EntityId>,
    /// Explicit byline and actor class, validated in the write transaction.
    pub actor: WriteActor,
}

/// Result of one append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendedRecord {
    /// Fresh record identifier.
    pub id: EntityId,
    /// HEAD after the append.
    pub head: Option<EntityId>,
    /// Durable Parent target.
    pub parent: Option<EntityId>,
}

/// Root-first main-line paging. A cursor must still be on the selected line.
#[derive(Debug, Default, Clone, Copy)]
pub struct DagPageRequest {
    /// Last record returned by a preceding page.
    pub after: Option<EntityId>,
    /// Page size, clamped to 1..=1000 (zero uses 100).
    pub limit: usize,
}

/// A coherent main-line page and its HEAD/root snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagPage {
    /// Current HEAD, absent for a conversation without a selected line.
    pub head: Option<EntityId>,
    /// Root of the selected line.
    pub root: Option<EntityId>,
    /// Root-first page.
    pub main_line: Vec<EntityId>,
    /// Exclusive cursor, present only when another page exists.
    pub next: Option<EntityId>,
}
