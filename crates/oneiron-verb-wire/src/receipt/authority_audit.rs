//! Moved from `crates/oneiron/src/receipt/authority_audit.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::ops::Bound;

/// `vault.authority.audit`'s input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorityAuditQuery {
    /// Resume after this AUTHORITY_LOG entry ref: the `next_after` of the
    /// page before. `None` starts at the first entry.
    #[serde(default)]
    pub after: Option<EntityId>,
    /// Rows to return, at most [`AUTHORITY_AUDIT_MAX_LIMIT`].
    #[serde(default)]
    pub limit: Option<usize>,
    /// Keep only stored rows of these kinds; empty keeps every row. Cold
    /// rows have no kind and are listed whatever this names.
    #[serde(default)]
    pub kinds: BTreeSet<AuthorityAuditEventKind>,
}

/// The display class of one entry. A classification over the op vocabulary,
/// not an authority enum: `source_op` and `detail` keep the exact op.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityAuditEventKind {
    /// A capability mint, a federation connect, an owner's agent Grant mint,
    /// or a person's yes to training on their conversations.
    Grant,
    /// A capability revoke, a federation disconnect or dissolve, an owner's
    /// agent Grant revoke, or a person turning training on their conversations off.
    Revoke,
    /// A federation confirm (its `detail` keeps accept, rescope, a2a connect
    /// or revoke) or a critical-write confirm (clear or decline).
    Confirm,
    /// Every other op: roster, key, actor-binding, machine, world and
    /// handover maintenance, a capability consume, a federation rescope or
    /// promote. None of these is consent to disclose content.
    Other,
}
