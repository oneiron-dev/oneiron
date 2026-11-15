//! Moved from `crates/oneiron/src/agent_dispatch/widen_record.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_consent_state::consent::grant::ConsentProposal;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::config::context_spec::ContextSpec;
use serde::Deserialize;
use serde::Serialize;

/// A parked dispatch. This is a proposal, never a read or dispatch grant.
#[derive(Debug, Clone, PartialEq)]
pub struct ContextWidenProposal {
    pub proposal_id: String,
    pub parent_attempt: AttemptId,
    /// Absent means the board cannot be proven; approval fails closed.
    pub board_attempt: Option<AttemptId>,
    pub parent_context: ContextSpec,
    pub requested_context: ContextSpec,
    pub widened_parent_context: ContextSpec,
    pub consent: ConsentProposal,
}

/// Preserve the caller's target kind. A wrapper is never an AGENT_DEF actor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", deny_unknown_fields)]
pub enum WidenTarget {
    Agent(String),
    Workflow(String),
}

/// Approval replay returns the original typed landing, not a guessed agent row.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(tag = "kind", content = "attempt", deny_unknown_fields)]
pub enum WidenLanding {
    Agent(AttemptId),
    Workflow(AttemptId),
}

/// The board's refusal of a proposal (OF-568): who declined it, and when on
/// the store's clock. A declined proposal never lands.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WidenDecline {
    /// The board owner's actor id, hex.
    pub by: String,
    pub at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SliceOverride {
    pub proposal_id: String,
    /// The immediate board above the widened parent; `None` for a root
    /// Owner's act on a parent with no board above (FIX 9565).
    pub board: Option<AttemptId>,
    /// Who answered as the board: a PERSON for a root Owner, the board's
    /// AGENT_DEF for its own leased agent.
    pub actor: String,
    /// What authorized the act, replayed live at every read of the slice.
    pub proof: BoardProof,
    pub spec: ContextSpec,
}

/// What authorized a landed board act (FIX 9565).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoardProof {
    /// A revalidated root Owner of this vault.
    RootOwner,
    /// The board attempt's own agent, under its live host lease.
    ParentAgent,
}
