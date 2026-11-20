//! Moved from `crates/oneiron/src/code_run/types/outcome.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::code_run::types::*;
use oneiron_base::edge::EdgeKind;
use oneiron_contracts::entity_id::EntityId;
use oneiron_retrieval::pipeline::ScoredEntity;
use oneiron_store::config::context_spec::ContextSpec;

/// A typed reply too large for one message, already spilled as a body of
/// the run (FIX449): `output` is the SAME already-spilled guest JSON card
/// `store_reply` returned (tainted, with facets), NOT a reconstructed
/// original typed value. The guest reads `{"output": card}`; replay never
/// rehydrates the original. The explicit source kind also distinguishes a
/// native receipt from reply content; `Changed`/`Pending` never become carriers.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfStoredReply {
    pub kind: SelfStoredReplyKind,
    pub output: serde_json::Value,
    /// A wait set's settled children's type feedback, kept typed beside the
    /// card and never inside the stored body, so its own release check
    /// judges it (FIX 10389/10390); empty for every other kind.
    pub program_steps: Vec<crate::code_run::ProgramStepFeedback>,
}

/// Which typed reply a [`SelfStoredReply`] spilled (FIX449): the exact
/// source kind, kept explicit so readers never guess from card text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfStoredReplyKind {
    InferenceDefaults,
    TaskAskSettled,
    TaskAskWorldPrivacy,
    /// A wait-set reply with no program feedback to release separately.
    TaskWaitSet,
    /// A wait-set reply whose program feedback stays typed beside its card.
    TaskWaitSetWithFeedback,
    /// A direct team start's native receipt, not reply content.
    TeamStartReceipt,
}

/// What one callable skill returned: JSON its contract's `returns` shape
/// admitted.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfSkillCallResult {
    pub skill: EntityId,
    pub output: serde_json::Value,
}

/// Result of the `self.context` descriptor bridge: the spec as-is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfContextResult {
    pub spec: ContextSpec,
}

/// Result of a `vault.search` fixture dispatch.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfMemorySearchResult {
    pub query: String,
    pub results: Vec<ScoredEntity>,
    /// What each verb hook bound to the search did, in a room (WILL L11-01
    /// S01-2c); empty outside one.
    pub hooks: Vec<SessionHookDisposition>,
}

/// Result of an internal fixture memory write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfMemoryWriteResult {
    pub id: EntityId,
}

/// Result of a public `vault.edges.put` trap.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SelfMemoryEdgeWriteResult {
    pub src: EntityId,
    pub kind: EdgeKind,
    pub tgt: EntityId,
}

/// Measured facts from a native proposal-spool disk-floor failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfSandboxProposalDiskFloor {
    pub needed: u64,
    pub available: u64,
    pub reserve: u64,
}

/// Why a dispatched effect parked instead of committing immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SelfDurableWaitReason {
    HumanInput,
    DestructiveEffect,
    OutboundEffect,
    /// Waiting on a peer executor's result landing on a delegated TASK
    /// (ONE-1700). The three reasons above are all consent-scale; this one is
    /// not, which is why it maps to its own trap kind.
    PeerResult,
}
