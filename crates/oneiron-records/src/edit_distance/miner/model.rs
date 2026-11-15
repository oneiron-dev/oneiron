//! Moved from `crates/oneiron/src/edit_distance/miner/model.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::inbox::compilation_target::CompilationTarget;
use oneiron_contracts::entity_id::EntityId;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One bucket of identical normalized substitutions inside one scope.
///
/// `receipt_refs` are ED-01 receipt ids — STRINGS, because that is what a
/// receipt id is in this engine (`gate:<hex>`, `proposal_outcome:<hex>`); the
/// Δ side-ledger and ED-03's judgment ledger key on the same type.
///
/// `actor` is part of the bucket's KEY, not derived from it. ARCH-0056 §5 pins
/// the scope as the `op × target class × skill/agent` cross, so a scope already
/// names one actor — keying on it explicitly is what lets the preference arm
/// name a SUBJECT without ever guessing between two candidates. `skill` IS
/// derived: it is the skill every citing amendment named, and `None` when they
/// disagree or none did, so a content arm never edits a skill on a split vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstitutionCluster {
    /// Authenticated decider, when the receipt used the actor-bound intake.
    /// Missing legacy identity is never treated as a global preference.
    pub principal: Option<EntityId>,
    /// Explicit host classification; absent semantics preserve the old chooser.
    pub target: CompilationTarget,
    /// The `(op × target class × skill/agent)` axis this bucket lives on.
    pub scope: String,
    /// Normalized text the decider removed.
    pub from: String,
    /// Normalized text the decider wrote instead.
    pub to: String,
    /// The actor whose output kept earning this correction.
    pub actor: EntityId,
    /// The skill every citing amendment rode, when they agree on one.
    pub skill: Option<EntityId>,
    /// At least one citing fallback amendment had no attribution judgment.
    pub unattributed: bool,
    /// Distinct amendment receipts showing this substitution, in receipt-id
    /// order so two passes over one ledger cite the same list in the same order.
    pub receipt_refs: Vec<String>,
    /// `receipt_refs.len()` — the recurrence count K is compared against.
    pub count: u32,
    /// The newest citing amendment's stamp; the emitted proposal's event time.
    pub at: u64,
}

/// Which lane a substitution routes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubstitutionClass {
    /// Every token on both sides is tone/stop lexicon: a phrasing swap.
    Lexical,
    /// At least one token is content: a factual or structural correction.
    Content,
}

impl SubstitutionClass {
    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lexical => "lexical",
            Self::Content => "content",
        }
    }

    /// The receipted rationale for this routing — pinned text, so two readers
    /// quoting a proposal quote the same sentence.
    #[must_use]
    pub const fn rationale(self) -> &'static str {
        match self {
            Self::Lexical => "every token on both sides is in the tone lexicon",
            Self::Content => "at least one token on one side is outside the tone lexicon",
        }
    }
}
