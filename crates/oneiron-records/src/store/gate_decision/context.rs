//! Moved from `crates/oneiron/src/store/gate_decision/context.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::federation::Scope;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::gate_decision::types::GateDecisionId;
use serde::Deserialize;
use serde::Serialize;

/// One placed private-thread turn (FIX 11000): the thread `root` and the
/// `turn` in it. Content-free ids only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GateThreadAnchor {
    /// The thread root.
    pub root: EntityId,
    /// The turn placed in it.
    pub turn: EntityId,
}

/// A record's own read position, as its write stamped it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReadPosition {
    /// The record's entity type.
    pub entity_type: u8,
    /// Its six-axis record Scope for the read verb.
    pub scope: Scope,
    /// A claim's own read selectors beside its Scope.
    pub claim: Option<GateClaimReadSelectors>,
}

/// What a claim's read selectors and scalar floor judge beside its Scope,
/// kept bit for bit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateClaimReadSelectors {
    /// The one person its scope names as its principal audience.
    pub principal: Option<EntityId>,
    /// Its sensitivity band, as its scope stamps it.
    pub sensitivity_band: Option<u8>,
    /// The relationship key the claim is scoped to: `None` for all, else
    /// its whole set (`[]` the explicit empty set).
    pub relationship: oneiron_store::write_envelope::claim_body::RelationshipScope,
    /// Whether its scope marks it private.
    pub private: bool,
    /// Its opaque scope selector, as MessagePack.
    pub scope: Option<Vec<u8>>,
    /// Its confidence, as the bits of the finite `f32` it was written with.
    pub confidence_bits: u32,
    /// Its salience, the same way.
    pub salience_bits: Option<u32>,
    /// Its staleness marker.
    pub stale: bool,
}

/// Which part of a loop a decision is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateLoopFamily {
    /// The loop's run admitted or refused.
    Admission,
    /// The loop's action, or the answer to it.
    Action,
}

/// The loop a decision came from: the producer, never the person who
/// answers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateLoopSource {
    /// The vault's Dreamer.
    Dreamer,
    /// The Coach.
    Coach,
    /// A resident's own dreaming or free time.
    Resident,
    /// A turn-woken program.
    TurnProgram,
    /// A Dreamer-runner run whose agent the writer did not resolve: a claim
    /// a run wrote names only its run.
    Runner,
}

/// The decision that admitted a loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateLoopOrigin {
    /// This decision is the admission itself.
    SelfDecision,
    /// An earlier decision in the ledger.
    Decision(GateDecisionId),
    /// The decision that admitted the loop was not resolved where this one
    /// was written.
    Unresolved,
}

/// The ruled risk vector (ARCH-0040 `dr:SK07`): each axis's result and what
/// its rules covered. Closed tokens only, never the bytes matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDecisionAnalysis {
    /// The rule set that computed it.
    pub rules: String,
    /// The input's surfaces the rules read, each by name; a surface not
    /// named was not read, so no axis speaks for it.
    pub surfaces: Vec<String>,
    /// A path to a credential or secret store.
    pub sensitive_path: GateRiskAxis,
    /// A secret-shaped argument or value.
    pub secret_argument: GateRiskAxis,
    /// A command of a destructive class.
    pub dangerous_command: GateRiskAxis,
}

/// One risk axis's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRiskAxis {
    /// What the rules found.
    pub state: GateRiskState,
    /// How much of the axis's surface they read.
    pub coverage: GateAnalysisCoverage,
    /// The rules that matched, each once.
    pub matched: Vec<String>,
}

/// What an axis's rules found. `NoHit` says the whole surface was read by
/// the stated rules, not that the input is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateRiskState {
    /// A rule matched.
    Hit,
    /// No rule matched over what was read.
    NoHit,
    /// The input has no surface this axis reads.
    NotApplicable,
    /// The surface could not be read.
    NotAnalysed,
}

/// How much of an axis's surface its rules read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateAnalysisCoverage {
    /// All of it.
    Complete,
    /// Some of it: part of the surface was not in a form the rules read.
    Partial,
    /// None of it.
    None,
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
