//! Moved from `crates/oneiron/src/memory/edge_provenance.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::edge::EdgeActorClass;
use oneiron_contracts::claim::ClaimLifecycleStatus;
use oneiron_contracts::gate::ReadFilterInput;
use oneiron_store::write_envelope::provenance::edge_ref::SupersessionStatus;
use serde::Deserialize;
use serde::Serialize;

/// `vault.edges.provenance` input: one directed edge, named by its two
/// endpoint refs and its kind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EdgeProvenanceRequest {
    /// The edge's source entity, by short ref or 32-hex id.
    pub source_ref: String,
    /// The snake_case `EdgeKind` name of the edge.
    pub edge_kind: String,
    /// The edge's target entity, by short ref or 32-hex id.
    pub target_ref: String,
    /// Caller retrieval filter on the provenance claims; met with the actor
    /// ceiling, it only narrows.
    #[serde(default)]
    pub filter: Option<ReadFilterInput>,
}

/// The write-time validated class of a provenance claim's actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EdgeProvenanceActorClass {
    Human,
    Agent,
    System,
}

impl From<EdgeActorClass> for EdgeProvenanceActorClass {
    fn from(class: EdgeActorClass) -> Self {
        match class {
            EdgeActorClass::Human => Self::Human,
            EdgeActorClass::Agent => Self::Agent,
            EdgeActorClass::System => Self::System,
        }
    }
}

/// A provenance claim's authoritative `supersession_status`, the value the
/// edge's `confirmation_status` flag mirrors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EdgeProvenanceSupersession {
    Proposed,
    Confirmed,
    Disputed,
    Retracted,
}

impl From<SupersessionStatus> for EdgeProvenanceSupersession {
    fn from(status: SupersessionStatus) -> Self {
        match status {
            SupersessionStatus::Proposed => Self::Proposed,
            SupersessionStatus::Confirmed => Self::Confirmed,
            SupersessionStatus::Disputed => Self::Disputed,
            SupersessionStatus::Retracted => Self::Retracted,
        }
    }
}

/// The wrapping claim's stored lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EdgeProvenanceLifecycle {
    Active,
    Superseded,
    Retracted,
}

impl From<ClaimLifecycleStatus> for EdgeProvenanceLifecycle {
    fn from(lifecycle: ClaimLifecycleStatus) -> Self {
        match lifecycle {
            ClaimLifecycleStatus::Active => Self::Active,
            ClaimLifecycleStatus::Superseded => Self::Superseded,
            ClaimLifecycleStatus::Retracted => Self::Retracted,
        }
    }
}

/// One readable `edge.provenance` claim of the audited edge. Every ref is
/// lowercase hex; an absent optional field was not recorded. A ref names a
/// record and grants no read of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EdgeProvenanceView {
    /// 32-hex id of the provenance claim.
    pub claim_ref: String,
    /// The claim's short ref, when assigned.
    pub short_ref: Option<String>,
    /// 32-hex id of the edge's source entity.
    pub source_ref: String,
    /// snake_case `EdgeKind` name of the edge.
    pub edge_kind: String,
    /// 32-hex id of the edge's target entity.
    pub target_ref: String,
    /// 32-hex id of the PERSON, agent or MACHINE that asserted the edge.
    pub actor_entity_ref: String,
    /// The actor's write-time validated class.
    pub actor_class: EdgeProvenanceActorClass,
    /// 32-hex ref of the source document revision the assertion was read
    /// at; absent when no source document exists.
    pub source_revision_ref: Option<String>,
    /// 32-hex citation of the exact text the actor read, when recorded.
    pub body_snapshot_ref: Option<String>,
    /// The actor's confidence, in [0, 1].
    pub confidence: f32,
    /// The authoritative supersession status.
    pub supersession_status: EdgeProvenanceSupersession,
    /// Valid-time start (Unix s), when recorded.
    pub valid_from: Option<u64>,
    /// Valid-time end (Unix s); absent while the assertion still holds.
    pub valid_to: Option<u64>,
    /// 32-hex id of the MODEL substrate that produced the write, when recorded.
    pub substrate_ref: Option<String>,
    /// The substrate's reasoning-effort setting for the write, when recorded.
    pub reasoning_effort: Option<String>,
    /// The wrapping claim's stored lifecycle.
    pub lifecycle: EdgeProvenanceLifecycle,
    /// Whether an active claim's cited source was erased: the engine then
    /// counts it as withdrawn, never as live.
    pub stale: bool,
    /// When the vault learned the claim (Unix s), the precedence key.
    pub learned_at: u64,
    /// The claim envelope's occurred start (Unix s).
    pub occurred_start: u64,
    /// The claim envelope's occurred end (Unix s).
    pub occurred_end: u64,
    /// Whether this is the claim the edge's two flags are stamped from: the
    /// winner among the live claims by learned_at, then confidence, then
    /// claim id. No readable claim is marked when that winner is withheld.
    pub winner: bool,
}
