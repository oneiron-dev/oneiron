//! Moved from `crates/oneiron/src/task_verb/brief.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::task_verb::brief::BriefConstraints;
pub use oneiron_verb_wire::task_verb::brief::BriefIntent;
pub use oneiron_verb_wire::task_verb::brief::Care;
pub use oneiron_verb_wire::task_verb::brief::Criterion;
pub use oneiron_verb_wire::task_verb::brief::EscalationTrigger;
pub use oneiron_verb_wire::task_verb::brief::SpawnPins;
pub use oneiron_verb_wire::task_verb::brief::TypeRef;
pub(crate) use oneiron_verb_wire::task_verb::brief::decode_hex;
pub(crate) use oneiron_verb_wire::task_verb::brief::hex32;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// A context pack pinned by digest: a pack ref promises no immutability, so
/// the brief keeps what it read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PinnedPack {
    pub pack_ref: EntityId,
    #[serde(default)]
    pub context_version: Option<u64>,
    #[serde(default)]
    pub retrieval_run_id: Option<EntityId>,
    #[serde(with = "hex32")]
    #[schemars(with = "String")]
    pub digest: [u8; 32],
}

/// One read-first handle pinned by digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PinnedRef {
    pub target: EntityId,
    #[serde(default)]
    pub frontier: Option<Vec<u8>>,
    #[serde(with = "hex32")]
    #[schemars(with = "String")]
    pub digest: [u8; 32],
}

/// Provenance of a model-composed brief. Excluded from the digest: who
/// drafted a brief never changes what it asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComposerStamp {
    pub seat: String,
    #[serde(with = "hex32")]
    #[schemars(with = "String")]
    pub one_liner_digest: [u8; 32],
    #[serde(default)]
    pub lens_refs: Vec<EntityId>,
    pub at: u64,
}

/// The version one try was leased under. ATTEMPT payloads and receipts carry
/// it, so a running try is never retargeted by a later revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BriefStamp {
    pub rev: u32,
    #[serde(with = "hex32")]
    #[schemars(with = "String")]
    pub digest: [u8; 32],
    pub type_ref: TypeRef,
}
