//! Moved from `crates/oneiron/src/skill_optimize/gate/measurement.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::gate::*;
pub use oneiron_verb_wire::skill_optimize::gate::measurement::PreferredResponse;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::OnceLock;

/// A response-only preference frozen before either version's instructions or
/// an outcome label is read. The pair is two held-out responses whose
/// common-rubric scores are closest; this reference identifies that pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindPreference {
    pub pair_ref: String,
    pub preferred: PreferredResponse,
}

/// A pair measured on the same held-out basis. Neither number votes at the scalar gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPair {
    pub before: f32,
    pub after: f32,
}

/// Judge agreement with the observed outcome on an axis with labels.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldAxisScore {
    pub before: f32,
    pub after: f32,
    pub labelled_receipts: u64,
}

/// The judge against the human picks in the skill's anchor (ARCH-0053: the
/// anchor grows through settled outcomes and human picks). A pick between the
/// judge's answer and another's scores it; a pick between two answers of one
/// judge, a retest flip, or of two other judges is counted but scores none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorLabelScore {
    /// The judge that answers now; `None` before a swap pass named one.
    pub judge: Option<String>,
    /// The scorer revision this score was read under: the verdict's
    /// `judge_revision`, beside the incumbent's `model@version` above.
    pub judge_revision: String,
    pub labels: u64,
    /// Picks between this judge's answer and another judge's.
    pub scored: u64,
    /// Of those, the picks that chose this judge's answer.
    pub agreed: u64,
    /// Hash of each label's ask id and chosen option, in anchor order.
    pub digest: String,
}

/// Measurements made outside the write transaction, sealed with the scored basis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeMeasurements {
    pub structural: AuditPair,
    pub contrastive: AuditPair,
    /// Response-only preferences fixed before scoring either rubric.
    pub blind_preferences: Vec<BlindPreference>,
    pub world_axes: BTreeMap<String, WorldAxisScore>,
    /// Hash of receipt ids AND their observed labels in the scored snapshot.
    pub world_labels_digest: String,
    /// The judge against the human picks in the skill's anchor, read before scoring.
    pub anchor: AnchorLabelScore,
    /// The pin of the judge rubric the scoring read, taken in the pre-score
    /// transaction, beside the verdict's `judge_revision` (FIX 3585): the
    /// rubric text's BLAKE3, lower hex; `None` while no rubric is in force.
    pub judge_rubric_digest: Option<String>,
}

/// A complete, independently checked held-out replay. Counts come from the
/// decided hidden-flaw findings, not from the executor's self-assessment. Every
/// objective is checked, so held-out honesty measurements have sampling probability one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HonestyReplayObservation {
    pub receipt: String,
    pub checked_objectives: u32,
    pub hidden_flaws: u32,
}
