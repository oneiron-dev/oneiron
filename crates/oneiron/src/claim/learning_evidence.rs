//! Anchored learning evidence and retest request vocabulary.

use serde::{Deserialize, Serialize};

use crate::claim::learning_estimate::EstimateForm;
use crate::claim::learning_predicate::LearningPredicate;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::task_type_ref::TypeRef;
use crate::side_table::{self, Named, SideTable};

#[doc(hidden)]
use oneiron_verb_wire::claim::learning_evidence::MAX_CATEGORY_BYTES;
#[doc(hidden)]
pub use oneiron_verb_wire::claim::learning_evidence::{
    Anchor, EvidenceRow, EvidenceSource, LearningEvidence, Observation,
};

/// Evidence rows. Key: cell digest + receipt reference.
pub(crate) const EVIDENCE: SideTable<([u8; 32], String), EvidenceRow, Named> =
    SideTable::new(&side_table::LEARNING_EVIDENCE);

/// One same-case retest by one scorer.
#[derive(Debug, Clone, PartialEq)]
pub struct Retest {
    /// The scorer: a judge skill, a critic lens, any scoring subject.
    pub scorer: EntityId,
    /// The scorer's executor at revision.
    pub executor: String,
    pub axis: String,
    pub type_ref: Option<TypeRef>,
    /// The retest receipt: one row per receipt.
    pub receipt: String,
    pub first: RetestScore,
    pub second: RetestScore,
    pub at: u64,
}

/// One of the two scores a retest compares.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RetestScore {
    /// A pass/fail verdict.
    Pass(bool),
    /// A numeric score.
    Value(f64),
}
