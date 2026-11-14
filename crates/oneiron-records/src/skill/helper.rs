//! Moved from `crates/oneiron/src/skill/helper.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::skill::call::frozen::amend::CallableAmendOutcome;
pub use oneiron_verb_wire::skill::call::frozen::amend::CallableAmendRequest;
pub use oneiron_verb_wire::skill::helper::CallableCard;
pub use oneiron_verb_wire::skill::helper::CallableCardView;
pub use oneiron_verb_wire::skill::helper::SkillForkRequest;
pub use oneiron_verb_wire::skill::helper::SkillSaveRequest;
pub use oneiron_verb_wire::skill::helper::SkillSourceFile;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value as JsonValue;

pub fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(reason))
}

/// One frozen case: the arguments a call took and the result it should give.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallableCase {
    /// The receipt or task the case was frozen from.
    pub case_ref: String,
    pub arguments: JsonValue,
    pub expected: JsonValue,
    /// Who supplied the case. A helper's own author never supplies its gate.
    pub source_author: Option<EntityId>,
}

/// What the shared paired measurement says of a helper against its parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperPairedVerdict {
    /// Its sufficiency card found the helper not worse.
    NotWorse,
    /// Its card found the helper worse.
    Worse,
    /// No finished card yet, or one that reads unknown.
    Pending,
}

/// A pass rate before and after: the incumbent (the parent helper, or no
/// helper at all) against the candidate.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct HarnessScore {
    pub baseline: f64,
    pub candidate: f64,
}

impl HarnessScore {
    #[must_use]
    pub fn delta(&self) -> f64 {
        self.candidate - self.baseline
    }

    fn validate(&self) -> Result<()> {
        if (0.0..=1.0).contains(&self.baseline) && (0.0..=1.0).contains(&self.candidate) {
            Ok(())
        } else {
            Err(invalid("a harness score is a pass rate in [0, 1]"))
        }
    }
}

/// A helper's standing promotion verdict, bound to the exact content scored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallableGateVerdict {
    pub skill: EntityId,
    pub content_hash: Option<String>,
    pub in_sample: HarnessScore,
    pub held_out: HarnessScore,
    pub in_sample_cases: usize,
    pub held_out_cases: usize,
    /// The shared paired measurement read, by its digest.
    pub measurement: String,
    /// What that measurement's sufficiency card says of the helper.
    pub paired: HelperPairedVerdict,
    pub accepted: bool,
    pub reason: String,
    pub at: u64,
}
