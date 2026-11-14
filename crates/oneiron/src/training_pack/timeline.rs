//! A run's data timeline (ARCH-0053 #training-timeline): where a run changed
//! its data mixture or restarted from an earlier checkpoint, so its record
//! says which mixture trained which interval. A final dataset hash alone
//! cannot. The trainer reports it in its receipt under
//! [`TIMELINE_RECEIPT_KEY`]; the run's result keeps it typed once its shape
//! holds. Planned phases stay apart from executed ones, and a failed or
//! aborted attempt stays on the record.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Result;
use crate::task_verb::hex32;

use super::invalid;

/// The key a trainer's receipt carries its data timeline under.
pub const TIMELINE_RECEIPT_KEY: &str = "timeline";

/// A point inside one run: the optimizer step and the tokens trained so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingBoundary {
    pub step: u64,
    pub tokens: u64,
}

impl TrainingBoundary {
    /// The run's start, at its starting checkpoint.
    pub const START: Self = Self { step: 0, tokens: 0 };
}

/// A data mixture, pinned by the BLAKE3 of its definition, with the weight
/// of each source in it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MixturePin {
    #[serde(with = "hex32")]
    pub definition_blake3: [u8; 32],
    pub weights: BTreeMap<String, f64>,
}

/// The earlier checkpoint a phase restarted from, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentCheckpoint {
    pub step: u64,
    #[serde(with = "hex32")]
    pub blake3: [u8; 32],
    pub reason: String,
}

/// How an executed phase ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseOutcome {
    Completed,
    Failed,
    Aborted,
}

/// One phase of the recipe's schedule: from this boundary on, this mixture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannedPhase {
    pub from: TrainingBoundary,
    pub mixture: MixturePin,
}

/// One phase as it ran, a failed or aborted attempt included.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutedPhase {
    pub from: TrainingBoundary,
    pub to: TrainingBoundary,
    pub mixture: MixturePin,
    /// The earlier checkpoint this phase restarted from; none when it went
    /// on from where the phase before it ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<ParentCheckpoint>,
    pub outcome: PhaseOutcome,
}

/// The phases the recipe planned, and apart from them the phases that ran.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataTimeline {
    #[serde(default)]
    pub planned: Vec<PlannedPhase>,
    pub executed: Vec<ExecutedPhase>,
}

impl DataTimeline {
    /// The timeline a trainer's receipt carries, checked; none when it
    /// carries none (a run with no mixture change and no restart).
    pub(super) fn from_receipt(receipt: &Value) -> Result<Option<Self>> {
        let Some(value) = receipt
            .get(TIMELINE_RECEIPT_KEY)
            .filter(|value| !value.is_null())
        else {
            return Ok(None);
        };
        let timeline: Self = serde_json::from_value(value.clone())
            .map_err(|e| invalid(&format!("the training receipt's data timeline: {e}")))?;
        timeline.validate()?;
        Ok(Some(timeline))
    }

    fn validate(&self) -> Result<()> {
        if self.executed.is_empty() {
            return Err(invalid(
                "the training receipt's data timeline names no executed phase",
            ));
        }
        let mut last_step = None;
        for phase in &self.planned {
            phase.mixture.validate()?;
            if last_step.is_some_and(|step| phase.from.step <= step) {
                return Err(invalid(
                    "the training receipt's planned phases must start at rising steps",
                ));
            }
            last_step = Some(phase.from.step);
        }
        let mut previous = None;
        for phase in &self.executed {
            phase.validate(previous)?;
            previous = Some(phase);
        }
        Ok(())
    }
}

impl ExecutedPhase {
    /// A phase ends at or after its start. A restart names a non-blank
    /// reason and a checkpoint at or before its start; a phase that goes on
    /// starts where a completed phase before it ended (the first at the
    /// run's start), never after a failed or aborted one.
    fn validate(&self, previous: Option<&Self>) -> Result<()> {
        self.mixture.validate()?;
        if self.to.step < self.from.step || self.to.tokens < self.from.tokens {
            return Err(invalid(
                "a phase in the training receipt's data timeline ends before it starts",
            ));
        }
        if let Some(parent) = &self.parent {
            if parent.reason.trim().is_empty() || parent.step > self.from.step {
                return Err(invalid(
                    "a restart in the training receipt's data timeline names its reason and \
                     an earlier checkpoint",
                ));
            }
            return Ok(());
        }
        let went_on = match previous {
            None => self.from == TrainingBoundary::START,
            Some(previous) => {
                previous.outcome == PhaseOutcome::Completed && self.from == previous.to
            }
        };
        if !went_on {
            return Err(invalid(
                "a phase in the training receipt's data timeline that names no parent \
                 checkpoint goes on from where a completed phase ended",
            ));
        }
        Ok(())
    }
}

impl MixturePin {
    /// Every source is named, every weight finite and nonnegative, and not
    /// all of them zero.
    fn validate(&self) -> Result<()> {
        let named = self.weights.keys().all(|source| !source.trim().is_empty());
        let finite = self
            .weights
            .values()
            .all(|weight| weight.is_finite() && *weight >= 0.0);
        if !named || !finite || !self.weights.values().any(|weight| *weight > 0.0) {
            return Err(invalid(
                "a mixture in the training receipt's data timeline names each source with a \
                 finite, nonnegative weight, not all zero",
            ));
        }
        Ok(())
    }
}
