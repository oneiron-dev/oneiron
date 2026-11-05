//! A handoff keeps its replay address and result after its evidence is erased.
use serde::{Deserialize, Serialize};

use super::{FeedbackTriageHandoff, FeedbackTriageSourceRef, invalid_job};
use crate::{EntityId, Result};

/// The source a handoff still retains, or its content-free erased identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum FeedbackTriageHandoffSource {
    /// The exact revision and its retained evidence.
    Retained {
        /// The item and revision.
        source_ref: FeedbackTriageSourceRef,
        /// The ASSET holding that revision.
        evidence: EntityId,
    },
    /// The owner erased the evidence; only the item's name remains.
    Erased {
        /// The source's name.
        source: String,
        /// The item's id in that source.
        id: String,
        /// Vault seconds the erase was settled.
        at: u64,
    },
}

impl FeedbackTriageHandoffSource {
    pub(super) fn name(&self) -> (&str, &str) {
        match self {
            Self::Retained { source_ref, .. } => (&source_ref.source, &source_ref.id),
            Self::Erased { source, id, .. } => (source, id),
        }
    }

    pub(super) fn matches(&self, requested: &FeedbackTriageSourceRef) -> bool {
        match self {
            Self::Retained { source_ref, .. } => source_ref == requested,
            Self::Erased { source, id, .. } => source == &requested.source && id == &requested.id,
        }
    }
}

impl FeedbackTriageHandoff {
    pub(crate) fn retained(&self) -> Result<(&FeedbackTriageSourceRef, EntityId)> {
        match &self.source {
            FeedbackTriageHandoffSource::Retained {
                source_ref,
                evidence,
            } => Ok((source_ref, *evidence)),
            FeedbackTriageHandoffSource::Erased { .. } => Err(invalid_job()),
        }
    }

    pub(super) fn erased_at(&self) -> Option<u64> {
        match &self.source {
            FeedbackTriageHandoffSource::Erased { at, .. } => Some(*at),
            FeedbackTriageHandoffSource::Retained { .. } => None,
        }
    }

    pub(super) fn erase_source(&mut self, at: u64) {
        if let FeedbackTriageHandoffSource::Retained { source_ref, .. } = &self.source {
            self.source = FeedbackTriageHandoffSource::Erased {
                source: source_ref.source.clone(),
                id: source_ref.id.clone(),
                at,
            };
        }
        self.work = None;
    }
}
