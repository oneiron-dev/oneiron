//! Moved from `crates/oneiron/src/critic/review/dissent.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::critic::review::*;
use crate::critic::*;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::critic_lens::invalid_critic_config;
use oneiron_store::model_decision::questions::OutcomeBinding;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriticPrediction {
    pub what: String,
    /// Absolute Unix seconds; absence of a fact by this time is not a negative label.
    pub by_when: u64,
    pub how_checked: OutcomeBinding,
}

impl CriticPrediction {
    pub fn validate(&self, predicted_at: u64) -> Result<()> {
        self.how_checked.validate()?;
        if self.what.trim().is_empty()
            || self.what.len() > MAX_SUGGESTED_EDIT_BYTES
            || self.by_when <= predicted_at
            || self.by_when - predicted_at != self.how_checked.horizon
        {
            return Err(invalid_critic_config(
                "prediction requires what, a future horizon and an outcome binding",
            ));
        }
        Ok(())
    }
}

/// Retained beside the private review, not a vault claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewDissent {
    pub artifact_id: String,
    pub note: Option<EntityId>,
    pub question: Option<EntityId>,
    pub settled_fact: Option<EntityId>,
}
