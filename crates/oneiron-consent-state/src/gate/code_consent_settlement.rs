//! Moved from `crates/oneiron/src/gate/code_consent_settlement.rs` (core split slice 2: consent state below core).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// A policy filter, not a grant. A named person must still hold the exact power.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "mode",
    content = "holders",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CodeConsentSettlementEligibility {
    AllPowerHolders,
    Named(BTreeSet<String>),
}

impl CodeConsentSettlementEligibility {
    pub fn admits(&self, person: EntityId) -> bool {
        match self {
            Self::AllPowerHolders => true,
            Self::Named(holders) => holders.contains(&person.to_hex()),
        }
    }

    pub fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::AllPowerHolders, other) | (other, Self::AllPowerHolders) => other.clone(),
            (Self::Named(left), Self::Named(right)) => {
                Self::Named(left.intersection(right).cloned().collect())
            }
        }
    }
}

/// Frozen data only. The answering writer must resolve and compare it again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeConsentSettlementSource {
    pub manifest_ref: String,
    pub body_hash: [u8; 32],
    pub version: u16,
    pub origin: CodeConsentSettlementOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeConsentSettlementOrigin {
    Seeded,
    Authored,
    Narrowing,
}

impl CodeConsentSettlementOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Seeded => "seeded",
            Self::Authored => "authored",
            Self::Narrowing => "narrowing",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedCodeConsentSettlement {
    pub eligible: CodeConsentSettlementEligibility,
    pub sources: Vec<CodeConsentSettlementSource>,
    /// Distinct authored baselines remain a conflict even under a common meet.
    pub conflicting_authored_rows: bool,
}
