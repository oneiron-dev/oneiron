//! Moved from `crates/oneiron/src/receipt/pack_attribution.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// A contribution check is distinct from loading or citing an input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ContributionCheck {
    pub receipt: String,
    pub contributed: bool,
}

/// A derived-from edge the run actually used, directed from output to input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UsedProvenanceEdge {
    pub derived: EntityId,
    pub source: EntityId,
    pub check: Option<ContributionCheck>,
}

/// An attributed contribution by a loaded skill, including a team pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillContribution {
    pub skill: EntityId,
    pub check: ContributionCheck,
}

/// The lineage-credit controls in effect for this run. No depth cap means the
/// full used chain; a zero decay or disabled credit passes no late credit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CreditOptions {
    pub enabled: bool,
    pub depth_cap: Option<u32>,
    pub check_every_hop: bool,
}

pub fn reference(text: &str) -> Result<()> {
    if text.is_empty() || text.len() > 256 || text.chars().any(char::is_control) {
        return Err(Error::InvalidClaimBody(
            "an attribution reference is 1..=256 bytes without controls",
        ));
    }
    Ok(())
}
