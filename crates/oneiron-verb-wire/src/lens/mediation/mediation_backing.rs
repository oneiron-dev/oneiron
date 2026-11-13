//! Moved from `crates/oneiron/src/lens/mediation/mediation_backing.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_lens_wire::lens::wire_ids::LensHandleRole;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LensBackingTargetKind {
    Entity,
    Claim,
}

/// The read reach a selection may carry: [`LensHandleRole`] minus
/// [`LensHandleRole::ActionTarget`]. An action-target binding is reach for the action
/// backchannel, so it can never be laundered into a selection handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LensReadReach {
    ClaimSet,
    EntitySet,
    Timeline,
    QueryResult,
}

impl TryFrom<LensHandleRole> for LensReadReach {
    type Error = Error;

    fn try_from(role: LensHandleRole) -> Result<Self> {
        match role {
            LensHandleRole::ClaimSet => Ok(Self::ClaimSet),
            LensHandleRole::EntitySet => Ok(Self::EntitySet),
            LensHandleRole::Timeline => Ok(Self::Timeline),
            LensHandleRole::QueryResult => Ok(Self::QueryResult),
            LensHandleRole::ActionTarget => Err(Error::InvalidConfig(
                "lens action-target bindings are not selectable read reach".to_string(),
            )),
        }
    }
}
