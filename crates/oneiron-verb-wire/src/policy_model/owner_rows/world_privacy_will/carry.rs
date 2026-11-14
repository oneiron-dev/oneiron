//! Moved from `crates/oneiron/src/policy_model/owner_rows/world_privacy_will/carry.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::policy_model::owner_rows::world_privacy_will::record::WorldPrivacyRequestStatus;
use oneiron_authority::authority::WorldPrivacy;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

/// The domain a leg's transcript is signed under.
pub const CARRY_DOMAIN: &str = "oneiron/world-privacy/connect-carry/v1";

/// Which way a carried leg goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ForeignWorldPrivacyLeg {
    /// An agent's ask, from the vault that received the world to the vault
    /// that owns it.
    Ask,
    /// The owning vault's answer, back to the asking vault.
    Answer,
}

/// The signed body of one leg.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForeignWorldPrivacyCarry {
    pub leg: ForeignWorldPrivacyLeg,
    /// The pact, as 64 hex.
    pub pact: String,
    /// The pact's consent epoch when the leg was signed.
    pub epoch: u64,
    /// The vault whose host signed, as 64 hex.
    pub source_vault: String,
    /// The vault the leg is for, as 64 hex.
    pub recipient_vault: String,
    /// The world as its owning vault names it, as hex.
    pub world: String,
    /// The asking vault's request, as hex: both legs name it.
    pub ask: String,
    /// The agent that asked, as hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// The settings asked for.
    pub settings: WorldPrivacy,
    /// On an answer: how the owning vault's holders settled the ask.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<WorldPrivacyRequestStatus>,
}

impl ForeignWorldPrivacyCarry {
    /// What the sending host signs: the body under its own domain.
    pub fn transcript(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(&(CARRY_DOMAIN, self))
            .map_err(|_| Error::InvalidConfig("world-settings delivery encoding failed".to_owned()))
    }
}

/// One signed leg, as an owner carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForeignWorldPrivacyDelivery {
    pub body: ForeignWorldPrivacyCarry,
    /// The sending host's signature over the body's transcript, as hex.
    pub signature: String,
}

/// `vault.federation.connect.world_privacy.export`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForeignWorldPrivacyExportRequest {
    /// The world-privacy request, as hex: a pending ask on a world a
    /// connected vault owns, or a settled one a connected vault's agent sent
    /// here.
    pub request: String,
}
