//! Moved from `crates/oneiron/src/policy_model/owner_rows/world_privacy_will/sdk.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::policy_model::owner_rows::world_privacy_will::record::parse_revision;
use oneiron_authority::authority::ModelOrder;
use oneiron_authority::authority::PolicyRevision;
use oneiron_authority::authority::ReadLocation;
use oneiron_authority::authority::SealedCopies;
use oneiron_authority::authority::WorldPrivacy;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Where the world may be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum WorldReadInput {
    /// Only on one machine the owner marked "yours", as hex.
    OneMachine {
        machine: String,
    },
    MyMachines,
    Everywhere,
}

/// Where the world's sealed copies may rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorldSealedInput {
    Off,
    MyMachines,
    CloudAndMyMachines,
}

/// One request to change a world's settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorldPrivacySetInput {
    /// The WORLD row, as hex.
    pub world: String,
    pub read: WorldReadInput,
    pub sealed: WorldSealedInput,
    /// The model routes the world prefers, in order; none keeps the vault's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub models: Option<Vec<String>>,
    /// The settings revision the agent read, as 64 hex; none takes the
    /// current one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen: Option<String>,
}

impl WorldPrivacySetInput {
    /// The world, the settings and the revision the input names.
    ///
    /// # Errors
    /// [`Error::InvalidConfig`] for an id or a revision that is not hex of
    /// its length.
    pub fn parse(&self) -> Result<(EntityId, WorldPrivacy, Option<PolicyRevision>)> {
        let id = |hex: &str| {
            EntityId::from_hex(hex)
                .map_err(|_| Error::InvalidConfig("a world-privacy id is 32 hex".to_owned()))
        };
        let read = match &self.read {
            WorldReadInput::OneMachine { machine } => ReadLocation::OneMachine(id(machine)?),
            WorldReadInput::MyMachines => ReadLocation::MyMachines,
            WorldReadInput::Everywhere => ReadLocation::Everywhere,
        };
        let sealed = match self.sealed {
            WorldSealedInput::Off => SealedCopies::Off,
            WorldSealedInput::MyMachines => SealedCopies::MyMachines,
            WorldSealedInput::CloudAndMyMachines => SealedCopies::CloudAndMyMachines,
        };
        let models = self
            .models
            .clone()
            .map_or(ModelOrder::Inherit, ModelOrder::Ordered);
        let seen = self
            .seen
            .as_deref()
            .map(|seen| {
                parse_revision(seen).ok_or_else(|| {
                    Error::InvalidConfig("a world-privacy revision is 64 hex".to_owned())
                })
            })
            .transpose()?;
        Ok((
            id(&self.world)?,
            WorldPrivacy {
                read,
                sealed,
                models,
            },
            seen,
        ))
    }
}
