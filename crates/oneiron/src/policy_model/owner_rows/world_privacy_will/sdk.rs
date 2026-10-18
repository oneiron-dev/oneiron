//! `vault.worlds.privacy.set`, the agent's door (FIX 4480): its input names a
//! world, the settings and the revision read, never an owner or a Grant; its
//! answer says whether the change applied, waits as a proposal, or waits as an
//! ask. The run's own actor is the agent whose request it is.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::authority::{ModelOrder, PolicyRevision, ReadLocation, SealedCopies, WorldPrivacy};
use crate::error::{Error, Result};

use super::WorldPrivacyOutcome;
use super::record::parse_revision;

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

/// What the request came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum WorldPrivacySetOutput {
    /// The settings changed, within the agent's Grant: the receipt id. Every
    /// holder was told, with a one-tap undo.
    Applied { receipt: String },
    /// A tighten no Grant line names waits for a holder: the proposal id.
    Proposed { proposal: String },
    /// A widen waits for the holders' yes: the request id, and the decision
    /// ask its holders see once queued. The run may wait on it; the widen is
    /// never the agent's own act.
    Asked {
        ask: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ask_seq: Option<u64>,
    },
}

impl From<&WorldPrivacyOutcome> for WorldPrivacySetOutput {
    fn from(outcome: &WorldPrivacyOutcome) -> Self {
        match outcome {
            WorldPrivacyOutcome::Applied(receipt) => Self::Applied {
                receipt: receipt.receipt_id.clone(),
            },
            WorldPrivacyOutcome::Proposed(request) => Self::Proposed {
                proposal: request.request_id.clone(),
            },
            WorldPrivacyOutcome::Asked(request) => Self::Asked {
                ask: request.request_id.clone(),
                ask_seq: request.ask,
            },
        }
    }
}
