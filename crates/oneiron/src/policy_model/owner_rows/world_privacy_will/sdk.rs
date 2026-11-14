//! `vault.worlds.privacy.set`, the agent's door (FIX 4480): its input names a
//! world, the settings and the revision read, never an owner or a Grant; its
//! answer says whether the change applied, waits as a proposal, or waits as an
//! ask. The run's own actor is the agent whose request it is, and the one
//! actor that waits on it, by the handle its answer names (FIX 4706).

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::authority::task_ask_handle::TaskAskHandle;
use crate::authority::{ModelOrder, PolicyRevision, ReadLocation, SealedCopies, WorldPrivacy};
use crate::error::{Error, Result};

use super::WorldPrivacyOutcome;
use super::record::{WorldPrivacyRequest, parse_revision};

#[doc(hidden)]
pub use oneiron_verb_wire::policy_model::owner_rows::world_privacy_will::sdk::{
    WorldPrivacySetInput, WorldReadInput, WorldSealedInput,
};

/// What the request came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum WorldPrivacySetOutput {
    /// The settings changed, within the agent's Grant: the receipt id. Every
    /// holder was told, with a one-tap undo.
    Applied { receipt: String },
    /// A tighten no Grant line names waits for a holder: the proposal id,
    /// and the handle `wait` (or the run's `tasks.wait({request})`) waits on
    /// it by, until a holder applies or declines it. `grant_omitted` names
    /// why a Grant that named it was passed over (`pact_standing_lapsed`,
    /// FIX 7548), when one was.
    Proposed {
        proposal: String,
        wait: TaskAskHandle,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant_omitted: Option<String>,
    },
    /// A widen waits for the holders' yes: the request id, the decision ask
    /// its holders see once queued, and the handle `wait` (or the run's
    /// `tasks.wait({request})`) waits on it by, until a holder applies or
    /// declines it. The widen is never the agent's own act. `grant_omitted`
    /// as for a proposal.
    Asked {
        ask: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ask_seq: Option<u64>,
        wait: TaskAskHandle,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant_omitted: Option<String>,
    },
}

impl TryFrom<&WorldPrivacyOutcome> for WorldPrivacySetOutput {
    type Error = Error;

    /// # Errors
    /// [`Error::CorruptedIndex`] for a request whose id does not read back.
    fn try_from(outcome: &WorldPrivacyOutcome) -> Result<Self> {
        // The request's immutable id is its wait's (FIX 4706).
        let wait = |request: &WorldPrivacyRequest| -> Result<TaskAskHandle> {
            Ok(TaskAskHandle {
                group_ref: request.id()?,
            })
        };
        Ok(match outcome {
            WorldPrivacyOutcome::Applied(receipt) => Self::Applied {
                receipt: receipt.receipt_id.clone(),
            },
            WorldPrivacyOutcome::Proposed(request) => Self::Proposed {
                proposal: request.request_id.clone(),
                wait: wait(request)?,
                grant_omitted: request.grant_omitted.clone(),
            },
            WorldPrivacyOutcome::Asked(request) => Self::Asked {
                ask: request.request_id.clone(),
                ask_seq: request.ask,
                wait: wait(request)?,
                grant_omitted: request.grant_omitted.clone(),
            },
        })
    }
}
