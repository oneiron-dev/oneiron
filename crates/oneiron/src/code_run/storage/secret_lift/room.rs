//! The positive MESSAGE-linked lift proposals still in one room's overlay.

use serde::{Deserialize, Serialize};

use super::{CodeRunSecretLiftProposalView, lift_proposal};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::{Result, Vault};

/// Selects an actual room and its named off-record stretch. No body is read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunRoomSecretLiftRequest {
    pub room_ref: String,
    pub session_ref: String,
}

impl Vault {
    /// Lists positive MESSAGE-linked secret lift proposals from this room's
    /// overlay, under the owner's live participant and historical sight.
    /// This is not a taint or clearance query: absent proposals say nothing
    /// about runs with no visible MESSAGE or other result occurrences.
    ///
    /// # Errors
    /// An invalid room id, an absent room stretch, a proof or membership
    /// that no longer holds, or malformed stored metadata.
    pub fn code_run_room_secret_lifts_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        request: &CodeRunRoomSecretLiftRequest,
    ) -> Result<Vec<CodeRunSecretLiftProposalView>> {
        let actor = owner.actor_for_read(self)?;
        let room = EntityId::from_hex(&request.room_ref)?;
        let session = self
            .off_record_session_vault()
            .bind_in_room(&request.session_ref, room, actor)?
            .for_participant(actor)?;
        session
            .code_run_room_secret_marks_as_owner(owner, room)?
            .into_iter()
            .map(|(key, reason)| lift_proposal(&key, reason).map(Into::into))
            .collect()
    }
}
