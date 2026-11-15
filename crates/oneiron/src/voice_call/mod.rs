//! Transcripts of voice calls with other people (UNBUILT-02 PR 3; Engine
//! ruling VOICE-CALL-SCOPE, corrected 15 Nov 22:53). A phone call is kept
//! like any other conversation, under the owner's own Setting: the engine
//! sets no legal limit, since recording-consent rules differ by place and
//! bind the vault's owner, who chooses. The keys live in the Setting
//! catalogue ([`setting_keys`]); the server reads them when a call opens.
//! With `voice.call_transcripts.announce` on, the agent opens the call by
//! saying it is transcribed (UNBUILT-02 PR 3B).

pub mod setting_keys;

use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::{MemoryResult, WitnessReceipt, WitnessTurn};

impl Vault {
    /// Whether calls with other people keep their transcripts here: the
    /// vault's `voice.call_transcripts.keep`, on unless the owner turned it
    /// off. With it off a call keeps only its two divider rows.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn keeps_call_transcripts(&self) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(setting_keys::CALL_TRANSCRIPTS_KEEP
            .read_in_txn(self, &txn, &[], None)?
            .value)
    }

    /// Whether a call with another person opens with the agent saying it is
    /// transcribed: the vault's `voice.call_transcripts.announce`, on unless
    /// the owner turned it off. A row that does not read reads as on.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn announces_call_transcripts(&self) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(setting_keys::CALL_TRANSCRIPTS_ANNOUNCE
            .read_in_txn(self, &txn, &[], None)?
            .value)
    }

    /// The name a call's opening line gives the vault's owner: the display
    /// name on the owner's own PERSON row. `None` when the vault records no
    /// live owner PERSON, several, or one with no name of its own: the
    /// embedded owner's seeded name names the role, not the person.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn call_owner_display_name(&self) -> Result<Option<String>> {
        let txn = self.store.env.read_txn()?;
        let owners = crate::policy_model::owners_in_txn(self, &txn)?;
        let [owner] = owners.as_slice() else {
            return Ok(None);
        };
        let crate::vault::LiveEntityRow::Live {
            entity_type: crate::registry::ENTITY_TYPE_PERSON,
            body,
        } = crate::vault::live_entity_row_in_txn(&self.store, &txn, owner)?
        else {
            return Ok(None);
        };
        Ok(oneiron_records::context_board::people::person_name(&body)
            .map(|name| name.trim().to_owned())
            .filter(|name| !name.is_empty() && name != crate::vault::EMBEDDED_OWNER_ACTOR_NAME))
    }

    /// Witnesses one turn of a call with another person, written by the
    /// answering `agent`, and holds the conversation's turns in the
    /// conversation's own thread SESSION in the same write
    /// (PHONE-CALL-SESSION = A, as UNBUILT-02-SITTING = A rules for mail and
    /// LINE threads). That SESSION is no actor's sitting, so no sitting's
    /// close learns from a stranger's words.
    ///
    /// # Errors
    ///
    /// The turn names no conversation id, the witness refuses it, or the
    /// thread SESSION does not hold.
    pub fn witness_call_turn(
        &self,
        agent: EntityId,
        turn: &WitnessTurn,
    ) -> MemoryResult<WitnessReceipt> {
        let conversation = EntityId::from_hex(&turn.conversation_ref)?;
        let now = self.now_recorded_at();
        self.memory(agent, EdgeActorClass::Agent)
            .witness_with_route_prepare_and_txn_effect(
                turn,
                None,
                crate::store::Callback::Audited,
                || {},
                |_| Ok(None),
                |txn| {
                    crate::ingest::hold_in_thread_session_in_txn(
                        self,
                        txn,
                        agent,
                        conversation,
                        now,
                    )
                },
            )
    }
}
