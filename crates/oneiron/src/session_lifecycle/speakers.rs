//! Who spoke in a sitting (FIX 2015), kept on its lifecycle record so an
//! ended sitting still names them after this process's presence is gone:
//! every agent bound as its answerer, and every participant with the display
//! name it had when bound. Bindings accumulate and never overwrite: two
//! answerers stay two, so a reader sees that "assistant" is ambiguous there.
//! An actor's erase takes its bindings out and counts them (FIX 3520); a
//! sitting that lost one cannot prove a name unique any more.
use heed::RwTxn;
use serde::{Deserialize, Serialize};

use super::{RECORDS, SessionKey, open_session_in_txn, validated_record};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};

#[doc(hidden)]
pub use oneiron_records::session_lifecycle::speakers::{SessionParticipant, SessionSpeakers};

/// The name a speaker binds under, as it stands in this write: an agent
/// definition's display name, else its agent id; a person's stored display
/// name. `None` for any other entity, or a person with no name.
fn speaker_name_in_txn(vault: &Vault, wtxn: &RwTxn<'_>, actor: EntityId) -> Result<Option<String>> {
    match vault.get_entity_type_in_txn(wtxn, &actor)? {
        Some(ENTITY_TYPE_AGENT_DEF) => {
            let definition = vault.read_agent_definition_in_txn(wtxn, &actor)?;
            Ok(Some(definition.display_name.unwrap_or(definition.agent_id)))
        }
        Some(ENTITY_TYPE_PERSON) => crate::reaction::person_name_in(vault, wtxn, actor),
        _ => Ok(None),
    }
}

/// Binds `agent` as `session`'s answerer and each of `participants` under
/// its name as it stands in this write. A sitting with no lifecycle record,
/// an id with no name, and a binding already held add nothing.
pub(crate) fn bind_session_speakers_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    session: &EntityId,
    agent: Option<EntityId>,
    participants: &[EntityId],
) -> Result<()> {
    let Some(record) = RECORDS.get(&vault.store, wtxn, session)? else {
        return Ok(());
    };
    let mut record = validated_record(record)?;
    let mut changed = false;
    if let Some(agent) = agent {
        changed |= record.speakers.bind_agent(agent);
    }
    for actor in participants {
        if let Some(name) = speaker_name_in_txn(vault, wtxn, *actor)? {
            changed |= record.speakers.bind_participant(*actor, name);
        }
    }
    if changed {
        RECORDS.put(&vault.store, wtxn, session, &record)?;
    }
    Ok(())
}

/// An erased actor's bindings, out of every sitting's record (FIX 3520): its
/// answerer and participant entries go with the names they kept, and each
/// record counts what went. Runs in the erase's transaction.
pub(crate) fn erase_session_speaker_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let mut named = Vec::new();
    for (session, mut record) in RECORDS.scan(&vault.store, wtxn)? {
        if record.speakers.forget(*actor) {
            named.push((session, record));
        }
    }
    for (session, record) in named {
        RECORDS.put(&vault.store, wtxn, &session, &record)?;
    }
    Ok(())
}

impl Vault {
    /// Binds the answering `agent` to the sitting open for `key` (FIX 2015),
    /// with the agent and the sitting's person as participants under their
    /// names as they stand now. Returns the sitting; `None` when none is
    /// open for `key`.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn bind_session_answer(
        &self,
        key: SessionKey,
        agent: EntityId,
    ) -> Result<Option<EntityId>> {
        self.with_write_txn_grouped(|wtxn| {
            let Some((session, _)) = open_session_in_txn(&self.store, wtxn, key)? else {
                return Ok(None);
            };
            bind_session_speakers_in_txn(self, wtxn, &session, Some(agent), &[agent, key.actor])?;
            Ok(Some(session))
        })
    }

    /// Binds each of `ids` to `session` as a participant under its name as
    /// it stands now (FIX 2015): the durable trace of a presence this
    /// process forgets on restart.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn bind_session_participants(&self, session: EntityId, ids: &[EntityId]) -> Result<()> {
        self.with_write_txn_grouped(|wtxn| {
            bind_session_speakers_in_txn(self, wtxn, &session, None, ids)
        })
    }

    /// The speakers bound to `session`; empty for a sitting with none bound
    /// or no lifecycle record.
    ///
    /// # Errors
    ///
    /// Storage errors, or an unsupported record version.
    pub fn session_speakers(&self, session: &EntityId) -> Result<SessionSpeakers> {
        Ok(self
            .session_lifecycle_record(session)?
            .map_or_else(SessionSpeakers::default, |record| record.speakers))
    }

    /// Every TURN `session`'s membership rows name, by `(learned_at, id)`,
    /// whoever spoke it; `None` when the sitting has no membership row at
    /// all, as one recorded before them has none.
    pub(crate) fn session_member_turns(&self, session: &EntityId) -> Result<Option<Vec<EntityId>>> {
        let rtxn = self.store.env.read_txn()?;
        self.member_turns_in_txn(&rtxn, session, |_, _| true)
    }
}
