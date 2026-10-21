//! Session mode persists; active participant presence belongs only to this process.
//! People and agent personas are present; engine upkeep never is. Presence
//! keeps arrival order, earliest first: room hosting settles a tie by who
//! came first, never by id.
use super::*;
use crate::federation::{ScopeAxis, ScopeId};
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Participants one session's presence holds past which this process says
/// so, once, at the crossing. Not a bound: presence of any size is kept.
const PRESENCE_NOTICE: usize = 10_000;
/// Active sessions past which this process says so, once, at the crossing.
/// Not a bound: every session's presence is kept.
const ACTIVE_SESSIONS_NOTICE: usize = 1024;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    #[default]
    Direct,
    Group,
    Council,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPresence {
    pub mode: SessionMode,
    /// Who is here now, earliest arrival first.
    pub active_participant_ids: Vec<EntityId>,
}
impl Vault {
    pub fn session_presence(&self, session: EntityId) -> Result<SessionPresence> {
        let txn = self.store.env.read_txn()?;
        let raw = require_kind(self, &txn, session, ENTITY_TYPE_SESSION)?;
        let body: serde_json::Value = decode(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let mode = body
            .get("mode")
            .map(|v| serde_json::from_value(v.clone()).map_err(|_| invalid("session mode")))
            .transpose()?
            .unwrap_or_default();
        let active_participant_ids = self
            .conversation_presence
            .lock()
            .map_err(|_| state("presence lock"))?
            .get(&session)
            .cloned()
            .unwrap_or_default();
        Ok(SessionPresence {
            mode,
            active_participant_ids,
        })
    }
    /// The facet a session's mode names for the writes made in it (owner
    /// ruling FACET-READ): a credential narrowed to some facets writes there
    /// when it is one of them. `None` when the mode names none.
    pub fn session_facet(&self, session: EntityId) -> Result<Option<EntityId>> {
        let txn = self.store.env.read_txn()?;
        session_facet_of(&require_kind(self, &txn, session, ENTITY_TYPE_SESSION)?)
    }
    /// Sets the session's mode and the facet it names for the writes made in
    /// it, a FACET; with none, the mode names no facet.
    pub fn set_session_mode(
        &self,
        session: EntityId,
        mode: SessionMode,
        facet: Option<EntityId>,
        actor: WriteActor,
    ) -> Result<()> {
        self.set_session_mode_within(session, mode, facet, actor, &ScopeAxis::All)
    }
    /// [`Self::set_session_mode`] by a writer narrowed to `facets` (owner
    /// ruling FACET-READ): it changes only a session whose mode already names
    /// one of them, and any other id answers as a missing session. A writer
    /// never narrowed passes `All`.
    pub fn set_session_mode_within(
        &self,
        session: EntityId,
        mode: SessionMode,
        facet: Option<EntityId>,
        actor: WriteActor,
        facets: &ScopeAxis<ScopeId>,
    ) -> Result<()> {
        let narrowed = !matches!(facets, ScopeAxis::All);
        self.with_write_txn_grouped(|txn| {
            authorize(self, txn, actor)?;
            let raw = match require_kind(self, txn, session, ENTITY_TYPE_SESSION) {
                Err(Error::Record(RecordError::InvalidConversationBody(_))) if narrowed => {
                    return Err(Error::EntityNotFound);
                }
                raw => raw?,
            };
            if narrowed
                && !session_facet_of(&raw)
                    .ok()
                    .flatten()
                    .is_some_and(|placed| facets.contains(&ScopeId(placed)))
            {
                return Err(Error::EntityNotFound);
            }
            if let Some(facet) = facet {
                require_kind(self, txn, facet, ENTITY_TYPE_FACET)?;
            }
            let h =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("session header"))?;
            let mut body: serde_json::Value = decode(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            let map = body.as_object_mut().ok_or(invalid("session body"))?;
            map.insert(
                "mode".into(),
                serde_json::to_value(mode).map_err(|_| invalid("session mode"))?,
            );
            match facet {
                Some(facet) => map.insert("facet_ref".into(), facet.to_hex().into()),
                None => map.remove("facet_ref"),
            };
            map.remove("active_participant_ids");
            self.batch_in()
                .put(
                    &session,
                    ENTITY_TYPE_SESSION,
                    crate::TimeRange {
                        start: h.occurred_start,
                        end: h.occurred_end,
                    },
                    h.learned_at,
                    &encode(&body)?,
                )
                .apply(txn)
        })
    }
    /// Replaces ephemeral presence. It never changes the room ledger, and a
    /// restart starts empty instead of mistaking old presence for membership.
    /// Arrival order is kept: a participant still here keeps its place, and
    /// newcomers follow in the order `ids` names them.
    pub fn set_presence(
        &self,
        session: EntityId,
        ids: &[EntityId],
        actor: WriteActor,
    ) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        authorize(self, &txn, actor)?;
        require_kind(self, &txn, session, ENTITY_TYPE_SESSION)?;
        let mut named = BTreeSet::new();
        let ids: Vec<EntityId> = ids.iter().copied().filter(|id| named.insert(*id)).collect();
        for id in &ids {
            // A PERSON or an AGENT_DEF persona, never a MACHINE: room hosting
            // reads this set as who is here now.
            if require_kind(self, &txn, *id, ENTITY_TYPE_PERSON).is_err() {
                require_kind(self, &txn, *id, ENTITY_TYPE_AGENT_DEF)?;
            }
        }
        drop(txn);
        // Presence is forgotten on restart; who was here is not (FIX 2015):
        // each one joins the sitting's speakers under its name as it stands.
        // A sitting with no lifecycle record keeps none, and a failed write
        // never fails the presence.
        if !ids.is_empty()
            && let Err(error) = self.bind_session_participants(session, &ids)
        {
            tracing::warn!(kind = ?error.kind(), "a sitting's participants were not recorded");
        }
        let mut presence = self
            .conversation_presence
            .lock()
            .map_err(|_| state("presence lock"))?;
        if ids.is_empty() {
            presence.remove(&session);
            return Ok(());
        }
        // Rule 5: presence of any size is kept whole, and no count refuses it.
        if !presence.contains_key(&session) && presence.len() == ACTIVE_SESSIONS_NOTICE {
            tracing::info!(
                sessions = presence.len() + 1,
                "active sessions passed 1,024; every one is kept"
            );
        }
        if presence.get(&session).map_or(0, Vec::len) <= PRESENCE_NOTICE
            && ids.len() > PRESENCE_NOTICE
        {
            tracing::info!(
                participants = ids.len(),
                "a session's presence passed 10,000 participants; every one is kept"
            );
        }
        let mut arrived: Vec<EntityId> = presence
            .get(&session)
            .into_iter()
            .flatten()
            .copied()
            .filter(|id| named.contains(id))
            .collect();
        let stayed: BTreeSet<EntityId> = arrived.iter().copied().collect();
        arrived.extend(ids.into_iter().filter(|id| !stayed.contains(id)));
        presence.insert(session, arrived);
        Ok(())
    }
}

/// The facet the stored SESSION row `raw` names for the writes made in it.
fn session_facet_of(raw: &[u8]) -> Result<Option<EntityId>> {
    let body: serde_json::Value = decode(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    body.get("facet_ref")
        .map(|facet| {
            facet
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or(invalid("session facet"))
        })
        .transpose()
}
