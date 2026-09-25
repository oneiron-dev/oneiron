//! Session mode persists; active participant presence belongs only to this process.
use super::*;
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
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
    pub fn set_session_mode(
        &self,
        session: EntityId,
        mode: SessionMode,
        actor: WriteActor,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            authorize(self, txn, actor)?;
            let raw = require_kind(self, txn, session, ENTITY_TYPE_SESSION)?;
            let h =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("session header"))?;
            let mut body: serde_json::Value = decode(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            let map = body.as_object_mut().ok_or(invalid("session body"))?;
            map.insert(
                "mode".into(),
                serde_json::to_value(mode).map_err(|_| invalid("session mode"))?,
            );
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
    pub fn set_presence(
        &self,
        session: EntityId,
        ids: &[EntityId],
        actor: WriteActor,
    ) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        authorize(self, &txn, actor)?;
        require_kind(self, &txn, session, ENTITY_TYPE_SESSION)?;
        let ids: BTreeSet<_> = ids.iter().copied().collect();
        if ids.len() > 10_000 {
            return Err(Error::IndexOverflow("session presence"));
        }
        for id in &ids {
            require_kind(self, &txn, *id, ENTITY_TYPE_PERSON)?;
        }
        let mut presence = self
            .conversation_presence
            .lock()
            .map_err(|_| state("presence lock"))?;
        if !presence.contains_key(&session) && presence.len() >= 1024 {
            return Err(Error::IndexOverflow("active sessions"));
        }
        if ids.is_empty() {
            presence.remove(&session);
        } else {
            presence.insert(session, ids.into_iter().collect());
        }
        Ok(())
    }
}
