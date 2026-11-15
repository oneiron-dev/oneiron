//! A connector thread's own SESSION (OWN-VOICE-EPOCHS = C; Engine ruling
//! UNBUILT-02-SITTING = A). An external thread, such as an email or a LINE
//! chat, keeps its own epochs, and an epoch's lineage is a conversation's
//! turns within one SESSION. So each thread gets one SESSION, its id derived
//! from the thread's conversation, minted at the thread's first connector
//! witness and held open for the thread's life.
//!
//! It is no actor's sitting. It holds no open pointer, so no app-open
//! re-signal joins it and no other sitting collides with it; the driver's
//! idle floor never sees it (`open_sessions` walks the open pointers), so it
//! never ends and never fires a SessionEnd. Its turns are numbered by when
//! they occurred, since their ids derive from their exchange, not from time
//! (`compaction::conversation::order`).

use super::*;

/// A connector thread's SESSION. Parts: the thread's conversation.
const THREAD_SESSION_DOMAIN: &[u8] = b"oneiron.session.connector_thread.v1";

/// The SESSION the connector thread `conversation` holds its turns in.
///
/// # Errors
///
/// The id does not derive.
pub(crate) fn thread_session_id(conversation: EntityId) -> Result<EntityId> {
    Ok(EntityId::derive(
        THREAD_SESSION_DOMAIN,
        &[conversation.as_bytes()],
    )?)
}

impl Vault {
    /// The connector thread `conversation`'s SESSION in `wtxn`, minted when
    /// absent: its entity and an open lifecycle record started at `now`,
    /// keyed to `actor` on this vault's machine, and no open pointer.
    ///
    /// # Errors
    ///
    /// Storage errors, and a derived id that is taken by another kind of row.
    pub(crate) fn thread_session_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        conversation: EntityId,
        actor: EntityId,
        now: u64,
    ) -> Result<EntityId> {
        let id = thread_session_id(conversation)?;
        if RECORDS.get(&self.store, wtxn, &id)?.is_some() {
            return Ok(id);
        }
        if crate::ports::EntityStoreRead::port_entity_raw(&self.store, wtxn, &id)?.is_some() {
            return Err(Error::InvariantViolation(
                "a thread session's id names a row with no lifecycle record",
            ));
        }
        let machine = crate::identity::load_or_mint_machine_id_in_txn(self, wtxn)?;
        let key = SessionKey { actor, machine };
        let effective_ms = now.saturating_mul(1_000);
        let record = SessionLifecycleRecord {
            version: SESSION_LIFECYCLE_RECORD_VERSION,
            key,
            started_at: now,
            last_activity: now,
            ended_at: None,
            end_reason: None,
            started_effective_ms: effective_ms,
            last_effective_ms: effective_ms,
            // No app opened it: a thread is no visit.
            app_open_hints: Vec::new(),
            activity_periods: Vec::new(),
            explicit_end_hint: None,
            close_hook_stop: None,
            speakers: SessionSpeakers::default(),
            summary_attempt: None,
        };
        let body = session_entity_body(key)?;
        self.batch_in()
            .put(
                &id,
                ENTITY_TYPE_SESSION,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &body,
            )
            .apply(wtxn)?;
        RECORDS.put(&self.store, wtxn, &id, &record)?;
        Ok(id)
    }
}
