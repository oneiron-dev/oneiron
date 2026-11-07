//! Current read authority for the positively typed content in a retained transcript.

use super::{AgentDispatcher, EdgeActorClass, EntityId, Error, HashSet, Result, StepReaders};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::claim::ScopedReadActorKey;
use crate::conversation::AudienceCache;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_NOTE, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};

impl AgentDispatcher<'_> {
    /// Erase dependencies also name actors, rooms and metadata. Only actual
    /// content rows are re-read on the workflow's current member/binder lanes.
    pub(in crate::agent_dispatch) fn workflow_tool_sources_readable_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: &AttemptRecord,
        sources: &[EntityId],
    ) -> Result<bool> {
        let mut content = Vec::new();
        for source in sources {
            if matches!(
                self.vault.get_entity_type_in_txn(txn, source)?,
                Some(
                    ENTITY_TYPE_CLAIM
                        | ENTITY_TYPE_TURN
                        | ENTITY_TYPE_MESSAGE
                        | ENTITY_TYPE_SUMMARY
                        | ENTITY_TYPE_NOTE
                )
            ) && !content.contains(source)
            {
                content.push(*source);
            }
        }
        if content.is_empty() {
            return Ok(true);
        }
        let readers = self.workflow_tool_readers_in_txn(txn, attempt.id)?;
        let mut keys = Vec::new();
        if let Some(member) = readers.member {
            keys.push(
                ScopedReadActorKey::with_actor_class(
                    member.to_hex(),
                    EdgeActorClass::Human.gate_actor_class(),
                )
                .ok_or(Error::InvariantViolation(
                    "a member's id builds no read key",
                ))?
                .require_access_grants(Some(member)),
            );
        }
        let mut actors = readers.binders.clone();
        if readers.member.is_none() && actors.is_empty() {
            let input = super::record_dispatch_input(attempt).ok_or(Error::InvariantViolation(
                "a workflow step carries no dispatch input",
            ))?;
            actors.push(crate::agent_dispatch::agent_dispatch_actor(&input)?);
        }
        for actor in actors {
            keys.push(super::own_key_in(self.vault, txn, actor)?);
        }
        for key in keys {
            if self
                .vault
                .scoped_read(key)
                .entities_readable_in_txn(txn, &content)?
                .contains(&false)
            {
                return Ok(false);
            }
        }
        // Hydration intersects grants; a binder's selector also applies its
        // private-thread and own-entry rules before any words are selected.
        for source in &content {
            if !self.binder_cuts_admit_in_txn(txn, &readers, source)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether `source` passes the cuts each binder's selector applies
    /// before any words are selected: its private-thread rules, and, for an
    /// agent or system binder, its own-entry rule. A row no selector chose,
    /// a sibling task's result (FIX 7742), must pass them here.
    pub(super) fn binder_cuts_admit_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        readers: &StepReaders,
        source: &EntityId,
    ) -> Result<bool> {
        for binder in &readers.binders {
            let key = ScopedReadActorKey::with_actor_class(
                binder.entity_ref().to_hex(),
                binder.actor_class().gate_actor_class(),
            )
            .ok_or(Error::InvariantViolation(
                "a binder's id builds no read key",
            ))?;
            if !self
                .vault
                .scoped_read(key)
                .private_threads_admit_in(txn, source)?
            {
                return Ok(false);
            }
        }
        let own_entry = readers
            .binders
            .iter()
            .filter(|binder| {
                matches!(
                    binder.actor_class(),
                    EdgeActorClass::Agent | EdgeActorClass::System
                )
            })
            .map(|binder| binder.entity_ref())
            .collect::<Vec<_>>();
        let entry = AudienceCache::default();
        let dbs = self.vault.store.read();
        super::super::member_context::own_entry_admits_in(
            self.vault, &entry, &dbs, txn, *source, &own_entry,
        )
    }

    fn workflow_tool_readers_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: AttemptId,
    ) -> Result<StepReaders> {
        let queue = AttemptQueue::new(self.vault);
        let mut readers = StepReaders {
            member: None,
            binders: Vec::new(),
        };
        let mut cursor = Some(attempt);
        let mut seen = HashSet::new();
        while let Some(id) = cursor {
            if !seen.insert(id) {
                return Err(Error::InvariantViolation("context ancestor cycle"));
            }
            let record = queue
                .get_in_txn(txn, id)?
                .ok_or(Error::InvariantViolation("context ancestor is missing"))?;
            if super::is_wrapper(&record) {
                if readers.member.is_none() {
                    readers.member = self.workflow_member_in_txn(txn, &record)?;
                }
                readers
                    .binders
                    .extend(self.workflow_binder_in_txn(txn, &record)?);
                cursor = self.workflow_authority_parent_in_txn(txn, Some(id))?;
            } else {
                if super::record_dispatch_input(&record).is_none() {
                    return Err(Error::InvariantViolation(
                        "context ancestor is not dispatch lineage",
                    ));
                }
                cursor = super::decode_dreamer_attempt_payload(&record.payload)?.parent_attempt;
            }
        }
        Ok(readers)
    }
}
