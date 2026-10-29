//! Session-owned typed asks in the keep: open, read, answer and rollback.
//! Records and pauses share the same close-scoped `Kept` row.

use super::*;
use crate::memory::MemoryResult;

impl SessionHookKeep {
    /// Opens one session-owned typed ask and its paused call atomically in
    /// the keep. An existing group replays; no base row or fanout exists.
    pub(in super::super) fn open_ask(
        &self,
        vault: &Vault,
        key: &SessionHookKey,
        parts: SessionAskParts,
        paused: SessionVerbAsk,
        invocation: [u8; 16],
        paused_at: u64,
    ) -> Option<(crate::task_verb::TaskAskReceipt, bool, bool)> {
        let group = parts.group_ref;
        self.with_live(vault, key, |kept| {
            let idempotent = kept.ask_records.contains_key(&group);
            let pause_existed = kept.asks.contains_key(&invocation);
            let record = kept
                .ask_records
                .entry(group)
                .or_insert_with(|| SessionAskRecord::new(parts));
            let receipt = record.receipt(idempotent);
            kept.asks.entry(invocation).or_insert_with(|| KeptAsk {
                ask: paused,
                paused_at,
                used_at: None,
            });
            (receipt, idempotent, pause_existed)
        })
    }

    /// Rolls back a newly opened ask if the chain's own write fails.
    pub(in super::super) fn discard_ask(
        &self,
        key: &SessionHookKey,
        group: EntityId,
        invocation: [u8; 16],
        idempotent: bool,
        pause_existed: bool,
    ) {
        if idempotent && pause_existed {
            return;
        }
        if let Some(kept) = self
            .kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(key)
        {
            if !idempotent {
                kept.ask_records.remove(&group);
            }
            if !pause_existed {
                kept.asks.remove(&invocation);
            }
        }
    }

    /// Status of a live session-owned group, or `None` when this keep has
    /// no such group and the canonical door should answer instead.
    pub(crate) fn status_ask(
        &self,
        vault: &Vault,
        group: EntityId,
        actor: EntityId,
    ) -> Option<MemoryResult<TaskAskStatus>> {
        let kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
        for (key, held) in kept.iter() {
            let Some(record) = held.ask_records.get(&group) else {
                continue;
            };
            if key.live(vault) {
                return Some(record.status(actor));
            }
            return Some(Err(MemoryError::bad_request("unknown ask handle")));
        }
        None
    }

    /// Answers a live session-owned group without a base write or peer
    /// signal. The answer and its settlement stay in this keep.
    pub(crate) fn answer_ask(
        &self,
        vault: &Vault,
        group: EntityId,
        actor: EntityId,
        actor_class: crate::EdgeActorClass,
        word: &TaskAskWord,
        now: u64,
    ) -> Option<MemoryResult<TaskAskAnswer>> {
        let mut kept = self.kept.lock().unwrap_or_else(PoisonError::into_inner);
        for (key, held) in kept.iter_mut() {
            let Some(record) = held.ask_records.get_mut(&group) else {
                continue;
            };
            if !key.live(vault) {
                return Some(Err(MemoryError::bad_request("unknown ask handle")));
            }
            let actor_kind = if actor_class == crate::EdgeActorClass::Human {
                crate::registry::ENTITY_TYPE_PERSON
            } else {
                crate::registry::ENTITY_TYPE_AGENT_DEF
            };
            let result_kind = match vault.get_entity_type(&word.result_ref) {
                Ok(kind) => kind.unwrap_or(crate::registry::ENTITY_TYPE_TASK),
                Err(error) => return Some(Err(MemoryError::from(error))),
            };
            let word_ref = match vault.store.clock.entity_id() {
                Ok(id) => id,
                Err(error) => return Some(Err(MemoryError::from(error))),
            };
            return Some(record.answer(
                actor,
                actor_class,
                actor_kind,
                result_kind,
                word,
                word_ref,
                now,
            ));
        }
        None
    }
}
