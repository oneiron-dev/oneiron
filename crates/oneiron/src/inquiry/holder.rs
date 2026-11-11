//! The task-held answer (federation.md #inquiry-keep: "held with the task
//! and bound to the asking actor ... dropped at task end or at valid_until";
//! Engine ruling INQUIRE-SHAPE Q6 = A). It is a map in this process's
//! memory on the asking vault, keyed by the asking actor, the task and the
//! inquiry. No table, journal or image carries it, so a restart loses it and
//! the agent asks again.
//!
//! An entry stands while its task is an open TASK of this vault and before
//! its `valid_until`. Each touch of the map (a send, a read,
//! [`Vault::evict_inquiry_answers`]) first drops every entry whose task has
//! ended or whose `valid_until` has come, so no read returns an ended task's
//! answer. Each housekeeping pass also calls [`Vault::evict_inquiry_answers`]
//! (Engine ruling INQUIRE-HOLDER-EVICT), so on a server, whose lifecycle tick
//! starts a pass every 60 s, an ended task's answer leaves memory within one
//! tick even when nothing touches the map.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::record::InquiryStatement;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_TASK;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Whose answer, for which task, to which inquiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct HeldKey {
    actor: EntityId,
    task: EntityId,
    inquiry: EntityId,
}

/// The statements of one answered inquiry, good until `valid_until`. No
/// `Debug`: nothing prints the member's words.
struct HeldAnswer {
    statements: Vec<InquiryStatement>,
    valid_until: u64,
}

/// The vault's task-held answers. In memory only: never persisted, never
/// restored.
#[derive(Default)]
pub(crate) struct InquiryAnswerHolder {
    held: Mutex<BTreeMap<HeldKey, HeldAnswer>>,
}

impl InquiryAnswerHolder {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<HeldKey, HeldAnswer>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn tasks(&self) -> BTreeSet<EntityId> {
        self.lock().keys().map(|key| key.task).collect()
    }

    /// How many answers the map holds now, without dropping any.
    #[cfg(oneiron_test_support)]
    pub(crate) fn held_count(&self) -> usize {
        self.lock().len()
    }
}

impl Vault {
    /// The statements this vault holds for `actor`'s `task` from the
    /// answered inquiry `inquiry`, or `None` once the task has ended, its
    /// `valid_until` has come, or the process restarted.
    ///
    /// # Errors
    ///
    /// Storage errors while it reads the held tasks' state.
    pub fn held_inquiry_answer(
        &self,
        actor: EntityId,
        task: EntityId,
        inquiry: EntityId,
    ) -> Result<Option<Vec<InquiryStatement>>> {
        self.evict_inquiry_answers()?;
        let key = HeldKey {
            actor,
            task,
            inquiry,
        };
        Ok(self
            .inquiry_answers
            .lock()
            .get(&key)
            .map(|held| held.statements.clone()))
    }

    /// Drops every held answer whose task has ended (settled or cancelled,
    /// or no longer a TASK of this vault) or whose `valid_until` has come.
    /// Returns how many it dropped.
    ///
    /// # Errors
    ///
    /// Storage errors while it reads the held tasks' state.
    pub fn evict_inquiry_answers(&self) -> Result<usize> {
        let mut ended = BTreeSet::new();
        for task in self.inquiry_answers.tasks() {
            if !inquiry_task_is_open(self, task)? {
                ended.insert(task);
            }
        }
        let now = self.now_recorded_at();
        let mut held = self.inquiry_answers.lock();
        let before = held.len();
        held.retain(|key, answer| !ended.contains(&key.task) && answer.valid_until > now);
        Ok(before - held.len())
    }

    /// Holds `statements` for `actor`'s `task` from `inquiry` until
    /// `valid_until`. Returns whether it holds them: never for a task that
    /// is not open, nor past `valid_until`.
    pub(super) fn hold_inquiry_answer(
        &self,
        actor: EntityId,
        task: EntityId,
        inquiry: EntityId,
        statements: &[InquiryStatement],
        valid_until: u64,
    ) -> Result<bool> {
        self.evict_inquiry_answers()?;
        if valid_until <= self.now_recorded_at() || !inquiry_task_is_open(self, task)? {
            return Ok(false);
        }
        let key = HeldKey {
            actor,
            task,
            inquiry,
        };
        self.inquiry_answers.lock().insert(
            key,
            HeldAnswer {
                statements: statements.to_vec(),
                valid_until,
            },
        );
        Ok(true)
    }
}

/// Whether `task` is an open TASK of `vault`: a live TASK row that has not
/// settled and has no Cancelled fact.
///
/// # Errors
///
/// Storage errors; a TASK body no reader decodes.
pub(super) fn inquiry_task_is_open(vault: &Vault, task: EntityId) -> Result<bool> {
    let is_task = {
        let txn = vault.store.env.read_txn()?;
        matches!(
            live_entity_row_in_txn(&vault.store, &txn, &task)?,
            LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_TASK
        )
    };
    if !is_task {
        return Ok(false);
    }
    Ok(!crate::task_verb::task_is_terminal(vault, task)?
        && !crate::context_board::task_is_cancelled(vault, task)?)
}
