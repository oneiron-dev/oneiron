//! Who a task row names, and the erase that forgets it (FIX 3520): a fan-out
//! launch's launcher, an ask wait's waiter, a journaled report's reporter
//! and a lifecycle record's actor.

use super::ask_facade::TASK_ASK_WAITS;
use super::fanout_launch::{FANOUT_LAUNCHES, StoredLaunch};
use crate::Vault;
use crate::attempt_queue::{AttemptInterventionKind, AttemptQueue, InterveneAttempt};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::ERASED_CALL_IDENTITY;
use serde::{Deserialize, Serialize};

/// The intervention actor an erase cancels a held planning attempt as.
const ACTOR_ERASE_INTERVENTION: &str = "engine:actor_erase";

/// Who a task row names: an actor, or no one once that actor was erased
/// (FIX 3520). It reads and writes as the actor's hex id, or as
/// [`ERASED_CALL_IDENTITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskActor {
    Actor(EntityId),
    Erased,
}

impl TaskActor {
    /// Whether this is `actor`.
    #[must_use]
    pub fn is(self, actor: EntityId) -> bool {
        self == Self::Actor(actor)
    }

    /// The actor, while it is not erased.
    #[must_use]
    pub const fn id(self) -> Option<EntityId> {
        match self {
            Self::Actor(id) => Some(id),
            Self::Erased => None,
        }
    }

    /// Makes this no one when it is `actor`; whether it was.
    pub(super) fn forget(&mut self, actor: EntityId) -> bool {
        let named = self.is(actor);
        if named {
            *self = Self::Erased;
        }
        named
    }
}

impl Serialize for TaskActor {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Actor(id) => serializer.serialize_str(&id.to_hex()),
            Self::Erased => serializer.serialize_str(ERASED_CALL_IDENTITY),
        }
    }
}

impl<'de> Deserialize<'de> for TaskActor {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value == ERASED_CALL_IDENTITY {
            return Ok(Self::Erased);
        }
        EntityId::from_hex(&value)
            .map(Self::Actor)
            .map_err(serde::de::Error::custom)
    }
}

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the task rows.
pub(super) fn names_no_actor(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    if let Some(raw) = vault.get_raw_in(txn, id)?
        && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
    {
        return Ok(!matches!(
            header.entity_type,
            crate::registry::ENTITY_TYPE_PERSON
                | crate::registry::ENTITY_TYPE_MACHINE
                | crate::registry::ENTITY_TYPE_AGENT_DEF
        ));
    }
    Ok(false)
}

/// Erasing `actor` from the fan-out launches it started (FIX 3520). A launch
/// still held, denied or not, is an act still to run: it goes, and each
/// planning attempt still parked under its hold is cancelled. A launch that
/// went out keeps its payload, statement, rows, ruling, TASKs and times, and
/// names no one: its plan's actor and its policy scope read as erased, and
/// its digest stays the one the owner saw. Nothing rules on it again, since
/// a ruling runs as its launcher. One-way, in the erase's own transaction.
/// An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, a launch row that cannot be read, or a held attempt the
/// queue cannot cancel.
pub(crate) fn erase_launch_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut launches = Vec::new();
    for (key, mut launch) in FANOUT_LAUNCHES.scan(&vault.store, wtxn)? {
        if launch.actor.forget(*actor) {
            launches.push((key, launch));
        }
    }
    let hex = actor.to_hex();
    for (key, mut launch) in launches {
        if launch.dispatched_at.is_none() {
            cancel_held_attempts_in(vault, wtxn, &launch)?;
            FANOUT_LAUNCHES.delete(&vault.store, wtxn, &key)?;
            continue;
        }
        launch.plan.actor_ref = ERASED_CALL_IDENTITY.to_owned();
        launch.scope = launch.scope.replacen(&hex, ERASED_CALL_IDENTITY, 1);
        FANOUT_LAUNCHES.put(&vault.store, wtxn, &key, &launch)?;
    }
    Ok(())
}

/// Cancels each planning attempt still parked under `launch`'s hold: with
/// the hold gone, no approval releases it. A row a person resumed or
/// cancelled since stays as it is.
fn cancel_held_attempts_in(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    launch: &StoredLaunch,
) -> Result<()> {
    let queue = AttemptQueue::new(vault);
    let now = vault.now_recorded_at();
    for id in &launch.held_attempts {
        let Some(record) = queue.get_in_write_txn(wtxn, *id)? else {
            continue;
        };
        if !record.fanout_hold_for(launch.launch_ref) {
            continue;
        }
        queue.intervene_in_txn(
            wtxn,
            InterveneAttempt {
                id: *id,
                kind: AttemptInterventionKind::Cancel,
                actor: ACTOR_ERASE_INTERVENTION.to_owned(),
                note: Some(format!(
                    "fanout launch {} erased with its launcher",
                    launch.launch_ref.to_hex()
                )),
                now,
            },
        )?;
    }
    Ok(())
}

/// Erasing `actor` from the ask waits it registered (FIX 3520). A wait not
/// yet consumed is an act still to run: it goes, so no answer signals it and
/// no call binds it again. A consumed wait keeps its row, which still counts
/// among the ask's wait identities and keeps its answer exactly-once, and
/// names no one: no live actor binds it. One-way, in the erase's own
/// transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a wait row that cannot be read.
pub(crate) fn erase_wait_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut waits = Vec::new();
    for (key, mut row) in TASK_ASK_WAITS.scan(&vault.store, wtxn)? {
        if row.actor.forget(*actor) {
            waits.push((key, row));
        }
    }
    for (key, row) in waits {
        if row.consumed {
            TASK_ASK_WAITS.put(&vault.store, wtxn, &key, &row)?;
        } else {
            TASK_ASK_WAITS.delete(&vault.store, wtxn, &key)?;
        }
    }
    Ok(())
}
