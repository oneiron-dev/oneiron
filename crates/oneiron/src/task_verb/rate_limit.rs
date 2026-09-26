use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::{
    PolicyApprovalCeiling, dispatched_agent_effective_ceiling, resolve_policy_manifest,
};
use crate::memory::MemoryResult;
use crate::side_table::{self, RawValue, SideTable};
use crate::task_verb::sdk::AgentVerb;
use crate::write_envelope::WriteActor;

use super::create_spec::TaskCreateRateLimit;

/// Per-(actor, window_seconds) create-rate window, node-local: a property of
/// THIS machine's admission history, not of the task, so it stays in
/// `vault_meta` and does not replicate.
pub(super) const TASK_CREATE_RATE_WINDOWS: SideTable<(EntityId, u64), RateWindow, side_table::Raw> =
    SideTable::new(&side_table::TASK_CREATE_RATE_WINDOW);

/// One rate window's bytes: little-endian window index then little-endian
/// count, matching the layout this row has always written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RateWindow {
    pub(super) window: u64,
    pub(super) count: u64,
}

impl RawValue for RateWindow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&self.window.to_le_bytes());
        out.extend_from_slice(&self.count.to_le_bytes());
        Ok(out)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        let stored: [u8; 16] = bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex("tasks.create.rate"))?;
        let (window, count) = stored.split_at(8);
        Ok(Self {
            window: u64::from_le_bytes(window.try_into().expect("split at 8")),
            count: u64::from_le_bytes(count.try_into().expect("split at 8")),
        })
    }
}

pub(super) fn task_verb_contract(verb: AgentVerb) -> &'static str {
    verb.as_str()
}

pub(super) fn task_actor_ceiling(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> MemoryResult<PolicyApprovalCeiling> {
    let policy = resolve_policy_manifest(&vault.store, txn)?;
    let policy_projection = policy.actor_ceiling(
        actor_class.gate_actor_class(),
        Some(actor.to_hex().as_str()),
    );
    let definition = crate::gate::agent_definition_ceiling_for_actor(
        &vault.store,
        txn,
        WriteActor::new(actor, actor_class),
    );
    Ok(definition.map_or(policy_projection, |definition| {
        dispatched_agent_effective_ceiling(definition, policy_projection)
    }))
}

pub(super) fn record_task_create(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    now: u64,
    rate_limit: TaskCreateRateLimit,
) -> Result<u64> {
    let window_seconds = rate_limit.window_seconds.max(1);
    let window = now / window_seconds;
    // One node-local key per (actor, window_seconds), overwritten each window:
    // value = {window, count}. A stored window other than the current one
    // resets the count, so elapsed windows overwrite the same key instead of
    // leaving a per-window residue that grows unbounded over the vault's life.
    let count = read_window(vault, wtxn, actor, window_seconds, window)?;
    let next = count.saturating_add(1);
    TASK_CREATE_RATE_WINDOWS.put(
        &vault.store,
        wtxn,
        &(actor, window_seconds),
        &RateWindow {
            window,
            count: next,
        },
    )?;
    Ok(next)
}

/// Fan-out admission gate on the generic create quota: refuses (without
/// recording) once the actor's current-window count reaches the limit, else
/// records one slot and admits. C07 consult fan-out is the only caller; the
/// generic create lane stays accounting-only (OF-520).
pub(super) fn consume_create_rate_slot(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    now: u64,
    rate_limit: TaskCreateRateLimit,
) -> Result<bool> {
    let window_seconds = rate_limit.window_seconds.max(1);
    let window = now / window_seconds;
    let count = read_window(vault, wtxn, actor, window_seconds, window)?;
    if count >= rate_limit.limit as u64 {
        return Ok(false);
    }
    record_task_create(vault, wtxn, actor, now, rate_limit)?;
    Ok(true)
}

fn read_window(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    window_seconds: u64,
    window: u64,
) -> Result<u64> {
    let Some(stored) = TASK_CREATE_RATE_WINDOWS.get(&vault.store, txn, &(actor, window_seconds))?
    else {
        return Ok(0);
    };
    Ok(if stored.window == window {
        stored.count
    } else {
        0
    })
}

/// The actor whose ceiling admitted this create, read from the replicated
/// Owner authority fact. ONE-1708's follow-up driver sends its reminders as
/// this actor, so a nudge rides the same gate, budget and delivery-window
/// pipeline as any other send the owner makes.
///
/// The proof travels WITH the task now: a peer that materialized the TASK
/// materialized its Owner fact too, so the owner is the same principal on
/// every replica instead of a row only the minting node held.
pub(crate) fn task_create_owner(vault: &Vault, task_ref: EntityId) -> Result<Option<EntityId>> {
    Ok(vault
        .task_authority_state(task_ref)?
        .map(|state| state.owner_ref))
}

/// The same owner proof, read through a caller-owned transaction.
///
/// The hard cancel rung re-verifies ownership INSIDE its write transaction
/// before it terminalizes anything (ONE-1896 §7): a pre-transaction check is a
/// TOCTOU window, and the one door that cannot be refused is the last place to
/// leave one open.
pub(super) fn task_create_owner_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> Result<Option<EntityId>> {
    Ok(vault
        .task_authority_state_in(txn, task_ref)?
        .map(|state| state.owner_ref))
}

impl Vault {
    /// Current engine-clock window count. This is accounting, never admission.
    pub fn task_create_count(&self, actor: EntityId, window_seconds: u64) -> Result<u64> {
        let window_seconds = window_seconds.max(1);
        let txn = self.store.env.read_txn()?;
        read_window(
            self,
            &txn,
            actor,
            window_seconds,
            crate::unix_seconds_now() / window_seconds,
        )
    }
}
