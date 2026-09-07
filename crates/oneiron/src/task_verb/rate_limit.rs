use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::{
    PolicyApprovalCeiling, dispatched_agent_effective_ceiling, resolve_policy_manifest,
};
use crate::memory::MemoryResult;
use crate::write_envelope::WriteActor;

use super::consts::TASK_CREATE_RATE_KEY_PREFIX;
use super::create_spec::TaskCreateRateLimit;
use super::verb_kind::TasksVerb;

pub(super) fn task_verb_contract(verb: TasksVerb) -> &'static str {
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

pub(super) fn consume_create_rate_slot(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    now: u64,
    rate_limit: TaskCreateRateLimit,
) -> Result<bool> {
    let window_seconds = rate_limit.window_seconds.max(1);
    let window = now / window_seconds;
    // One node-local key per (actor, window_seconds), overwritten each window:
    // value = {window, count}. A stored window other than the current one
    // resets the count, so elapsed windows overwrite the same key instead of
    // leaving a per-window residue that grows unbounded over the vault's life.
    let key = task_create_rate_key(actor, window_seconds);
    let count = match vault.store.vault_meta.get(&*wtxn, key.as_slice())? {
        Some(raw) => {
            let stored: [u8; 16] = raw
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("tasks.create.rate"))?;
            let stored_window = u64::from_le_bytes(stored[..8].try_into().expect("rate window"));
            if stored_window == window {
                u64::from_le_bytes(stored[8..].try_into().expect("rate count"))
            } else {
                0
            }
        }
        None => 0,
    };
    if count >= rate_limit.limit as u64 {
        return Ok(false);
    }
    let mut value = [0u8; 16];
    value[..8].copy_from_slice(&window.to_le_bytes());
    value[8..].copy_from_slice(&count.saturating_add(1).to_le_bytes());
    vault.store.vault_meta.put(wtxn, key.as_slice(), &value)?;
    Ok(true)
}

pub(super) fn task_create_rate_key(actor: EntityId, window_seconds: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        TASK_CREATE_RATE_KEY_PREFIX.len() + actor.as_bytes().len() + size_of::<u64>(),
    );
    key.extend_from_slice(TASK_CREATE_RATE_KEY_PREFIX);
    key.extend_from_slice(actor.as_bytes());
    key.extend_from_slice(&window_seconds.to_be_bytes());
    key
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
pub(crate) fn task_create_owner_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> Result<Option<EntityId>> {
    Ok(vault
        .task_authority_state_in(txn, task_ref)?
        .map(|state| state.owner_ref))
}
