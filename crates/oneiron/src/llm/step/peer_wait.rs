//! Peer-result delegation (ONE-1700): local TASK-to-trap bindings and peer signal reconcile.

use super::codec::{expect_key, expect_map, expect_u64, invalid_trap, pinned_key_index};
use super::trap::{register_wait_in_txn, send_trap_signal, trap_head};
use super::types::{
    DREAMER_PEER_WAIT_KEYS, DREAMER_PEER_WAIT_SCHEMA_VERSION, DREAMER_PRIVATE_PEER_WAIT_PREFIX,
    DREAMER_PRIVATE_PEER_WAIT_TRAP_PREFIX, DreamerTrapKind, DreamerTrapState, KEY_AT,
    KEY_SCHEMA_VERSION, KEY_STEP_HASH, KEY_TRAP_CLAIM_ID, TrapRef,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use rmpv::Value;

// ---------------------------------------------------------------------------
// Peer-result delegation (ONE-1700): local TASK→trap binding over the SAME
// trap record, signal, and consume path. No second waiter, no second resumer.
// ---------------------------------------------------------------------------
/// The device-local binding a peer delegation leaves behind so a terminal TASK
/// — landed locally or replicated in from the peer — can find the trap that is
/// waiting on it. Claim-ACT mechanics: it never syncs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerResultWaitBinding {
    pub task_ref: EntityId,
    pub trap_claim_id: EntityId,
    pub step_hash: [u8; 32],
    pub created_at: u64,
}

/// Moves a freshly opened peer-delegation trap to `Waiting` AND stores the
/// local TASK→trap binding in ONE write transaction, so a crash can never
/// leave a waiting trap that nothing can locate.
///
/// Signal-before-wait keeps working: a trap already `Sent` is returned as-is
/// and still records its binding, because the consume path has yet to run.
pub fn register_peer_result_wait(
    vault: &Vault,
    trap: &TrapRef,
    task_ref: EntityId,
    now: u64,
) -> Result<DreamerTrapState> {
    if trap.kind != DreamerTrapKind::PeerResult {
        return Err(invalid_trap("peer-result wait requires a peer_result trap"));
    }
    vault.with_write_txn(|wtxn| {
        let state = register_wait_in_txn(vault, wtxn, trap, now)?;
        peer_wait_binding_put_in_txn(
            vault,
            wtxn,
            &PeerResultWaitBinding {
                task_ref,
                trap_claim_id: trap.trap_claim_id,
                step_hash: trap.step_hash,
                created_at: now,
            },
        )?;
        Ok(state)
    })
}

/// Performs `Waiting→Sent` for a peer-assigned TASK that has reached a terminal
/// record, and nothing else — resuming is [`consume_trap_signal`]'s job.
///
/// Returns the signal claim id when this call sent it, and `None` when there is
/// nothing to do: no local delegation waits on this task, the task has not
/// settled yet (no early resume), or the signal already landed. All three are
/// ordinary outcomes on a path that both the local writer and the replicated
/// apply call, so none of them is an error.
pub fn send_peer_result_signal(
    vault: &Vault,
    task_ref: EntityId,
    now: u64,
) -> Result<Option<EntityId>> {
    let Some(binding) = peer_wait_binding_read(vault, &task_ref)? else {
        return Ok(None);
    };
    if !crate::task_verb::task_is_terminal(vault, task_ref)? {
        return Ok(None);
    }
    let (_, head) = trap_head(vault, &binding.trap_claim_id)?;
    if matches!(
        head.state,
        DreamerTrapState::Sent | DreamerTrapState::Consumed
    ) {
        return Ok(None);
    }
    send_trap_signal(vault, &binding.trap_claim_id, binding.step_hash, now).map(Some)
}

/// Replays the terminal-write→signal edge for every local delegation binding
/// whose TASK has since settled: the crash window between committing a terminal
/// TASK and sending its signal, and the replicated-landing case where no local
/// writer ran at all.
///
/// It walks the small binding index, never the TASK index, and returns how many
/// signals it sent.
///
/// NOT YET WIRED: the intended host call sites are Dreamer admission/startup
/// and the tail of a TASK sync apply, both of which live in files ONE-1700 does
/// not claim (`dreamer_wake.rs` is ONE-1708's; sync apply is unclaimed). Until
/// one of those lanes calls this, a crash in the terminal-write→signal gap is
/// recoverable but not automatically recovered. Banked as a PACKET_AMEND
/// candidate; the behavior itself is covered by the crash-replay test.
pub fn reconcile_peer_result_signals(vault: &Vault, now: u64) -> Result<usize> {
    let mut sent = 0;
    for binding in peer_wait_bindings(vault)? {
        if send_peer_result_signal(vault, binding.task_ref, now)?.is_some() {
            sent += 1;
        }
    }
    Ok(sent)
}

// ---------------------------------------------------------------------------
// Private peer-result wait bindings (ONE-1700), stored under both directions:
// task→trap so a landing result finds its trap, and trap→task so consume can
// retire the binding without knowing which task opened it.
// ---------------------------------------------------------------------------
fn peer_wait_key(task_ref: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DREAMER_PRIVATE_PEER_WAIT_PREFIX.len() + 16);
    key.extend_from_slice(DREAMER_PRIVATE_PEER_WAIT_PREFIX);
    key.extend_from_slice(task_ref.as_bytes());
    key
}

fn peer_wait_trap_key(trap_claim_id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DREAMER_PRIVATE_PEER_WAIT_TRAP_PREFIX.len() + 16);
    key.extend_from_slice(DREAMER_PRIVATE_PEER_WAIT_TRAP_PREFIX);
    key.extend_from_slice(trap_claim_id.as_bytes());
    key
}

fn peer_wait_binding_put_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    binding: &PeerResultWaitBinding,
) -> Result<()> {
    let entries = vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_PEER_WAIT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_TRAP_CLAIM_ID),
            Value::Binary(binding.trap_claim_id.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_STEP_HASH),
            Value::Binary(binding.step_hash.to_vec()),
        ),
        (Value::from(KEY_AT), Value::from(binding.created_at)),
    ];
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &Value::Map(entries))
        .map_err(|_| invalid_trap("peer-result wait binding MessagePack encode failed"))?;
    vault
        .store
        .vault_meta
        .put(wtxn, &peer_wait_key(&binding.task_ref), &encoded)?;
    vault.store.vault_meta.put(
        wtxn,
        &peer_wait_trap_key(&binding.trap_claim_id),
        binding.task_ref.as_bytes(),
    )?;
    Ok(())
}

fn decode_peer_wait_binding(task_ref: EntityId, raw: &[u8]) -> Result<PeerResultWaitBinding> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| invalid_trap("peer-result wait binding MessagePack decode failed"))?;
    let entries = expect_map(&value, "peer-result wait binding must be a MessagePack map")?;

    let mut schema_version = None;
    let mut trap_claim_id = None;
    let mut step_hash = None;
    let mut created_at = None;
    let mut seen = [false; DREAMER_PEER_WAIT_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "peer-result wait binding keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_PEER_WAIT_KEYS)
            .ok_or(invalid_trap("peer-result wait binding key is not pinned"))?;
        if seen[index] {
            return Err(invalid_trap("duplicate peer-result wait binding key"));
        }
        seen[index] = true;

        match DREAMER_PEER_WAIT_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "peer-result wait binding schema_version must be an integer",
                )?);
            }
            KEY_TRAP_CLAIM_ID => {
                let Value::Binary(bytes) = value else {
                    return Err(invalid_trap(
                        "peer-result wait binding trap_claim_id must be binary",
                    ));
                };
                let raw: [u8; 16] = bytes.as_slice().try_into().map_err(|_| {
                    invalid_trap("peer-result wait binding trap_claim_id must be 16 bytes")
                })?;
                trap_claim_id = Some(EntityId::from_bytes(raw)?);
            }
            KEY_STEP_HASH => {
                let Value::Binary(bytes) = value else {
                    return Err(invalid_trap(
                        "peer-result wait binding step_hash must be binary",
                    ));
                };
                let raw: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    invalid_trap("peer-result wait binding step_hash must be 32 bytes")
                })?;
                step_hash = Some(raw);
            }
            KEY_AT => {
                created_at = Some(expect_u64(
                    value,
                    "peer-result wait binding at must be an integer",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_PEER_WAIT_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_trap(
        "missing peer-result wait binding schema_version",
    ))?;
    if schema_version != DREAMER_PEER_WAIT_SCHEMA_VERSION {
        return Err(invalid_trap(
            "unsupported peer-result wait binding schema_version",
        ));
    }

    Ok(PeerResultWaitBinding {
        task_ref,
        trap_claim_id: trap_claim_id.ok_or(invalid_trap(
            "missing peer-result wait binding trap_claim_id",
        ))?,
        step_hash: step_hash.ok_or(invalid_trap("missing peer-result wait binding step_hash"))?,
        created_at: created_at.ok_or(invalid_trap("missing peer-result wait binding at"))?,
    })
}

pub(super) fn peer_wait_binding_read(
    vault: &Vault,
    task_ref: &EntityId,
) -> Result<Option<PeerResultWaitBinding>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, &peer_wait_key(task_ref))?
    else {
        return Ok(None);
    };
    decode_peer_wait_binding(*task_ref, &raw).map(Some)
}

/// Every live delegation binding on this device, in key order.
pub(super) fn peer_wait_bindings(vault: &Vault) -> Result<Vec<PeerResultWaitBinding>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut bindings = Vec::new();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, DREAMER_PRIVATE_PEER_WAIT_PREFIX)?
    {
        let (key, raw) = row?;
        let suffix = key
            .get(DREAMER_PRIVATE_PEER_WAIT_PREFIX.len()..)
            .ok_or(invalid_trap("peer-result wait binding key is truncated"))?;
        let task_bytes: [u8; 16] = suffix
            .try_into()
            .map_err(|_| invalid_trap("peer-result wait binding key is not a task ref"))?;
        bindings.push(decode_peer_wait_binding(
            EntityId::from_bytes(task_bytes)?,
            &raw,
        )?);
    }
    Ok(bindings)
}

/// Reads the trap→task reverse pointer, if this trap came from a delegation.
pub(super) fn peer_wait_task_for_trap(
    vault: &Vault,
    trap_claim_id: &EntityId,
) -> Result<Option<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, &peer_wait_trap_key(trap_claim_id))?
    else {
        return Ok(None);
    };
    let bytes: [u8; 16] = raw
        .as_ref()
        .try_into()
        .map_err(|_| invalid_trap("peer-result wait reverse pointer is not a task ref"))?;
    Ok(Some(EntityId::from_bytes(bytes)?))
}

pub(super) fn peer_wait_binding_delete_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: &EntityId,
    trap_claim_id: &EntityId,
) -> Result<()> {
    vault
        .store
        .vault_meta
        .delete(wtxn, &peer_wait_key(task_ref))?;
    vault
        .store
        .vault_meta
        .delete(wtxn, &peer_wait_trap_key(trap_claim_id))?;
    Ok(())
}
