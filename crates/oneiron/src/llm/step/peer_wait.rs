//! Peer-result delegation (ONE-1700): local TASK-to-trap bindings and peer signal reconcile.

use super::codec::{expect_key, expect_map, expect_u64, invalid_trap, pinned_key_index};
use super::trap::{register_wait_in_txn, send_trap_signal, trap_head};
use super::types::{
    DREAMER_PEER_WAIT_KEYS, DREAMER_PEER_WAIT_SCHEMA_VERSION, DreamerTrapKind, DreamerTrapState,
    KEY_AT, KEY_SCHEMA_VERSION, KEY_STEP_HASH, KEY_TRAP_CLAIM_ID, TrapRef,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use rmpv::Value;

/// One local delegation binding, keyed by (task ref, trap claim id). The value drops
/// `task_ref` (the key's own leading component) and keeps everything else the pre-migration
/// MessagePack row carried.
struct PeerWaitBindingValue {
    trap_claim_id: EntityId,
    step_hash: [u8; 32],
    created_at: u64,
}

const PEER_WAIT: SideTable<(EntityId, EntityId), PeerWaitBindingValue, Raw> =
    SideTable::new(&side_table::DREAMER_PEER_WAIT);
/// Reverse trap-claim -> task-ref pointer.
const PEER_WAIT_TRAP: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::DREAMER_PEER_WAIT_TRAP);

impl RawValue for PeerWaitBindingValue {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let entries = vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(DREAMER_PEER_WAIT_SCHEMA_VERSION),
            ),
            (
                Value::from(KEY_TRAP_CLAIM_ID),
                Value::Binary(self.trap_claim_id.as_bytes().to_vec()),
            ),
            (
                Value::from(KEY_STEP_HASH),
                Value::Binary(self.step_hash.to_vec()),
            ),
            (Value::from(KEY_AT), Value::from(self.created_at)),
        ];
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &Value::Map(entries))
            .map_err(|_| invalid_trap("peer-result wait binding MessagePack encode failed"))?;
        Ok(encoded)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let value = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes))
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
                return Err(invalid_trap("duplicate peer-result wait binding key").into());
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
                        )
                        .into());
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
                        )
                        .into());
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
            return Err(invalid_trap("unsupported peer-result wait binding schema_version").into());
        }

        Ok(PeerWaitBindingValue {
            trap_claim_id: trap_claim_id.ok_or(invalid_trap(
                "missing peer-result wait binding trap_claim_id",
            ))?,
            step_hash: step_hash
                .ok_or(invalid_trap("missing peer-result wait binding step_hash"))?,
            created_at: created_at.ok_or(invalid_trap("missing peer-result wait binding at"))?,
        })
    }
}

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
    if trap_head(vault, &trap.trap_claim_id)?.1.step_hash != trap.step_hash {
        return Err(invalid_trap("peer-result wait step hash mismatch"));
    }
    let state = vault.with_write_txn(|wtxn| {
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
    })?;
    // Result-before-wait and the terminal-write/signal crash window both
    // reconcile AFTER the binding commits. The canonical trap consumes once.
    send_peer_result_signal(vault, task_ref, now)?;
    if state == DreamerTrapState::Sent {
        return Ok(state);
    }
    Ok(trap_head(vault, &trap.trap_claim_id)?.1.state)
}

/// Performs `Waiting→Sent` for a peer-assigned TASK that has reached a terminal
/// record, and nothing else — resuming is [`consume_trap_signal`](crate::llm::consume_trap_signal)'s job.
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
    crate::task_verb::settle_ask_if_due(vault, task_ref)?;
    if !crate::task_verb::task_is_terminal(vault, task_ref)? {
        return Ok(None);
    }
    let mut first = None;
    for binding in peer_wait_bindings_at(vault, task_ref.as_bytes())? {
        let (_, head) = trap_head(vault, &binding.trap_claim_id)?;
        if matches!(
            head.state,
            DreamerTrapState::Sent | DreamerTrapState::Consumed
        ) {
            continue;
        }
        let signal = send_trap_signal(
            vault,
            &binding.trap_claim_id,
            binding.step_hash,
            now.max(head.at),
        )?;
        first.get_or_insert(signal);
    }
    Ok(first)
}

/// Replays the terminal-write→signal edge for every local delegation binding
/// whose TASK has since settled: the crash window between committing a terminal
/// TASK and sending its signal, and the replicated-landing case where no local
/// writer ran at all.
///
/// It walks the small binding index, never the TASK index, and returns how many
/// handles it signaled (one handle may wake several steps).
///
/// Wired at Dreamer wake-pass admission. The host may also call it after a
/// sync batch; a missing immediate call is recovered by the next wake pass.
pub fn reconcile_peer_result_signals(vault: &Vault, now: u64) -> Result<usize> {
    crate::task_verb::settle_waiting_asks(vault)?;
    let mut sent = 0;
    let handles: std::collections::BTreeSet<_> = peer_wait_bindings(vault)?
        .into_iter()
        .map(|binding| binding.task_ref)
        .collect();
    for handle in handles {
        if send_peer_result_signal(vault, handle, now)?.is_some() {
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
fn peer_wait_binding_put_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    binding: &PeerResultWaitBinding,
) -> Result<()> {
    if let Some(existing) = PEER_WAIT_TRAP.get(&vault.store, wtxn, &binding.trap_claim_id)?
        && existing != binding.task_ref
    {
        return Err(invalid_trap("peer-result trap already binds another task"));
    }
    if let Some(existing) = PEER_WAIT.get(
        &vault.store,
        wtxn,
        &(binding.task_ref, binding.trap_claim_id),
    )? && existing.step_hash != binding.step_hash
    {
        return Err(invalid_trap("peer-result wait binding hash mismatch"));
    }
    PEER_WAIT.put(
        &vault.store,
        wtxn,
        &(binding.task_ref, binding.trap_claim_id),
        &PeerWaitBindingValue {
            trap_claim_id: binding.trap_claim_id,
            step_hash: binding.step_hash,
            created_at: binding.created_at,
        },
    )?;
    PEER_WAIT_TRAP.put(
        &vault.store,
        wtxn,
        &binding.trap_claim_id,
        &binding.task_ref,
    )?;
    Ok(())
}

/// Every live delegation binding on this device, in key order.
pub(super) fn peer_wait_bindings(vault: &Vault) -> Result<Vec<PeerResultWaitBinding>> {
    peer_wait_bindings_at(vault, &[])
}

fn peer_wait_bindings_at(vault: &Vault, key_prefix: &[u8]) -> Result<Vec<PeerResultWaitBinding>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(PEER_WAIT
        .scan_from(&vault.store, &rtxn, key_prefix)?
        .into_iter()
        .map(|((task_ref, _trap_ref), value)| PeerResultWaitBinding {
            task_ref,
            trap_claim_id: value.trap_claim_id,
            step_hash: value.step_hash,
            created_at: value.created_at,
        })
        .collect())
}

/// Reads the trap→task reverse pointer, if this trap came from a delegation.
pub(super) fn peer_wait_task_for_trap(
    vault: &Vault,
    trap_claim_id: &EntityId,
) -> Result<Option<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    PEER_WAIT_TRAP.get(&vault.store, &rtxn, trap_claim_id)
}

pub(super) fn peer_wait_binding_delete_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: &EntityId,
    trap_claim_id: &EntityId,
) -> Result<()> {
    PEER_WAIT.delete(&vault.store, wtxn, &(*task_ref, *trap_claim_id))?;
    PEER_WAIT_TRAP.delete(&vault.store, wtxn, trap_claim_id)?;
    Ok(())
}

/// Wake-pass recovery for committed handle bindings. Sending and consuming may
/// straddle a crash; both are idempotent through the trap chain and owner row.
pub(crate) fn resume_peer_result_steps(vault: &Vault, now_ms: u64) -> Result<usize> {
    reconcile_peer_result_signals(vault, now_ms)?;
    let runner = crate::dreamer_runner::DreamerRunnerStore::new(vault);
    let mut resumed = 0;
    for binding in peer_wait_bindings(vault)? {
        let (_, head) = trap_head(vault, &binding.trap_claim_id)?;
        if head.state != DreamerTrapState::Sent
            || !crate::task_verb::task_is_terminal(vault, binding.task_ref)?
        {
            continue;
        }
        let trap = TrapRef {
            trap_claim_id: binding.trap_claim_id,
            kind: DreamerTrapKind::PeerResult,
            step_hash: binding.step_hash,
        };
        super::trap::consume_trap_signal(vault, &runner, &trap, now_ms.max(head.at))?;
        resumed += 1;
    }
    Ok(resumed)
}
