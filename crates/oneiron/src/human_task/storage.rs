//! Core half of `human_task::storage`: its store-layer items live in `oneiron_store::human_task::storage` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::human_task::storage::*;

use super::model::{
    HUMAN_TASK_FOLLOWUP_SCHEMA_VERSION, HumanFollowupStage, HumanTaskFollowupRecord,
    HumanTaskWaitBinding,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use rmpv::Value;

/// The follow-up cursor for one TASK, keyed by the task's own id.
pub(super) const FOLLOWUPS: SideTable<EntityId, HumanTaskFollowupRecord, Raw> =
    SideTable::new(&side_table::HUMAN_TASK_FOLLOWUP);

/// The TASK whose follow-up cursor the due sweep read last. Key: ().
pub(super) const FOLLOWUP_SWEEP: SideTable<(), EntityId, Raw> =
    SideTable::new(&side_table::HUMAN_TASK_FOLLOWUP_SWEEP);

/// One C9 wait binding per parked trap, keyed by `(task, trap claim)`: every
/// workflow parked on the same TASK keeps its own (FIX 9867).
pub(super) const WAIT_BINDINGS: SideTable<(EntityId, EntityId), HumanTaskWaitBinding, Raw> =
    SideTable::new(&side_table::HUMAN_TASK_WAIT_BINDING);

/// Records which response event already produced a signal for one wait, so a
/// re-delivered response returns the first signal instead of re-driving the
/// trap state machine. Keyed by the trap claim id; value is
/// `(signal_ref, surface_event_ref)`.
pub(super) const WAIT_SIGNALS: SideTable<EntityId, (EntityId, EntityId), Raw> =
    SideTable::new(&side_table::HUMAN_TASK_WAIT_SIGNAL);

/// Synced-truth address field on a comm-owned PERSON body.
pub(super) const KEY_PARTY_KEY: &str = "party_key";

pub(super) fn put_followup_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &HumanTaskFollowupRecord,
) -> Result<()> {
    FOLLOWUPS.put(&vault.store, wtxn, &record.task_ref, record)?;
    Ok(())
}

pub(super) fn followup_record_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> Result<Option<HumanTaskFollowupRecord>> {
    FOLLOWUPS.get(&vault.store, rtxn, &task_ref)
}

pub(super) fn put_wait_binding_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    binding: &HumanTaskWaitBinding,
) -> Result<()> {
    WAIT_BINDINGS.put(
        &vault.store,
        wtxn,
        &(binding.task_ref, binding.trap_claim_id),
        binding,
    )?;
    Ok(())
}

pub(super) fn put_wait_signal_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    trap_claim_id: EntityId,
    signal_ref: EntityId,
    surface_event_ref: EntityId,
) -> Result<()> {
    WAIT_SIGNALS.put(
        &vault.store,
        wtxn,
        &trap_claim_id,
        &(signal_ref, surface_event_ref),
    )?;
    Ok(())
}

pub(super) fn wait_signal_marker(
    vault: &Vault,
    trap_claim_id: EntityId,
) -> Result<Option<(EntityId, EntityId)>> {
    let rtxn = vault.store.env.read_txn()?;
    WAIT_SIGNALS.get(&vault.store, &rtxn, &trap_claim_id)
}
