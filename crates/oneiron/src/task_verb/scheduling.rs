//! Live TASK dependency and symbol readiness at every attempt-claim door.
use super::TaskTerminalDisposition;
use super::wire_decode::{decode_task_verb_body, task_body_has_typed_subkind};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::linear_sync::{LinearSyncError, WaveResult};
use crate::store::Store;
use crate::wave_orchestration::{ValidatedWavePlan, WaveOrchestrator, WaveTaskPort, WaveTaskWrite};
use crate::{EntityId, edge::EdgeKind};

pub(crate) fn terminal_success_in_store(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
) -> Result<bool> {
    let Some(raw) = store.entities.get(txn, task.as_bytes())? else {
        return Ok(false);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("task header"))?;
    terminal_success_from_body(header.entity_type, &raw[ENTITY_METADATA_HEADER_LEN..])
}

/// The same terminal check for an adapter that already holds decoded row metadata.
pub(crate) fn terminal_success_from_body(entity_type: u8, body: &[u8]) -> Result<bool> {
    if entity_type != crate::registry::ENTITY_TYPE_TASK || !task_body_has_typed_subkind(body)? {
        return Ok(false);
    }
    Ok(decode_task_verb_body(body)?
        .terminal()
        .is_some_and(|terminal| terminal.disposition == TaskTerminalDisposition::Completed))
}

/// Read-only port over the claim transaction. Dispatch consults the SAME
/// computed ready-set as wave composition, without opening another txn after
/// its atomic claim window has begun.
struct DispatchWavePort<'a, 'txn> {
    store: &'a Store,
    txn: &'a heed::RoTxn<'txn>,
}

impl WaveTaskPort for DispatchWavePort<'_, '_> {
    fn apply_validated_plan(
        &mut self,
        _plan: &ValidatedWavePlan,
        _now: u64,
    ) -> WaveResult<Vec<WaveTaskWrite>> {
        Err(Error::InvariantViolation("dispatch port is read-only").into())
    }

    fn task_terminal_success(&self, task: EntityId) -> WaveResult<bool> {
        Ok(terminal_success_in_store(self.store, self.txn, task)?)
    }

    fn blockers(&self, task: EntityId) -> WaveResult<Vec<EntityId>> {
        let prefix = crate::vault::edge_kind_prefix(&task, EdgeKind::BlockedBy);
        let mut blockers = Vec::new();
        for row in self.store.edges_out.prefix_iter(self.txn, &prefix)? {
            let (key, value) = row?;
            blockers.push(crate::vault::parse_edge_record(&key, &value)?.target);
        }
        Ok(blockers)
    }
}

pub(crate) fn task_dispatch_ready(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    task_ref: Option<&str>,
    now: u64,
) -> Result<bool> {
    let Some(task) = task_ref.and_then(|id| EntityId::from_hex(id).ok()) else {
        return Ok(true);
    };
    let ready = WaveOrchestrator::new(DispatchWavePort { store, txn })
        .ready_set(&[task])
        .map_err(|error| match error {
            LinearSyncError::Store(error) => error,
            other => Error::InvalidConfig(other.to_string()),
        })?;
    Ok(!ready.is_empty() && super::symbols_ready(store, txn, task, now)?)
}

pub(crate) fn acquire_task_symbols(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    task_ref: Option<&str>,
    now: u64,
) -> Result<()> {
    if let Some(task) = task_ref.and_then(|id| EntityId::from_hex(id).ok()) {
        super::acquire_symbols(store, txn, task, now)?;
    }
    Ok(())
}
