//! The native audit append program and its ordered, caller-owned projection.

use std::borrow::Cow;
use std::collections::HashMap;

use heed::{RoTxn, RwTxn};

use super::super::lmdb_aux::{BY_ACTOR, BY_ENTITY, CHANGE_LOG_KEY_PREFIX};
use super::super::time::{PreparedRecordingClock, RecordingClockProjection};
use super::{
    ChangeLogRecord, EntityPutAudit, MutationAudit, entity_put_mutation, prepare_mutation_audit,
};
use crate::error::{Error, Result};
use crate::store::Store;

trait ChangelogRows {
    fn recorded_at(&mut self) -> Result<u64>;
    fn row(&self, key: &[u8]) -> Result<Option<Cow<'_, [u8]>>>;
    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<()>;
}

fn append_changelog(rows: &mut impl ChangelogRows, record: &ChangeLogRecord) -> Result<()> {
    rows.recorded_at()?;
    let key = [CHANGE_LOG_KEY_PREFIX, &record.id].concat();
    let bytes = rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("changelog encode"))?;
    if let Some(prior) = rows.row(&key)? {
        if prior.as_ref() != bytes.as_slice() {
            return Err(Error::InvariantViolation("changelog rows are immutable"));
        }
        return Ok(());
    }
    rows.put(key, bytes)?;
    for (family, owner) in [
        (BY_ENTITY, record.entity),
        (BY_ACTOR, record.actor_principal),
    ] {
        let index = [
            family,
            owner.as_bytes(),
            &record.recorded_at.to_be_bytes(),
            &record.id,
        ]
        .concat();
        rows.put(index, record.id.to_vec())?;
    }
    Ok(())
}

struct WriterRows<'store, 'write, 'env> {
    store: &'store Store,
    txn: &'write mut RwTxn<'env>,
}

impl ChangelogRows for WriterRows<'_, '_, '_> {
    fn recorded_at(&mut self) -> Result<u64> {
        super::super::recorded_at_in_txn(self.store, self.txn)
    }

    fn row(&self, key: &[u8]) -> Result<Option<Cow<'_, [u8]>>> {
        self.store.vault_meta.get(self.txn, key)
    }

    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        self.store.vault_meta.put(self.txn, &key, &value)
    }
}

pub(in crate::ports) fn append_changelog_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    record: &ChangeLogRecord,
) -> Result<()> {
    append_changelog(&mut WriterRows { store, txn }, record)
}

enum AuditOperation<'store> {
    Clock(PreparedRecordingClock<'store, Store>),
    Put(Vec<u8>, Vec<u8>),
}

/// Selects the actual audit rows over the snapshot and this projection's
/// preceding audit writes. IDs and both recording times use the REAL store
/// clock: this advances process-local state, not just projected rows. It is
/// neither read-only nor an abort-isolated setup supplier or authority.
pub(crate) struct MutationAuditProjection<'store, 'read, 'env> {
    store: &'store Store,
    clocks: RecordingClockProjection<'store, 'read, 'env, Store>,
    txn: &'read RoTxn<'env>,
    rows: HashMap<Vec<u8>, Vec<u8>>,
    operations: Vec<AuditOperation<'store>>,
}

impl<'store, 'read, 'env> MutationAuditProjection<'store, 'read, 'env> {
    /// Continue the caller's existing floor view rather than starting a
    /// competing clock projection at an older native prefix.
    pub(crate) fn new(mut clocks: RecordingClockProjection<'store, 'read, 'env, Store>) -> Self {
        let preceding = clocks.take_plan();
        Self {
            store: clocks.store(),
            txn: clocks.snapshot(),
            clocks,
            rows: HashMap::new(),
            operations: vec![AuditOperation::Clock(preceding)],
        }
    }

    /// Keep ordinary recording-clock intervals in the same ordered program
    /// when other native effects sit between audit operations.
    pub(crate) fn recorded_at(&mut self) -> Result<u64> {
        let recorded_at = self.clocks.recorded_at();
        self.operations
            .push(AuditOperation::Clock(self.clocks.take_plan()));
        recorded_at
    }

    pub(crate) fn persist_id_floor(&mut self) -> Result<()> {
        let result = self.clocks.persist_id_floor();
        self.operations
            .push(AuditOperation::Clock(self.clocks.take_plan()));
        result
    }

    pub(crate) fn observe_clock_floor(&mut self) -> Result<u64> {
        let result = self.clocks.observe_clock_floor();
        self.operations
            .push(AuditOperation::Clock(self.clocks.take_plan()));
        result
    }

    /// Allocate once at the native mutation position, then run the native
    /// append, including its SECOND recording-floor call before encoding.
    pub(crate) fn mutation(&mut self, mutation: MutationAudit<'_>) -> Result<ChangeLogRecord> {
        let store = self.store;
        let record = prepare_mutation_audit(&store.clock, || self.recorded_at(), mutation)?;
        append_changelog(self, &record)?;
        Ok(record)
    }

    /// `prior` is the actual entity row at this put's native prefix, including
    /// earlier selected entity writes. It is NOT an unchanged snapshot for a
    /// future-Put list. As in the native path, an unchanged put takes no ID
    /// or recording time. Entity/body writes belong to their own program.
    pub(crate) fn entity_put(
        &mut self,
        prior: Option<&[u8]>,
        put: EntityPutAudit<'_>,
    ) -> Result<Option<ChangeLogRecord>> {
        entity_put_mutation(prior, put)
            .map(|mutation| self.mutation(mutation))
            .transpose()
    }

    /// Drain only this native interval. Earlier rows and floors remain visible
    /// to the next interval. A caller can also take the selected partial prefix
    /// after an error; successful projection does not predict LMDB put errors.
    pub(crate) fn take_plan(&mut self) -> PreparedMutationAudit<'store> {
        PreparedMutationAudit {
            store: self.store,
            operations: std::mem::take(&mut self.operations),
        }
    }
}

impl ChangelogRows for MutationAuditProjection<'_, '_, '_> {
    fn recorded_at(&mut self) -> Result<u64> {
        MutationAuditProjection::recorded_at(self)
    }

    fn row(&self, key: &[u8]) -> Result<Option<Cow<'_, [u8]>>> {
        match self.rows.get(key) {
            Some(bytes) => Ok(Some(Cow::Borrowed(bytes))),
            None => self.store.vault_meta.get(self.txn, key),
        }
    }

    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        self.rows.insert(key.clone(), value.clone());
        self.operations.push(AuditOperation::Put(key, value));
        Ok(())
    }
}

/// One interval's actual selected audit writes. Keeps the original store but
/// NO snapshot borrow, so the caller can consume it in its SAME writer at the
/// original native position. No unrepresented audit/floor mutation may
/// intervene. This plan does not reallocate IDs, resample clocks, or append
/// again; all other setup effects and their admission remain the caller's.
pub(crate) struct PreparedMutationAudit<'store> {
    store: &'store Store,
    operations: Vec<AuditOperation<'store>>,
}

impl PreparedMutationAudit<'_> {
    pub(crate) fn apply_in_txn(self, txn: &mut RwTxn<'_>) -> Result<()> {
        for operation in self.operations {
            match operation {
                AuditOperation::Clock(plan) => plan.apply_in_txn(txn)?,
                AuditOperation::Put(key, value) => {
                    self.store.vault_meta.put(txn, &key, &value)?;
                }
            }
        }
        Ok(())
    }
}
