//! A state request constructible only inside the typed SKILL doors.

use super::{SkillLifecycle, SkillRecord, encode_skill_record};
use crate::EntityId;
use crate::entity_doc::SkillStateSnapshot;
use crate::error::{Error, Result};
use crate::store::Store;
use heed::RoTxn;

/// This carries a target-bound request, not a committed native fact.
/// Admission, scan, caller effects and the batch terminal still have to run.
pub(crate) struct SkillStateWrite {
    snapshot: SkillStateSnapshot,
    lifecycle: SkillLifecycle,
}

impl std::fmt::Debug for SkillStateWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkillStateWrite")
            .field("entity", &self.entity())
            .finish_non_exhaustive()
    }
}

impl SkillStateWrite {
    pub(super) fn prepare(
        store: &Store,
        txn: &RoTxn<'_>,
        entity: EntityId,
        record: &SkillRecord,
    ) -> Result<Option<Self>> {
        let requested = encode_skill_record(record)?;
        Ok(
            SkillStateSnapshot::capture(store, txn, entity, &requested)?.map(|snapshot| Self {
                snapshot,
                lifecycle: record.lifecycle_status,
            }),
        )
    }

    pub(crate) fn entity(&self) -> EntityId {
        self.snapshot.entity()
    }

    /// The old scan may update approval; it cannot replace the requested lifecycle.
    pub(crate) fn recheck_final(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        entity: &EntityId,
        final_body: &[u8],
    ) -> Result<SkillRecord> {
        let record = self.snapshot.recheck(store, txn, entity, final_body)?;
        if record.lifecycle_status != self.lifecycle {
            return Err(Error::InvariantViolation(
                "headed SKILL lifecycle differs from its typed request",
            ));
        }
        Ok(record)
    }

    /// The current prior for overwrite validation, after checking the final
    /// request against this exact writer. `recheck_final` returns the UPDATED
    /// record; using it as the prior would hide the state change.
    pub(crate) fn rechecked_prior_body(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        entity: &EntityId,
        final_body: &[u8],
    ) -> Result<&[u8]> {
        self.recheck_final(store, txn, entity, final_body)?;
        Ok(self.snapshot.logical_prior_body())
    }

    pub(crate) fn snapshot(&self) -> &SkillStateSnapshot {
        &self.snapshot
    }
}
