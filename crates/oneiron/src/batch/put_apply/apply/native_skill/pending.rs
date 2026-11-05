//! Owned final-put data carried past the lower apply, not admission.

use super::{FixedPut, NativeSkillPostGate};
use crate::error::Result;
use crate::skill::SkillRecord;
use crate::{EntityId, WriteActor};

/// The original P4 result has no request/context borrow and no publisher.
/// Whole-batch, actor-after and terminal checks still have to succeed.
pub(in crate::batch) struct PendingNativeSkillPut {
    entity: EntityId,
    record: SkillRecord,
    final_body: Vec<u8>,
    actor: Option<WriteActor>,
    recorded_at: u64,
}

impl PendingNativeSkillPut {
    pub(in crate::batch::put_apply::apply) fn capture(
        store: &crate::store::Store,
        txn: &heed::RoTxn<'_>,
        fixed: &FixedPut<'_>,
        final_body: &[u8],
    ) -> Result<Option<Self>> {
        Ok(
            NativeSkillPostGate::capture(store, txn, fixed, final_body)?.map(|input| Self {
                entity: input.entity(),
                record: input.record,
                final_body: input.final_body,
                actor: input.actor,
                recorded_at: input.recorded_at,
            }),
        )
    }

    pub(in crate::batch) fn entity(&self) -> EntityId {
        self.entity
    }

    pub(in crate::batch) fn record(&self) -> &SkillRecord {
        &self.record
    }

    pub(in crate::batch) fn final_body(&self) -> &[u8] {
        &self.final_body
    }

    pub(in crate::batch) fn actor(&self) -> Option<WriteActor> {
        self.actor
    }

    pub(in crate::batch) fn recorded_at(&self) -> u64 {
        self.recorded_at
    }
}
