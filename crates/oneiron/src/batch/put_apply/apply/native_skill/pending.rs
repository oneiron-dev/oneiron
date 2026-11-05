//! Owned final-put data carried past the lower apply, not admission.

use super::FixedPut;
use crate::error::{Error, Result};
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
        let Some(request) = fixed.skill_state_write else {
            return Ok(None);
        };
        let context = fixed.native_publication.ok_or(Error::InvariantViolation(
            "native SKILL state request has no applying Vault",
        ))?;
        if !std::ptr::eq(store, &context.vault.store)
            || fixed.entity_type != crate::registry::ENTITY_TYPE_SKILL
            || fixed.replicated
        {
            return Err(Error::InvariantViolation(
                "native SKILL state request differs from its applying put",
            ));
        }
        let record = request.recheck_final(store, txn, &fixed.id, final_body)?;
        Ok(Some(Self {
            entity: request.entity(),
            record,
            final_body: final_body.to_vec(),
            actor: context.actor,
            recorded_at: fixed.mutation_recorded_at,
        }))
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
