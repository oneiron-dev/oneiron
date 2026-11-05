//! The closed per-put input to native SKILL state publication.

use super::admission::FixedPut;
use crate::entity_doc::SkillStateSnapshot;
use crate::error::{Error, Result};
use crate::skill::{SkillRecord, SkillStateWrite};
use crate::{EntityId, Vault, WriteActor};
use heed::RoTxn;

mod pending;
pub(in crate::batch) use pending::PendingNativeSkillPut;

/// Constructed only by this apply module, after its ordinary put checks.
/// It remains provisional until the batch's actor effects and terminal succeed.
pub(crate) struct NativeSkillPostGate<'a> {
    vault: &'a Vault,
    request: &'a SkillStateWrite,
    record: SkillRecord,
    final_body: Vec<u8>,
    actor: Option<WriteActor>,
    content_inputs: Option<crate::batch::ContentWriteInputs<'a>>,
    recorded_at: u64,
}

impl<'a> NativeSkillPostGate<'a> {
    pub(super) fn capture(
        store: &crate::store::Store,
        txn: &RoTxn<'_>,
        fixed: &FixedPut<'a>,
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
            vault: context.vault,
            request,
            record,
            final_body: final_body.to_vec(),
            actor: context.actor,
            content_inputs: context
                .content_writes
                .and_then(|writes| writes.native_inputs(fixed.id)),
            recorded_at: fixed.mutation_recorded_at,
        }))
    }

    pub(crate) fn recheck_in_txn(&self, txn: &RoTxn<'_>) -> Result<()> {
        self.request
            .recheck_final(&self.vault.store, txn, &self.entity(), &self.final_body)?;
        Ok(())
    }

    pub(crate) fn vault(&self) -> &'a Vault {
        self.vault
    }

    pub(crate) fn entity(&self) -> EntityId {
        self.request.entity()
    }

    pub(crate) fn snapshot(&self) -> &SkillStateSnapshot {
        self.request.snapshot()
    }

    pub(crate) fn record(&self) -> &SkillRecord {
        &self.record
    }

    /// Read-only actual successor binding of the closed supersede request.
    pub(crate) fn superseding_revision(&self) -> Option<&crate::skill::SkillSupersessionRead> {
        self.request.superseding_revision()
    }

    pub(crate) fn actor(&self) -> Option<WriteActor> {
        self.actor
    }

    /// Only observations already available at this provisional point. The
    /// original after gates have not run yet and are not attested here.
    pub(crate) fn content_inputs(&self) -> Option<&crate::batch::ContentWriteInputs<'a>> {
        self.content_inputs.as_ref()
    }

    pub(crate) fn recorded_at(&self) -> u64 {
        self.recorded_at
    }
}
