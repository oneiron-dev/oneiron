//! Closed local inputs produced after the batch's original checks.

use super::super::actor_content::ContentWriteSet;
use super::super::base_apply::PendingNativeSkillBatch;
use super::super::put_apply::PendingNativeSkillPut;
use crate::batch::ContentWriteInputs;
use crate::entity_doc::SkillStateSnapshot;
use crate::error::{Error, Result};
use crate::skill::{SkillRecord, SkillStateWrite};
use crate::{EntityId, Vault, WriteActor};

/// Owns the actual request, final P4 value and original before/after frame.
/// This is not a commit, recipient admission or authority from source data.
/// Only the builder's final local continuation can construct it.
pub(crate) struct NativeSkillFinalInput<'vault> {
    vault: &'vault Vault,
    request: SkillStateWrite,
    put: PendingNativeSkillPut,
    content_writes: Option<ContentWriteSet>,
}

impl<'vault> NativeSkillFinalInput<'vault> {
    pub(super) fn finish(
        vault: &'vault Vault,
        txn: &heed::RoTxn<'_>,
        pending: PendingNativeSkillBatch,
        content_writes: Option<ContentWriteSet>,
    ) -> Result<Option<Self>> {
        let (request, mut puts) = pending.into_parts();
        let Some(request) = request else {
            return Ok(None);
        };
        // Every matching put passed its original gates. Recheck every owned
        // final value before choosing the last value of this one request.
        for put in &puts {
            let record =
                request.recheck_final(&vault.store, txn, &put.entity(), put.final_body())?;
            if &record != put.record() {
                return Err(Error::InvariantViolation(
                    "native SKILL final put differs from its captured result",
                ));
            }
        }
        let put = puts.pop().ok_or(Error::InvariantViolation(
            "native SKILL request has no final applying put",
        ))?;
        // One typed request publishes one final register value, not one
        // operation per intermediate put with the same original prior.
        drop(puts);
        Ok(Some(Self {
            vault,
            request,
            put,
            content_writes,
        }))
    }

    pub(crate) fn recheck_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<()> {
        self.request.recheck_final(
            &self.vault.store,
            txn,
            &self.put.entity(),
            self.put.final_body(),
        )?;
        Ok(())
    }

    pub(crate) fn vault(&self) -> &Vault {
        self.vault
    }

    pub(crate) fn entity(&self) -> EntityId {
        self.put.entity()
    }

    pub(crate) fn snapshot(&self) -> &SkillStateSnapshot {
        self.request.snapshot()
    }

    pub(crate) fn record(&self) -> &SkillRecord {
        self.put.record()
    }

    pub(crate) fn superseding_revision(&self) -> Option<&crate::skill::SkillSupersessionRead> {
        self.request.superseding_revision()
    }

    pub(crate) fn actor(&self) -> Option<WriteActor> {
        self.put.actor()
    }

    /// Missing means unobserved. A personal observation exists only when
    /// the original actor frame took its real personal-vault branch.
    pub(crate) fn content_inputs(&self) -> Option<ContentWriteInputs<'_>> {
        self.content_writes
            .as_ref()
            .and_then(|writes| writes.native_inputs(self.entity()))
    }

    pub(crate) fn recorded_at(&self) -> u64 {
        self.put.recorded_at()
    }
}
