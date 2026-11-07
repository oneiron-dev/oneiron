//! `vault.batch` (OF-181): an atomic core entity batch, the write `POST
//! /v1/core/batch` makes. Every put commits in one transaction or none
//! does. The grade it commits at is its host credential's, which no input
//! names: below owner grade, a put that turns an agent definition back on
//! is refused in the write transaction
//! ([`crate::BatchBuilder::commit_below_owner`]).

use super::shape::{AnnouncementAuthority, core_write_times, stage_core_put, text_pairs, write_id};
use super::{CoreBatchCommit, CoreBatchEntityReceipt, CoreBatchWriteInput, CoreBatchWriteReceipt};
use crate::Vault;
use crate::batch::BatchBuilder;
use crate::claim::ScopedRead;
use oneiron_contracts::memory::{MemoryError, MemoryResult};

/// The lane a core write's caller is held to (OF-063; FIX 1223, 6068,
/// 10781), which its host selects from the credential that sent it.
pub enum CoreWriteLane<'v> {
    /// The read the caller's credential reads under: each stored row a put
    /// names must be one it reads, and each CLAIM's typed record refs must
    /// resolve under it.
    Read(ScopedRead<'v>),
    /// For a credential that grants no read, the read its target key gives:
    /// each stored row a put names must lie inside the bounds of what the
    /// credential may write to. Its CLAIMs' refs are judged as an unbound
    /// writer's are.
    Target(ScopedRead<'v>),
    /// No bounds to judge (an owner-grade caller whose read is refused, or a
    /// caller with no read and no target key): it writes as before.
    Unbound,
}

/// A caller-transaction view of the write lane. It borrows the actual reader,
/// including its room and destination bounds, rather than rebuilding its key.
#[derive(Clone, Copy)]
pub(crate) enum CoreWriteLaneRef<'v> {
    Read(&'v ScopedRead<'v>),
    Target(&'v ScopedRead<'v>),
    Unbound,
}

impl CoreWriteLane<'_> {
    pub(crate) fn as_ref(&self) -> CoreWriteLaneRef<'_> {
        match self {
            Self::Read(reader) => CoreWriteLaneRef::Read(reader),
            Self::Target(reader) => CoreWriteLaneRef::Target(reader),
            Self::Unbound => CoreWriteLaneRef::Unbound,
        }
    }
}

impl CoreWriteLane<'_> {
    /// Whether this lane's caller may put at every id of `ids` in `txn`
    /// (FIX 6068, 10781): a fresh id always; a stored row only when the
    /// lane reads it, its original judged whatever it holds; the TURN doors'
    /// owner ([`Vault::turn_doors_owner`]) as before. An unbound lane puts
    /// anywhere, as before.
    pub(crate) fn admits_puts_in(
        &self,
        txn: &heed::RoTxn<'_>,
        ids: &[crate::EntityId],
    ) -> crate::Result<bool> {
        self.as_ref().admits_puts_in(txn, ids)
    }
}

impl CoreWriteLaneRef<'_> {
    pub(crate) fn admits_puts_in(
        self,
        txn: &heed::RoTxn<'_>,
        ids: &[crate::EntityId],
    ) -> crate::Result<bool> {
        let (Self::Read(lane) | Self::Target(lane)) = self else {
            return Ok(true);
        };
        if ids.is_empty() || lane.vault().turn_doors_owner_in(lane, txn)? {
            return Ok(true);
        }
        for id in ids {
            if !crate::batch::put_target_admitted_in(lane, txn, id)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl Vault {
    /// Stages every put of `input` and commits them once, at `commit`. A
    /// TURN is a platform announcement only at the owner's `announcement`.
    /// # Errors
    /// A bad id, interval or body, or the commit's
    /// refusal; nothing is written then.
    pub fn write_core_batch(
        &self,
        input: &CoreBatchWriteInput,
        commit: CoreBatchCommit,
        announcement: AnnouncementAuthority,
    ) -> MemoryResult<CoreBatchWriteReceipt> {
        let (batch, entities) = self.stage_core_batch(input, announcement)?;
        match commit {
            CoreBatchCommit::Owner => batch.commit(),
            CoreBatchCommit::BelowOwner => batch.commit_below_owner(),
        }?;
        Ok(CoreBatchWriteReceipt {
            count: entities.len(),
            entities,
        })
    }

    /// [`Self::write_core_batch`] held to `lane` (OF-063; FIX 1223, 6068). A
    /// read lane takes a stored row a put names only when it reads that row,
    /// judged against the row in the batch's own writer before any put
    /// lands, and each CLAIM's typed record refs must resolve under it. A
    /// target lane takes a stored row only inside the bounds of what its
    /// credential may write to, judged the same way; its CLAIMs commit as an
    /// unbound writer's do. An unbound lane writes as
    /// [`Self::write_core_batch`] does.
    /// # Errors
    /// As [`Self::write_core_batch`]; a named stored row outside the lane as
    /// missing; under a read lane, a CLAIM's unresolved ref as the claim
    /// gate's denial.
    pub fn write_core_batch_in_lane(
        &self,
        input: &CoreBatchWriteInput,
        commit: CoreBatchCommit,
        announcement: AnnouncementAuthority,
        lane: &CoreWriteLane<'_>,
    ) -> MemoryResult<CoreBatchWriteReceipt> {
        let (batch, entities) = self.stage_core_batch(input, announcement)?;
        batch.commit_in_core_lane(lane, commit)?;
        Ok(CoreBatchWriteReceipt {
            count: entities.len(),
            entities,
        })
    }

    /// Every put of `input` staged in one batch, and its receipt rows. The
    /// batch's entity count is measured against `core_batch_entities`
    /// (FIX 57): past it the row asks, and every entity is still staged in
    /// this one batch, so the write stays one atomic transaction.
    fn stage_core_batch(
        &self,
        input: &CoreBatchWriteInput,
        announcement: AnnouncementAuthority,
    ) -> MemoryResult<(BatchBuilder<'_>, Vec<CoreBatchEntityReceipt>)> {
        let _ = self.measure_limit(
            crate::limit_ask::EngineLimit::CoreBatchEntities,
            input.entities.len() as u64,
        );
        let mut batch = self.batch();
        let mut entities = Vec::with_capacity(input.entities.len());
        for entity in &input.entities {
            // A thread binding is its room door's to stamp (FIX 2951), and
            // an audience edit its thread's audience door's (FIX 5545).
            if entity.entity_type == crate::registry::ENTITY_TYPE_TURN
                && [
                    crate::store::conversation_body::ROOM_THREAD_KEY,
                    crate::store::conversation_body::ROOM_THREAD_AUDIENCE_KEY,
                ]
                .iter()
                .any(|key| entity.body.get(*key).is_some())
            {
                return Err(MemoryError::bad_request(
                    "a TURN's room_thread and room_thread_audience are stamped by its room's thread doors",
                ));
            }
            let id = write_id(entity.id.as_deref())?;
            let times = core_write_times(
                entity.occurred_start,
                entity.occurred_end,
                entity.learned_at,
            )?;
            batch = stage_core_put(
                batch,
                &id,
                entity.entity_type,
                times,
                &entity.body,
                announcement,
                entity.text.as_deref().map(text_pairs),
            )?;
            entities.push(CoreBatchEntityReceipt {
                id: id.to_hex(),
                entity_type: entity.entity_type,
            });
        }
        Ok((batch, entities))
    }
}
