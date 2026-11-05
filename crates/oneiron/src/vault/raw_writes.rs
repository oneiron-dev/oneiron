//! Core half of `vault::raw_writes`: its store-layer items live in `oneiron_store::vault::raw_writes` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::vault::raw_writes::*;

use self::session::RawOp;
use crate::batch::BatchBuilder;
use crate::core_write::CoreWriteLane;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{Memory, MemoryResult, SafeDeleteReason};
use crate::temporal::TimeRange;
use serde::{Deserialize, Serialize};

mod session;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SafeDeleteRequest {
    pub entity_ref: String,
    pub reason: SafeDeleteReason,
}

impl Memory<'_> {
    /// Puts one entity blob as this surface's caller: [`Self::raw_put_entities`]
    /// with one put.
    ///
    /// # Errors
    ///
    /// As [`Self::raw_put_entities`].
    pub fn raw_put_entity(&self, put: RawEntityPut<'_>) -> MemoryResult<()> {
        self.raw_put_entities(std::slice::from_ref(&put))
    }

    /// Puts every blob of `puts` in one transaction, as this surface's
    /// caller, or none of them.
    ///
    /// # Errors
    ///
    /// The actor's refusal (it is missing, its stored type does not admit its
    /// class, or a shared vault grants it no content write), a below-owner
    /// refusal (a put that turns an agent definition back on), or the
    /// batch's own refusal; nothing is written then.
    pub fn raw_put_entities(&self, puts: &[RawEntityPut<'_>]) -> MemoryResult<()> {
        let staged: Vec<_> = puts.iter().copied().map(RawOp::Put).collect();
        if self.raw_write_in_session(&staged)? {
            return Ok(());
        }
        // Read before the writer opens; receipted only for a batch that lands.
        let unlinked_prose = self.raw_put_prose(puts)?;
        let mut batch = self.vault().batch();
        for put in puts {
            batch = self.raw_put_on(batch, put)?;
        }
        self.commit_raw_batch(batch, puts)?;
        crate::gate::record_references::receipt_landed_prose(self, &unlinked_prose);
        Ok(())
    }

    /// Puts a directed edge as this surface's caller.
    ///
    /// # Errors
    ///
    /// As [`Self::raw_put_entities`], and the edge kind gate's refusal.
    pub fn raw_put_edge(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
    ) -> MemoryResult<()> {
        let staged = RawOp::Edge {
            src: *src,
            kind,
            tgt: *tgt,
            weight,
        };
        if self.raw_write_in_session(&[staged])? {
            return Ok(());
        }
        self.commit_raw_batch(self.vault().batch().edge(src, kind, tgt, weight), &[])
    }

    /// Puts an entity's vector as this surface's caller.
    ///
    /// # Errors
    ///
    /// As [`Self::raw_put_entities`], and the vector's own refusal.
    pub fn raw_put_vector(&self, id: &EntityId, vector: &[f32]) -> MemoryResult<()> {
        if self.raw_write_in_session(&[RawOp::Vector { id: *id, vector }])? {
            return Ok(());
        }
        self.commit_raw_batch(self.vault().batch().vector(id, vector), &[])
    }

    /// Deletes `id` as this surface's caller through the `vault.delete` row
    /// (a `user_delete`), and answers whether a record was there. A row only
    /// the off-record room this surface's session names staged is deleted
    /// in that room, which base never held (FIX 10763).
    ///
    /// # Errors
    ///
    /// `INVENTED_REFERENCE` when `id` names no record, the owner gate's
    /// refusal, the room's own refusals, and the delete's own.
    pub fn raw_delete_entity(&self, id: &EntityId) -> MemoryResult<bool> {
        if self.raw_delete_in_session(id)? {
            return Ok(true);
        }
        let request = SafeDeleteRequest {
            entity_ref: id.to_hex(),
            reason: SafeDeleteReason::UserDelete,
        };
        crate::gate::record_references::admit_row_references(
            self,
            "vault.delete",
            &request,
            &["/entity_ref"],
        )?;
        self.safe_delete(&request.entity_ref, request.reason)
            .map(|receipt| receipt.existed)
    }

    /// Commits `batch`, which puts `puts`, below owner grade once its writer
    /// snapshot proves this surface's actor, keeping that proof's typed
    /// refusal. It is held to this surface's write lane
    /// ([`Memory::core_write_lane`], FIX 1223, 6068): a read lane in the
    /// batch's own terminal, a target lane in that same writer snapshot.
    fn commit_raw_batch(
        &self,
        batch: BatchBuilder<'_>,
        puts: &[RawEntityPut<'_>],
    ) -> MemoryResult<()> {
        let lane = self.core_write_lane()?;
        let ids: Vec<EntityId> = puts.iter().map(|put| put.id).collect();
        let mut refusal = None;
        let guard = |txn: &heed::RoTxn<'_>| -> crate::Result<()> {
            if let Err(error) = self.verify_actor_write_in_txn(txn) {
                refusal = Some(error);
                return Err(Error::InvariantViolation(
                    "a bound raw write's actor was refused",
                ));
            }
            if matches!(lane, CoreWriteLane::Target(_)) && !lane.admits_puts_in(txn, &ids)? {
                return Err(Error::EntityNotFound);
            }
            Ok(())
        };
        let committed = match &lane {
            CoreWriteLane::Read(lane) => batch.commit_below_owner_read_by(lane, guard),
            CoreWriteLane::Target(_) | CoreWriteLane::Unbound => {
                batch.commit_below_owner_with_guard(guard)
            }
        };
        committed.map_err(|error| refusal.take().unwrap_or_else(|| error.into()))
    }
}
