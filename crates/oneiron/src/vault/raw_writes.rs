//! The raw storage writes a bound caller makes (OF-063, FIX 3387).
//!
//! The raw native vault handles (the C ABI, JNI's `NativeVault`, the raw
//! napi vault) put entity blobs, edges and vectors by id and delete by id.
//! A handle its app host bound to a principal and, optionally, an off-record
//! session writes through here, as that caller: each write takes the
//! caller's [`Memory`] and runs the doors a `Memory` surface's writes run, so
//! the bound actor and session ride every admission and receipt those doors
//! write. An unbound handle keeps the bare [`crate::Vault`] doors, as before.
//!
//! - A put, a batch of puts, an edge and a vector commit as one batch whose
//!   writer snapshot first proves the actor, as every verified actor write
//!   does: its stored type admits its class, and a shared vault grants it
//!   content writes. It commits below owner grade, as an embedded handle's
//!   `vault.batch` does ([`Memory::core_batch_write`]), and its gate
//!   decisions are receipted as any batch's are. It is held to the caller's
//!   own read (OF-063, FIX 1223, 6068): a put over a stored row it does not
//!   read refuses as missing, and a CLAIM's typed record refs must resolve
//!   for it. A caller whose credential grants no read puts only fresh rows,
//!   and no CLAIM.
//! - A delete is the `vault.delete` row: its target is admitted as a record
//!   ref, so an id naming no record is refused `INVENTED_REFERENCE` with a
//!   reference-refusal receipt, none inside an anonymous off-record session
//!   the actor is verified in; then the owner's
//!   [`Memory::safe_delete`] runs with its gate and redaction receipt.
//!
//! A raw body is opaque bytes here. NOTE and keyed-value prose admission
//! (L01's, FIX 1228) runs on their typed writers only, so a raw put of such
//! a body is not read for links.

use crate::batch::BatchBuilder;
use crate::claim::ClaimReadStatus;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{Memory, MemoryResult, SafeDeleteReason};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::task_verb::sdk::{SafeDeleteRequest, vault_delete};
use crate::temporal::TimeRange;

/// One entity blob a bound raw write puts ([`Memory::raw_put_entities`]).
#[derive(Debug, Clone, Copy)]
pub struct RawEntityPut<'a> {
    /// The entity's id.
    pub id: EntityId,
    /// Its entity type byte.
    pub entity_type: u8,
    /// When what it records happened.
    pub occurred: TimeRange,
    /// When the vault learned it.
    pub learned_at: u64,
    /// Its body bytes, borrowed for the call.
    pub data: &'a [u8],
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
        let mut batch = self.vault().batch();
        for put in puts {
            batch = batch.put(
                &put.id,
                put.entity_type,
                put.occurred,
                put.learned_at,
                put.data,
            );
        }
        self.commit_raw_batch(batch, puts)
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
        self.commit_raw_batch(self.vault().batch().edge(src, kind, tgt, weight), &[])
    }

    /// Puts an entity's vector as this surface's caller.
    ///
    /// # Errors
    ///
    /// As [`Self::raw_put_entities`], and the vector's own refusal.
    pub fn raw_put_vector(&self, id: &EntityId, vector: &[f32]) -> MemoryResult<()> {
        self.commit_raw_batch(self.vault().batch().vector(id, vector), &[])
    }

    /// Deletes `id` as this surface's caller through the `vault.delete` row
    /// (a `user_delete`), and answers whether a record was there.
    ///
    /// # Errors
    ///
    /// `INVENTED_REFERENCE` when `id` names no record, the owner gate's
    /// refusal, and the delete's own.
    pub fn raw_delete_entity(&self, id: &EntityId) -> MemoryResult<bool> {
        vault_delete(
            self,
            SafeDeleteRequest {
                entity_ref: id.to_hex(),
                reason: SafeDeleteReason::UserDelete,
            },
        )
        .map(|receipt| receipt.existed)
    }

    /// Commits `batch`, which puts `puts`, below owner grade once its writer
    /// snapshot proves this surface's actor, keeping that proof's typed
    /// refusal. It is held to this surface's own read lane (FIX 1223, 6068);
    /// a lane its credential refuses keeps that refusal for a CLAIM or a put
    /// over a stored row.
    fn commit_raw_batch(
        &self,
        batch: BatchBuilder<'_>,
        puts: &[RawEntityPut<'_>],
    ) -> MemoryResult<()> {
        let lane = match self.read_lane(ClaimReadStatus::Recorded) {
            Ok(lane) => Ok(lane),
            Err(unread) if puts.iter().any(|put| put.entity_type == ENTITY_TYPE_CLAIM) => {
                return Err(unread);
            }
            Err(unread) => Err(unread),
        };
        let mut refusal = None;
        let guard = |txn: &heed::RoTxn<'_>| -> crate::Result<()> {
            if let Err(error) = self.verify_actor_write_in_txn(txn) {
                refusal = Some(error);
                return Err(Error::InvariantViolation(
                    "a bound raw write's actor was refused",
                ));
            }
            if let Err(unread) = &lane {
                let store = &self.vault().store;
                for put in puts {
                    if store.port_entity_present(txn, &put.id)? {
                        refusal = Some(unread.clone());
                        return Err(Error::EntityNotFound);
                    }
                }
            }
            Ok(())
        };
        let committed = match &lane {
            Ok(lane) => batch.commit_below_owner_read_by(lane, guard),
            Err(_) => batch.commit_below_owner_with_guard(guard),
        };
        committed.map_err(|error| refusal.take().unwrap_or_else(|| error.into()))
    }
}
