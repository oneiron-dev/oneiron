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
//!   decisions are receipted as any batch's are.
//! - A delete is the `vault.delete` row: its target is admitted as a record
//!   ref, so an id naming no record is refused `INVENTED_REFERENCE` with a
//!   reference-refusal receipt, none inside an anonymous off-record session
//!   the actor is verified in; then the owner's
//!   [`Memory::safe_delete`] runs with its gate and redaction receipt.
//!
//! A handle bound inside an off-record session writes into its room while
//! the room is off record, and reads the room over base (FIX 8119, 8603;
//! `session`); a raw CLAIM put carries its verified caller's envelope
//! through its gate and apply (FIX 8118).
//!
//! A raw body is opaque bytes here. NOTE and keyed-value prose admission
//! (L01's, FIX 1228) runs on their typed writers only, so a raw put of such
//! a body is not read for links.

use crate::batch::BatchBuilder;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{Memory, MemoryResult, SafeDeleteReason};
use crate::task_verb::sdk::{SafeDeleteRequest, vault_delete};
use crate::temporal::TimeRange;

mod session;

use self::session::RawOp;

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
        let staged: Vec<_> = puts.iter().copied().map(RawOp::Put).collect();
        if self.raw_write_in_session(&staged)? {
            return Ok(());
        }
        let mut batch = self.vault().batch();
        for put in puts {
            batch = self.raw_put_on(batch, put)?;
        }
        self.commit_raw_batch(batch)
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
        self.commit_raw_batch(self.vault().batch().edge(src, kind, tgt, weight))
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
        self.commit_raw_batch(self.vault().batch().vector(id, vector))
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

    /// Commits `batch` below owner grade once its writer snapshot proves this
    /// surface's actor, keeping that proof's typed refusal.
    fn commit_raw_batch(&self, batch: BatchBuilder<'_>) -> MemoryResult<()> {
        let mut refusal = None;
        let committed = batch.commit_below_owner_with_guard(|txn| {
            self.verify_actor_write_in_txn(txn).map_err(|error| {
                refusal = Some(error);
                Error::InvariantViolation("a bound raw write's actor was refused")
            })
        });
        committed.map_err(|error| refusal.take().unwrap_or_else(|| error.into()))
    }
}
