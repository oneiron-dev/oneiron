//! The ask path's world-setting refusals, named (FIX 7463a). Where a row an
//! ask reads, a group a handle's call answers from or a record an ask or an
//! answer names is kept from the caller's destination by the world it lies
//! in, the call is refused with that setting's typed hold: the owner's world
//! recipient choice, or a placement that cannot be verified. It is never
//! read as a row that is not there. The decision is the one the shared
//! readers make, in the same snapshot and toward the same destination; only
//! its refusal is named. Where the caller's rows go is the world's read
//! setting, the owner's own choice for that world, and nothing here reads
//! where the caller runs.

use super::ask_record::{AskGroup, AskGroupRead};
use crate::entity_id::EntityId;
use crate::gate::record_references::{
    ReferenceRefusal, admit_row_references, record_references_at, validate_record_references,
};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::receipt::{ReferenceOutcome, ReferenceRefusalFacts, receipt_reference_refusals};
use crate::settings::ReleaseHold;

impl Memory<'_> {
    /// Reads `row` as a producer of what an ask answers, as
    /// [`Memory::read_producer_in`] does: it is listed, and one the world
    /// settings keep from this surface's destination is refused, here with
    /// that setting's named hold rather than as no row.
    pub(super) fn ask_read_producer_in(
        &self,
        txn: &heed::RoTxn<'_>,
        row: EntityId,
    ) -> crate::Result<()> {
        self.produced_from([row]);
        match self.ask_row_hold_in(txn, row)? {
            Some(hold) => Err(hold.into_error()),
            None => Ok(()),
        }
    }

    /// The named hold on `row` when the world settings keep it from this
    /// surface's destination, judged as [`Memory::read_producer_in`] judges
    /// it, in `txn`.
    fn ask_row_hold_in(
        &self,
        txn: &heed::RoTxn<'_>,
        row: EntityId,
    ) -> crate::Result<Option<ReleaseHold>> {
        let destination = self.destination();
        let kept = crate::settings::device_local_worlds_for(self.vault(), txn, destination)?;
        if !crate::settings::device_local_keeps_among(&self.vault().store, txn, &kept, &row)? {
            return Ok(None);
        }
        Ok(Some(crate::settings::withheld_row_hold_in(
            self.vault(),
            txn,
            &kept,
            &row,
            destination,
        )))
    }

    /// The ask group `id` for a call that names this one handle, as
    /// [`Memory::ask_group_in`] reads it, except that a group a member,
    /// class, question or context row's world setting keeps from this
    /// surface's destination is refused with that setting's named hold to
    /// the ask's owner and the people it asks. Anyone else reads it as no
    /// group, as before, and so does a group never stored.
    pub(super) fn ask_group_named_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
    ) -> crate::Result<Option<AskGroup>> {
        match self.ask_group_read_in(txn, id)? {
            Some(AskGroupRead::Readable(group)) => Ok(Some(group)),
            Some(AskGroupRead::Held { group, row, kept }) if addressed(&group, self.actor()) => {
                Err(crate::settings::withheld_row_hold_in(
                    self.vault(),
                    txn,
                    &kept,
                    &row,
                    self.destination(),
                )
                .into_error())
            }
            Some(AskGroupRead::Held { .. }) | None => Ok(None),
        }
    }
}

/// Whether `actor` is the ask's owner or one of the people it asks.
fn addressed(group: &AskGroup, actor: EntityId) -> bool {
    let actor = actor.to_hex();
    group.owner == actor || group.members.iter().any(|member| member.actor == actor)
}

/// The OF-063 record-ref check of `tasks.ask` and `tasks.answer`: the first
/// ref the generic check would refuse is refused with its world setting's
/// named hold when that setting keeps it from the writer's destination,
/// receipted as the generic check receipts its refusal. Every other outcome,
/// a refused ref the world does not keep among them, is the unchanged
/// generic check's ([`admit_row_references`]).
pub(super) fn admit_ask_references<T: serde::Serialize>(
    memory: &Memory<'_>,
    row: &'static str,
    input: &T,
    pointers: &[&str],
) -> MemoryResult<()> {
    let value = serde_json::to_value(input).map_err(|_| {
        MemoryError::bad_request("the verb input could not be read for the records it names")
    })?;
    let refs = record_references_at(&value, pointers);
    if let Err(ReferenceRefusal::Unresolved { pointer }) = validate_record_references(memory, &refs)
        && let Some(named) = refs.iter().find(|named| named.pointer == pointer)
        && let Some(hold) = reference_hold(memory, &named.reference)?
    {
        receipt_reference_refusals(
            memory,
            &[ReferenceRefusalFacts {
                actor: memory.actor(),
                actor_class: memory.actor_class(),
                row,
                field: pointer,
                outcome: ReferenceOutcome::Refused,
            }],
        )?;
        return Err(MemoryError::from(hold.into_error()));
    }
    admit_row_references(memory, row, input, pointers)
}

/// The named hold on the record `reference` names (a pinned ref judged by
/// its record) when its world setting keeps it from `memory`'s destination.
/// A ref that names no record has none.
fn reference_hold(memory: &Memory<'_>, reference: &str) -> MemoryResult<Option<ReleaseHold>> {
    let reference = reference
        .rsplit_once('@')
        .map_or(reference, |(reference, _)| reference);
    let Ok(row) = crate::memory::resolve_entity_ref(memory.vault(), reference) else {
        return Ok(None);
    };
    let txn = memory
        .vault()
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)?;
    memory.ask_row_hold_in(&txn, row).map_err(MemoryError::from)
}
