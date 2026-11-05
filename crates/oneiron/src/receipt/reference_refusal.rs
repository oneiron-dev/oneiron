//! Reference-refusal receipts (OF-063): a record ref a write named does not
//! resolve for its writer. In a typed ref slot the write was refused
//! (`refused`); in AI-written prose (OF-063 prose links: Engine ruling 10-17)
//! the text is kept as written and the link shows as its plain label
//! (`unlinked`).
//!
//! The refusal is receipted where it happens, on its own write, before the
//! caller hears it; the refused write never ran. An `unlinked` receipt is
//! written before the engine call that would land the text, so it records the
//! AI's attempt: it stands even when that write then fails (a gate refusal, a
//! cap), and it is no proof the text landed. The receipt names the actor,
//! the actor's class, the verb row, the field pointer and the time, as its own
//! RECEIPT_RECORD. It never holds the ref, the rejected value or any other
//! content of the attempt: the audit family keeps only that a write was
//! refused, by whom, through which row and at which field.
//!
//! The one exception is an anonymous off-record session (Engine ruling 10-17,
//! matching OF-538's call receipts; ARCH-0052): a call inside one is refused
//! or unlinked as anywhere else, but no reference-refusal record is written,
//! since such a session keeps nothing ([`receipt_reference_refusals`]).
//!
//! The record names its writer by the writer's opaque stamp token (FIX
//! 11040, 10930), never the actor's id: the writer's erase hard-erases the
//! token's claim, so the record then names no one, a legal hold that keeps
//! the record keeping the token until it lifts. A reader sees the actor the
//! token resolves to, or `erased` ([`resolved_receipt`]).
//!
//! The record carries one typed reason ([`RefusalReason`], Engine 10-18):
//! `INVENTED_REFERENCE` for a ref that does not resolve (in a typed slot, or
//! an answer's citation its pack does not carry), and `GATE_REFUSED` for a
//! claim element the gate or its door refused. A refused element of a
//! per-element batch is receipted by [`receipt_refusal`] once its own write
//! has rolled back, so the receipt survives the rollback, and its id is
//! answered with the typed refusal.

use super::{ERASED_CALL_IDENTITY, ReceiptKind, ReceiptRecord};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::RefusalReason;
use crate::write_envelope::WriteActor;

use crate::store::reference_refusal::receipt_id;
pub(crate) use crate::store::reference_refusal::{ReferenceOutcome, ReferenceRefusalFacts};
pub(super) use crate::store::reference_refusal::{binds, reference_refusal_receipt};

/// Receipts each of `refusals`, `memory`'s writer's, as its own
/// reference-refusal record, all on one grouped write of their own; the
/// refused write staged nothing, so nothing else rides it, and the caller
/// hears the refusal only once it commits. `Ok(false)` when nothing was
/// written: none to write, or the host bound the call to an anonymous
/// off-record session ([`crate::memory::Memory::in_off_record_session`]),
/// which keeps no record (Engine ruling 10-17, the same signal OF-538's call
/// receipts read). The refusal or the unlinking stands either way.
pub(crate) fn receipt_reference_refusals(
    memory: &crate::memory::Memory<'_>,
    refusals: &[ReferenceRefusalFacts],
) -> Result<bool> {
    if refusals.is_empty() || memory.keeps_no_record() {
        return Ok(false);
    }
    record_reference_refusals(memory.vault(), refusals)?;
    Ok(true)
}

/// Receipts each of `refusals` as its own reference-refusal record inside
/// the caller's open write (OF-063, FIX 3417): for a writer that reads its
/// text's links in that write, so its receipts land, or roll back, with the
/// text they name. Nothing to write writes nothing.
pub(crate) fn record_reference_refusals_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    refusals: &[ReferenceRefusalFacts],
) -> Result<()> {
    if refusals.is_empty() {
        return Ok(());
    }
    let stamped = refusals
        .iter()
        .map(|facts| stamped_facts(vault, txn, facts))
        .collect::<Result<Vec<_>>>()?;
    // The ids first: the floor `recorded_at_in_txn` persists covers them.
    let ids = refusals
        .iter()
        .map(|_| vault.store.clock.entity_id())
        .collect::<Result<Vec<_>>>()?;
    let at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    for (id, facts) in ids.into_iter().zip(&stamped) {
        super::record::put_reference_refusal_in_txn(
            vault,
            txn,
            id,
            facts,
            RefusalReason::InventedReference,
            at,
        )?;
    }
    Ok(())
}

/// Receipts each of `refusals` as its own reference-refusal record, all on
/// one grouped write of their own.
fn record_reference_refusals(vault: &Vault, refusals: &[ReferenceRefusalFacts]) -> Result<()> {
    if refusals.is_empty() {
        return Ok(());
    }
    vault.store.write_in_group(|txn| {
        let stamped = refusals
            .iter()
            .map(|facts| stamped_facts(vault, txn, facts))
            .collect::<Result<Vec<_>>>()?;
        // The ids first: the floor `recorded_at_in_txn` persists covers them.
        let ids = refusals
            .iter()
            .map(|_| vault.store.clock.entity_id())
            .collect::<Result<Vec<_>>>()?;
        let at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        for (id, facts) in ids.into_iter().zip(&stamped) {
            super::record::put_reference_refusal_in_txn(
                vault,
                txn,
                id,
                facts,
                RefusalReason::InventedReference,
                at,
            )?;
        }
        Ok(())
    })
}

/// Receipts one refusal, `memory`'s writer's, as its own reference-refusal
/// record under `reason`, on a grouped write of its own (Engine 10-18). The
/// caller runs it once the refused write has rolled back, so the receipt
/// stands outside that write and survives it. Answers the receipt's id
/// (`reference_refusal:<hex>`), or `None` when the host bound the call to an
/// anonymous off-record session, which keeps no record (#1968).
pub(crate) fn receipt_refusal(
    memory: &crate::memory::Memory<'_>,
    facts: &ReferenceRefusalFacts,
    reason: RefusalReason,
) -> Result<Option<String>> {
    if memory.keeps_no_record() {
        return Ok(None);
    }
    let vault = memory.vault();
    let id = vault.store.write_in_group(|txn| {
        let facts = stamped_facts(vault, txn, facts)?;
        // The id first: the floor `recorded_at_in_txn` persists covers it.
        let id = vault.store.clock.entity_id()?;
        let at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        super::record::put_reference_refusal_in_txn(vault, txn, id, &facts, reason, at)?;
        Ok(id)
    })?;
    Ok(Some(receipt_id(&id)))
}

/// `facts` as their record stores them, in the receipt's own write (FIX
/// 11040): a refusal names its writer's stamp token in the actor's place,
/// minted on the writer's first record (FIX 10930); a creation status names
/// no actor and takes none.
fn stamped_facts(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    facts: &ReferenceRefusalFacts,
) -> Result<ReferenceRefusalFacts> {
    let mut stamped = facts.clone();
    if facts.outcome != ReferenceOutcome::CreationNotProven {
        let writer = WriteActor::new(facts.actor, facts.actor_class);
        stamped.actor = crate::provenance::actor_stamp_in_txn(vault, txn, writer)?.token;
    }
    Ok(stamped)
}

/// `receipt`, a stored reference-refusal record, as a reader sees it (FIX
/// 11040): its actor is the actor its stamp token resolves to here, or
/// [`ERASED_CALL_IDENTITY`] once nothing resolves it (its writer erased), so
/// a query by actor never matches it. A creation status names no actor and
/// stays as it is.
pub(super) fn resolved_receipt(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    mut receipt: ReceiptRecord,
) -> Result<ReceiptRecord> {
    let Some(token) = receipt
        .actor
        .as_deref()
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(receipt);
    };
    let actor = crate::provenance::resolve_actor_stamp_in_txn(vault, txn, &token)?;
    receipt.actor = Some(match actor {
        Some(actor) => actor.entity_ref().to_hex(),
        None => ERASED_CALL_IDENTITY.to_owned(),
    });
    Ok(receipt)
}

/// Records, best effort, that a landed reply's `created` records at
/// `pointers` are not proven made by `memory`'s writer (FIX 1211), each as
/// its own content-free reference record, naming the writer's class but no
/// actor id, on one grouped write of their own after the turn has committed:
/// a failure there is logged and the reply stands. An anonymous off-record
/// session keeps none, as for refusals.
pub(crate) fn receipt_creations_not_proven(
    memory: &crate::memory::Memory<'_>,
    row: &'static str,
    pointers: &[String],
) {
    let statuses: Vec<ReferenceRefusalFacts> = pointers
        .iter()
        .map(|pointer| ReferenceRefusalFacts {
            actor: memory.actor(),
            actor_class: memory.actor_class(),
            row,
            field: pointer.clone(),
            outcome: ReferenceOutcome::CreationNotProven,
        })
        .collect();
    if let Err(error) = receipt_reference_refusals(memory, &statuses) {
        tracing::warn!(%error, "creation-not-proven receipts were not written; the reply stands");
    }
}
