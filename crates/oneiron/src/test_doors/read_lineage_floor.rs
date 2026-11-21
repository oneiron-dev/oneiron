//! Test doors for READ-LINEAGE L1: a row's floor, and the policies the
//! source-audience walk meets on a read of it (the oracle a floor holds).

use std::collections::BTreeSet;

use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::{EntityId, Vault};

/// The floor of the stored row `row`: the source it was born in and every
/// source its stored floor names. Empty for a row this vault does not hold.
///
/// # Errors
///
/// Storage failures.
pub fn floor_of(vault: &Vault, row: EntityId) -> Result<BTreeSet<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let dbs = vault.store.read();
    let Some(raw) = dbs.port_entity_raw(&txn, &row)? else {
        return Ok(BTreeSet::new());
    };
    crate::source_audience::floor::floor_in(vault, &txn, &row, &raw)
}

/// The policies the source-audience walk meets on a read of `row` by
/// `viewers`, along the lineage it walks (`read_audience_in`).
///
/// # Errors
///
/// Storage failures.
pub fn walked_policies_of(
    vault: &Vault,
    row: EntityId,
    viewers: &[EntityId],
) -> Result<BTreeSet<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let dbs = vault.store.read();
    crate::source_audience::read_audience_in(vault, &dbs, &txn, &[row], viewers)
}

/// Whether the floor of `row` is not known whole here (#9289 review 2
/// P1-1, P1-2; Fable design pass 31): its verdict waits on an input that is
/// not bound and whole yet, or the migration has not judged it yet while it
/// names one.
///
/// # Errors
///
/// Storage failures.
pub fn floor_waits(vault: &Vault, row: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(crate::source_audience::floor_read_in(vault, &txn, &row)?
        == crate::source_audience::FloorRead::Waiting)
}

/// Whether `row` reads to no one, the owner included (READ-LINEAGE-L3 = A):
/// its verdict is sealed, by a source on its stored floor that names no
/// source or by an open input that reads erased (Fable design pass 31).
///
/// # Errors
///
/// Storage failures.
pub fn floor_sealed(vault: &Vault, row: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(crate::source_audience::floor_read_in(vault, &txn, &row)?
        == crate::source_audience::FloorRead::Sealed)
}

/// Whether the row passes `withheld_from_replication_in` on
/// `ReplicationScope::Restricted`, a lane that carries no audience (#9289
/// review 3 P1-3).
///
/// # Errors
///
/// Storage and replication-walk failures.
pub fn travels_restricted(vault: &Vault, row: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(!crate::source_audience::withheld_from_replication_in(
        vault,
        &txn,
        &row,
        crate::source_audience::ReplicationScope::Restricted,
    )?)
}

/// Forgets every floor's open set and the migration's state, so the vault
/// reads as one whose rows were written before floors were (#9289 review 2
/// P1-2). The floors already taken stay.
///
/// # Errors
///
/// Storage failures.
pub fn forget_floor_state(vault: &Vault) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    crate::source_audience::forget_floor_state_in_txn(vault, &mut txn)?;
    txn.commit()?;
    Ok(())
}

/// Ends the floor backfill's pass as a build before the backfill raised
/// archived rows (FLOOR-BACKFILL-SKIPS-ARCHIVED-ROWS) ends it: the backfill
/// is done, its raised marks are cleared, and each row keeps the floor it
/// has.
///
/// # Errors
///
/// Storage failures.
pub fn end_backfill_without_archived_rows(vault: &Vault) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    crate::source_audience::end_backfill_without_archived_rows_in_txn(vault, &mut txn)?;
    txn.commit()?;
    Ok(())
}

/// Marks the floor backfill done as the last page of a pass of a build
/// before this one commits it, before its clearing pages run: the raised
/// marks stay (#10265 review 2 P1-2).
///
/// # Errors
///
/// Storage failures.
pub fn mark_backfill_done(vault: &Vault) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    crate::source_audience::mark_backfill_done_in_txn(vault, &mut txn)?;
    txn.commit()?;
    Ok(())
}

/// Runs the floor backfill to the end of its run from the cursor a pass of
/// a build before this one saved after the page that ended at `after`, as
/// the sweep does when the scheduler kept that cursor though the pass's
/// last page had ended it (#10265 review 2 P1-1).
///
/// # Errors
///
/// Storage failures.
pub fn backfill_from_an_older_pass_cursor(vault: &Vault, after: EntityId) -> Result<()> {
    crate::source_audience::sweep_floors_from_raising_cursor(vault, &after)
}

/// Runs the first write of a floor backfill pass in this build, as the
/// housekeeping sweep does when a pass begins, and drops where the pass
/// would go on.
///
/// # Errors
///
/// Storage failures.
pub fn backfill_first_page(vault: &Vault) -> Result<()> {
    crate::source_audience::sweep_floors(vault, None, || true).map(|_| ())
}

/// Marks `row` raised as a write of a build before the backfill raised
/// archived rows marked a row it raised while the backfill ran, without the
/// archived rows it was written from (#10265 Opus review P2-2).
///
/// # Errors
///
/// Storage failures.
pub fn mark_raised(vault: &Vault, row: EntityId) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    crate::source_audience::mark_raised_in_txn(vault, &mut txn, &row)?;
    txn.commit()?;
    Ok(())
}

/// Leaves `row` waiting on `source`, with its mark, as the backfill of a
/// build before #10222 left a row learnt from an archived row it read as
/// erased (#10265 Opus review P2-3).
///
/// # Errors
///
/// Storage failures.
pub fn mark_waiting_on(vault: &Vault, row: EntityId, source: EntityId) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    crate::source_audience::mark_waiting_in_txn(vault, &mut txn, &row, &source)?;
    txn.commit()?;
    Ok(())
}

/// Lands `id` as a peer's TURN whose phone mark names no thread, written
/// straight into the store as a sync landed it before floors were: no floor
/// raised and no landing noted. Its own source is the seal, so it reads to
/// no one (#9289 review 2 P2-5; #10265 Opus review 3 P2-1).
///
/// # Errors
///
/// Storage failures.
pub fn land_peer_turn_marked_with_no_thread(vault: &Vault, id: EntityId) -> Result<()> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("role"), rmpv::Value::from("user")),
            (
                rmpv::Value::from("text"),
                rmpv::Value::from("a peer's turn"),
            ),
            (
                rmpv::Value::from(crate::voice_call::PHONE_THREAD_KEY),
                rmpv::Value::from("names no thread"),
            ),
        ]),
    )
    .map_err(|_| crate::error::Error::InvalidConfig("encode the peer's TURN".into()))?;
    let at = vault.now_recorded_at();
    let record = crate::test_fixtures::entity_record(
        crate::registry::ENTITY_TYPE_TURN,
        crate::temporal::TimeRange { start: at, end: at },
        at,
        0,
        &body,
    );
    vault.with_write_txn(|txn| {
        vault.store.entities.put(txn, id.as_bytes(), &record)?;
        let type_key = crate::store::Store::encode_type_key(crate::registry::ENTITY_TYPE_TURN, &id);
        vault.store.type_index.put(txn, &type_key, &[])?;
        Ok(())
    })
}

/// Lands the binding of `row` here as a replicated binding does once its
/// policy resolves (`bind_replicated_in_txn`): the rows waiting on `row`
/// take its floor if it is bound and whole now (#9289 Opus review 3 P1-B).
///
/// # Errors
///
/// Storage failures.
pub fn binding_lands(vault: &Vault, row: EntityId) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    crate::source_audience::fold_waiters_in_txn(vault, &mut txn, &row)?;
    txn.commit()?;
    Ok(())
}

/// Lands `made_by` as the stated birth of the live row `id` the way sync
/// lands a replicated row's birth (`stamp_birth_or_warn`): the birth, then
/// the row's floor (#9289 Opus review 3 P2-4).
///
/// # Errors
///
/// Storage failures.
#[cfg(feature = "sync")]
pub fn replicated_birth_lands(
    vault: &Vault,
    id: EntityId,
    made_by: crate::provenance::made_by::MadeBy,
) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    crate::sync::row_birth::stamp_birth_or_warn(
        vault,
        &mut txn,
        &id,
        &crate::store::row_birth::RowBirth::stated(made_by),
    )?;
    txn.commit()?;
    Ok(())
}
