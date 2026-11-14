//! The standing outbound grant indexes by grant id and by principal
//! (ARCH-0044 H424, census L3-28A): the by-id read and the by-principal read
//! used to decode every standing consent Grant row per call. These derived
//! indexes name, per grant id and per principal, the Grant rows that are
//! outbound grants. They are a prefilter only: every hit is re-read from its
//! Grant row and checked, and any doubt (flag unset, a key that disagrees
//! with its row, a read error) falls back to the full scan in
//! [`super::doors`], which answers (or errors) exactly as it does today.
//!
//! A Grant row's key is its bound's digest (`consent_grant_row_grant_ref`),
//! and every rewrite of a row (a re-mint, a revoke) keeps its bound, so the
//! index keys of a row never change and no Grant row is ever deleted: the
//! one write door in `consent::codec` adds a row's keys at each put.

use super::bound::StandingOutboundGrant;
use crate::Vault;
use crate::consent::ConsentGrantRow;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// Keys are `(grant id, Grant row reference)`; the value is an empty marker.
const ID_INDEX: SideTable<(EntityId, String), (), Raw> =
    SideTable::new(&side_table::OUTBOUND_GRANT_ID_INDEX);

/// Keys are `(blake3 of the principal reference, grant id, Grant row
/// reference)`; the value is an empty marker. The hash gives the variable
/// principal reference the fixed width a leading key part needs.
const PRINCIPAL_INDEX: SideTable<([u8; 32], EntityId, String), (), Raw> =
    SideTable::new(&side_table::OUTBOUND_GRANT_PRINCIPAL_INDEX);

/// `Some(1)` once a whole rebuild of both indexes has committed.
const INDEX_STATE: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::OUTBOUND_GRANT_INDEX_STATE);

const INDEX_VERSION: u64 = 1;

fn principal_key(principal_ref: &str) -> [u8; 32] {
    *blake3::hash(principal_ref.as_bytes()).as_bytes()
}

fn index_complete_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> bool {
    matches!(INDEX_STATE.get(store, txn, &()), Ok(Some(INDEX_VERSION)))
}

/// Adds the index keys of the Grant row stored under `grant_ref`, in the
/// writing transaction, when the row is an outbound grant; a row of any
/// other kind indexes nothing.
pub(crate) fn index_standing_outbound_grant_row_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    grant_ref: &str,
    row: &ConsentGrantRow,
) -> Result<()> {
    let Some(grant) = StandingOutboundGrant::from_row(row) else {
        return Ok(());
    };
    ID_INDEX.put(store, wtxn, &(grant.id, grant_ref.to_owned()), &())?;
    PRINCIPAL_INDEX.put(
        store,
        wtxn,
        &(
            principal_key(&grant.principal_ref),
            grant.id,
            grant_ref.to_owned(),
        ),
        &(),
    )
}

impl Vault {
    /// Rebuilds both outbound grant indexes from the Grant rows when they are
    /// missing or stale, in one write transaction (a crash leaves nothing or
    /// everything). Runs at writable open and after a checkpoint restore
    /// (`force`); complete indexes are left alone.
    ///
    /// # Errors
    ///
    /// At open (`force` false) none: a failed rebuild of these Derived
    /// indexes never refuses the open; the flag stays unset and the reads
    /// keep the full scan. The restore rebuild (`force`) propagates its
    /// store and codec errors like its sibling backfills.
    pub(crate) fn backfill_standing_outbound_grant_index(&self, force: bool) -> Result<()> {
        match self.rebuild_standing_outbound_grant_index(force) {
            Err(error) if !force => {
                tracing::warn!(
                    %error,
                    "standing outbound grant index rebuild failed; grant reads keep the full scan"
                );
                Ok(())
            }
            other => other,
        }
    }

    fn rebuild_standing_outbound_grant_index(&self, force: bool) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        if !force && index_complete_in_txn(&self.store, &wtxn) {
            return Ok(());
        }
        let rows = crate::consent::standing_grant_rows_in_txn(&self.store, &wtxn)?;
        ID_INDEX.delete_from(&self.store, &mut wtxn, &[])?;
        PRINCIPAL_INDEX.delete_from(&self.store, &mut wtxn, &[])?;
        for (grant_ref, row) in &rows {
            index_standing_outbound_grant_row_in_txn(&self.store, &mut wtxn, grant_ref, row)?;
        }
        INDEX_STATE.put(&self.store, &mut wtxn, &(), &INDEX_VERSION)?;
        wtxn.commit()?;
        Ok(())
    }
}

/// The outbound grant one indexed Grant row reference names, re-read from
/// its row. `None` when the row is missing, unreadable or no outbound grant:
/// the index disagrees with the rows.
fn indexed_grant_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    grant_ref: &str,
) -> Option<StandingOutboundGrant> {
    let row = crate::consent::standing_grant_row_in_txn(store, txn, grant_ref).ok()??;
    StandingOutboundGrant::from_row(&row)
}

/// Every outbound grant `principal_ref` holds, revoked ones included, in id
/// order (then Grant row reference order, as the scan's stable sort leaves
/// them), served from the index when it is complete. `None` means any doubt
/// at all: the caller runs the full scan.
pub(crate) fn indexed_grants_for_principal_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    principal_ref: &str,
) -> Option<Vec<StandingOutboundGrant>> {
    if !index_complete_in_txn(store, txn) {
        return None;
    }
    let hash = principal_key(principal_ref);
    let keys = PRINCIPAL_INDEX.scan_keys(store, txn, &hash).ok()?;
    let mut grants = Vec::with_capacity(keys.len());
    for (key_hash, id, grant_ref) in keys {
        if key_hash != hash {
            return None;
        }
        let grant = indexed_grant_in_txn(store, txn, &grant_ref)?;
        // A hash collision or a stale key is doubt, never a partial answer.
        if grant.id != id || grant.principal_ref != principal_ref {
            return None;
        }
        grants.push(grant);
    }
    Some(grants)
}

/// Every outbound grant whose id is `id`, revoked ones included, in Grant
/// row reference order (the scan's order among rows of one id), served from
/// the index when it is complete. `None` means any doubt at all: the caller
/// runs the full scan.
pub(crate) fn indexed_grants_with_id_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Option<Vec<StandingOutboundGrant>> {
    if !index_complete_in_txn(store, txn) {
        return None;
    }
    let keys = ID_INDEX.scan_keys(store, txn, id.as_bytes()).ok()?;
    let mut grants = Vec::with_capacity(keys.len());
    for (key_id, grant_ref) in keys {
        if key_id != *id {
            return None;
        }
        let grant = indexed_grant_in_txn(store, txn, &grant_ref)?;
        if grant.id != *id {
            return None;
        }
        grants.push(grant);
    }
    Some(grants)
}

/// Drops both indexes and their completeness flag, as a vault older than
/// the indexes holds them, so a test can watch the open rebuild them.
#[cfg(oneiron_test_support)]
pub(crate) fn drop_standing_outbound_grant_index(vault: &Vault) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        ID_INDEX.delete_from(&vault.store, wtxn, &[])?;
        PRINCIPAL_INDEX.delete_from(&vault.store, wtxn, &[])?;
        INDEX_STATE.delete(&vault.store, wtxn, &())?;
        Ok(())
    })
}

/// Whether both indexes are complete.
#[cfg(oneiron_test_support)]
pub(crate) fn standing_outbound_grant_index_complete(vault: &Vault) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(index_complete_in_txn(&vault.store, &rtxn))
}
