//! The candidate intake's keyed reads (FIX 7535): which received refs of
//! one object store the drain still reads, and which incoming tips of a
//! store already resolved, each kept beside its source row in the same
//! writer, so a drain pass reads only its store's open rows and a
//! predecessor check is one key.
use heed::{RoTxn, RwTxn};

use super::super::document_candidate_types::{ReceivedCandidateRef, ReceivedRefIngress};
use super::super::document_ingress::{CODE_OPERATIONS, ProvenanceRefKey};
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Vault};

/// Store hash, push provenance, ref-name hash: one open received ref.
const PENDING: SideTable<([u8; 32], EntityId, [u8; 32]), (), Raw> =
    SideTable::new(&side_table::ORIGIN_CODE_PENDING);
/// Store hash, incoming tip: a received ref of that store resolved there.
const RESOLVED_TIP: SideTable<([u8; 32], String), (), Raw> =
    SideTable::new(&side_table::ORIGIN_CODE_RESOLVED_TIP);

fn store_hash(store: &str) -> [u8; 32] {
    *blake3::hash(store.as_bytes()).as_bytes()
}

fn pending_key(store: &str, key: &ProvenanceRefKey) -> ([u8; 32], EntityId, [u8; 32]) {
    (store_hash(store), key.provenance, key.ref_name_hash)
}

/// Whether the intake still reads `row`: no resolution yet, or one
/// resolved from a masked copy, whose projection hold it refreshes.
fn still_read(row: &ReceivedRefIngress) -> bool {
    row.candidate
        .as_ref()
        .is_none_or(|candidate| candidate.resolved.is_none() || candidate.projected.is_some())
}

/// A hold no later pass can change: it reads only the row's own source
/// and objects, or a one-way erase.
fn hold_is_final(reason: &str) -> bool {
    matches!(
        reason,
        "ref_deleted"
            | "no_old_tip"
            | "not_a_commit"
            | "pusher_erased"
            | "no_change"
            | "non_fast_forward"
    )
}

/// Keeps `row`'s markers under `key` true to it in `wtxn`: open while the
/// intake still reads it and its hold is not final, and its incoming tip
/// marked once it resolved.
///
/// # Errors
/// A store failure.
pub(in crate::origin) fn index_received_row_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    key: &ProvenanceRefKey,
    row: &ReceivedRefIngress,
) -> Result<()> {
    let store = &row.source.object_store;
    let pending = pending_key(store, key);
    let held_final = row
        .candidate
        .as_ref()
        .and_then(|candidate| candidate.hold.as_ref())
        .is_some_and(|held| hold_is_final(&held.reason));
    if still_read(row) && !held_final {
        PENDING.put(&vault.store, wtxn, &pending, &())?;
    } else {
        PENDING.delete(&vault.store, wtxn, &pending)?;
    }
    if let (Some(tip), true) = (
        &row.source.new_oid,
        row.candidate
            .as_ref()
            .is_some_and(|candidate| candidate.resolved.is_some()),
    ) {
        RESOLVED_TIP.put(&vault.store, wtxn, &(store_hash(store), tip.clone()), &())?;
    }
    Ok(())
}

impl Vault {
    /// The received refs of the object store `store` the intake still
    /// reads, each read by its key and judged by `keep`, in key order.
    ///
    /// # Errors
    /// A store failure.
    pub(super) fn open_received_candidates_in_txn(
        &self,
        txn: &RoTxn<'_>,
        store: &str,
        mut keep: impl FnMut(&ReceivedRefIngress) -> bool,
        out: &mut Vec<ReceivedCandidateRef>,
    ) -> Result<()> {
        for marker in PENDING.iter_from(&self.store, txn, &store_hash(store))? {
            let ((_, provenance, ref_name_hash), ()) = marker?;
            let key = ProvenanceRefKey {
                provenance,
                ref_name_hash,
            };
            let Some(row) = CODE_OPERATIONS.get(&self.store, txn, &key)? else {
                continue;
            };
            if row.source.object_store == store && keep(&row) {
                out.push(ReceivedCandidateRef {
                    object_store: row.source.object_store,
                    provenance,
                    ref_name: row.source.ref_name,
                });
            }
        }
        Ok(())
    }

    /// Whether a received ref of `store` resolved to the incoming tip
    /// `tip`, one keyed read.
    ///
    /// # Errors
    /// A store failure.
    pub(super) fn received_tip_resolved(&self, store: &str, tip: &str) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        RESOLVED_TIP.contains(&self.store, &txn, &(store_hash(store), tip.to_owned()))
    }
}
