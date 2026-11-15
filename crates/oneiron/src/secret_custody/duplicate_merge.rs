//! A custody record this install minted for a file's key, merged into the
//! synced record of the same value once that record opens here
//! (FILE-CUSTODY-MERGE-AFTER-REWRAP; Engine RULING CUSTODY-MERGE-RETIRE-ACT
//! = A, Sun 15 Nov 20:51).
//!
//! Install A writes a file holding a key: its write door mints record `a`
//! and marks the file with it. Install B, another machine of the same owner,
//! lands the file before `a` opens there, and its own write door mints a
//! second record `b` of the same value; both stand until then
//! (FILE-CUSTODY-DUP-UNOPENED = A). Once `a` opens on B, through a rewrap to
//! B or through a transition that stands only after B's fold caught up, B
//! rebinds the rows `b`'s mint wrote to `a`, revokes `b` here with its value
//! erased, and keeps a value-free merge receipt.
//!
//! Only a record that never left B merges: a mint for a key in a stored
//! file (its mask origin's place is `file`), still active at its first
//! generation with no binding, that no custody transition here, no owner
//! work request, lease, reveal, label, payment mark, purpose or settled
//! found key names. Any other duplicate keeps both records
//! (FILE-CUSTODY-DUP-UNOPENED = A). The merge is this install's alone: `b`
//! never reached another install, so no other install holds a row to change,
//! and no wire kind or signed act is added (stored change: keep).

use heed::RwTxn;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::types::{SecretCustodyRecord, SecretCustodyStatus};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::ShortIdStoreRead;
use crate::secret_record::custody_portable;
use crate::side_table::{self, Named, SideTable};

/// Each record a merge retired, keyed by its id. It holds no value.
const MERGES: SideTable<EntityId, CustodyMerge, Named> =
    SideTable::new(&side_table::SECRET_CUSTODY_MERGE);

/// The receipt of one merge: the record that holds the value now, and when
/// the merge was written. It holds no value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CustodyMerge {
    pub(crate) winner: EntityId,
    pub(crate) merged_at: u64,
}

/// One value's known-value entry, as a merge compares it: its length and
/// keyed fingerprint. The fingerprint is wiped when it drops.
struct ValueEntry {
    len: u32,
    fingerprint: Zeroizing<[u8; 32]>,
}

/// Merges into the record `winner`, which `opened` now holds open here, each
/// record this install minted for a key in a stored file that holds the
/// same value and never left this install, in `wtxn`, the writer that
/// opened `winner`. Each is rebound and revoked, and its receipt kept, at
/// `at`. Returns how many records merged.
///
/// # Errors
///
/// Storage and custody faults.
pub(crate) fn merge_local_duplicates_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    winner: &EntityId,
    opened: &SecretCustodyRecord,
    at: u64,
) -> Result<usize> {
    if opened.status != SecretCustodyStatus::Active || !custody_portable(opened) {
        return Ok(0);
    }
    let store = &vault.store;
    let mints = crate::batch::secret_scan::file_mints_in_txn(store, wtxn)?;
    if mints.iter().all(|mint| mint == winner) {
        return Ok(0);
    }
    // A value the known-value index does not key (a short one, or a name
    // never keyed) is never compared, and no record of it merges.
    let Some(value) = value_entry_in_txn(vault, wtxn, winner, Some(opened.rotation_generation))?
    else {
        return Ok(0);
    };
    let Some(handle) = store
        .port_short_id_reference(&*wtxn, winner)?
        .map(|(handle, _)| handle)
    else {
        return Ok(0);
    };
    let mut merged = 0;
    for loser in mints {
        if loser == *winner {
            continue;
        }
        let Some(record) = super::read_secret_custody_meta_in_txn(store, wtxn, &loser)? else {
            continue;
        };
        if !mint_unchanged(&record) {
            continue;
        }
        let Some(held) = value_entry_in_txn(vault, wtxn, &loser, None)? else {
            continue;
        };
        if held.len != value.len || *held.fingerprint != *value.fingerprint {
            continue;
        }
        if !never_left_in_txn(vault, wtxn, &loser, &record)? {
            continue;
        }
        crate::store::file_key_masks::rebind_masked_key_in_txn(store, wtxn, &loser, winner)?;
        super::found_keys::rebind_found_key_custody_in_txn(store, wtxn, &loser, winner, &handle)?;
        crate::batch::secret_scan::move_mask_origin_in_txn(store, wtxn, &loser, winner)?;
        crate::secret_rotation::revoke_custody_in_txn(
            vault,
            wtxn,
            &loser,
            crate::secret_rotation::RevokeCause::Revoked,
            at,
        )?;
        // Its value is erased and `winner` holds the same bytes, which go on
        // being masked under `winner`'s handle: the merged record's
        // known-value history goes, so no later match names it.
        store.stage_known_history_erase_in_txn(wtxn, &loser)?;
        MERGES.put(
            store,
            wtxn,
            &loser,
            &CustodyMerge {
                winner: *winner,
                merged_at: at,
            },
        )?;
        merged += 1;
    }
    if merged > 0 {
        tracing::debug!(
            merged,
            "custody records minted here merged into an opened record"
        );
    }
    Ok(merged)
}

/// Whether a write door's mint is as the mint wrote it: active and
/// portable at its first generation, with no binding and not held to this
/// device.
fn mint_unchanged(record: &SecretCustodyRecord) -> bool {
    record.status == SecretCustodyStatus::Active
        && custody_portable(record)
        && !record.device_only
        && record.rotation_generation == 0
        && record.bindings.is_empty()
}

/// The known-value entry of the record `id`, read in the writer `wtxn`: the
/// one at `generation`, or, for `None`, its only one. `None` when the index
/// keys no value of it, or more than one where `generation` is `None`.
fn value_entry_in_txn(
    vault: &Vault,
    wtxn: &RwTxn<'_>,
    id: &EntityId,
    generation: Option<u32>,
) -> Result<Option<ValueEntry>> {
    let Some((_master, entries)) = vault.store.known_entries_for_in_writer(wtxn, id)? else {
        return Ok(None);
    };
    let mut picked = entries
        .iter()
        .filter(|(held, _)| generation.is_none_or(|generation| *held == generation));
    let (Some((_, entry)), None) = (picked.next(), picked.next()) else {
        return Ok(None);
    };
    Ok(Some(ValueEntry {
        len: entry.len,
        fingerprint: Zeroizing::new(entry.fingerprint),
    }))
}

/// Whether the record `id`, a write door's mint held here as `record`,
/// never left this install: no custody transition here and no owner work
/// request names it, and no lease, reveal, label, payment mark, purpose or
/// settled found key does. A record any of them names keeps standing beside
/// the opened one (FILE-CUSTODY-DUP-UNOPENED = A).
fn never_left_in_txn(
    vault: &Vault,
    wtxn: &RwTxn<'_>,
    id: &EntityId,
    record: &SecretCustodyRecord,
) -> Result<bool> {
    let store = &vault.store;
    let fold = vault.authority_view_readonly_in_txn(wtxn)?;
    if fold.owner_work_names(id) || fold.custody_revoked(id) {
        return Ok(false);
    }
    Ok(
        !super::transition::custody_transition_held_in_txn(store, wtxn, id)?
            && crate::store::secret_handle_labels::LABEL
                .get(store, wtxn, id)?
                .is_none()
            && crate::store::secret_payment_marks::PAYMENT_MARK
                .get(store, wtxn, id)?
                .is_none()
            && crate::store::secret_handle_purpose::PURPOSE
                .get(store, wtxn, id)?
                .is_none()
            && !super::reveal::custody_ever_revealed_in_txn(store, wtxn, id)?
            && !crate::secret_rotation::secret_ever_leased_in_txn(store, wtxn, &record.name)?
            && !super::found_keys::found_key_settled_in_txn(store, wtxn, id)?,
    )
}
