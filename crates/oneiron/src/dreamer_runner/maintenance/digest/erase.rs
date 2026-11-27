//! PROACTIVITY-DIGEST-COPY-ERASURE (disk half): a stored digest keeps a
//! proposal's predicate and value in its summary and its rendered text.
//! Both delete doors (`deletion::derived_rows`) drop those copies in the
//! erase's own transaction via `maintenance::erase_source_copies_in_txn`.
//! A rewritten digest keeps its locator and gets a new content hash.
//! A withdrawal is not an erase; D1 hides the withdrawn item in the view.
//! The first erase indexes every digest stored before the membership table
//! existed, once per vault, before its lookup. The pass and its marker are
//! written in that erase's transaction. A row that does not decode or
//! verify is deleted whole.

use std::collections::BTreeSet;

use super::{DIGEST, ProactivityDigest, view};
use crate::side_table::{self, SideTable};
use crate::store::Store;
use crate::{EntityId, Result};

/// Each stored digest under each proposal CLAIM it copied.
pub(super) const CLAIM_DIGESTS: SideTable<(EntityId, [u8; 32]), (), side_table::Raw> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_CLAIM_DIGESTS);

/// Marks the vault's one-time backfill of stored digest memberships.
const CLAIM_DIGESTS_INDEXED: SideTable<(), Vec<u8>, side_table::Raw> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_CLAIM_DIGESTS_INDEXED);

/// Indexes the stored digest once for each distinct CLAIM it copied.
pub(super) fn index_digest_claims_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    digest: &ProactivityDigest,
) -> Result<()> {
    let claims: BTreeSet<_> = digest
        .groups
        .values()
        .flatten()
        .map(|proposal| proposal.claim_ref)
        .collect();
    for claim in claims {
        CLAIM_DIGESTS.put(store, txn, &(claim, digest.id), &())?;
    }
    Ok(())
}

fn index_stored_digests_once_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    if CLAIM_DIGESTS_INDEXED.contains(store, txn, &())? {
        return Ok(());
    }
    let rows = super::DIGEST
        .iter_raw_from(store, txn, &[])?
        .collect::<Result<Vec<_>>>()?;
    for (key, bytes) in rows {
        let Ok(locator) = <[u8; 32]>::try_from(key.as_slice()) else {
            // A key of the wrong length cannot come from a typed put.
            continue;
        };
        if let Some(digest) = verify_digest_or_delete_in_txn(store, txn, locator, &bytes)? {
            index_digest_claims_in_txn(store, txn, &digest)?;
        }
    }
    CLAIM_DIGESTS_INDEXED.put(store, txn, &(), &b"1".to_vec())
}

/// Drops the erased CLAIM's copies and its index rows. A no-op for an id
/// no digest copied.
pub(crate) fn erase_sources_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    // Index pre-existing digests once in this transaction, before the lookup.
    index_stored_digests_once_in_txn(store, txn)?;
    for (_, locator) in CLAIM_DIGESTS.scan_keys(store, txn, id.as_bytes())? {
        scrub_digest_in_txn(store, txn, locator, id)?;
        CLAIM_DIGESTS.delete(store, txn, &(*id, locator))?;
    }
    Ok(())
}

/// Removes the CLAIM from one stored digest and renders it again. A row
/// that does not verify goes whole; a missing row needs no scrub.
fn scrub_digest_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    locator: [u8; 32],
    id: &EntityId,
) -> Result<()> {
    let Some(bytes) = DIGEST.get_bytes(store, txn, &locator)? else {
        return Ok(());
    };
    let Some(mut digest) = verify_digest_or_delete_in_txn(store, txn, locator, &bytes)? else {
        return Ok(());
    };
    let mut removed = false;
    digest.groups.retain(|_, proposals| {
        let before = proposals.len();
        proposals.retain(|proposal| proposal.claim_ref != *id);
        removed |= proposals.len() != before;
        !proposals.is_empty()
    });
    if !removed {
        return Ok(());
    }
    let rendered = view::render(&digest, &digest.groups);
    digest.rendered = rendered;
    DIGEST.admit(store, txn, &locator, &mut digest)?;
    digest.content_hash = view::content_hash(&digest)?;
    DIGEST.put(store, txn, &locator, &digest)
}

/// Decodes one stored digest and checks its locator and content hash, deleting it on failure.
fn verify_digest_or_delete_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    locator: [u8; 32],
    bytes: &[u8],
) -> Result<Option<ProactivityDigest>> {
    let digest = DIGEST.decode_value(bytes).ok().filter(|digest| {
        digest.id == locator
            && view::content_hash(digest).is_ok_and(|hash| hash == digest.content_hash)
    });
    if digest.is_none() {
        DIGEST.delete(store, txn, &locator)?;
    }
    Ok(digest)
}

/// Leaves the stored digests with no membership index or backfill marker, as before D2.
#[cfg(oneiron_test_support)]
pub(crate) fn forget_claim_digest_index_for_test(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    let keys = CLAIM_DIGESTS.scan_keys(store, txn, &[])?;
    for key in keys {
        CLAIM_DIGESTS.delete(store, txn, &key)?;
    }
    CLAIM_DIGESTS_INDEXED.delete(store, txn, &())?;
    Ok(())
}

/// Checks whether the stored digest membership backfill is marked complete.
#[cfg(oneiron_test_support)]
pub(crate) fn claim_digests_indexed_for_test(store: &Store, txn: &heed::RoTxn<'_>) -> Result<bool> {
    CLAIM_DIGESTS_INDEXED.contains(store, txn, &())
}
