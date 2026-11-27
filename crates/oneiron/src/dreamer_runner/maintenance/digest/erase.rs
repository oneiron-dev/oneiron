//! PROACTIVITY-DIGEST-COPY-ERASURE (disk half): a stored digest keeps a
//! proposal's predicate and value in its summary and its rendered text.
//! Both delete doors (`deletion::derived_rows`) drop those copies in the
//! erase's own transaction via `maintenance::erase_source_copies_in_txn`.
//! A rewritten digest keeps its locator and gets a new content hash.
//! A withdrawal is not an erase; D1 hides the withdrawn item in the view.
//! Digests stored before this index have no membership rows. D1's view
//! check hides their items whose proposals no longer stand as copied.

use std::collections::BTreeSet;

use super::{DIGEST, ProactivityDigest, view};
use crate::side_table::{self, SideTable};
use crate::store::Store;
use crate::{EntityId, Result};

/// Each stored digest under each proposal CLAIM it copied.
pub(super) const CLAIM_DIGESTS: SideTable<(EntityId, [u8; 32]), (), side_table::Raw> =
    SideTable::new(&side_table::DREAMER_PROACTIVITY_CLAIM_DIGESTS);

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

/// Drops the erased CLAIM's copies and its index rows. A no-op for an id
/// no digest copied.
pub(crate) fn erase_sources_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
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
    let Some(mut digest) = DIGEST.decode_value(&bytes).ok().filter(|digest| {
        digest.id == locator
            && view::content_hash(digest).is_ok_and(|hash| hash == digest.content_hash)
    }) else {
        DIGEST.delete(store, txn, &locator)?;
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
