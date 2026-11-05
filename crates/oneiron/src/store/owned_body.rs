//! Stored body descriptors, digest holders, and the released-file queue.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::ManifestDbs;
pub use crate::store::body_descriptor::{
    BodyLocation, BodyRef, BodyState, OwnedBody, RetainedResultProvenance,
};
use heed::{RoTxn, RwTxn};

/// Body descriptors by owner. Key: id16 (owner) + id16 (occurrence).
pub(crate) const BODY: SideTable<(EntityId, EntityId), OwnedBody, Named> =
    SideTable::new(&side_table::PROVENANCE_BODY);

/// Who holds a digest. Key: bytes32 (BLAKE3) + id16 (occurrence); value: the owner.
pub(crate) const BODY_DIGEST: SideTable<([u8; 32], EntityId), EntityId, Named> =
    SideTable::new(&side_table::PROVENANCE_BODY_DIGEST);

/// File digests no descriptor holds any longer, for the file collector.
/// Key: bytes32 (BLAKE3); value: recorded-at of the release.
pub(crate) const BODY_RELEASED: SideTable<[u8; 32], u64, Named> =
    SideTable::new(&side_table::PROVENANCE_BODY_RELEASED);

/// One occurrence's descriptor.
// The result body store (OF-597) and artifact versions call it.
#[allow(dead_code)]
pub(crate) fn owned_body_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    owner: &EntityId,
    occurrence: &EntityId,
) -> Result<Option<OwnedBody>> {
    BODY.get(store, txn, &(*owner, *occurrence))
}

/// Every body `owner` holds, in occurrence order.
pub(crate) fn owned_bodies_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    owner: &EntityId,
) -> Result<Vec<OwnedBody>> {
    Ok(BODY
        .scan_from(store, txn, owner.as_bytes())?
        .into_iter()
        .map(|(_, body)| body)
        .collect())
}

/// The file a raw `vault_meta` row holds when it is a descriptor whose held
/// body (a complete one, or an incomplete one's retained part) is a file: its
/// digest and length. A checkpoint reads its rows raw, so this is how it
/// finds every file a descriptor holds, a legal hold's superseded ASSET file
/// included (FIX 5348).
///
/// # Errors
///
/// A descriptor row that does not decode.
pub(crate) fn file_body_of_row(key: &[u8], value: &[u8]) -> Result<Option<([u8; 32], u64)>> {
    if !key.starts_with(BODY.decl().prefix) {
        return Ok(None);
    }
    Ok(BODY
        .decode_value(value)?
        .state
        .held()
        .filter(|held| held.location == BodyLocation::File)
        .map(|held| (held.blake3, held.bytes)))
}

/// Among raw `vault_meta` rows, every descriptor holding `digest` turned
/// explicitly incomplete with nothing safe to show, and `digest`'s holder
/// and release rows dropped: a restore's prune of a body whose instance an
/// erase retired (KS-2A). Never an unreadable complete body. Rows stay in
/// order.
///
/// # Errors
///
/// A descriptor row that does not decode.
pub(crate) fn prune_digest_in_rows(
    rows: &mut Vec<(Vec<u8>, Vec<u8>)>,
    digest: &[u8; 32],
) -> Result<()> {
    let mut holders = BODY_DIGEST.decl().prefix.to_vec();
    holders.extend_from_slice(digest);
    let released = BODY_RELEASED.key_bytes(digest);
    rows.retain(|(key, _)| !key.starts_with(&holders) && *key != released);
    for (key, value) in rows.iter_mut() {
        if !key.starts_with(BODY.decl().prefix) {
            continue;
        }
        let mut body = BODY.decode_value(value)?;
        if body.state.held().is_some_and(|held| held.blake3 == *digest) {
            body.state = BodyState::Incomplete { retained: None };
            *value = BODY.encode_value(&body)?;
        }
    }
    Ok(())
}

/// Whether any descriptor still holds `blake3`.
pub(crate) fn digest_is_held_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    blake3: &[u8; 32],
) -> Result<bool> {
    Ok(!BODY_DIGEST.scan_keys(store, txn, blake3)?.is_empty())
}

/// Up to `limit` released file digests, oldest key first. The collector
/// unlinks a file only once its reader pins allow and [`take_released_in_txn`]
/// confirms no descriptor took the digest back.
// The result body store (OF-597) and artifact versions call it.
#[allow(dead_code)]
pub(crate) fn released_bodies_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    limit: usize,
) -> Result<Vec<[u8; 32]>> {
    BODY_RELEASED
        .iter_from(store, txn, &[])?
        .take(limit)
        .map(|row| row.map(|(digest, _)| digest))
        .collect()
}

/// Takes `blake3` off the release queue. `true` when the file may go: the
/// digest was queued and no descriptor holds it.
// The result body store (OF-597) and artifact versions call it.
#[allow(dead_code)]
pub(crate) fn take_released_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    blake3: &[u8; 32],
) -> Result<bool> {
    let queued = BODY_RELEASED.delete(store, txn, blake3)?;
    Ok(queued && !digest_is_held_in_txn(store, txn, blake3)?)
}

/// Queues the file of `blake3` for the collector, its holders gone: an
/// activation's prune of a body its source retired (KS-2B1, FIX 6020).
///
/// # Errors
///
/// Storage errors.
pub(crate) fn queue_pruned_file_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    blake3: &[u8; 32],
) -> Result<()> {
    let at = crate::ports::recorded_at_in_txn(store, txn)?;
    BODY_RELEASED.put(store, txn, blake3, &at)
}
