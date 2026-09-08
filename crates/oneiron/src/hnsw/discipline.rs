//! Symmetric vs legacy link discipline and rebuild counters.

use heed::{RoTxn, RwTxn};

use crate::error::{Error, Result};
use crate::store::ManifestDbs;

use super::keys::{
    ERR_FALLBACK_COUNTER_BYTES, ERR_LEGACY_REBUILDS_BYTES, ERR_SYMMETRIC_MARKER_BYTES,
    LEGACY_REBUILDS_KEY, REFRESH_FALLBACK_REBUILDS_KEY, SYMMETRIC_LINKS_ENABLED,
    SYMMETRIC_LINKS_KEY,
};

/// Link discipline of the persisted graph, derived from
/// [`SYMMETRIC_LINKS_KEY`]. Decoding is fail-closed: a present-but-malformed
/// marker is a typed corruption error, never a silent legacy downgrade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinkDiscipline {
    /// Symmetric-link invariant holds: backlinks ≡ forward neighbors.
    Symmetric,
    /// Pre-migration graph: links may be one-way; deletes scan the full
    /// neighbors DB and refreshes rebuild from snapshot.
    Legacy,
}

pub(crate) fn read_link_discipline(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
) -> Result<LinkDiscipline> {
    match store.hnsw_meta().get(txn, SYMMETRIC_LINKS_KEY)? {
        None => Ok(LinkDiscipline::Legacy),
        Some(raw) if *raw == [SYMMETRIC_LINKS_ENABLED] => Ok(LinkDiscipline::Symmetric),
        Some(_) => Err(Error::CorruptedIndex(ERR_SYMMETRIC_MARKER_BYTES)),
    }
}

/// Stamps the vault as maintaining the symmetric-link invariant. Called when
/// a graph is created from empty (fresh vaults) and when a full rebuild
/// rewrites every row symmetrically (the one-time migration path).
pub(crate) fn mark_symmetric_links(store: &impl ManifestDbs, wtxn: &mut RwTxn<'_>) -> Result<()> {
    store
        .hnsw_meta()
        .put(wtxn, SYMMETRIC_LINKS_KEY, &[SYMMETRIC_LINKS_ENABLED])?;
    Ok(())
}

pub(crate) fn read_refresh_fallback_rebuilds(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
) -> Result<u64> {
    let Some(raw) = store.hnsw_meta().get(txn, REFRESH_FALLBACK_REBUILDS_KEY)? else {
        return Ok(0);
    };
    let bytes: [u8; 8] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_FALLBACK_COUNTER_BYTES))?;
    Ok(u64::from_le_bytes(bytes))
}

pub(super) fn increment_refresh_fallback_rebuilds(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
) -> Result<()> {
    let next = read_refresh_fallback_rebuilds(store, &*wtxn)?
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("hnsw refresh fallback counter"))?;
    store
        .hnsw_meta()
        .put(wtxn, REFRESH_FALLBACK_REBUILDS_KEY, &next.to_le_bytes())?;
    Ok(())
}

pub(crate) fn read_legacy_snapshot_rebuilds(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
) -> Result<u64> {
    let Some(raw) = store.hnsw_meta().get(txn, LEGACY_REBUILDS_KEY)? else {
        return Ok(0);
    };
    let bytes: [u8; 8] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_LEGACY_REBUILDS_BYTES))?;
    Ok(u64::from_le_bytes(bytes))
}

pub(super) fn increment_legacy_snapshot_rebuilds(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
) -> Result<()> {
    let next = read_legacy_snapshot_rebuilds(store, &*wtxn)?
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("hnsw legacy rebuild counter"))?;
    store
        .hnsw_meta()
        .put(wtxn, LEGACY_REBUILDS_KEY, &next.to_le_bytes())?;
    Ok(())
}
