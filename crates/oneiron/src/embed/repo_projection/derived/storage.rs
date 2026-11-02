//! The rows [`super`] keeps (FIX 7608 S3F): one per derived text or probe
//! query a marked repo blob reaches, pending or ready with the proof its
//! safe copy was derived under. A node-local cache: no source bytes, no
//! old words and no secret value, so a row lost or restored stale is only
//! derived again.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// The one schema a row is written in.
pub(crate) const REPO_DERIVED_INDEX_COPY_SCHEMA: u8 = 1;

/// The copies. Key: owner tag + id16.
const COPIES: SideTable<([u8; 1], [u8; 16]), RepoDerivedIndexCopy, Named> =
    SideTable::new(&side_table::REPO_DERIVED_INDEX_COPY);

/// What a copy stands in for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RepoDerivedOwner {
    /// An ASSET_TEXT's indexed text.
    Text(EntityId),
    /// A space probe's evaluation query, by the probe's table id.
    Probe([u8; 16]),
}

impl RepoDerivedOwner {
    const TEXT: u8 = 0;
    const PROBE: u8 = 1;

    fn key(self) -> ([u8; 1], [u8; 16]) {
        match self {
            Self::Text(id) => ([Self::TEXT], *id.as_bytes()),
            Self::Probe(id) => ([Self::PROBE], id),
        }
    }

    fn of_key((tag, id): ([u8; 1], [u8; 16])) -> Result<Self> {
        match tag[0] {
            Self::TEXT => Ok(Self::Text(EntityId::from_bytes(id)?)),
            Self::PROBE => Ok(Self::Probe(id)),
            _ => Err(Error::CorruptedIndex("repo derived index copy owner tag")),
        }
    }
}

/// One copy row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RepoDerivedIndexCopy {
    pub(crate) schema: u8,
    pub(crate) state: RepoDerivedCopyState,
}

/// Where a copy stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RepoDerivedCopyState {
    /// No safe copy holds under the current proof: an index reads the
    /// sealed-file placeholder, an evaluation leaves the probe out, and the
    /// next pass derives it.
    Pending,
    Ready(RepoDerivedReady),
}

/// A safe copy and what it was derived under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RepoDerivedReady {
    /// The owner's content and every source's identity when it was derived.
    pub(crate) proof: [u8; 32],
    /// The sources it was derived from, sorted.
    pub(crate) sources: Vec<[u8; 16]>,
    /// Text derived from the sources' masked copies only.
    pub(crate) safe_text: String,
    /// The model that derived it.
    pub(crate) provenance: String,
}

impl RepoDerivedIndexCopy {
    fn pending() -> Self {
        Self {
            schema: REPO_DERIVED_INDEX_COPY_SCHEMA,
            state: RepoDerivedCopyState::Pending,
        }
    }

    /// The safe copy when it was derived under `proof`.
    pub(crate) fn ready_under(&self, proof: &[u8; 32]) -> Option<&RepoDerivedReady> {
        match &self.state {
            RepoDerivedCopyState::Ready(ready)
                if self.schema == REPO_DERIVED_INDEX_COPY_SCHEMA && ready.proof == *proof =>
            {
                Some(ready)
            }
            _ => None,
        }
    }
}

/// `owner`'s row; a row that does not decode reads as pending, never as a
/// copy.
///
/// # Errors
/// A store failure.
pub(crate) fn copy_in(
    store: &Store,
    txn: &RoTxn<'_>,
    owner: RepoDerivedOwner,
) -> Result<Option<RepoDerivedIndexCopy>> {
    let Some(bytes) = COPIES.get_bytes(store, txn, &owner.key())? else {
        return Ok(None);
    };
    Ok(Some(
        COPIES
            .decode_value(&bytes)
            .unwrap_or_else(|_| RepoDerivedIndexCopy::pending()),
    ))
}

/// Marks `owner`'s copy pending, unless it is ready under `proof`.
///
/// # Errors
/// A store failure.
pub(crate) fn put_pending_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    owner: RepoDerivedOwner,
    proof: Option<&[u8; 32]>,
) -> Result<()> {
    let row = copy_in(store, wtxn, owner)?;
    let current = match (&row, proof) {
        (Some(row), Some(proof)) => row.ready_under(proof).is_some(),
        (Some(row), None) => row.state == RepoDerivedCopyState::Pending,
        (None, _) => false,
    };
    if current {
        return Ok(());
    }
    COPIES.put(store, wtxn, &owner.key(), &RepoDerivedIndexCopy::pending())
}

/// Stores `owner`'s safe copy.
///
/// # Errors
/// A store failure.
pub(crate) fn put_ready_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    owner: RepoDerivedOwner,
    ready: RepoDerivedReady,
) -> Result<()> {
    COPIES.put(
        store,
        wtxn,
        &owner.key(),
        &RepoDerivedIndexCopy {
            schema: REPO_DERIVED_INDEX_COPY_SCHEMA,
            state: RepoDerivedCopyState::Ready(ready),
        },
    )
}

/// Drops `owner`'s row.
///
/// # Errors
/// A store failure.
pub(crate) fn delete_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    owner: RepoDerivedOwner,
) -> Result<()> {
    COPIES.delete(store, wtxn, &owner.key())?;
    Ok(())
}

/// Every row's owner with its row, in key order: texts, then probes.
///
/// # Errors
/// A store failure.
pub(crate) fn copies_in(
    store: &Store,
    txn: &RoTxn<'_>,
) -> Result<Vec<(RepoDerivedOwner, RepoDerivedIndexCopy)>> {
    COPIES
        .scan_keys(store, txn, &[])?
        .into_iter()
        .map(|key| {
            let owner = RepoDerivedOwner::of_key(key)?;
            let row = copy_in(store, txn, owner)?.unwrap_or_else(RepoDerivedIndexCopy::pending);
            Ok((owner, row))
        })
        .collect()
}

/// The pending owners, at most `max_items`, texts first.
///
/// # Errors
/// A store failure.
pub(crate) fn pending_in(
    store: &Store,
    txn: &RoTxn<'_>,
    max_items: usize,
) -> Result<Vec<RepoDerivedOwner>> {
    Ok(copies_in(store, txn)?
        .into_iter()
        .filter(|(_, row)| row.state == RepoDerivedCopyState::Pending)
        .map(|(owner, _)| owner)
        .take(max_items)
        .collect())
}
