//! Source-world evidence for the exact bytes of a thin read cache.

use std::collections::BTreeSet;

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use crate::ports::EntityStoreRead;
use crate::{EntityId, Vault};

/// Worlds read from one original document's exporting transaction. This is
/// cache provenance, not read authority. A cache's bytes must still match it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedItemWorlds {
    source: EntityId,
    blob_digest: [u8; 32],
    document_digest: [u8; 32],
    worlds: BTreeSet<EntityId>,
}

impl CachedItemWorlds {
    /// Whether this evidence names exactly the cached row and document.
    pub fn matches(&self, item: EntityId, blob: &[u8], document: &[u8]) -> bool {
        self.source == item
            && self.blob_digest == *blake3::hash(blob).as_bytes()
            && self.document_digest == *blake3::hash(document).as_bytes()
    }

    /// Whether this provenance belongs to the item named by its cache key.
    pub(crate) fn names(&self, item: EntityId) -> bool {
        self.source == item
    }

    /// Decode optional cache provenance. Malformed evidence proves nothing.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        rmp_serde::from_slice(bytes).ok()
    }

    /// The complete known world set at the exporting transaction.
    pub fn worlds(&self) -> &BTreeSet<EntityId> {
        &self.worlds
    }
}

/// Only an original, unprojected document whose actual row is the served
/// blob can give this evidence. A failed optional observation leaves the
/// existing read intact and its cache provenance unknown.
pub(crate) fn capture_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    source: EntityId,
    requested: EntityId,
    blob: &[u8],
    document: &[u8],
    copied: bool,
    scope: crate::FederationGrantScope,
    selector: &super::super::selector::SyncSelector,
) -> Option<CachedItemWorlds> {
    if copied || source != requested {
        return None;
    }
    let aliases = super::super::selector::RepoCopyAliases::read_in_txn(vault, txn).ok()?;
    if aliases.stored(&source) != source {
        return None;
    }
    let raw = vault.store.port_entity_raw(txn, &source).ok()??;
    if raw.as_slice() != blob {
        return None;
    }
    let carried = crate::settings::carried_worlds_in(&vault.store, txn, &source).ok()?;
    if carried.unknown
        || !super::super::selector::cache_worlds_admitted_in_txn(
            vault,
            txn,
            scope,
            selector,
            &carried.worlds,
        )
        .ok()?
    {
        return None;
    }
    Some(CachedItemWorlds {
        source,
        blob_digest: *blake3::hash(blob).as_bytes(),
        document_digest: *blake3::hash(document).as_bytes(),
        worlds: carried.worlds,
    })
}
