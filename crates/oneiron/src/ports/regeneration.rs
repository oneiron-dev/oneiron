//! Generation-fenced completion of derived artifacts. Deletion is never undone.
use super::{EntityStoreRead, SourceSpan, TombstoneStoreRead};
use crate::{
    EntityId,
    error::{Error, Result},
    store::ManifestDbs,
};
use heed::{RoTxn, RwTxn};
const REVERSE: &[u8] = b"ports:dependency_reverse:v1:";
pub(super) fn reverse_prefix(id: &EntityId) -> Vec<u8> {
    [REVERSE, id.as_bytes()].concat()
}

pub(super) fn complete(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    dependent: &EntityId,
    regenerated_at: u64,
    sources: &[SourceSpan],
) -> Result<bool> {
    let Some(raw) = store
        .vault_meta()
        .get(txn, &super::integrity::stale_key(dependent))?
    else {
        return Ok(false);
    };
    let stale_revision = u64::from_be_bytes(
        raw.as_ref()
            .try_into()
            .map_err(|_| Error::CorruptedIndex("stale generation"))?,
    );
    if regenerated_at <= stale_revision || store.port_deletion_state(txn, dependent)?.deleted {
        return Ok(false);
    }
    // A dependent a pending walk still withdraws holds the body its mark
    // covered: no regeneration of it completes, as none would after a
    // single-transaction walk had marked it again.
    if super::dependent_walk::withdrawn_directly_in(store, txn, dependent)? {
        return Ok(false);
    }
    let Some(row) = store.port_entity_record(txn, dependent)? else {
        return Ok(false);
    };
    if row.learned_at != regenerated_at || super::safe_read::body_is_stale(&row.body) {
        return Ok(false);
    }
    for source in sources {
        if source.document == *dependent {
            return Err(Error::InvariantViolation("self dependency"));
        }
        let visibility = store.port_deletion_state(txn, &source.document)?;
        if visibility.deleted || visibility.stale {
            return Ok(false);
        }
        let Some(row) = store.port_entity_record(txn, &source.document)? else {
            return Ok(false);
        };
        if row.learned_at != source.frontier || super::safe_read::body_is_stale(&row.body) {
            return Ok(false);
        }
    }
    // Every export door judges an epoch summary by the sources its
    // `DerivedFrom` edges name, and a deletion withdraws it through its
    // dependency rows. It is fresh again only once the two agree: the edges
    // name exactly the sources it was regenerated from. A dependency row
    // alone certifies nothing a door reads, and an edge to an undeclared
    // source would lose the row that withdraws it on that source's erase; an
    // obsolete edge goes through the batch door first, which withdraws. An
    // ASSET_TEXT is read only beside the sources its edges name (facet rule
    // C), so it is held to the same agreement.
    if row.entity_type == crate::registry::ENTITY_TYPE_ASSET_TEXT
        || (row.entity_type == crate::registry::ENTITY_TYPE_SUMMARY
            && crate::compaction::stored_epoch_in(store, txn, dependent, &row.body)?.may_be())
    {
        let named = super::EdgeStoreRead::port_edges(
            store,
            txn,
            dependent,
            super::EdgeDirection::Out,
            Some(crate::edge::EdgeKind::DerivedFrom),
            None,
        )?
        .map(|edge| edge.map(|edge| edge.target))
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
        let declared = sources
            .iter()
            .map(|source| source.document)
            .collect::<std::collections::BTreeSet<_>>();
        if named != declared {
            return Ok(false);
        }
    }
    // Replace only this dependent's reverse-indexed rows. Never scan all sources.
    for (key, source) in reverse_rows(store, txn, dependent)? {
        store.vault_meta().delete(txn, &key)?;
        let forward = [
            super::integrity::source_prefix(source).as_slice(),
            dependent.as_bytes(),
        ]
        .concat();
        store.vault_meta().delete(txn, &forward)?;
    }
    for source in sources {
        super::integrity::record_dependency_in_txn(store, txn, *source, dependent)?;
    }
    // What an epoch summary was withdrawn for stays: its old words still sit
    // in window history and in snapshots already packed, which a door judges
    // by this row (Sol round 20). It retires with the body.
    store
        .vault_meta()
        .delete(txn, &super::integrity::stale_key(dependent))?;
    Ok(true)
}
/// Takes every dependency row naming `dependent` as derived, forward and
/// reverse, as [`complete`] takes them before re-recording: a deleted row
/// keeps no registration behind it. Reads only `dependent`'s own reverse
/// rows, never all sources.
pub(crate) fn remove_dependency_rows_for_dependent_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    dependent: &EntityId,
) -> Result<()> {
    for (key, source) in reverse_rows(store, txn, dependent)? {
        store.vault_meta().delete(txn, &key)?;
        let forward = [
            super::integrity::source_prefix(source).as_slice(),
            dependent.as_bytes(),
        ]
        .concat();
        store.vault_meta().delete(txn, &forward)?;
    }
    Ok(())
}
/// The sources `dependent` is registered as derived from.
pub(crate) fn dependency_sources_in(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    dependent: &EntityId,
) -> Result<Vec<EntityId>> {
    Ok(reverse_rows(store, txn, dependent)?
        .into_iter()
        .map(|(_, source)| source.document)
        .collect())
}

/// The source versions `dependent` is registered as derived from.
pub(super) fn sources_of(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    dependent: &EntityId,
) -> Result<Vec<SourceSpan>> {
    Ok(reverse_rows(store, txn, dependent)?
        .into_iter()
        .map(|(_, source)| source)
        .collect())
}

/// Every reverse row of `dependent`; a read never refuses for how many
/// (rule 5).
fn reverse_rows(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    dependent: &EntityId,
) -> Result<Vec<(Vec<u8>, SourceSpan)>> {
    let prefix = reverse_prefix(dependent);
    let mut rows = Vec::new();
    for row in store.vault_meta().prefix_iter(txn, &prefix)? {
        let (key, _) = row?;
        if key.len() != prefix.len() + 24 {
            return Err(Error::CorruptedIndex("reverse dependency key"));
        }
        let document = EntityId::from_bytes(
            key[prefix.len()..prefix.len() + 16]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("reverse dependency id"))?,
        )?;
        let frontier = u64::from_be_bytes(
            key[prefix.len() + 16..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("reverse dependency frontier"))?,
        );
        rows.push((key.to_vec(), SourceSpan { document, frontier }));
    }
    Ok(rows)
}

impl<T: ManifestDbs> super::DependencyIndex for T {
    fn port_dependency_put(
        &self,
        txn: &mut RwTxn<'_>,
        source: SourceSpan,
        dependent: &EntityId,
    ) -> Result<()> {
        super::integrity::record_dependency_in_txn(self, txn, source, dependent)
    }
    fn port_dependency_list_by_source(
        &self,
        txn: &heed::RoTxn<'_>,
        source: SourceSpan,
    ) -> Result<Vec<EntityId>> {
        super::integrity::list_by_source(self, txn, source)
    }
    fn port_dependency_complete_regeneration(
        &self,
        txn: &mut RwTxn<'_>,
        dependent: &EntityId,
        regenerated_at: u64,
        sources: &[SourceSpan],
    ) -> Result<bool> {
        complete(self, txn, dependent, regenerated_at, sources)
    }
}
