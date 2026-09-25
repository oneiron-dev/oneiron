//! Generation-fenced completion of derived artifacts. Deletion is never undone.
use super::{EntityStoreRead, SourceSpan, TombstoneStoreRead};
use crate::{
    EntityId,
    error::{Error, Result},
    store::ManifestDbs,
};
use heed::RwTxn;
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
    if sources.len() > 100_000 {
        return Err(Error::IndexOverflow("regeneration sources"));
    }
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
    // Replace only this dependent's reverse-indexed rows. Never scan all sources.
    let prefix = reverse_prefix(dependent);
    let mut old = Vec::new();
    for row in store.vault_meta().prefix_iter(txn, &prefix)? {
        if old.len() >= 100_000 {
            return Err(Error::IndexOverflow("regeneration old sources"));
        }
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
        old.push((key.to_vec(), SourceSpan { document, frontier }));
    }
    for (key, source) in old {
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
    store
        .vault_meta()
        .delete(txn, &super::integrity::stale_key(dependent))?;
    Ok(true)
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
