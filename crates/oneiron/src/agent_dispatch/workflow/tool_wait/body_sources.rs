//! Historical source-to-body obligations in exterior custody history.
//!
//! Facts name a source, body owner, published digest and real vault instance.
//! They survive live actor scrubbing and restore with custody history. They
//! never authorize a read; missing facts never mean complete source lineage.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};

use crate::EntityId;
use crate::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::ManifestDbs;
use crate::store::Store;

const TABLE: SideTable<Vec<u8>, Vec<u8>, Raw> = SideTable::new(&side_table::PROVENANCE_BODY_SOURCE);

/// A strict fact key after the prefix: source, body owner, digest, and instance. `None` for any
/// other length or for a source/owner that is not a valid entity id.
fn decode_fact(key: &[u8]) -> Option<(EntityId, EntityId, [u8; 32], [u8; 16])> {
    if key.len() != 80 {
        return None;
    }
    let source_bytes: [u8; 16] = key[0..16].try_into().ok()?;
    let owner_bytes: [u8; 16] = key[16..32].try_into().ok()?;
    let digest: [u8; 32] = key[32..64].try_into().ok()?;
    let instance: [u8; 16] = key[64..80].try_into().ok()?;
    let source = EntityId::from_bytes(source_bytes).ok()?;
    let owner = EntityId::from_bytes(owner_bytes).ok()?;
    Some((source, owner, digest, instance))
}

/// Journals facts for successfully published bodies in the publication's
/// writer. Only native vault instances are recorded; no instance is invented.
#[cfg(unix)]
pub(super) fn record_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    owner: EntityId,
    published_digests: &[[u8; 32]],
    sources: &[EntityId],
) -> Result<()> {
    if published_digests.is_empty() || sources.is_empty() {
        return Ok(());
    }
    let mut uniq_sources = BTreeSet::new();
    for source in sources {
        uniq_sources.insert(*source);
    }
    let mut seen_digests = BTreeSet::new();
    let mut new_rows: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for digest in published_digests {
        if !seen_digests.insert(*digest) {
            continue;
        }
        let mut instances = BTreeSet::new();
        if let Some(row) = crate::store::body_key_row_in_txn(store, txn, digest)? {
            if row.is_vault() {
                instances.insert(row.instance);
            }
        }
        for instance in crate::store::remembered_body_instances_in_txn(store, txn, digest)? {
            instances.insert(instance);
        }
        if instances.is_empty() {
            continue;
        }
        for source in &uniq_sources {
            for instance in &instances {
                let mut key = Vec::with_capacity(80);
                key.extend_from_slice(source.as_bytes());
                key.extend_from_slice(owner.as_bytes());
                key.extend_from_slice(digest);
                key.extend_from_slice(instance);
                if TABLE.contains(store, txn, &key)? {
                    continue;
                }
                TABLE.put(store, txn, &key, &Vec::new())?;
                new_rows.push((TABLE.key_bytes(&key), Vec::new()));
            }
        }
    }
    if !new_rows.is_empty() {
        store.key_custody().journal_body_history(new_rows)?;
    }
    Ok(())
}

/// Native body-key instance storage is unix-only.
#[cfg(not(unix))]
pub(super) fn record_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    owner: EntityId,
    published_digests: &[[u8; 32]],
    sources: &[EntityId],
) -> Result<()> {
    let _ = (store, txn, owner, published_digests, sources);
    Ok(())
}

/// The actual owners and their deduped digests that the historical facts obligate for `source`.
/// Strict 80-byte decode only; no checkpoint read and no author authority.
pub(super) fn matching_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    source: &EntityId,
) -> Result<BTreeMap<EntityId, Vec<[u8; 32]>>> {
    let mut acc: BTreeMap<EntityId, BTreeSet<[u8; 32]>> = BTreeMap::new();
    for key in TABLE.scan_keys(store, txn, source.as_bytes())? {
        let Some((fact_source, owner, digest, _instance)) = decode_fact(&key) else {
            continue;
        };
        if fact_source != *source {
            continue;
        }
        acc.entry(owner).or_default().insert(digest);
    }
    Ok(acc
        .into_iter()
        .map(|(owner, digests)| (owner, digests.into_iter().collect()))
        .collect())
}

/// Historical sources supplement live checkpoint dependencies after actor scrubbing.
pub(super) fn body_dependencies(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
) -> Result<BTreeMap<EntityId, Vec<EntityId>>> {
    let mut acc: BTreeMap<EntityId, BTreeSet<EntityId>> = BTreeMap::new();
    for key in TABLE.scan_keys(dbs, txn, &[])? {
        let Some((source, owner, _digest, _instance)) = decode_fact(&key) else {
            continue;
        };
        acc.entry(owner).or_default().insert(source);
    }
    Ok(acc
        .into_iter()
        .map(|(owner, sources)| (owner, sources.into_iter().collect()))
        .collect())
}

/// Drops this source's live facts after typed erase handed its instances to
/// native retirement. Exterior history keeps instances still owed a retirement.
pub(super) fn forget_source_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    source: &EntityId,
) -> Result<()> {
    for key in TABLE.scan_keys(store, txn, source.as_bytes())? {
        let Some((fact_source, _owner, _digest, _instance)) = decode_fact(&key) else {
            continue;
        };
        if fact_source != *source {
            continue;
        }
        TABLE.delete(store, txn, &key)?;
    }
    Ok(())
}
