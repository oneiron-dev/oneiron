//! Ordered PPR invalidation against a writer or its caller-owned read projection.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use heed::{RoTxn, RwTxn};

use super::{CACHE_DEP_KEY_LEN, CACHE_HEADER_LEN, CACHE_STALE_OFFSET, SEED_HASH_LEN};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::Result;
use crate::scan_check::{EngineScan, ScanCount};
use crate::store::{ManifestDbs, Store};

type SeedHash = [u8; SEED_HASH_LEN];
type DependencyKeys<'a> = Box<dyn Iterator<Item = Result<Cow<'a, [u8]>>> + 'a>;

trait InvalidationRows {
    fn dependency_keys<'a>(&'a self, prefix: Option<&'a EntityId>) -> Result<DependencyKeys<'a>>;
    fn cache(&self, hash: &SeedHash) -> Result<Option<Cow<'_, [u8]>>>;
    fn put_cache(&mut self, hash: SeedHash, value: Vec<u8>) -> Result<()>;
    fn delete_cache(&mut self, hash: &SeedHash) -> Result<()>;
    fn delete_dependency(&mut self, key: &[u8]) -> Result<()>;
    fn start_scan(&self) -> Result<ScanCount>;
    fn defer_scan(&mut self, rows: ScanCount);
}

fn invalidate(rows: &mut impl InvalidationRows, entity_id: &EntityId) -> Result<()> {
    let mut hashes = HashSet::<SeedHash>::new();
    let mut dep_keys_to_delete = Vec::new();
    for entry in rows.dependency_keys(Some(entity_id))? {
        let key = entry?;
        if key.len() != CACHE_DEP_KEY_LEN {
            dep_keys_to_delete.push(key.to_vec());
            continue;
        }

        let mut seed_hash = [0_u8; SEED_HASH_LEN];
        seed_hash.copy_from_slice(&key[ENTITY_ID_LEN..CACHE_DEP_KEY_LEN]);
        hashes.insert(seed_hash);
    }

    for key in &dep_keys_to_delete {
        rows.delete_dependency(key)?;
    }

    for seed_hash in hashes {
        let Some(raw) = rows.cache(&seed_hash)? else {
            delete_dependencies(rows, &seed_hash)?;
            continue;
        };
        if raw.len() < CACHE_HEADER_LEN {
            rows.delete_cache(&seed_hash)?;
            delete_dependencies(rows, &seed_hash)?;
            continue;
        }
        let mut patched = raw.to_vec();
        patched[CACHE_STALE_OFFSET] = 1;
        rows.put_cache(seed_hash, patched)?;
    }

    Ok(())
}

fn delete_dependencies(rows: &mut impl InvalidationRows, seed_hash: &SeedHash) -> Result<()> {
    let mut count = rows.start_scan()?;
    let mut dep_keys = Vec::new();
    for entry in rows.dependency_keys(None)? {
        let key = entry?;
        count.row();
        if key.len() == CACHE_DEP_KEY_LEN && &key[ENTITY_ID_LEN..] == seed_hash {
            dep_keys.push(key.to_vec());
        }
    }
    rows.defer_scan(count);

    for key in dep_keys {
        rows.delete_dependency(&key)?;
    }
    Ok(())
}

struct WriterRows<'a, 'env> {
    store: &'a Store,
    txn: &'a mut RwTxn<'env>,
}

impl InvalidationRows for WriterRows<'_, '_> {
    fn dependency_keys<'a>(&'a self, prefix: Option<&'a EntityId>) -> Result<DependencyKeys<'a>> {
        dependency_keys(self.store, self.txn, prefix)
    }

    fn cache(&self, hash: &SeedHash) -> Result<Option<Cow<'_, [u8]>>> {
        Ok(self.store.ppr_cache().get(self.txn, hash)?)
    }

    fn put_cache(&mut self, hash: SeedHash, value: Vec<u8>) -> Result<()> {
        self.store.ppr_cache().put(self.txn, &hash, &value)?;
        Ok(())
    }

    fn delete_cache(&mut self, hash: &SeedHash) -> Result<()> {
        self.store.ppr_cache().delete(self.txn, hash)?;
        Ok(())
    }

    fn delete_dependency(&mut self, key: &[u8]) -> Result<()> {
        self.store.ppr_cache_deps.delete(self.txn, key)?;
        Ok(())
    }

    fn start_scan(&self) -> Result<ScanCount> {
        ScanCount::start(self.store, self.txn, EngineScan::PprCacheDepRows, &[])
    }

    fn defer_scan(&mut self, rows: ScanCount) {
        rows.defer(self.store);
    }
}

fn dependency_keys<'a>(
    store: &'a Store,
    txn: &'a RoTxn<'_>,
    prefix: Option<&'a EntityId>,
) -> Result<DependencyKeys<'a>> {
    match prefix {
        Some(id) => Ok(Box::new(
            store
                .ppr_cache_deps
                .prefix_iter(txn, id.as_bytes())?
                .map(|row| row.map(|(key, _)| key)),
        )),
        None => Ok(Box::new(
            store
                .ppr_cache_deps
                .iter(txn)?
                .map(|row| row.map(|(key, _)| key)),
        )),
    }
}

pub(super) fn invalidate_ppr_caches(
    store: &Store,
    txn: &mut RwTxn<'_>,
    entity_id: &EntityId,
) -> Result<()> {
    invalidate(&mut WriterRows { store, txn }, entity_id)
}

pub(super) fn delete_dep_rows_for_seed_hash(
    store: &Store,
    txn: &mut RwTxn<'_>,
    seed_hash: &SeedHash,
) -> Result<()> {
    delete_dependencies(&mut WriterRows { store, txn }, seed_hash)
}

/// Reads the caller's snapshot plus earlier invalidations in this projection.
/// It stages no canonical rows and publishes no scan checks.
///
/// This covers only cache/dependency invalidation, not the graph write,
/// admission, clock or callbacks which caused it.
pub(crate) struct PprInvalidationProjection<'a, 'env> {
    store: &'a Store,
    txn: &'a RoTxn<'env>,
    cache: HashMap<SeedHash, Option<Arc<[u8]>>>,
    deleted_dependencies: HashSet<Vec<u8>>,
    operations: Vec<InvalidationOp>,
}

impl<'a, 'env> PprInvalidationProjection<'a, 'env> {
    pub(crate) fn new(store: &'a Store, txn: &'a RoTxn<'env>) -> Self {
        Self {
            store,
            txn,
            cache: HashMap::new(),
            deleted_dependencies: HashSet::new(),
            operations: Vec::new(),
        }
    }

    /// Keep the native source-then-target order, including equal endpoints.
    pub(crate) fn invalidate_for_edge(&mut self, src: &EntityId, tgt: &EntityId) -> Result<()> {
        invalidate(self, src)?;
        invalidate(self, tgt)
    }

    pub(crate) fn into_plan(self) -> PreparedPprInvalidation {
        PreparedPprInvalidation {
            operations: self.operations,
        }
    }
}

impl InvalidationRows for PprInvalidationProjection<'_, '_> {
    fn dependency_keys<'a>(&'a self, prefix: Option<&'a EntityId>) -> Result<DependencyKeys<'a>> {
        Ok(Box::new(
            dependency_keys(self.store, self.txn, prefix)?.filter(|row| match row {
                Ok(key) => !self.deleted_dependencies.contains(key.as_ref()),
                Err(_) => true,
            }),
        ))
    }

    fn cache(&self, hash: &SeedHash) -> Result<Option<Cow<'_, [u8]>>> {
        match self.cache.get(hash) {
            Some(value) => Ok(value.as_deref().map(Cow::Borrowed)),
            None => Ok(self.store.ppr_cache().get(self.txn, hash)?),
        }
    }

    fn put_cache(&mut self, hash: SeedHash, value: Vec<u8>) -> Result<()> {
        let value: Arc<[u8]> = value.into();
        self.cache.insert(hash, Some(Arc::clone(&value)));
        self.operations.push(InvalidationOp::PutCache(hash, value));
        Ok(())
    }

    fn delete_cache(&mut self, hash: &SeedHash) -> Result<()> {
        self.cache.insert(*hash, None);
        self.operations.push(InvalidationOp::DeleteCache(*hash));
        Ok(())
    }

    fn delete_dependency(&mut self, key: &[u8]) -> Result<()> {
        self.deleted_dependencies.insert(key.to_vec());
        self.operations
            .push(InvalidationOp::DeleteDependency(key.to_vec()));
        Ok(())
    }

    fn start_scan(&self) -> Result<ScanCount> {
        ScanCount::start(self.store, self.txn, EngineScan::PprCacheDepRows, &[])
    }

    fn defer_scan(&mut self, rows: ScanCount) {
        self.operations.push(InvalidationOp::DeferScan(rows));
    }
}

enum InvalidationOp {
    PutCache(SeedHash, Arc<[u8]>),
    DeleteCache(SeedHash),
    DeleteDependency(Vec<u8>),
    DeferScan(ScanCount),
}

/// Exact ordered effects selected from one caller-owned snapshot. This is
/// data, not admission or a reusable permission to mutate a later snapshot.
pub(crate) struct PreparedPprInvalidation {
    operations: Vec<InvalidationOp>,
}

impl PreparedPprInvalidation {
    /// Consume at the original invalidation position in the caller's writer.
    /// Only invalidations staged through this projection may have changed its
    /// cache/dependency rows since the captured reads.
    pub(crate) fn apply_in_txn(self, store: &Store, txn: &mut RwTxn<'_>) -> Result<()> {
        for operation in self.operations {
            match operation {
                InvalidationOp::PutCache(hash, value) => {
                    store.ppr_cache().put(txn, &hash, &value)?;
                }
                InvalidationOp::DeleteCache(hash) => {
                    store.ppr_cache().delete(txn, &hash)?;
                }
                InvalidationOp::DeleteDependency(key) => {
                    store.ppr_cache_deps.delete(txn, &key)?;
                }
                InvalidationOp::DeferScan(rows) => rows.defer(store),
            }
        }
        Ok(())
    }
}
