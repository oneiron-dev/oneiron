//! Which records a federation pact delivered here, and at which consent
//! epoch (FIX 321). An import under a pact-bound grant attributes each row of
//! the peer's update that an entity door writes, in the transaction that
//! writes it, to the grant's pact and that pact's epoch, with the world the
//! record sits in. A foreign world it lands in is registered to the pact. A
//! courtesy deletion ask names a pact, worlds and an epoch cutoff; the
//! owner's review reads the records it covers from these rows. Nothing here
//! deletes anything.
//!
//! Every entity door runs on the importing thread (`birth_watch`), so a
//! delivery rides a thread-local for the import's span. Only a row written
//! with the exact bytes the peer's update brought is the pact's: a row this
//! vault already held unchanged writes nothing, and another writer's image
//! is not the peer's.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use loro::LoroMap;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::{EntityId, ForeignWorldId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::sync::loro_support::map_for_each_value_bytes;
use crate::{Vault, ports};

/// Each record one pact delivered at one epoch, with the world it sits in
/// (16 raw bytes; empty for base reality). Key: hex64 (pact) ":" hex16
/// (epoch) ":" hex32 (record).
const DELIVERED: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::FEDERATION_DELIVERED_RECORD);

thread_local! {
    static DELIVERY: RefCell<Option<Delivery>> = const { RefCell::new(None) };
}

/// One import's delivery: the pact and epoch its grant resolves to, and the
/// digest of each row the peer's update brought.
pub(in crate::sync) struct Delivery {
    vault: PathBuf,
    pact: [u8; 32],
    epoch: u64,
    rows: BTreeMap<EntityId, [u8; 32]>,
}

impl Delivery {
    /// The delivery of `rows` ([`delivered_rows`]) into `vault` under pact
    /// `pact` at consent epoch `epoch`.
    pub(in crate::sync) fn new(
        vault: &Vault,
        (pact, epoch): ([u8; 32], u64),
        rows: &BTreeMap<EntityId, [u8; 32]>,
    ) -> Self {
        Self {
            vault: vault.store.env.path().to_path_buf(),
            pact,
            epoch,
            rows: rows.clone(),
        }
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// Every row of a peer's admitted entities map, with the digest of the bytes
/// it brings.
pub(in crate::sync) fn delivered_rows(entities: &LoroMap) -> BTreeMap<EntityId, [u8; 32]> {
    let mut rows = BTreeMap::new();
    map_for_each_value_bytes(entities, |key, value| {
        if let (Ok(id), Some(blob)) = (EntityId::from_hex(key), value) {
            rows.insert(id, digest(blob));
        }
    });
    rows
}

/// Puts back the delivery an outer import installed, on every exit.
struct Restore(Option<Delivery>);

impl Drop for Restore {
    fn drop(&mut self) {
        let outer = self.0.take();
        DELIVERY.with(|slot| *slot.borrow_mut() = outer);
    }
}

/// Runs `import` while the entity doors on this thread attribute what they
/// write from `delivery`'s rows. With no delivery it only runs `import`.
pub(in crate::sync) fn with_delivery<T, E>(
    delivery: Option<Delivery>,
    import: impl FnOnce() -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    let Some(delivery) = delivery else {
        return import();
    };
    let _restore = Restore(DELIVERY.with(|slot| slot.borrow_mut().replace(delivery)));
    import()
}

fn delivery_key(pact: &[u8; 32], epoch: u64, record: EntityId) -> String {
    format!(
        "{}:{epoch:016x}:{}",
        bytes_to_hex_lower(pact),
        record.to_hex()
    )
}

/// Attributes `blob`, which an entity door wrote at `id` in `wtxn`, to the
/// pact and epoch of the delivery an import on this thread carries, when it
/// is that delivery's row with the bytes the peer brought. A foreign world
/// the record sits in is registered to the pact in the same transaction.
pub(in crate::sync) fn note_delivered_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    blob: &[u8],
) -> Result<()> {
    let delivered = DELIVERY.with(|slot| {
        slot.borrow().as_ref().and_then(|delivery| {
            (delivery.vault == vault.store.env.path()
                && delivery.rows.get(&id) == Some(&digest(blob)))
            .then_some((delivery.pact, delivery.epoch))
        })
    });
    let Some((pact, epoch)) = delivered else {
        return Ok(());
    };
    let (Some(header), Some(body)) = (
        EntityMetadataHeader::parse(blob),
        blob.get(ENTITY_METADATA_HEADER_LEN..),
    ) else {
        return Ok(());
    };
    let world = crate::federation::record_scope::record_world_in(
        &vault.store,
        wtxn,
        id,
        header.entity_type,
        body,
    )?
    .flatten();
    let place = world.map_or_else(Vec::new, |world| world.as_bytes().to_vec());
    DELIVERED.put(&vault.store, wtxn, &delivery_key(&pact, epoch, id), &place)?;
    if let Some(foreign) = world.and_then(|world| ForeignWorldId::from_entity_id(world).ok()) {
        crate::federation::register_foreign_world_for_pact_in(vault, wtxn, &pact, foreign)?;
    }
    Ok(())
}

fn corrupt() -> Error {
    Error::CorruptedIndex("federation delivered record")
}

impl Vault {
    /// The records pact `pact_id` delivered here at a consent epoch at or
    /// before `epoch_cutoff`, that sit in one of `worlds`, or in any world
    /// the pact delivered when `worlds` is empty (FIX 321). Base reality is
    /// named by the base world's id. Only records this vault still holds
    /// and has not removed are named. The owner picks from them; this
    /// deletes nothing.
    ///
    /// # Errors
    ///
    /// Storage errors, and a delivery row whose key does not decode.
    pub fn cooperative_deletion_candidates(
        &self,
        pact_id: &[u8; 32],
        worlds: &[EntityId],
        epoch_cutoff: u64,
    ) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let prefix = format!("{}:", bytes_to_hex_lower(pact_id));
        let base = crate::claim::base_world_id();
        let mut candidates = BTreeSet::new();
        for (key, place) in DELIVERED.scan_from(&self.store, &txn, prefix.as_bytes())? {
            let (epoch, record) = key
                .strip_prefix(&prefix)
                .and_then(|rest| rest.split_once(':'))
                .ok_or_else(corrupt)?;
            let epoch = u64::from_str_radix(epoch, 16)
                .ok()
                .filter(|_| epoch.len() == 16)
                .ok_or_else(corrupt)?;
            let record = EntityId::from_hex(record)
                .ok()
                .filter(|id| id.to_hex() == record)
                .ok_or_else(corrupt)?;
            let world = match <[u8; 16]>::try_from(place.as_slice()) {
                Ok(bytes) => EntityId::from_bytes(bytes).map_err(|_| corrupt())?,
                Err(_) if place.is_empty() => base,
                Err(_) => return Err(corrupt()),
            };
            if epoch > epoch_cutoff
                || (!worlds.is_empty() && !worlds.contains(&world))
                || candidates.contains(&record)
                || !ports::EntityStoreRead::port_entity_present(&self.store, &txn, &record)?
                || ports::removed_in_txn(&self.store, &txn, &record)?
            {
                continue;
            }
            candidates.insert(record);
        }
        Ok(candidates.into_iter().collect())
    }
}
