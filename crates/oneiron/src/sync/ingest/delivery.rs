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
//!
//! The import also records each row as an intent before it lands any of them
//! (FIX 3498), so a row forward rematerialization writes after a crash,
//! outside the import's span, is still the pact's. An intent goes when a
//! write lands its row, or other bytes there; it never expires.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::path::PathBuf;
use std::time::Duration;

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

/// A row one pact's import brings, recorded before the import lands it: the
/// pact (32 bytes), its epoch and when it was recorded (u64 big-endian
/// seconds each), then the digest of the row's bytes. Key: hex32 (record)
/// ":" hex64 (pact).
const INTENT: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::FEDERATION_DELIVERY_INTENT);

/// How long an intent waits for the write that lands its row: no limit
/// (FIX 3498). A vault offline across a restart must not age a pact's
/// attribution out; an intent goes only when its row lands, when other bytes
/// land there, or when the pact delivers the row again.
const DELIVERY_INTENT_EXPIRY: Option<Duration> = None;

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

    /// Records each row of this delivery as an intent, committed before the
    /// import lands any of them, so the write that lands one after a crash
    /// still attributes it (FIX 3498). The pact's later delivery of the same
    /// row supersedes its intent.
    pub(in crate::sync) fn record_intents(&self, vault: &Vault) -> Result<()> {
        if self.rows.is_empty() {
            return Ok(());
        }
        let held = crate::unix_seconds_now().to_be_bytes();
        let epoch = self.epoch.to_be_bytes();
        vault.with_write_txn_grouped(|wtxn| {
            for (id, sent) in &self.rows {
                let intent = [&self.pact[..], &epoch, &held, sent].concat();
                INTENT.put(&vault.store, wtxn, &intent_key(*id, &self.pact), &intent)?;
            }
            Ok(())
        })
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

/// Every row a peer's raw window update brings in its entities map, those
/// its admission keeps out included: a retained batch holds every byte the
/// peer sent (FIX 11184). An update that does not import names none.
pub(in crate::sync) fn payload_rows(
    key: &crate::sync::types::WindowKey,
    update: &[u8],
) -> BTreeSet<EntityId> {
    let raw = crate::sync::schema::create_window_doc("federation-remote", key);
    if raw.import(update).is_err() {
        return BTreeSet::new();
    }
    delivered_rows(&raw.get_map("entities")).into_keys().collect()
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

fn intent_key(record: EntityId, pact: &[u8; 32]) -> String {
    format!("{}:{}", record.to_hex(), bytes_to_hex_lower(pact))
}

/// An intent row's pact, epoch, when it was recorded and row digest.
fn parse_intent(intent: &[u8]) -> Option<([u8; 32], u64, u64, [u8; 32])> {
    let (pact, rest) = intent.split_first_chunk::<32>()?;
    let (epoch, rest) = rest.split_first_chunk::<8>()?;
    let (held, rest) = rest.split_first_chunk::<8>()?;
    let sent = <[u8; 32]>::try_from(rest).ok()?;
    Some((
        *pact,
        u64::from_be_bytes(*epoch),
        u64::from_be_bytes(*held),
        sent,
    ))
}

/// Takes every intent recorded for `id` in `wtxn`, returning the pact and
/// epoch of each that waited for the bytes that landed (`landed`). One that
/// waited for other bytes goes too: its row was replaced.
fn take_intents_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    landed: &[u8; 32],
) -> Result<BTreeSet<([u8; 32], u64)>> {
    let mut pacts = BTreeSet::new();
    let prefix = format!("{}:", id.to_hex());
    for (key, intent) in INTENT.scan_from(&vault.store, wtxn, prefix.as_bytes())? {
        let (pact, epoch, held, sent) =
            parse_intent(&intent).ok_or(Error::CorruptedIndex("federation delivery intent"))?;
        let lapsed = DELIVERY_INTENT_EXPIRY.is_some_and(|expiry| {
            crate::unix_seconds_now().saturating_sub(held) >= expiry.as_secs()
        });
        if sent == *landed && !lapsed {
            pacts.insert((pact, epoch));
        }
        INTENT.delete(&vault.store, wtxn, &key)?;
    }
    Ok(pacts)
}

/// Attributes `blob`, which an entity door wrote at `id` in `wtxn`, to the
/// pact and epoch of the delivery an import on this thread carries, when it
/// is that delivery's row with the bytes the peer brought, and to those of
/// each intent recorded for those bytes (FIX 3498). A foreign world the
/// record sits in is registered to the pact in the same transaction. A
/// guest's WORLD row lands under its foreign id (FIX 3657): that id is the
/// world it sits in, registered as a foreign CLAIM's world is.
pub(in crate::sync) fn note_delivered_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    blob: &[u8],
) -> Result<()> {
    let landed = digest(blob);
    let mut pacts = take_intents_in_txn(vault, wtxn, id, &landed)?;
    pacts.extend(DELIVERY.with(|slot| {
        slot.borrow().as_ref().and_then(|delivery| {
            (delivery.vault == vault.store.env.path() && delivery.rows.get(&id) == Some(&landed))
                .then_some((delivery.pact, delivery.epoch))
        })
    }));
    if pacts.is_empty() {
        return Ok(());
    }
    let (Some(header), Some(body)) = (
        EntityMetadataHeader::parse(blob),
        blob.get(ENTITY_METADATA_HEADER_LEN..),
    ) else {
        return Ok(());
    };
    let world = if header.entity_type == crate::registry::ENTITY_TYPE_WORLD
        && ForeignWorldId::from_entity_id(id).is_ok()
    {
        Some(id)
    } else {
        crate::federation::record_scope::record_world_in(
            &vault.store,
            wtxn,
            id,
            header.entity_type,
            body,
        )?
        .flatten()
    };
    let place = world.map_or_else(Vec::new, |world| world.as_bytes().to_vec());
    let foreign = world.and_then(|world| ForeignWorldId::from_entity_id(world).ok());
    for (pact, epoch) in pacts {
        DELIVERED.put(&vault.store, wtxn, &delivery_key(&pact, epoch, id), &place)?;
        if let Some(foreign) = foreign {
            crate::federation::register_foreign_world_for_pact_in(vault, wtxn, &pact, foreign)?;
        }
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
    /// named by the base world's id. `worlds` are the requester's own ids, as
    /// its ask names them: each is matched as the foreign WORLD it lands in
    /// here (FIX 3497), and one that lands nowhere matches nothing. Only
    /// records this vault still holds and has not removed are named. The
    /// owner picks from them; this deletes nothing.
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
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let worlds = crate::federation::courtesy_ask_worlds_here(&fold, pact_id, worlds)?;
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
                || worlds
                    .as_ref()
                    .is_some_and(|worlds| !worlds.contains(&world))
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

impl crate::store::Store {
    /// The first consent epoch at which pact `pact_id` delivered `record`
    /// here, as the ledger reads in `txn` (FIX 1322): retrieval holds a copy
    /// to a retained courtesy ask's epoch cutoff by it. It walks only the
    /// epochs the pact delivered something at, in order, seeking past every
    /// epoch it delivered nothing at (FIX 6695), so it reads one row per
    /// delivering epoch, never the pact's records. `None` when the ledger
    /// names no delivery of `record` by the pact.
    ///
    /// # Errors
    ///
    /// Storage errors, and a delivery row whose key does not decode.
    pub(crate) fn federation_first_delivery_epoch_in(
        &self,
        txn: &heed::RoTxn<'_>,
        pact_id: &[u8; 32],
        record: EntityId,
    ) -> Result<Option<u64>> {
        let pact = bytes_to_hex_lower(pact_id);
        let mut from = 0;
        while let Some(epoch) = self.federation_next_delivery_epoch_in(txn, &pact, from)? {
            if DELIVERED.contains(self, txn, &delivery_key(pact_id, epoch, record))? {
                return Ok(Some(epoch));
            }
            let Some(next) = epoch.checked_add(1) else {
                return Ok(None);
            };
            from = next;
        }
        Ok(None)
    }

    /// The first epoch at or after `from` at which the pact whose lowercase
    /// hex id is `pact` delivered anything, read from the one ledger row that
    /// begins it: a seek, so the epochs it delivered nothing at cost nothing.
    fn federation_next_delivery_epoch_in(
        &self,
        txn: &heed::RoTxn<'_>,
        pact: &str,
        from: u64,
    ) -> Result<Option<u64>> {
        let table = side_table::FEDERATION_DELIVERED_RECORD.prefix;
        let start = [table, format!("{pact}:{from:016x}:").as_bytes()].concat();
        // `;` follows `:`, so this bounds the seek to the pact's own rows.
        let end = [table, format!("{pact};").as_bytes()].concat();
        let Some(row) = self
            .sync_state
            .range_bytes(
                txn,
                &(
                    Bound::Included(start.as_slice()),
                    Bound::Excluded(end.as_slice()),
                ),
            )?
            .next()
        else {
            return Ok(None);
        };
        let (key, _) = row?;
        key.strip_prefix(table)
            .and_then(|key| std::str::from_utf8(key).ok())
            .and_then(|key| key.strip_prefix(pact))
            .and_then(|rest| rest.strip_prefix(':'))
            .and_then(|rest| rest.split_once(':'))
            .map(|(epoch, _)| epoch)
            .filter(|epoch| epoch.len() == 16)
            .and_then(|epoch| u64::from_str_radix(epoch, 16).ok())
            .map(Some)
            .ok_or_else(corrupt)
    }
}
