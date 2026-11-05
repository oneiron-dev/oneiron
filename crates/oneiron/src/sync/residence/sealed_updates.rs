//! The home's queue of sealed world updates (DEC-0005 fix 8, CLIP-SYNC = A,
//! FIX 12586), and this machine's place in it and its own sealed updates
//! still to be stored.
//!
//! The home keeps each update as opaque bytes, in arrival order, numbered
//! from 1 within the queue's epoch, once per id, for
//! [`SEALED_UPDATE_KEEP_SECS`]. It reads none of them. A machine keeps the
//! epoch and the last number it took (its cursor), and each update it sealed
//! until its home says the update is stored (its outbox).

use std::ops::Bound;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::sync::transport::{SEALED_UPDATE_EPOCH_LEN, SEALED_UPDATE_FRAME_ID_LEN};

/// How long the home keeps a sealed update, and a machine an update it could
/// not get stored: 90 days, as the home keeps sealed bundles (BUNDLE-RETENTION
/// = A, owner 2026-10-18). A machine away longer takes the world from the
/// daily sealed bundle.
pub const SEALED_UPDATE_KEEP_SECS: u64 = 90 * 24 * 60 * 60;
/// The most updates one catch-up page carries.
pub const SEALED_UPDATE_PAGE_ENTRIES: usize = 256;
/// The most sealed bytes one catch-up page carries past its first update.
pub const SEALED_UPDATE_PAGE_BYTES: usize = 16 * 1024 * 1024;
/// The most aged updates one store retires: the rest go at the next stores.
const RETIRE_PER_STORE: usize = 64;

/// A home's queue epoch.
pub type SealedUpdateEpoch = [u8; SEALED_UPDATE_EPOCH_LEN];
/// A sealed update's id.
pub type SealedUpdateId = [u8; SEALED_UPDATE_FRAME_ID_LEN];

/// u64be stored-at second ‖ id, before the sealed bytes of a home entry.
const ENTRY_HEADER_LEN: usize = 8 + SEALED_UPDATE_FRAME_ID_LEN;
/// id ‖ world ‖ u64be sealed-at second, before the sealed bytes of an outbox
/// row.
const OUTBOX_HEADER_LEN: usize = SEALED_UPDATE_FRAME_ID_LEN + 16 + 8;

const ENTRIES: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_SEALED_UPDATE_ENTRY);
const IDS: SideTable<String, Vec<u8>, Raw> = SideTable::new(&side_table::SYNC_SEALED_UPDATE_ID);
const QUEUE: SideTable<(), Vec<u8>, Raw> = SideTable::new(&side_table::SYNC_SEALED_UPDATE_QUEUE);
const CURSOR: SideTable<(), Vec<u8>, Raw> = SideTable::new(&side_table::SYNC_SEALED_UPDATE_CURSOR);
const OUTBOX: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_SEALED_UPDATE_OUTBOX);
const OUTBOX_IDS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_SEALED_UPDATE_OUTBOX_ID);

fn seq_key(seq: u64) -> String {
    format!("{seq:016x}")
}

fn id_key(id: &SealedUpdateId) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn corrupt(what: &'static str) -> Error {
    Error::InvariantViolation(what)
}

fn be_u64(raw: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(raw.try_into().map_err(|_| {
        corrupt("a sealed update row holds a malformed number")
    })?))
}

/// The home's queue: its epoch and the last number it gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedUpdateQueue {
    pub epoch: SealedUpdateEpoch,
    pub head: u64,
}

impl SealedUpdateQueue {
    fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() != SEALED_UPDATE_EPOCH_LEN + 8 {
            return Err(corrupt("the sealed update queue row is malformed"));
        }
        let mut epoch = [0u8; SEALED_UPDATE_EPOCH_LEN];
        epoch.copy_from_slice(&raw[..SEALED_UPDATE_EPOCH_LEN]);
        Ok(Self {
            epoch,
            head: be_u64(&raw[SEALED_UPDATE_EPOCH_LEN..])?,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SEALED_UPDATE_EPOCH_LEN + 8);
        out.extend_from_slice(&self.epoch);
        out.extend_from_slice(&self.head.to_be_bytes());
        out
    }
}

/// The queue in `wtxn`, its epoch minted when the home has none yet.
fn queue_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>) -> Result<SealedUpdateQueue> {
    if let Some(raw) = QUEUE.get(&vault.store, wtxn, &())? {
        return SealedUpdateQueue::decode(&raw);
    }
    let mut epoch = [0u8; SEALED_UPDATE_EPOCH_LEN];
    crate::key_material::os_fill(&mut epoch)?;
    let queue = SealedUpdateQueue { epoch, head: 0 };
    QUEUE.put(&vault.store, wtxn, &(), &queue.encode())?;
    Ok(queue)
}

/// The home's queue, its epoch minted on first use.
///
/// # Errors
/// Store errors; a malformed queue row.
pub fn sealed_update_queue(vault: &Vault) -> Result<SealedUpdateQueue> {
    {
        let txn = vault.store.env.read_txn()?;
        if let Some(raw) = QUEUE.get(&vault.store, &txn, &())? {
            return SealedUpdateQueue::decode(&raw);
        }
    }
    vault.with_write_txn_grouped(|wtxn| queue_in_txn(vault, wtxn))
}

/// Where the home stored one update: its number in the queue's epoch, and
/// whether this store put it there or an earlier one did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredSealedUpdate {
    pub epoch: SealedUpdateEpoch,
    pub seq: u64,
    pub fresh: bool,
}

/// The home stores `sealed` under `id`, once: an id it holds already keeps
/// its first number. The same commit retires updates kept past
/// [`SEALED_UPDATE_KEEP_SECS`].
///
/// # Errors
/// Store errors; a malformed queue or index row; a queue at `u64::MAX`.
pub fn store_sealed_update(
    vault: &Vault,
    id: &SealedUpdateId,
    sealed: &[u8],
) -> Result<StoredSealedUpdate> {
    vault.with_write_txn_grouped(|wtxn| {
        let mut queue = queue_in_txn(vault, wtxn)?;
        if let Some(raw) = IDS.get(&vault.store, wtxn, &id_key(id))? {
            return Ok(StoredSealedUpdate {
                epoch: queue.epoch,
                seq: be_u64(&raw)?,
                fresh: false,
            });
        }
        let now = vault.instant_in_txn(wtxn)?.secs();
        retire_in(vault, wtxn, now)?;
        queue.head = queue
            .head
            .checked_add(1)
            .ok_or(corrupt("the sealed update queue is full"))?;
        let mut row = Vec::with_capacity(ENTRY_HEADER_LEN + sealed.len());
        row.extend_from_slice(&now.to_be_bytes());
        row.extend_from_slice(id);
        row.extend_from_slice(sealed);
        ENTRIES.put(&vault.store, wtxn, &seq_key(queue.head), &row)?;
        IDS.put(
            &vault.store,
            wtxn,
            &id_key(id),
            &queue.head.to_be_bytes().to_vec(),
        )?;
        QUEUE.put(&vault.store, wtxn, &(), &queue.encode())?;
        Ok(StoredSealedUpdate {
            epoch: queue.epoch,
            seq: queue.head,
            fresh: true,
        })
    })
}

/// Retires, oldest first, at most [`RETIRE_PER_STORE`] updates stored
/// before `now` less [`SEALED_UPDATE_KEEP_SECS`].
fn retire_in(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, now: u64) -> Result<()> {
    let cutoff = now.saturating_sub(SEALED_UPDATE_KEEP_SECS);
    let mut aged = Vec::new();
    for row in ENTRIES.iter_raw_from(&vault.store, wtxn, &[])? {
        let (key, raw) = row?;
        if aged.len() >= RETIRE_PER_STORE || raw.len() < ENTRY_HEADER_LEN {
            break;
        }
        if be_u64(&raw[..8])? >= cutoff {
            break;
        }
        let mut id = [0u8; SEALED_UPDATE_FRAME_ID_LEN];
        id.copy_from_slice(&raw[8..ENTRY_HEADER_LEN]);
        let key = String::from_utf8(key).map_err(|_| corrupt("a sealed update key is not text"))?;
        aged.push((key, id));
    }
    for (key, id) in aged {
        ENTRIES.delete(&vault.store, wtxn, &key)?;
        IDS.delete(&vault.store, wtxn, &id_key(&id))?;
    }
    Ok(())
}

/// One catch-up page: the updates after a machine's cursor, in order, and
/// the number the machine has taken through once it takes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedUpdatePage {
    pub epoch: SealedUpdateEpoch,
    pub entries: Vec<(u64, Vec<u8>)>,
    pub through: u64,
    pub more: bool,
}

/// The updates the home keeps after `after` in `epoch`, from the queue's
/// start when `epoch` is not the queue's: at most
/// [`SEALED_UPDATE_PAGE_ENTRIES`] updates and [`SEALED_UPDATE_PAGE_BYTES`]
/// sealed bytes past the first. With nothing more to send, `through` is the
/// queue's head, so a cursor passes updates already retired.
///
/// # Errors
/// Store errors; a malformed queue or entry row.
pub fn sealed_updates_since(
    vault: &Vault,
    epoch: &SealedUpdateEpoch,
    after: u64,
) -> Result<SealedUpdatePage> {
    sealed_update_queue(vault)?;
    let txn = vault.store.env.read_txn()?;
    let queue = QUEUE
        .get(&vault.store, &txn, &())?
        .map(|raw| SealedUpdateQueue::decode(&raw))
        .transpose()?
        .ok_or(corrupt("the sealed update queue went missing"))?;
    let start = if *epoch == queue.epoch { after } else { 0 };
    let mut page = SealedUpdatePage {
        epoch: queue.epoch,
        entries: Vec::new(),
        through: start,
        more: false,
    };
    let mut bytes = 0usize;
    let from = seq_key(start);
    for row in ENTRIES.iter_range(&vault.store, &txn, Bound::Excluded(&from), Bound::Unbounded)? {
        let (key, raw) = row?;
        let seq = u64::from_str_radix(&key, 16)
            .map_err(|_| corrupt("a sealed update key is not a number"))?;
        let sealed = raw
            .get(ENTRY_HEADER_LEN..)
            .ok_or(corrupt("a sealed update entry is malformed"))?;
        if page.entries.len() >= SEALED_UPDATE_PAGE_ENTRIES
            || (!page.entries.is_empty() && bytes + sealed.len() > SEALED_UPDATE_PAGE_BYTES)
        {
            page.more = true;
            break;
        }
        bytes += sealed.len();
        page.entries.push((seq, sealed.to_vec()));
        page.through = seq;
    }
    if !page.more {
        page.through = page.through.max(queue.head);
    }
    Ok(page)
}

/// This machine's place in its home's queue: the epoch and the last number
/// it took. `None` until a home first offered sealed updates.
///
/// # Errors
/// Store errors; a malformed cursor row.
pub fn sealed_update_cursor(vault: &Vault) -> Result<Option<(SealedUpdateEpoch, u64)>> {
    let txn = vault.store.env.read_txn()?;
    CURSOR
        .get(&vault.store, &txn, &())?
        .map(|raw| SealedUpdateQueue::decode(&raw).map(|queue| (queue.epoch, queue.head)))
        .transpose()
}

/// Records this machine's place in its home's queue.
///
/// # Errors
/// Store errors.
pub fn put_sealed_update_cursor(vault: &Vault, epoch: &SealedUpdateEpoch, seq: u64) -> Result<()> {
    let row = SealedUpdateQueue {
        epoch: *epoch,
        head: seq,
    }
    .encode();
    vault.with_write_txn_grouped(|wtxn| CURSOR.put(&vault.store, wtxn, &(), &row))
}

/// One update this machine sealed, still to be stored on its home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxSealedUpdate {
    pub id: SealedUpdateId,
    pub world: EntityId,
    pub sealed: Vec<u8>,
}

/// Keeps `sealed`, of `world`, until the home stores it, after every row kept
/// before it: the outbox goes in the order its updates were made, so an
/// update never reaches a reader before one it stands on. An id kept already
/// keeps its place.
///
/// # Errors
/// Store errors; a malformed outbox row.
pub fn put_sealed_update_outbox(
    vault: &Vault,
    id: &SealedUpdateId,
    world: EntityId,
    sealed: &[u8],
) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        if OUTBOX_IDS.contains(&vault.store, wtxn, &id_key(id))? {
            return Ok(());
        }
        let last = match OUTBOX.iter_rev_from(&vault.store, wtxn, &[])?.next() {
            Some(row) => {
                let (key, _) = row?;
                u64::from_str_radix(&key, 16)
                    .map_err(|_| corrupt("a sealed outbox key is not a number"))?
            }
            None => 0,
        };
        let seq = last
            .checked_add(1)
            .ok_or(corrupt("the sealed outbox is full"))?;
        let now = vault.instant_in_txn(wtxn)?.secs();
        let mut row = Vec::with_capacity(OUTBOX_HEADER_LEN + sealed.len());
        row.extend_from_slice(id);
        row.extend_from_slice(world.as_bytes());
        row.extend_from_slice(&now.to_be_bytes());
        row.extend_from_slice(sealed);
        OUTBOX.put(&vault.store, wtxn, &seq_key(seq), &row)?;
        OUTBOX_IDS.put(&vault.store, wtxn, &id_key(id), &seq.to_be_bytes().to_vec())
    })
}

/// The first `limit` updates still to be stored, in the order they were
/// kept. Rows kept past [`SEALED_UPDATE_KEEP_SECS`] go instead: the home
/// would have retired them.
///
/// # Errors
/// Store errors; a malformed outbox row.
pub fn sealed_update_outbox(vault: &Vault, limit: usize) -> Result<Vec<OutboxSealedUpdate>> {
    let (now, rows) = {
        let txn = vault.store.env.read_txn()?;
        let now = vault.instant_in_txn(&txn)?.secs();
        let mut rows = Vec::new();
        for row in OUTBOX.iter_raw_from(&vault.store, &txn, &[])? {
            let (key, raw) = row?;
            rows.push((key, raw));
            if rows.len() >= limit {
                break;
            }
        }
        (now, rows)
    };
    let cutoff = now.saturating_sub(SEALED_UPDATE_KEEP_SECS);
    let mut out = Vec::with_capacity(rows.len());
    let mut aged = Vec::new();
    for (key, raw) in rows {
        let key = String::from_utf8(key).map_err(|_| corrupt("a sealed outbox key is not text"))?;
        if raw.len() <= OUTBOX_HEADER_LEN {
            return Err(corrupt("a sealed outbox row is malformed"));
        }
        let mut id = [0u8; SEALED_UPDATE_FRAME_ID_LEN];
        id.copy_from_slice(&raw[..SEALED_UPDATE_FRAME_ID_LEN]);
        let world_at = SEALED_UPDATE_FRAME_ID_LEN + 16;
        if be_u64(&raw[world_at..OUTBOX_HEADER_LEN])? < cutoff {
            aged.push((key, id));
            continue;
        }
        let world = EntityId::from_bytes(
            raw[SEALED_UPDATE_FRAME_ID_LEN..world_at]
                .try_into()
                .map_err(|_| corrupt("a sealed outbox row is malformed"))?,
        )?;
        out.push(OutboxSealedUpdate {
            id,
            world,
            sealed: raw[OUTBOX_HEADER_LEN..].to_vec(),
        });
    }
    if !aged.is_empty() {
        vault.with_write_txn_grouped(|wtxn| {
            for (key, id) in &aged {
                OUTBOX.delete(&vault.store, wtxn, key)?;
                OUTBOX_IDS.delete(&vault.store, wtxn, &id_key(id))?;
            }
            Ok(())
        })?;
    }
    Ok(out)
}

/// Drops the outbox row `id`: its home stored it, or its world no longer
/// syncs sealed.
///
/// # Errors
/// Store errors; a malformed outbox index row.
pub fn drop_sealed_update_outbox(vault: &Vault, id: &SealedUpdateId) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        let Some(raw) = OUTBOX_IDS.get(&vault.store, wtxn, &id_key(id))? else {
            return Ok(());
        };
        OUTBOX.delete(&vault.store, wtxn, &seq_key(be_u64(&raw)?))?;
        OUTBOX_IDS.delete(&vault.store, wtxn, &id_key(id))?;
        Ok(())
    })
}
