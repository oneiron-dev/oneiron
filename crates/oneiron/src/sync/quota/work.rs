//! Signed maintenance operations kept for their turn instead of refused (FIX
//! 8565, 8858).
//!
//! An operation past its signer's share of a quota window, or behind that
//! signer's own waiting work, is kept with its exact bytes and the context
//! its door judged it in: the window it came through and the lease vault its
//! signature verifies against. The housekeeping pass drains it through the
//! same entity ladder, so the signature, lease, standing and echo checks run
//! again at replay. Signers take turns, each one's work oldest first. An
//! operation past its wait, refused at replay, or erased keeps a
//! content-free receipt.

use std::cell::Cell;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::entity_id::bytes_to_hex_lower;
use crate::error::SyncError;
use crate::side_table::{self, Named, SideTable, SideTableDbs};
use crate::store::Store;
use crate::sync::federation_burst::erase::{self, CarriedBy};
use crate::sync::federation_burst::schedule::{self, RetainedWorkQueue, Waiting};
use crate::sync::ingest::{EntityStep, IngestCtx, RefusalRetry, ingest_entity_in_txn};
use crate::sync::loro_support::TombstoneIndex;
use crate::{EntityId, Error, Result, Vault};

/// The retained operations, by signer key (64 hex) then entity id (32 hex).
const WORK: SideTable<String, RetainedMaintenance, Named> =
    SideTable::new(&side_table::SYNC_MAINTENANCE_RETAINED_WORK);

/// The schedule queue these operations wait in: its deadline index notes
/// each Pending one.
const QUEUE: RetainedWorkQueue = RetainedWorkQueue::MaintenanceIngest;

/// The most retained operations one drain pass replays; the next pass starts
/// with the signer after the last one served.
pub const MAINTENANCE_DRAIN_TURNS: usize = 4096;

/// Where a retained maintenance operation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceWorkState {
    /// It waits for its turn.
    Pending,
    /// Its wait ended before it landed.
    Expired,
    /// Its replay refused it for good.
    Rejected,
    /// An erase took its row.
    Erased,
}

#[derive(Serialize, Deserialize)]
struct RetainedMaintenance {
    /// When it was retained: a store clock id, so a signer's work drains
    /// oldest first.
    arrival: [u8; 16],
    /// When its wait ends, in seconds.
    deadline: u64,
    /// The window it came through.
    window: String,
    /// The lease vault its signature verifies against.
    lease_vault_id: u64,
    /// Its exact entities-map value; none once it is a receipt.
    blob: Option<Vec<u8>>,
    state: MaintenanceWorkState,
}

/// One retained maintenance operation as the owner sees it, without bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceRetainedReceipt {
    /// The signer key its share is counted under, as in the quota snapshots.
    pub peer_key_hex: String,
    /// The row it carries.
    pub entity: EntityId,
    /// When its wait ends, in Unix seconds.
    pub deadline_secs: u64,
    pub state: MaintenanceWorkState,
}

/// One operation a maintenance door would retain: the window it came
/// through, the lease vault its signature verifies against, its row and its
/// exact bytes.
pub(in crate::sync) struct MaintenanceOp<'a> {
    window: &'a str,
    lease_vault_id: u64,
    id: &'a EntityId,
    blob: &'a [u8],
}

impl<'a> MaintenanceOp<'a> {
    pub(in crate::sync) const fn new(
        window: &'a str,
        lease_vault_id: u64,
        id: &'a EntityId,
        blob: &'a [u8],
    ) -> Self {
        Self {
            window,
            lease_vault_id,
            id,
            blob,
        }
    }
}

thread_local! {
    static REPLAYING: Cell<bool> = const { Cell::new(false) };
}

/// Whether the door runs for the drain's replay, which admits now.
pub(super) fn replaying() -> bool {
    REPLAYING.with(Cell::get)
}

struct Replaying;

impl Drop for Replaying {
    fn drop(&mut self) {
        REPLAYING.with(|replaying| replaying.set(false));
    }
}

fn key(peer_key: &[u8; 32], id: &EntityId) -> String {
    format!("{}{}", bytes_to_hex_lower(peer_key), id.to_hex())
}

fn entity_of(key: &str) -> Result<EntityId> {
    key.get(64..)
        .and_then(|hex| EntityId::from_hex(hex).ok())
        .ok_or(Error::CorruptedIndex("retained maintenance work key"))
}

/// Whether the signer `peer_key` has work waiting.
pub(super) fn waiting_in(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    peer_key: &[u8; 32],
) -> Result<bool> {
    for row in WORK.iter_from(dbs, txn, bytes_to_hex_lower(peer_key).as_bytes())? {
        if row?.1.state == MaintenanceWorkState::Pending {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Keeps `op` from the signer `peer_key` for its turn, with its arrival and
/// its deadline from the owner's wait. An op already waiting stays as it
/// arrived first; a receipt for the same row gives way to the new wait.
pub(super) fn retain_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    peer_key: &[u8; 32],
    op: MaintenanceOp<'_>,
    now: u64,
) -> Result<()> {
    let key = key(peer_key, op.id);
    if WORK
        .get(vault, wtxn, &key)?
        .is_some_and(|saved| saved.state == MaintenanceWorkState::Pending)
    {
        return Ok(());
    }
    let wait = schedule::wait_secs_in(vault, wtxn, RetainedWorkQueue::MaintenanceIngest)?;
    let work = RetainedMaintenance {
        arrival: vault.store.clock.ulid()?,
        deadline: now.saturating_add(wait),
        window: op.window.to_owned(),
        lease_vault_id: op.lease_vault_id,
        blob: Some(op.blob.to_vec()),
        state: MaintenanceWorkState::Pending,
    };
    WORK.put(vault, wtxn, &key, &work)?;
    schedule::note_deadline_in_txn(&vault.store, wtxn, QUEUE, work.deadline, key.as_bytes())?;
    erase::register_in_txn(vault, wtxn, &[*op.id], &CarriedBy::Maintenance(key))
}

/// Ends the Pending op at `key` with `state`: its bytes go, and only the
/// content-free receipt stays.
fn end_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    key: &str,
    state: MaintenanceWorkState,
) -> Result<()> {
    let key = key.to_owned();
    let Some(mut work) = WORK.get(store, wtxn, &key)? else {
        return Ok(());
    };
    if work.state != MaintenanceWorkState::Pending {
        return Ok(());
    }
    work.blob = None;
    work.state = state;
    WORK.put(store, wtxn, &key, &work)?;
    schedule::drop_deadline_in_txn(store, wtxn, QUEUE, work.deadline, key.as_bytes())?;
    let id = entity_of(&key)?;
    erase::forget_in_txn(store, wtxn, &[id], &CarriedBy::Maintenance(key))
}

/// Scrubs the retained op at `key` for an erase of its row (FIX 7998).
pub(crate) fn erase_retained_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    key: &str,
) -> Result<()> {
    end_in_txn(store, wtxn, key, MaintenanceWorkState::Erased)
}

/// Replays the retained op at `key` through the entity ladder in a savepoint,
/// its share passed over; `true` when it landed. A refusal a later pass may
/// lift leaves it waiting; any other refusal ends it as Rejected. `windows`
/// holds the tombstones of each window this pass loaded, so a window is
/// loaded once per pass, however many of its ops the pass replays.
fn replay(vault: &Vault, key: &str, windows: &mut HashMap<String, TombstoneIndex>) -> Result<bool> {
    // The window first, in a read of its own: the tombstone index below
    // loads the window document, which opens its own read transactions and
    // takes the materializer lock on a live window — neither crosses into
    // the write below (lock order materializer → LMDB).
    let window = {
        let txn = vault.store.env.read_txn()?;
        let Some(work) = WORK.get(vault, &txn, &key.to_owned())? else {
            return Ok(false);
        };
        let (MaintenanceWorkState::Pending, Some(_)) = (work.state, &work.blob) else {
            return Ok(false);
        };
        work.window.clone()
    };
    let tombstones = windows
        .entry(window.clone())
        .or_insert_with(|| window_tombstones(vault, &window));
    vault.with_write_txn_grouped(|wtxn| {
        let Some(work) = WORK.get(vault, wtxn, &key.to_owned())? else {
            return Ok(false);
        };
        let (MaintenanceWorkState::Pending, Some(blob)) = (work.state, &work.blob) else {
            return Ok(false);
        };
        if work.window != window {
            // Re-retained under another window between the two reads; the
            // next pass loads that window's tombstones instead.
            return Ok(false);
        }
        let id = entity_of(key)?;
        let ctx = IngestCtx::new(vault, &work.window, work.lease_vault_id, tombstones);
        let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
        let step = {
            REPLAYING.with(|replaying| replaying.set(true));
            let _replaying = Replaying;
            ingest_entity_in_txn(&ctx, &mut savepoint, &id.to_hex(), Some(blob.as_slice()))?
        };
        if let EntityStep::Quarantine(refusal) = step {
            drop(savepoint);
            if refusal.retry == RefusalRetry::Terminal {
                end_in_txn(&vault.store, wtxn, key, MaintenanceWorkState::Rejected)?;
            }
            return Ok(false);
        }
        savepoint.commit()?;
        WORK.delete(vault, wtxn, &key.to_owned())?;
        schedule::drop_deadline_in_txn(&vault.store, wtxn, QUEUE, work.deadline, key.as_bytes())?;
        erase::forget_in_txn(vault, wtxn, &[id], &CarriedBy::Maintenance(key.to_owned()))?;
        Ok(true)
    })
}

/// The tombstones of `window`, indexed for one replay (FIX 11185): the live
/// document's when the window is open here, else the persisted state with
/// its pending updates. A window that does not read replays as it did
/// before its index, gated by the `dt:` marker and the row fence the ladder
/// still checks.
fn window_tombstones(vault: &Vault, window: &str) -> TombstoneIndex {
    let Some(key) = crate::sync::WindowKey::try_new(window) else {
        tracing::warn!(
            "retained maintenance: window key does not parse; replaying without CRDT tombstones"
        );
        return empty_tombstones();
    };
    if let Some((live, materializer, _)) = vault.live_window(&key) {
        let _guard = materializer.lock();
        return TombstoneIndex::build(&live.doc.get_map("tombstones"));
    }
    let doc = match crate::sync::window::load_window_from_state(vault, "local", &key) {
        Ok(doc) => doc,
        Err(Error::Sync(SyncError::WindowNotFound { .. })) => {
            match crate::sync::window::rebuild_window_from_updates(vault, "local", &key) {
                Ok(doc) => doc,
                Err(error) => {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "retained maintenance: window rebuild failed; replaying without CRDT tombstones"
                    );
                    return empty_tombstones();
                }
            }
        }
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "retained maintenance: window load failed; replaying without CRDT tombstones"
            );
            return empty_tombstones();
        }
    };
    TombstoneIndex::build(&doc.get_map("tombstones"))
}

/// No tombstones: what a replay the window's index does not cover falls
/// back to.
fn empty_tombstones() -> TombstoneIndex {
    let doc = loro::LoroDoc::new();
    TombstoneIndex::build(&doc.get_map("tombstones"))
}

/// Replays the retained maintenance work whose turn has come, at most
/// [`MAINTENANCE_DRAIN_TURNS`] ops: signers in turn from the one after the
/// last served, each signer's oldest first. Work past its wait ends with its
/// receipt. Returns how many ops landed.
pub(crate) fn drain_retained_maintenance(vault: &Vault) -> Result<u64> {
    let queue = RetainedWorkQueue::MaintenanceIngest;
    let now = vault.now_recorded_at();
    let turns = {
        let txn = vault.store.env.read_txn()?;
        let after = schedule::cursor_in(vault, &txn, queue)?;
        let mut waiting = Vec::new();
        for row in WORK.iter_from(vault, &txn, &[])? {
            let (key, work) = row?;
            if work.state != MaintenanceWorkState::Pending {
                continue;
            }
            let caller = key
                .get(..64)
                .ok_or(Error::CorruptedIndex("retained maintenance work key"))?;
            waiting.push(Waiting {
                caller: caller.as_bytes().to_vec(),
                arrival: work.arrival,
                deadline: work.deadline,
                ready: true,
                item: key,
            });
        }
        schedule::turns(waiting, after.as_deref(), now)
    };
    if !turns.expired.is_empty() {
        vault.with_write_txn_grouped(|wtxn| {
            for key in &turns.expired {
                if WORK
                    .get(vault, wtxn, key)?
                    .is_some_and(|work| work.deadline <= now)
                {
                    end_in_txn(&vault.store, wtxn, key, MaintenanceWorkState::Expired)?;
                }
            }
            Ok(())
        })?;
    }
    let mut landed = 0;
    let mut served = None;
    // Each window this pass replays into is loaded once (FIX 11185).
    let mut windows = HashMap::new();
    for (caller, key) in turns.due.into_iter().take(MAINTENANCE_DRAIN_TURNS) {
        if replay(vault, &key, &mut windows)? {
            landed += 1;
        }
        served = Some(caller);
    }
    if let Some(caller) = served {
        vault
            .with_write_txn_grouped(|wtxn| schedule::set_cursor_in(vault, wtxn, queue, &caller))?;
    }
    Ok(landed)
}

/// The earliest deadline of the Pending retained ops, or `None` when none
/// waits: the same rows [`drain_retained_maintenance`] ends (FIX 11183),
/// read from the first row of their deadline index.
pub(crate) fn earliest_retained_deadline(vault: &Vault) -> Result<Option<u64>> {
    let txn = vault.store.env.read_txn()?;
    schedule::earliest_deadline_in(&vault.store, &txn, QUEUE)
}

/// Every retained maintenance operation and receipt, without bytes, by
/// signer then row.
pub fn maintenance_ingest_retained(vault: &Vault) -> Result<Vec<MaintenanceRetainedReceipt>> {
    let txn = vault.store.env.read_txn()?;
    let mut receipts = Vec::new();
    for row in WORK.iter_from(vault, &txn, &[])? {
        let (key, work) = row?;
        receipts.push(MaintenanceRetainedReceipt {
            peer_key_hex: key.get(..64).unwrap_or_default().to_owned(),
            entity: entity_of(&key)?,
            deadline_secs: work.deadline,
            state: work.state,
        });
    }
    Ok(receipts)
}
