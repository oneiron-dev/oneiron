//! One fair schedule for retained peer work (FIX 7996, 7997, 8565, 8890).
//!
//! Exact validated work is kept, never refused for a count or a byte total.
//! Each item keeps its arrival and a deadline. One caller's items are served
//! in arrival order, and callers take turns, starting after the one served
//! last. Work that is not ready is passed over. An item past its deadline
//! expires, and its queue keeps a typed, content-free receipt for it.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, Raw, SideTable, SideTableDbs};
use crate::store::Store;
use crate::{Error, Result, Vault};

const DAY: u64 = 24 * 60 * 60;

/// How long retained federation work waits for its turn unless the owner
/// sets another wait: a week.
pub const FEDERATION_BURST_WAIT_SECS: u64 = 7 * DAY;

/// How long a retained maintenance operation waits for its turn unless the
/// owner sets another wait: a week.
pub const MAINTENANCE_INGEST_WAIT_SECS: u64 = 7 * DAY;

/// How long a held facet stamp waits for its row unless the owner sets
/// another wait: 30 days, the hold the stamps always had.
pub const FACET_STAMP_WAIT_SECS: u64 = 30 * DAY;

/// The owner's wait for one queue, in seconds (u64 big-endian).
const WAIT: SideTable<String, Vec<u8>, Raw> = SideTable::new(&side_table::SYNC_RETAINED_WORK_WAIT);

/// The caller one queue served last, so the next pass starts after it.
const CURSOR: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RETAINED_WORK_CURSOR);

/// A queue of retained peer work the one schedule serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetainedWorkQueue {
    /// Deferred and isolated federation updates and deferred selector reads.
    /// A caller is one peer under one selector.
    FederationBurst,
    /// Signed maintenance operations past their signer's share of a quota
    /// window. A caller is one signer.
    MaintenanceIngest,
    /// Facet stamps held ahead of their rows. A caller is one sender's lane.
    FacetStamp,
}

impl RetainedWorkQueue {
    /// The queue's stable code: its key in the wait and cursor tables.
    pub const fn code(self) -> &'static str {
        match self {
            Self::FederationBurst => "federation_burst",
            Self::MaintenanceIngest => "maintenance_ingest",
            Self::FacetStamp => "facet_stamp",
        }
    }

    /// The wait the queue's work has when the owner sets none.
    pub const fn default_wait_secs(self) -> u64 {
        match self {
            Self::FederationBurst => FEDERATION_BURST_WAIT_SECS,
            Self::MaintenanceIngest => MAINTENANCE_INGEST_WAIT_SECS,
            Self::FacetStamp => FACET_STAMP_WAIT_SECS,
        }
    }
}

/// One retained item as the schedule sees it.
pub(crate) struct Waiting<T> {
    /// Whose turn serves it: the queue's fair key.
    pub(crate) caller: Vec<u8>,
    /// When it arrived: a store clock id, so later arrivals sort after.
    pub(crate) arrival: [u8; 16],
    /// When its wait ends, in seconds.
    pub(crate) deadline: u64,
    /// Whether it can run now.
    pub(crate) ready: bool,
    pub(crate) item: T,
}

/// The order one pass serves retained work in, and the items whose wait
/// has ended.
pub(crate) struct Turns<T> {
    /// Each ready item with its caller, in serving order.
    pub(crate) due: Vec<(Vec<u8>, T)>,
    /// Every item past its deadline, ready or not.
    pub(crate) expired: Vec<T>,
}

/// Orders `items` at `now`: oldest first within a caller, one item per
/// caller per round, the first round starting after the caller `after`.
pub(crate) fn turns<T>(items: Vec<Waiting<T>>, after: Option<&[u8]>, now: u64) -> Turns<T> {
    let mut callers = BTreeMap::<Vec<u8>, Vec<([u8; 16], T)>>::new();
    let mut expired = Vec::new();
    for waiting in items {
        if waiting.deadline <= now {
            expired.push(waiting.item);
        } else if waiting.ready {
            callers
                .entry(waiting.caller)
                .or_default()
                .push((waiting.arrival, waiting.item));
        }
    }
    let mut queues = callers
        .into_iter()
        .map(|(caller, mut items)| {
            items.sort_by(|left, right| left.0.cmp(&right.0));
            let items = items.into_iter().map(|(_, item)| item);
            (caller, items.collect::<VecDeque<_>>())
        })
        .collect::<Vec<_>>();
    let start = after.map_or(0, |after| {
        queues
            .iter()
            .position(|(caller, _)| caller.as_slice() > after)
            .unwrap_or(0)
    });
    queues.rotate_left(start);
    let mut due = Vec::new();
    loop {
        let mut served = false;
        for (caller, queue) in &mut queues {
            if let Some(item) = queue.pop_front() {
                due.push((caller.clone(), item));
                served = true;
            }
        }
        if !served {
            break;
        }
    }
    Turns { due, expired }
}

/// How long `queue`'s work waits from its arrival, read in `txn`.
pub(crate) fn wait_secs_in(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    queue: RetainedWorkQueue,
) -> Result<u64> {
    match WAIT.get(dbs, txn, &queue.code().to_owned())? {
        None => Ok(queue.default_wait_secs()),
        Some(bytes) => bytes
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| Error::CorruptedIndex("retained work wait")),
    }
}

/// The caller `queue` served last, read in `txn`.
pub(crate) fn cursor_in(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    queue: RetainedWorkQueue,
) -> Result<Option<Vec<u8>>> {
    CURSOR.get(dbs, txn, &queue.code().to_owned())
}

/// Records `caller` as the one `queue` served last.
pub(crate) fn set_cursor_in(
    dbs: &impl SideTableDbs,
    wtxn: &mut heed::RwTxn<'_>,
    queue: RetainedWorkQueue,
    caller: &[u8],
) -> Result<()> {
    CURSOR.put(dbs, wtxn, &queue.code().to_owned(), &caller.to_vec())
}

/// One queue's deadline index: `m:retained-deadline:v1:<code>:` then the
/// deadline (u64 big-endian) then the waiting item's key, empty-valued, in
/// the sync queue database. The writer that puts an item notes it, and the
/// writer that ends, lands or drops it drops its note, so the index holds
/// exactly the waiting items, earliest first, and the wake read takes its
/// first row (FIX 11183).
fn deadline_prefix(queue: RetainedWorkQueue) -> Vec<u8> {
    format!("m:retained-deadline:v1:{}:", queue.code()).into_bytes()
}

fn deadline_key(queue: RetainedWorkQueue, deadline: u64, item: &[u8]) -> Vec<u8> {
    let mut key = deadline_prefix(queue);
    key.extend_from_slice(&deadline.to_be_bytes());
    key.extend_from_slice(item);
    key
}

/// The deadline and item key of one index row under `prefix`.
fn deadline_row(prefix: &[u8], key: &[u8]) -> Result<(u64, Vec<u8>)> {
    let corrupt = || Error::CorruptedIndex("retained work deadline");
    let rest = key.get(prefix.len()..).ok_or_else(corrupt)?;
    let (deadline, item) = rest.split_at_checked(8).ok_or_else(corrupt)?;
    let deadline = u64::from_be_bytes(deadline.try_into().map_err(|_| corrupt())?);
    Ok((deadline, item.to_vec()))
}

/// Notes `item` of `queue` as waiting until `deadline`.
pub(crate) fn note_deadline_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    queue: RetainedWorkQueue,
    deadline: u64,
    item: &[u8],
) -> Result<()> {
    store
        .sync_queue
        .put(wtxn, &deadline_key(queue, deadline, item), &[])?;
    Ok(())
}

/// Drops the note of `item` of `queue` at `deadline`: it waits no more.
pub(crate) fn drop_deadline_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    queue: RetainedWorkQueue,
    deadline: u64,
    item: &[u8],
) -> Result<()> {
    store
        .sync_queue
        .delete(wtxn, &deadline_key(queue, deadline, item))?;
    Ok(())
}

/// The earliest deadline of `queue`'s waiting items, from one index row;
/// `None` when none waits.
pub(crate) fn earliest_deadline_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    queue: RetainedWorkQueue,
) -> Result<Option<u64>> {
    let prefix = deadline_prefix(queue);
    let Some(row) = store.sync_queue.prefix_iter(txn, &prefix)?.next() else {
        return Ok(None);
    };
    let (key, _) = row?;
    Ok(Some(deadline_row(&prefix, key)?.0))
}

/// Each of `queue`'s waiting items whose deadline is at or before `now`,
/// with that deadline, earliest first: the index rows up to `now` alone.
pub(crate) fn deadlines_through_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    queue: RetainedWorkQueue,
    now: u64,
) -> Result<Vec<(u64, Vec<u8>)>> {
    let prefix = deadline_prefix(queue);
    let mut items = Vec::new();
    for row in store.sync_queue.prefix_iter(txn, &prefix)? {
        let (key, _) = row?;
        let (deadline, item) = deadline_row(&prefix, key)?;
        if deadline > now {
            break;
        }
        items.push((deadline, item));
    }
    Ok(items)
}

impl Vault {
    /// How long `queue`'s retained work waits for its turn before it
    /// expires: the owner's wait, or the queue's default.
    pub fn retained_work_wait_secs(&self, queue: RetainedWorkQueue) -> Result<u64> {
        let txn = self.store.env.read_txn()?;
        wait_secs_in(self, &txn, queue)
    }

    /// Sets how long work `queue` retains from now on waits for its turn,
    /// or with `None` returns it to the default; answers the wait in force.
    pub fn set_retained_work_wait_secs(
        &self,
        owner: &AuthenticatedOwner,
        queue: RetainedWorkQueue,
        secs: Option<u64>,
    ) -> Result<u64> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let key = queue.code().to_owned();
            match secs {
                Some(0) => {
                    return Err(Error::InvalidConfig(
                        "a retained work wait must be greater than zero".into(),
                    ));
                }
                Some(secs) => WAIT.put(self, txn, &key, &secs.to_be_bytes().to_vec())?,
                None => {
                    WAIT.delete(self, txn, &key)?;
                }
            }
            wait_secs_in(self, txn, queue)
        })
    }
}
