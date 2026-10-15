//! Engine scans never refuse for how many rows they read (rule 5: ARCH-0044
//! C5, OF-520).
//!
//! Each engine scan over a table that grows with use has a threshold row. A
//! scan that reads past its row raises one [`ScanCheck`] for its scope and
//! reads on: the check is evidence for the host's "is everything okay"
//! question, never a refusal. Only machine floors (disk, memory) stop a scan.
//!
//! A scan counts in a `ScanCount`. A crossing waits with the vault, in
//! memory, until the vault's next write keeps it in the same transaction;
//! the host's read of the checks sees it either way. No scan ever opens a
//! writer, so none can wait on a writer its caller holds, on any thread.

use std::collections::BTreeMap;
use std::sync::Mutex;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::{ManifestDbs, Store};

/// Rows one engine scan reads past which it asks whether everything is
/// okay: ten times the count each of the origin scans once refused at.
pub const DEFAULT_SCAN_CHECK_THRESHOLD: u64 = 1_000_000;

/// Device-local threshold row of one scan. Key: the scan's tag.
const POLICY: SideTable<[u8; 1], u64, Raw> = SideTable::new(&side_table::ORIGIN_SCAN_POLICY);
/// The check one scan raised for one scope. Key: the scan's tag, then its
/// scope's bytes, or nothing for a vault-wide scan.
const CHECK: SideTable<([u8; 1], Vec<u8>), ScanCheck, Named> =
    SideTable::new(&side_table::ORIGIN_SCAN_CHECK);

type CheckKey = ([u8; 1], Vec<u8>);

/// Each engine scan whose table grows with use, and so each that once
/// refused past a row count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineScan {
    /// One repository's receive-pack intents: its pending pushes, and any
    /// settled one the scan prunes on its way.
    ReceivePackIntents,
    /// The vault's publication journal, every repository's history.
    PublicationRows,
    /// One repository's visible-ref slots: one per ref name it publishes.
    VisibleRefRows,
    /// One repository's keep-ref owners, every kind.
    KeepOwnerRows,
    /// The tasks an omitted ask target or task context is resolved from, for
    /// one asking actor.
    TaskCensusRows,
    /// One ask's words.
    AskWordRows,
    /// The room members' tasks a thread census reads, for one reader.
    RoomThreadTasks,
    /// The rows one session's read set holds.
    ReadSetRows,
    /// One room's history rows a message page passes over.
    RoomPageRows,
    /// One room's history rows a liveness snapshot reads.
    RoomHistoryRows,
}

impl EngineScan {
    /// Every scan, the list the check that none refuses for a count reads.
    pub const ALL: [Self; 10] = [
        Self::ReceivePackIntents,
        Self::PublicationRows,
        Self::VisibleRefRows,
        Self::KeepOwnerRows,
        Self::TaskCensusRows,
        Self::AskWordRows,
        Self::RoomThreadTasks,
        Self::ReadSetRows,
        Self::RoomPageRows,
        Self::RoomHistoryRows,
    ];

    /// The origin's scans, each over one repository or the publication
    /// journal.
    pub const ORIGIN: [Self; 4] = [
        Self::ReceivePackIntents,
        Self::PublicationRows,
        Self::VisibleRefRows,
        Self::KeepOwnerRows,
    ];

    /// The closed code the scan's row, check and log line name it by.
    pub const fn code(self) -> &'static str {
        match self {
            Self::ReceivePackIntents => "receive_pack_intents",
            Self::PublicationRows => "publication_rows",
            Self::VisibleRefRows => "visible_ref_rows",
            Self::KeepOwnerRows => "keep_owner_rows",
            Self::TaskCensusRows => "task_census_rows",
            Self::AskWordRows => "ask_word_rows",
            Self::RoomThreadTasks => "room_thread_tasks",
            Self::ReadSetRows => "read_set_rows",
            Self::RoomPageRows => "room_page_rows",
            Self::RoomHistoryRows => "room_history_rows",
        }
    }

    const fn tag(self) -> [u8; 1] {
        [match self {
            Self::ReceivePackIntents => 1,
            Self::PublicationRows => 2,
            Self::VisibleRefRows => 3,
            Self::KeepOwnerRows => 4,
            Self::TaskCensusRows => 32,
            Self::AskWordRows => 33,
            Self::RoomThreadTasks => 34,
            Self::ReadSetRows => 35,
            Self::RoomPageRows => 36,
            Self::RoomHistoryRows => 37,
        }]
    }
}

/// OF-520 question one engine scan raised for one scope, the first time it
/// read more rows than its threshold. Evidence for the host, never a
/// refusal: the scan read on and served.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanCheck {
    /// The scan ([`EngineScan::code`]).
    pub scan: String,
    /// The scope the scan read, in hex: a repository's or a record's id, a
    /// type byte, a window. `None` for a vault-wide scan.
    #[serde(alias = "repo_id")]
    pub scope: Option<String>,
    /// The threshold in force at the crossing.
    pub threshold: u64,
    /// Rows the scan read when it crossed it.
    pub rows: u64,
    /// Unix seconds of the crossing.
    pub raised_at: u64,
}

impl ScanCheck {
    /// Machine-readable check discriminator; presentation text belongs to hosts.
    pub const KIND: &'static str = "scan_size";
}

fn threshold_in_txn(store: &impl ManifestDbs, txn: &RoTxn<'_>, scan: EngineScan) -> Result<u64> {
    Ok(POLICY
        .get(store, txn, &scan.tag())?
        .unwrap_or(DEFAULT_SCAN_CHECK_THRESHOLD))
}

/// One scan's rows, counted against its threshold row.
#[must_use = "a count raises its check only when it is finished"]
pub(crate) struct ScanCount {
    scan: EngineScan,
    scope: Vec<u8>,
    threshold: u64,
    rows: u64,
}

impl ScanCount {
    /// Starts counting `scan` of `scope` (empty for a vault-wide scan), under
    /// the row `txn` reads.
    pub(crate) fn start(
        store: &impl ManifestDbs,
        txn: &RoTxn<'_>,
        scan: EngineScan,
        scope: &[u8],
    ) -> Result<Self> {
        Ok(Self {
            scan,
            scope: scope.to_vec(),
            threshold: threshold_in_txn(store, txn, scan)?,
            rows: 0,
        })
    }

    /// Counts one row read.
    pub(crate) fn row(&mut self) {
        self.rows = self.rows.saturating_add(1);
    }

    /// Raises the scan's check when it read past its row, once per scope:
    /// the vault's next write keeps it. The scan has served either way.
    pub(crate) fn finish(self, vault: &Vault) {
        self.defer(&vault.store);
    }

    /// [`Self::finish`] through a read target, for a scan that holds a
    /// store or a room's view rather than the vault.
    pub(crate) fn defer(self, store: &impl ManifestDbs) {
        if self.rows <= self.threshold {
            return;
        }
        let check = self.check();
        store
            .pending_scan_checks()
            .park((self.scan.tag(), self.scope), check);
    }

    fn check(&self) -> ScanCheck {
        ScanCheck {
            scan: self.scan.code().to_owned(),
            scope: (!self.scope.is_empty()).then(|| bytes_to_hex_lower(&self.scope)),
            threshold: self.threshold,
            rows: self.rows,
            raised_at: crate::unix_seconds_now(),
        }
    }
}

/// What one write kept of the crossings waiting with its vault. They leave
/// the waiting map, and are warned of, only once that write commits
/// ([`KeptChecks::committed`]); a write that rolls back leaves them waiting.
#[must_use = "kept checks leave the waiting map only once their write commits"]
#[derive(Default)]
pub(crate) struct KeptChecks {
    keys: Vec<CheckKey>,
    fresh: Vec<ScanCheck>,
}

impl KeptChecks {
    /// The write that kept these committed.
    pub(crate) fn committed(self, store: &Store) {
        store.pending_scan_checks.clear(&self.keys);
        self.fresh.iter().for_each(warn);
    }
}

/// Keeps the crossings waiting with the store inside the host's write
/// `txn`, each scope once, in a nested transaction of their own: a check that
/// cannot be written (a full map, a row error) is dropped from this write and
/// waits for the next one, and the host's write goes on as it would have.
pub(crate) fn keep_pending_in(store: &Store, txn: &mut RwTxn<'_>) -> KeptChecks {
    let waiting = store.pending_scan_checks.waiting();
    if waiting.is_empty() {
        return KeptChecks::default();
    }
    match keep_nested(store, txn, &waiting) {
        Ok(fresh) => KeptChecks {
            keys: waiting.into_keys().collect(),
            fresh,
        },
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "scan checks were not kept; they wait for the next write"
            );
            KeptChecks::default()
        }
    }
}

fn keep_nested(
    store: &Store,
    txn: &mut RwTxn<'_>,
    waiting: &BTreeMap<CheckKey, ScanCheck>,
) -> Result<Vec<ScanCheck>> {
    let mut nested = store.env.nested_write_txn(txn)?;
    let mut fresh = Vec::new();
    for (key, check) in waiting {
        if !CHECK.contains(store, &nested, key)? {
            CHECK.put(store, &mut nested, key, check)?;
            fresh.push(check.clone());
        }
    }
    nested.commit()?;
    Ok(fresh)
}

/// `check.scan` is always an [`EngineScan::code`]: a closed code.
fn warn(check: &ScanCheck) {
    tracing::warn!(
        kind = ScanCheck::KIND,
        scan = check.scan.as_str(),
        threshold = check.threshold,
        rows = check.rows,
        "a scan read past its threshold row and served; is everything okay?"
    );
}

/// Crossings a store holds until a point no write is held keeps them: one
/// per scan and scope, the first.
#[derive(Default)]
pub(crate) struct PendingScanChecks(Mutex<BTreeMap<CheckKey, ScanCheck>>);

impl PendingScanChecks {
    fn park(&self, key: CheckKey, check: ScanCheck) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(key)
            .or_insert(check);
    }

    fn waiting(&self) -> BTreeMap<CheckKey, ScanCheck> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn clear(&self, keys: &[CheckKey]) {
        let mut waiting = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for key in keys {
            waiting.remove(key);
        }
    }
}

impl Vault {
    /// The threshold row of one engine scan.
    pub fn scan_threshold(&self, scan: EngineScan) -> Result<u64> {
        let txn = self.store.env.read_txn()?;
        threshold_in_txn(&self.store, &txn, scan)
    }

    /// Sets one engine scan's device-local threshold row. Crossing it raises
    /// a check; no value makes the scan refuse.
    pub fn set_scan_threshold(&self, scan: EngineScan, threshold: u64) -> Result<()> {
        self.with_write_txn_grouped(|wtxn| {
            POLICY.put(&self.store, wtxn, &scan.tag(), &threshold)?;
            Ok(())
        })
    }

    /// Every OF-520 check an engine scan raised, kept or still waiting for
    /// the vault's next write. Checks are local-only.
    pub fn scan_checks(&self) -> Result<Vec<ScanCheck>> {
        let txn = self.store.env.read_txn()?;
        let mut checks = BTreeMap::new();
        for row in CHECK.iter_from(&self.store, &txn, &[])? {
            let (key, check) = row?;
            checks.insert(key, check);
        }
        for (key, check) in self.store.pending_scan_checks.waiting() {
            checks.entry(key).or_insert(check);
        }
        Ok(checks.into_values().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A check kept before the door served every engine scan named its scope
    /// `repo_id`; it reads as the same check.
    #[test]
    fn a_check_kept_by_the_origin_door_still_reads() {
        #[derive(Serialize)]
        struct OriginScanCheck {
            scan: String,
            repo_id: Option<String>,
            threshold: u64,
            rows: u64,
            raised_at: u64,
        }
        let kept = rmp_serde::to_vec_named(&OriginScanCheck {
            scan: "keep_owner_rows".to_owned(),
            repo_id: Some("0f".repeat(16)),
            threshold: 2,
            rows: 3,
            raised_at: 7,
        })
        .expect("encode");
        let check: ScanCheck = rmp_serde::from_slice(&kept).expect("decode");
        assert_eq!(check.scope.as_deref(), Some("0f".repeat(16).as_str()));
        assert_eq!((check.threshold, check.rows), (2, 3));
    }

    /// A crossing never opens a writer: inside a write it is kept by that
    /// write, outside one it waits, visible to the host, for the vault's
    /// next write. Each scope is kept once however often it crosses.
    #[test]
    fn a_crossing_waits_for_the_next_write_and_never_opens_one() {
        let dir = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(dir.path(), crate::VaultConfig::default()).expect("open");
        for scan in [EngineScan::PublicationRows, EngineScan::VisibleRefRows] {
            vault.set_scan_threshold(scan, 1).expect("threshold");
        }
        let cross = |txn: &RoTxn<'_>, scan| -> Result<ScanCount> {
            let mut count = ScanCount::start(&vault.store, txn, scan, &[])?;
            count.row();
            count.row();
            Ok(count)
        };
        vault
            .with_write_txn(|wtxn| {
                cross(wtxn, EngineScan::PublicationRows)?.finish(&vault);
                cross(wtxn, EngineScan::PublicationRows)?.defer(&vault.store);
                Ok(())
            })
            .expect("a write that crossed a scan row commits");
        assert!(vault.store.pending_scan_checks.waiting().is_empty());
        let txn = vault.store.env.read_txn().expect("read");
        cross(&txn, EngineScan::VisibleRefRows)
            .expect("count")
            .finish(&vault);
        drop(txn);
        assert_eq!(vault.store.pending_scan_checks.waiting().len(), 1);
        assert_eq!(vault.scan_checks().expect("checks").len(), 2);
        vault.with_write_txn(|_| Ok(())).expect("a write");
        assert!(vault.store.pending_scan_checks.waiting().is_empty());
        let checks = vault.scan_checks().expect("checks");
        assert_eq!(checks.len(), 2);
        assert!(
            checks
                .iter()
                .all(|check| (check.threshold, check.rows) == (1, 2))
        );
    }

    /// A waiting crossing leaves the map only with a write that commits: a
    /// write that keeps it and then rolls back, or a write that fails, leaves
    /// it waiting for the next.
    #[test]
    fn a_waiting_check_leaves_only_with_a_committed_write() {
        let dir = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(dir.path(), crate::VaultConfig::default()).expect("open");
        vault
            .set_scan_threshold(EngineScan::PublicationRows, 1)
            .expect("threshold");
        let txn = vault.store.env.read_txn().expect("read");
        let mut count =
            ScanCount::start(&vault.store, &txn, EngineScan::PublicationRows, &[]).expect("count");
        count.row();
        count.row();
        drop(txn);
        count.finish(&vault);

        let mut wtxn = vault.store.env.write_txn().expect("write");
        let kept = keep_pending_in(&vault.store, &mut wtxn);
        drop(kept);
        drop(wtxn);
        assert_eq!(vault.store.pending_scan_checks.waiting().len(), 1);
        let failed: Result<()> = vault.with_write_txn(|_| Err(crate::Error::InvalidKey));
        assert!(failed.is_err());
        assert_eq!(vault.store.pending_scan_checks.waiting().len(), 1);

        vault.with_write_txn(|_| Ok(())).expect("a write");
        assert!(vault.store.pending_scan_checks.waiting().is_empty());
        let txn = vault.store.env.read_txn().expect("read");
        assert_eq!(
            CHECK
                .iter_from(&vault.store, &txn, &[])
                .expect("rows")
                .count(),
            1
        );
    }

    /// A check that cannot be written never fails the write that carries it:
    /// the host's row commits and the check waits for the next write.
    #[test]
    fn a_check_that_cannot_be_kept_never_fails_the_host_write() {
        let dir = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(dir.path(), crate::VaultConfig::default()).expect("open");
        vault
            .set_scan_threshold(EngineScan::VisibleRefRows, 1)
            .expect("threshold");
        // A scope longer than any LMDB key: its check row can never be put.
        let txn = vault.store.env.read_txn().expect("read");
        let mut count = ScanCount::start(&vault.store, &txn, EngineScan::VisibleRefRows, &[7; 600])
            .expect("count");
        count.row();
        count.row();
        drop(txn);
        count.finish(&vault);

        vault
            .set_scan_threshold(EngineScan::KeepOwnerRows, 9)
            .expect("the host write commits");
        assert_eq!(
            vault
                .scan_threshold(EngineScan::KeepOwnerRows)
                .expect("row"),
            9
        );
        assert_eq!(vault.store.pending_scan_checks.waiting().len(), 1);
    }
}
