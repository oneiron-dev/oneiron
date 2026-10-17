//! Engine scans never refuse for how many rows they read (rule 5: ARCH-0044
//! C5, OF-520).
//!
//! Each engine scan over a table that grows with use has a threshold row. A
//! scan that reads past its row raises one [`ScanCheck`] for its scope and
//! reads on: the check is evidence for the host's "is everything okay"
//! question, never a refusal. Only machine floors (disk, memory) stop a scan.
//!
//! A scan counts in a `ScanCount`. A crossing waits with the vault, in
//! memory, until the vault's next write: that write's door first keeps it in
//! a write of its own, alone in its group. The host's read of the checks sees
//! it either way. No scan ever opens a writer, so none can wait on a writer
//! its caller holds, on any thread, and no check rides in a host's write.

use std::collections::BTreeMap;
use std::sync::Mutex;

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::{Callback, ManifestDbs, Rows, active_write_txn_depth};

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
    /// One entity type's rows in the type index.
    TypeIndexRows,
    /// One learned-at window's rows in the temporal index.
    LearnedRangeRows,
    /// One record's edges of one kind, one way.
    EdgePeerRows,
    /// The local receipt-record index a canonical window capture walks.
    ReceiptRecordRows,
    /// The records of one anchor's supersession chain.
    TimelineRecords,
    /// The gate-decision ledger a gate receipt query walks.
    GateDecisionRows,
    /// One record's edges a scoped reader's admission walks, one way.
    ScopedEdgeRows,
    /// The owner's MACHINE rows a mesh address bind walks for its endpoint.
    MachineRows,
    /// The access grants a companion persona list walks.
    AccessGrantRows,
    /// One seed's inbound mentions a specificity weight counts.
    MentionRows,
    /// The PPR cache's dependency rows a replaced or dead entry's walk reads.
    PprCacheDepRows,
    /// The sync rematerialization markers and quarantine rows a pack's
    /// exclusion index reads.
    PackQuarantineRows,
    /// The legacy lexical-hint claims a target's hint lookup walks.
    LexicalHintRows,
    /// The graduation answer log a gate receipt query projects.
    AnswerReceiptRows,
    /// The proposal artifacts a substitution-mining pass indexes.
    MinerArtifactRows,
    /// The synced edge map's entries an unseated child's parent arbitration
    /// walks.
    ChildOfMapEntries,
    /// The long-interval index a temporal window's spanner scan reads.
    TemporalSpannerRows,
    /// The timeline rows an occurred-range query reads, both halves.
    OccurredRangeRows,
    /// The retrieval run ledger a blend-weight tuning pass walks.
    BlendTuningRuns,
    /// One conversation's peers a Dreamer selection retry reads.
    DreamerRetryPeers,
    /// The pending gate-consent tray a consent list walks.
    PendingGateConsentRows,
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
    /// The TASK rows one board assembly reads.
    TaskBoardRows,
    /// One room's thread-children index rows a hang check walks, for one
    /// room or parent turn.
    RoomThreadChildRows,
    /// The message-to-project origin index rows a hang check walks, for one
    /// message.
    MessageOriginRows,
    /// A thread's bound and moved tasks, counted at bind and conversion.
    ThreadTaskCensus,
    /// The task and ask lists one PROJECT body's normalization reads.
    ProjectTaskRows,
    /// The vault's inbound STOPs this replica has not projected yet, which
    /// each external send reads. A STOP the projector keeps refusing stays.
    PendingCommStops,
    /// The contact claims naming a party, which an external send reads when
    /// a party-wide opt-out stands for its party and no contact row held it.
    PartyContactClaims,
    /// The soft-confirm notice deliveries one retry sweep's page reads,
    /// settled ones included.
    AskSoftConfirmDeliveryRows,
}

impl EngineScan {
    /// Every scan, the list the check that none refuses for a count reads.
    pub const ALL: [Self; 39] = [
        Self::ReceivePackIntents,
        Self::PublicationRows,
        Self::VisibleRefRows,
        Self::KeepOwnerRows,
        Self::TypeIndexRows,
        Self::LearnedRangeRows,
        Self::EdgePeerRows,
        Self::ReceiptRecordRows,
        Self::TimelineRecords,
        Self::GateDecisionRows,
        Self::ScopedEdgeRows,
        Self::MachineRows,
        Self::AccessGrantRows,
        Self::MentionRows,
        Self::PprCacheDepRows,
        Self::PackQuarantineRows,
        Self::LexicalHintRows,
        Self::AnswerReceiptRows,
        Self::MinerArtifactRows,
        Self::ChildOfMapEntries,
        Self::TemporalSpannerRows,
        Self::OccurredRangeRows,
        Self::BlendTuningRuns,
        Self::DreamerRetryPeers,
        Self::PendingGateConsentRows,
        Self::TaskCensusRows,
        Self::AskWordRows,
        Self::RoomThreadTasks,
        Self::ReadSetRows,
        Self::RoomPageRows,
        Self::RoomHistoryRows,
        Self::TaskBoardRows,
        Self::RoomThreadChildRows,
        Self::MessageOriginRows,
        Self::ThreadTaskCensus,
        Self::ProjectTaskRows,
        Self::PendingCommStops,
        Self::PartyContactClaims,
        Self::AskSoftConfirmDeliveryRows,
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
            Self::TypeIndexRows => "type_index_rows",
            Self::LearnedRangeRows => "learned_range_rows",
            Self::EdgePeerRows => "edge_peer_rows",
            Self::ReceiptRecordRows => "receipt_record_rows",
            Self::TimelineRecords => "memory_timeline_records",
            Self::GateDecisionRows => "gate_decision_rows",
            Self::ScopedEdgeRows => "scoped_edge_rows",
            Self::MachineRows => "machine_rows",
            Self::AccessGrantRows => "access_grant_rows",
            Self::MentionRows => "mention_rows",
            Self::PprCacheDepRows => "ppr_cache_dep_rows",
            Self::PackQuarantineRows => "pack_quarantine_rows",
            Self::LexicalHintRows => "lexical_hint_rows",
            Self::AnswerReceiptRows => "answer_receipt_rows",
            Self::MinerArtifactRows => "miner_artifact_rows",
            Self::ChildOfMapEntries => "child_of_map_entries",
            Self::TemporalSpannerRows => "temporal_spanner_rows",
            Self::OccurredRangeRows => "occurred_range_rows",
            Self::BlendTuningRuns => "blend_tuning_runs",
            Self::DreamerRetryPeers => "dreamer_retry_peers",
            Self::PendingGateConsentRows => "pending_gate_consent_rows",
            Self::TaskCensusRows => "task_census_rows",
            Self::AskWordRows => "ask_word_rows",
            Self::RoomThreadTasks => "room_thread_tasks",
            Self::ReadSetRows => "read_set_rows",
            Self::RoomPageRows => "room_page_rows",
            Self::RoomHistoryRows => "room_history_rows",
            Self::TaskBoardRows => "task_board_rows",
            Self::RoomThreadChildRows => "room_thread_child_rows",
            Self::MessageOriginRows => "message_origin_rows",
            Self::ThreadTaskCensus => "thread_task_census",
            Self::ProjectTaskRows => "project_task_rows",
            Self::PendingCommStops => "pending_comm_stops",
            Self::PartyContactClaims => "party_contact_claims",
            Self::AskSoftConfirmDeliveryRows => "ask_soft_confirm_delivery_rows",
        }
    }

    const fn tag(self) -> [u8; 1] {
        [match self {
            Self::ReceivePackIntents => 1,
            Self::PublicationRows => 2,
            Self::VisibleRefRows => 3,
            Self::KeepOwnerRows => 4,
            Self::TypeIndexRows => 16,
            Self::LearnedRangeRows => 17,
            Self::EdgePeerRows => 18,
            Self::ReceiptRecordRows => 19,
            Self::TimelineRecords => 20,
            Self::GateDecisionRows => 21,
            Self::ScopedEdgeRows => 22,
            Self::MachineRows => 23,
            Self::AccessGrantRows => 24,
            Self::MentionRows => 48,
            Self::PprCacheDepRows => 49,
            Self::PackQuarantineRows => 50,
            Self::LexicalHintRows => 51,
            Self::AnswerReceiptRows => 52,
            Self::MinerArtifactRows => 53,
            Self::ChildOfMapEntries => 54,
            Self::TemporalSpannerRows => 55,
            Self::OccurredRangeRows => 56,
            Self::BlendTuningRuns => 57,
            Self::DreamerRetryPeers => 58,
            Self::PendingGateConsentRows => 25,
            Self::TaskCensusRows => 32,
            Self::AskWordRows => 33,
            Self::RoomThreadTasks => 34,
            Self::ReadSetRows => 35,
            Self::RoomPageRows => 36,
            Self::RoomHistoryRows => 37,
            Self::TaskBoardRows => 38,
            Self::RoomThreadChildRows => 39,
            Self::MessageOriginRows => 40,
            Self::ThreadTaskCensus => 41,
            Self::ProjectTaskRows => 42,
            Self::PendingCommStops => 64,
            Self::PartyContactClaims => 65,
            Self::AskSoftConfirmDeliveryRows => 66,
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

    /// Starts counting `scan` of `scope` against `threshold`, for a scan
    /// whose caller's own policy row names when it asks.
    pub(crate) fn start_at(scan: EngineScan, scope: &[u8], threshold: u64) -> Self {
        Self {
            scan,
            scope: scope.to_vec(),
            threshold,
            rows: 0,
        }
    }

    /// Counts one row read.
    pub(crate) fn row(&mut self) {
        self.rows = self.rows.saturating_add(1);
    }

    /// Counts `rows` rows read at once, for a scan that holds its rows.
    pub(crate) fn rows(&mut self, rows: usize) {
        self.rows = self
            .rows
            .saturating_add(u64::try_from(rows).unwrap_or(u64::MAX));
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
    /// Keeps the crossings waiting with this vault, in a write of their own.
    /// The write door calls it before a host write takes the writer, so the
    /// thread holds no writer and no answer of that write yet. A check leaves
    /// the waiting map only once the write that keeps it commits; one that
    /// cannot be kept waits for the next write, which goes on regardless.
    pub(crate) fn keep_waiting_scan_checks(&self) {
        if active_write_txn_depth() > 0 {
            return;
        }
        let waiting = self.store.pending_scan_checks.waiting();
        if waiting.is_empty() {
            return;
        }
        match self.keep_scan_checks(&waiting) {
            Ok(fresh) => {
                let keys: Vec<CheckKey> = waiting.into_keys().collect();
                self.store.pending_scan_checks.clear(&keys);
                fresh.iter().for_each(warn);
            }
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "scan checks were not kept; they wait for the next write"
            ),
        }
    }

    /// Writes each waiting check not kept yet; a scope already kept costs a
    /// read, never a write.
    fn keep_scan_checks(&self, waiting: &BTreeMap<CheckKey, ScanCheck>) -> Result<Vec<ScanCheck>> {
        let fresh: Vec<(&CheckKey, &ScanCheck)> = {
            let txn = self.store.env.read_txn()?;
            let mut fresh = Vec::new();
            for (key, check) in waiting {
                if !CHECK.contains(&self.store, &txn, key)? {
                    fresh.push((key, check));
                }
            }
            fresh
        };
        if fresh.is_empty() {
            return Ok(Vec::new());
        }
        // Alone in its group: no host's rows share its commit, so its
        // failure fails no host's write.
        self.store.group_write_as(Callback::Opaque, None, |wtxn| {
            let mut kept = Vec::new();
            for (key, check) in &fresh {
                match CHECK.contains(&self.store, wtxn, key) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(error) => return Rows::Discard(Err(error)),
                }
                if let Err(error) = CHECK.put(&self.store, wtxn, key, check) {
                    return Rows::Discard(Err(error));
                }
                kept.push((*check).clone());
            }
            Rows::Commit(kept)
        })
    }

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
        // Waiting first: a check that leaves the map after this copy was
        // kept by a commit the later snapshot sees.
        let mut checks = self.store.pending_scan_checks.waiting();
        let txn = self.store.env.read_txn()?;
        for row in CHECK.iter_from(&self.store, &txn, &[])? {
            let (key, check) = row?;
            checks.insert(key, check);
        }
        Ok(checks.into_values().collect())
    }
}

#[cfg(test)]
mod table_tests;

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    use super::*;

    /// How long a write may wait before the test calls it a deadlock.
    const DEADLOCK_BOUND: Duration = Duration::from_secs(20);

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

    /// A crossing never opens a writer: inside a write or outside one it
    /// waits, visible to the host, for the vault's next write. Each scope is
    /// kept once however often it crosses.
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
        assert_eq!(vault.store.pending_scan_checks.waiting().len(), 1);
        let txn = vault.store.env.read_txn().expect("read");
        cross(&txn, EngineScan::VisibleRefRows)
            .expect("count")
            .finish(&vault);
        drop(txn);
        assert_eq!(vault.store.pending_scan_checks.waiting().len(), 2);
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

    /// A check that cannot be written never touches the host's write: its
    /// own write is refused alone, the host's commits, and the check leaves
    /// the waiting map only with a write that keeps it.
    #[test]
    fn a_check_that_cannot_be_kept_waits_and_never_fails_the_host_write() {
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

    /// A caller's callback may return a permit the next write's closure
    /// takes. With a check waiting, that caller still gets its answer and
    /// drops the permit: the check is kept before the caller's write, never
    /// after it while the answer holds the permit and the next write holds
    /// the writer.
    #[test]
    fn a_waiting_check_never_holds_a_returned_permit_against_the_next_write() {
        let dir = tempfile::tempdir().expect("vault dir");
        let vault = Arc::new(Vault::open(dir.path(), crate::VaultConfig::default()).expect("open"));
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

        let permit = Arc::new(Mutex::new(()));
        let (holding, held) = mpsc::channel();
        let (answer, holder) = mpsc::channel();
        {
            let (vault, permit) = (Arc::clone(&vault), Arc::clone(&permit));
            std::thread::spawn(move || {
                let returned = vault.try_with_write_txn(|_| {
                    let guard = permit.lock().expect("permit");
                    holding.send(()).expect("report the permit");
                    // The next write queues before this one commits.
                    while vault.store.group_commit.queued() == 0 {
                        std::thread::yield_now();
                    }
                    Ok::<_, crate::Error>(guard)
                });
                let _ = answer.send(returned.map(drop));
            });
        }
        held.recv_timeout(DEADLOCK_BOUND).expect("the callback ran");
        let (answer, taker) = mpsc::channel();
        {
            let (vault, permit) = (Arc::clone(&vault), Arc::clone(&permit));
            std::thread::spawn(move || {
                let _ = answer.send(vault.with_write_txn_grouped(|_| {
                    let _permit = permit.lock().expect("permit");
                    Ok(())
                }));
            });
        }
        for (name, answer) in [("holder", holder), ("taker", taker)] {
            answer
                .recv_timeout(DEADLOCK_BOUND)
                .unwrap_or_else(|_| panic!("the {name} deadlocked"))
                .unwrap_or_else(|err| panic!("the {name} failed: {err}"));
        }
        assert_eq!(vault.scan_checks().expect("checks").len(), 1);
    }
}
