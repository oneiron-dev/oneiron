//! The node's job service: the journal, the states of a key, admission
//! (`Reserve`, `Release`, `Submit`, and the stop of a key), the launch
//! commit, the end handling with its release check, recovery at start, the
//! signed receipt (design pass 33, sections 5.2, 5.3 and 7.2 to 7.7), the
//! status side's answers (`Keys`, `Signal`, `Fetch`, `Ack`) with the cleaning
//! of an acknowledged payload (row R4, 7.1 and 7.6 step 5), `Tail`, the
//! log by offset (pass 34 row Q3, 7.2), and the machine's own state
//! (pass 34 row Q4, 7.3): the idle readiness check with the DRAIN slot's
//! default rule, the incidents, and the breadcrumb lines of a running key,
//! and the disk check (7.9): a launched key whose payload passes its disk
//! request ends as `DiskLimit` ([`payload_usage`]).
//!
//! One lock, the admission lock, serialises every change of a key's state
//! and every read of the local controls. A reply is built only after its
//! record is synced to disk. A key never moves backwards, and `Ended` is
//! final:
//! - a closed key stays closed: a stop before the launch commit writes
//!   `Ended { Withdrawn }`, also for a key the node never saw, so a reserve
//!   or a submit that comes later finds the ended key and starts nothing;
//! - a refusal the issuer may treat as final is written down as
//!   `Ended { Refused }`; a condition that will pass answers `Busy` and
//!   writes nothing;
//! - a stop and a launch cannot interleave: both take the lock.
//!
//! The service takes its parts through [`node_parts`]: the node's own
//! configuration (row R1), the GPU slot table (OPUS-LE-FLEET), the memory
//! floor, the job unit (row R3b), the stager (row R3c) and the machine-key
//! signer. Its calls block; an async caller runs them on a blocking thread.
//! On Linux the server opens it and steps it on the mesh listener's tick
//! (`serving`).
//! One service per `state_dir`: it holds the journal's writer lock while any
//! handle of it lives, a staging worker's too. Once the server stops serving
//! it ([`NodeJobs::close`]), no staging begins and no launch commit begins,
//! and each staging worker returns at its next step, so the lock frees soon
//! after.

pub mod breadcrumb;
pub mod incidents;
pub mod job_unit;
pub mod journal;
pub mod journal_file;
pub mod node_parts;
pub mod payload_usage;
pub mod readiness;
pub mod receipt;
#[cfg(target_os = "linux")]
pub mod serving;
pub mod staging;

mod admission;
mod disk_check;
mod end;
mod launch;
mod log_tail;
mod outputs;
mod recovery;
mod status;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oneiron_organ_host::FloorLease;

pub use incidents::{IncidentKind, NodeIncident};
pub use job_unit::{
    EndRecord, JobKeyId, JobUnit, JobUnitError, JobUnitPhase, JobUnitStatus, LaunchFile, NodeClock,
    RenewRefusal, SystemNodeClock, scope_missing,
};
pub use journal::{
    EndingCause, JobJournal, JournalEvent, JournalRecord, KeyTable, NodeKey, Renewal,
};
pub use journal_file::{
    JournalDamage, JournalEpoch, JournalFile, JournalOpening, JournalWriterLock,
};
pub use node_parts::{
    AuthorityPosition, IssuerNotLive, NodeAdmission, NodeControls, NodeDevices, NodeJobParts,
    NodeJobPaths, NodeJobSettings, NodeJobsAttachment, StageFailure, StageOrder, Stager,
    StagingNotBuilt,
};
pub use payload_usage::{PayloadUsage, PayloadWalkBounds};
pub use readiness::{DRAIN_RULE_DEFAULT, DrainPick, drain_rule_default};
pub use receipt::{ReceiptClock, chunk_receipt_of, measured_secs, receipt_of, sign_receipt};
#[cfg(target_os = "linux")]
pub use serving::ServedNodeJobs;
pub use staging::{MirrorStager, StagingRefusal, TemplateMirrors};
pub use status::KEYS_PAGE_MAX_BYTES;

/// How long a `Busy` answer asks the issuer to wait before it asks again: a
/// protocol hint, not a policy.
pub const BUSY_RETRY_AFTER_MS: u64 = 2_000;

/// Whether the node answers admitting requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeGate {
    /// The start-up reconciliation has not ended: `Reserve`, `Submit` and
    /// `Release` answer `Busy`, and no launch commit runs.
    Recovering,
    /// Swept: every request is answered.
    Open,
    /// The journal that could have held a key is lost: every key question
    /// answers history lost, and nothing is admitted until
    /// `reset-history` at the box.
    HistoryLost { why: String },
}

/// Everything under the admission lock.
struct NodeBook {
    gate: NodeGate,
    /// `None` exactly when the history is lost.
    journal: Option<JobJournal>,
    /// The memory floor each launched key holds, until its release check
    /// passes.
    floors: BTreeMap<String, Box<dyn FloorLease>>,
    /// Keys whose staging worker runs now.
    staging: BTreeSet<String>,
    /// The cutoff the scope took for each renewed session run (row W1), by
    /// its first key. Empty after a start, so each live renewed run's
    /// cutoff is asked of the scope once again.
    armed_cutoffs: BTreeMap<String, u64>,
}

struct NodeJobsShared {
    paths: NodeJobPaths,
    parts: NodeJobParts,
    book: Mutex<NodeBook>,
    /// The server stopped serving this service ([`NodeJobs::close`]).
    closed: AtomicBool,
    /// The readiness record and the incidents, under locks of their own.
    readiness: readiness::NodeReadinessShared,
    /// Held while any handle lives: no second service writes this journal.
    _writer: JournalWriterLock,
}

/// The node's job service. Cloning it shares it.
#[derive(Clone)]
pub struct NodeJobs {
    shared: Arc<NodeJobsShared>,
}

impl std::fmt::Debug for NodeJobs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeJobs")
            .field("paths", &self.shared.paths)
            .finish_non_exhaustive()
    }
}

impl NodeJobs {
    fn lock(&self) -> MutexGuard<'_, NodeBook> {
        self.shared
            .book
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn parts(&self) -> &NodeJobParts {
        &self.shared.parts
    }

    fn paths(&self) -> &NodeJobPaths {
        &self.shared.paths
    }

    fn now(&self) -> ReceiptClock {
        let clock = &self.shared.parts.clock;
        ReceiptClock {
            boot_id: clock.boot_id(),
            boot_ns: clock.boot_ns(),
            wall_ms: clock.wall_ms(),
        }
    }

    /// The server stops serving this service: the mesh listener's stop, or
    /// a start that failed after the opening. From now on no staging begins
    /// and no launch commit begins (one that began already ends as it
    /// would have, and is journaled), each staging worker returns at its
    /// next step and leaves its key where it is, for the next opening to
    /// take up again (design 7.7: a key that has not launched is kept on the
    /// same boot), and the node's attached handle answers as a node with no
    /// keys. The journal's writer lock frees once the last staging worker
    /// has returned. It never waits for the admission lock.
    pub fn close(&self) {
        self.shared.closed.store(true, Ordering::SeqCst);
    }

    /// Whether [`Self::close`] ran.
    fn service_closed(&self) -> bool {
        self.shared.closed.load(Ordering::SeqCst)
    }

    /// Whether the start-up reconciliation has ended (`Node`'s `swept`).
    #[must_use]
    pub fn swept(&self) -> bool {
        self.lock().gate == NodeGate::Open
    }

    /// The gate now.
    #[must_use]
    pub fn gate(&self) -> NodeGate {
        self.lock().gate.clone()
    }

    /// The journal's epoch; `None` while the history is lost.
    #[must_use]
    pub fn epoch(&self) -> Option<JournalEpoch> {
        self.lock().journal.as_ref().map(JobJournal::epoch)
    }

    /// The disk the node's keys keep booked, in MiB.
    #[must_use]
    pub fn booked_disk_mib(&self) -> u64 {
        self.lock()
            .journal
            .as_ref()
            .map_or(0, |journal| journal.table().booked_disk_mib())
    }

    /// The issuers of every key that has not ended: the authority tick
    /// checks each one's standing, whatever the node's file names now.
    #[must_use]
    pub fn live_issuers(&self) -> BTreeSet<oneiron::EntityId> {
        self.lock()
            .journal
            .as_ref()
            .map(|journal| {
                journal
                    .table()
                    .iter()
                    .filter(|key| !key.is_ended())
                    .map(|key| key.issuer)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every key the journal holds now, as it holds them.
    #[must_use]
    pub fn keys(&self) -> Vec<NodeKey> {
        self.lock()
            .journal
            .as_ref()
            .map(|journal| journal.table().iter().cloned().collect())
            .unwrap_or_default()
    }

    /// EN-4 A: the fold no longer authorises `issuer`'s work here (`None`:
    /// no issuer's). Every key of that issuer that has not ended ends: one
    /// that has not launched closes as withdrawn, a launched one is stopped
    /// and ends as revoked. A key the gate keeps closed is ended at the
    /// next authority tick.
    pub fn revoke_live_keys(&self, issuer: Option<oneiron::EntityId>, why: &str) {
        for key in self.live_keys(issuer) {
            if let Err(error) = self.end_key(&key, EndingCause::Revoked) {
                tracing::warn!(key, why, %error, "revoked job key not ended yet; the next authority tick ends it");
            }
        }
    }

    /// `disable --stop` at the box: every key that has not ended ends; a
    /// launched one is stopped.
    pub fn stop_live_keys(&self) {
        for key in self.live_keys(None) {
            if let Err(error) = self.end_key(&key, EndingCause::Stopped) {
                tracing::warn!(key, %error, "job key not stopped yet; the next tick stops it");
            }
        }
    }

    /// The keys of `issuer` (`None`: of every issuer) that have not ended.
    fn live_keys(&self, issuer: Option<oneiron::EntityId>) -> Vec<String> {
        self.lock()
            .journal
            .as_ref()
            .map(|journal| {
                journal
                    .table()
                    .iter()
                    .filter(|key| !key.is_ended())
                    .filter(|key| issuer.is_none_or(|issuer| key.issuer == issuer))
                    .map(|key| key.key.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Sets the hook that runs between a journal append's write and its
    /// sync. A test's fault injection.
    #[cfg(oneiron_test_support)]
    pub fn set_journal_append_fault(&self, fault: Option<journal_file::JournalAppendFault>) {
        if let Some(journal) = self.lock().journal.as_mut() {
            journal.file_mut().set_append_fault(fault);
        }
    }
}
