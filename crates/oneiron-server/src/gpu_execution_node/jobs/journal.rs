//! The job journal's records and the table of keys they build (design pass
//! 33, 5.2 and 7.2). The journal is the only record of a key's state: the
//! table is rebuilt from it at every start, and every change of a key goes
//! through [`JobJournal::record`], which checks the move, syncs the record
//! to disk, and only then changes the table.
//!
//! A key never moves backwards and `Ended` is final. The same rules judge a
//! record at replay, so a journal that breaks them is a damaged history.

use std::collections::BTreeMap;

use oneiron::EntityId;
use oneiron::job_workload::DeviceLease;
use serde::{Deserialize, Serialize};

use super::job_unit::JobKeyId;
use super::journal_file::{JournalAppendError, JournalEpoch, JournalFile};
use crate::gpu_execution_node::wire::{
    DeviceRelease, JobEnd, JobReserve, JobState, OutputsState, SignedJobSubmit,
};

/// One record: `{ seq, boot_id, at_ms, key, issuer, event }`. `issuer` is
/// the machine the key is answered to; a key closed before any reserve
/// takes the issuer that closed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalRecord {
    pub seq: u64,
    pub boot_id: String,
    pub at_ms: u64,
    pub key: String,
    pub issuer: EntityId,
    pub event: JournalEvent,
}

/// What happened to a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalEvent {
    /// The reserve was admitted: the key and its disk space are held, no
    /// device.
    Reserved {
        reserve: JobReserve,
        /// The digest the node computed from the reserve's pin.
        pin_digest: String,
    },
    /// The signed submit was admitted; it is kept whole.
    Accepted { submit: SignedJobSubmit },
    /// Staging began.
    Staged,
    /// The launch commit: every lease of the request is claimed here, and
    /// occupancy starts at this record.
    Launching {
        /// The devices leased, one per placed claim; empty for a request
        /// with no device claim.
        devices: Vec<DeviceLease>,
        launch_boot_ns: u64,
        /// The latest boot-clock time the unit can be alive.
        cutoff_boot_ns: u64,
        /// The host memory leased from the machine's floor (the placement's
        /// `host_memory_mib`: the request's memory plus each unified
        /// device's claim memory).
        host_memory_mib: u64,
    },
    /// The unit was seen active.
    Running,
    /// An end cause the engine acts on, written before it stops the unit, or
    /// the unit was seen stopping.
    Ending { cause: EndingCause },
    /// The key's end. For a launched key, `end_boot_ns` is the end step's
    /// boot-clock time: the end of occupancy.
    Ended {
        end: JobEnd,
        end_boot_ns: Option<u64>,
    },
    /// The release check passed: the unit is empty and the device answered
    /// clean. The device and the memory are given back.
    Released { other_compute_pids: Vec<u32> },
    /// The release check could not pass, or the kernel could not empty the
    /// unit: the device stays out.
    Quarantined {
        why: String,
        other_compute_pids: Vec<u32>,
    },
    /// The declared outputs were hashed, after the release.
    Hashed { outputs: OutputsState },
    /// The issuer holds every returnable output it wants (`Ack`, design
    /// 7.1): the node keeps the payload for the keep time from here, and
    /// then may clean it. Never written for a key whose outputs a launch
    /// left unhashed.
    Acknowledged,
    /// The key's payload directory was removed, after its acknowledgement
    /// and the keep time: its outputs can no longer be fetched.
    Cleaned,
}

impl JournalEvent {
    fn name(&self) -> &'static str {
        match self {
            Self::Reserved { .. } => "reserved",
            Self::Accepted { .. } => "accepted",
            Self::Staged => "staged",
            Self::Launching { .. } => "launching",
            Self::Running => "running",
            Self::Ending { .. } => "ending",
            Self::Ended { .. } => "ended",
            Self::Released { .. } => "released",
            Self::Quarantined { .. } => "quarantined",
            Self::Hashed { .. } => "hashed",
            Self::Acknowledged => "acknowledged",
            Self::Cleaned => "cleaned",
        }
    }
}

/// Why the engine is ending a launched key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndingCause {
    /// The issuer asked.
    Stopped,
    /// The node saw a grant or a machine end (EN-4).
    Revoked,
    /// The payload directory passed its disk request.
    DiskLimit,
    /// The unit was seen stopping with no cause of the engine's.
    UnitStopping,
}

impl EndingCause {
    /// The end this cause names, when the end record names no limit of its
    /// own.
    #[must_use]
    pub fn end(self) -> Option<JobEnd> {
        match self {
            Self::Stopped => Some(JobEnd::Stopped),
            Self::Revoked => Some(JobEnd::Revoked),
            Self::DiskLimit => Some(JobEnd::DiskLimit),
            Self::UnitStopping => None,
        }
    }
}

/// The launch commit of a key, as journaled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLaunch {
    pub devices: Vec<DeviceLease>,
    pub boot_id: String,
    pub launch_boot_ns: u64,
    pub cutoff_boot_ns: u64,
    pub host_memory_mib: u64,
    pub launch_at_ms: u64,
}

impl KeyLaunch {
    /// The device the key holds, by the vendor's id: the first lease, as
    /// a key holds at most one device in this slice; `None` for a key with
    /// no device claim.
    #[must_use]
    pub fn device_id(&self) -> Option<&str> {
        self.devices.first().map(|lease| lease.device_id.as_str())
    }

    /// Whether the launch commit leased a device, so the release check
    /// probes one.
    #[must_use]
    pub fn has_device_lease(&self) -> bool {
        !self.devices.is_empty()
    }
}

/// One key as the journal holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeKey {
    pub key: String,
    pub id: JobKeyId,
    pub issuer: EntityId,
    pub reserve: Option<JobReserve>,
    pub pin_digest: Option<String>,
    pub submit: Option<SignedJobSubmit>,
    pub state: JobState,
    pub launch: Option<KeyLaunch>,
    pub ending_cause: Option<EndingCause>,
    pub end: Option<JobEnd>,
    pub end_boot_ns: Option<u64>,
    pub release: DeviceRelease,
    pub outputs: OutputsState,
    pub other_compute_pids: Vec<u32>,
    /// When the issuer acknowledged custody of the key's outputs (`Ack`).
    pub acknowledged_at_ms: Option<u64>,
    /// Whether the key's payload directory was removed.
    pub cleaned: bool,
    /// The sequence of the key's newest record.
    pub seq: u64,
    /// The boot of the key's newest record.
    pub boot_id: String,
    pub updated_at_ms: u64,
}

impl NodeKey {
    fn new(record: &JournalRecord) -> Self {
        Self {
            key: record.key.clone(),
            id: JobKeyId::for_key(&record.key),
            issuer: record.issuer,
            reserve: None,
            pin_digest: None,
            submit: None,
            state: JobState::Held,
            launch: None,
            ending_cause: None,
            end: None,
            end_boot_ns: None,
            release: DeviceRelease::NotHeld,
            outputs: OutputsState::Pending,
            other_compute_pids: Vec::new(),
            acknowledged_at_ms: None,
            cleaned: false,
            seq: record.seq,
            boot_id: record.boot_id.clone(),
            updated_at_ms: record.at_ms,
        }
    }

    /// Whether the workload's process may have existed: the key reached the
    /// launch commit, and its end does not say the workload never started.
    #[must_use]
    pub fn started(&self) -> bool {
        self.launch.is_some() && !matches!(self.end, Some(JobEnd::LaunchRefused { .. }))
    }

    /// Whether the key holds its leases now (its device, when it claimed
    /// one, and its memory): from the launch commit until the release check
    /// passes.
    #[must_use]
    pub fn holds_device(&self) -> bool {
        self.launch.is_some() && !matches!(self.release, DeviceRelease::Confirmed { .. })
    }

    /// The disk the key keeps booked on the payload disk, in MiB: a live key
    /// its request, an ended key whose workload may have started its
    /// request too until the issuer acknowledges its outputs (design 7.6
    /// step 5: an output nobody acknowledged keeps its space), and an ended
    /// key whose workload never started nothing: one that never launched,
    /// or one whose launch the unit's prepare step refused. After the
    /// acknowledgement the payload's own bytes count in the disk's free
    /// space until the cleaning removes them.
    #[must_use]
    pub fn booked_disk_mib(&self) -> u64 {
        let request = self
            .reserve
            .as_ref()
            .map_or(0, |reserve| reserve.pin.request.disk_mib);
        let keeps_payload = self.started() && self.acknowledged_at_ms.is_none();
        if self.state != JobState::Ended || keeps_payload {
            request
        } else {
            0
        }
    }

    /// Whether the issuer may acknowledge the key's outputs now: it ended,
    /// and a key whose workload may have started has its outputs hashed (or
    /// failed to), so a payload is never cleaned before the receipt names
    /// what it held. A key whose workload never started has nothing to wait
    /// for.
    #[must_use]
    pub fn acknowledgeable(&self) -> bool {
        self.state == JobState::Ended && (!self.started() || self.outputs != OutputsState::Pending)
    }

    /// Whether the key is past every change but the release check, the
    /// quarantine and the hashing.
    #[must_use]
    pub fn is_ended(&self) -> bool {
        self.state == JobState::Ended
    }
}

/// A record that breaks the journal's rules: a damaged history.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "job_journal.bad_move: record {seq} for key {key} moves {from} by {event}, which the journal never writes"
)]
pub struct JournalMoveError {
    pub seq: u64,
    pub key: String,
    pub from: String,
    pub event: &'static str,
}

/// Why a change of a key was not made.
#[derive(Debug, thiserror::Error)]
pub enum JournalWriteError {
    #[error(transparent)]
    Move(#[from] JournalMoveError),
    #[error(transparent)]
    Append(#[from] JournalAppendError),
    #[error("job_journal.encode: {0}")]
    Encode(String),
}

/// The keys the journal holds, by key.
#[derive(Debug, Clone, Default)]
pub struct KeyTable {
    keys: BTreeMap<String, NodeKey>,
    last_seq: u64,
}

impl KeyTable {
    /// The key's entry.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&NodeKey> {
        self.keys.get(key)
    }

    /// Every key, in key order.
    pub fn iter(&self) -> impl Iterator<Item = &NodeKey> {
        self.keys.values()
    }

    /// The newest record's sequence.
    #[must_use]
    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    /// The disk every key keeps booked, in MiB.
    #[must_use]
    pub fn booked_disk_mib(&self) -> u64 {
        self.keys.values().map(NodeKey::booked_disk_mib).sum()
    }

    /// The host memory the launched keys hold now, in MiB: each from its launch commit until its
    /// release check passes (row P0's memory room).
    #[must_use]
    pub fn held_host_memory_mib(&self) -> u64 {
        self.keys
            .values()
            .filter(|key| key.holds_device())
            .filter_map(|key| key.launch.as_ref())
            .map(|launch| launch.host_memory_mib)
            .sum()
    }

    /// Applies one record, checking it against the rules first.
    ///
    /// # Errors
    ///
    /// [`JournalMoveError`] for a record the journal never writes: an older
    /// sequence, or a move the key's state does not allow. Nothing changes.
    pub fn apply(&mut self, record: &JournalRecord) -> Result<(), JournalMoveError> {
        let next = self.check(record)?;
        self.last_seq = record.seq;
        self.keys.insert(record.key.clone(), next);
        Ok(())
    }

    /// The key as it would be after `record`.
    fn check(&self, record: &JournalRecord) -> Result<NodeKey, JournalMoveError> {
        let current = self.keys.get(&record.key);
        let refuse = || JournalMoveError {
            seq: record.seq,
            key: record.key.clone(),
            from: current.map_or_else(|| "nothing".to_owned(), |key| format!("{:?}", key.state)),
            event: record.event.name(),
        };
        if record.seq <= self.last_seq {
            return Err(refuse());
        }
        if let Some(current) = current
            && current.issuer != record.issuer
        {
            return Err(refuse());
        }
        let mut next = current.cloned().unwrap_or_else(|| NodeKey::new(record));
        next.seq = record.seq;
        next.boot_id.clone_from(&record.boot_id);
        next.updated_at_ms = record.at_ms;
        let state = current.map(|key| key.state);
        match (&record.event, state) {
            (
                JournalEvent::Reserved {
                    reserve,
                    pin_digest,
                },
                None,
            ) => {
                if reserve.key != record.key || reserve.issuer != record.issuer {
                    return Err(refuse());
                }
                next.reserve = Some(reserve.clone());
                next.pin_digest = Some(pin_digest.clone());
                next.state = JobState::Held;
            }
            (JournalEvent::Accepted { submit }, Some(JobState::Held)) => {
                if submit.submit.key != record.key || submit.submit.issuer != record.issuer {
                    return Err(refuse());
                }
                next.submit = Some(submit.clone());
                next.state = JobState::Accepted;
            }
            (JournalEvent::Staged, Some(JobState::Accepted)) => {
                next.state = JobState::Staging;
            }
            (
                JournalEvent::Launching {
                    devices,
                    launch_boot_ns,
                    cutoff_boot_ns,
                    host_memory_mib,
                },
                Some(JobState::Staging),
            ) => {
                next.launch = Some(KeyLaunch {
                    devices: devices.clone(),
                    boot_id: record.boot_id.clone(),
                    launch_boot_ns: *launch_boot_ns,
                    cutoff_boot_ns: *cutoff_boot_ns,
                    host_memory_mib: *host_memory_mib,
                    launch_at_ms: record.at_ms,
                });
                next.release = DeviceRelease::Held;
                next.state = JobState::Launching;
            }
            (JournalEvent::Running, Some(JobState::Launching)) => {
                next.state = JobState::Running;
            }
            (JournalEvent::Ending { cause }, Some(JobState::Launching | JobState::Running)) => {
                next.ending_cause = Some(*cause);
                next.state = JobState::Ending;
            }
            (JournalEvent::Ended { end, end_boot_ns }, state) => {
                let allowed = match state {
                    // A key closed before it was ever held: a stop or a
                    // submit for a key the node never saw, or a reserve the
                    // node refused.
                    None | Some(JobState::Held) => {
                        matches!(end, JobEnd::Withdrawn | JobEnd::Refused { .. })
                    }
                    Some(JobState::Accepted | JobState::Staging) => matches!(
                        end,
                        JobEnd::Withdrawn | JobEnd::Refused { .. } | JobEnd::LaunchRefused { .. }
                    ),
                    Some(JobState::Launching | JobState::Running | JobState::Ending) => {
                        !matches!(end, JobEnd::Withdrawn | JobEnd::Refused { .. })
                    }
                    Some(JobState::Ended) => false,
                };
                if !allowed {
                    return Err(refuse());
                }
                next.end = Some(end.clone());
                next.end_boot_ns = *end_boot_ns;
                next.state = JobState::Ended;
            }
            (JournalEvent::Released { other_compute_pids }, Some(JobState::Ended))
                if next.launch.is_some()
                    && !matches!(next.release, DeviceRelease::Confirmed { .. }) =>
            {
                next.other_compute_pids.clone_from(other_compute_pids);
                next.release = DeviceRelease::Confirmed {
                    at_ms: record.at_ms,
                };
            }
            (
                JournalEvent::Quarantined {
                    why,
                    other_compute_pids,
                },
                Some(JobState::Ended | JobState::Ending),
            ) if next.launch.is_some()
                && !matches!(next.release, DeviceRelease::Confirmed { .. }) =>
            {
                next.other_compute_pids.clone_from(other_compute_pids);
                next.release = DeviceRelease::Unconfirmed { why: why.clone() };
            }
            (JournalEvent::Hashed { outputs }, Some(JobState::Ended))
                if matches!(next.release, DeviceRelease::Confirmed { .. })
                    && next.outputs == OutputsState::Pending =>
            {
                next.outputs = outputs.clone();
            }
            (JournalEvent::Acknowledged, Some(JobState::Ended))
                if next.acknowledged_at_ms.is_none() && next.acknowledgeable() =>
            {
                next.acknowledged_at_ms = Some(record.at_ms);
            }
            (JournalEvent::Cleaned, Some(JobState::Ended))
                if next.acknowledged_at_ms.is_some() && !next.cleaned =>
            {
                next.cleaned = true;
            }
            _ => return Err(refuse()),
        }
        Ok(next)
    }
}

/// The journal file and the table it builds, written only together.
#[derive(Debug)]
pub struct JobJournal {
    file: JournalFile,
    table: KeyTable,
}

impl JobJournal {
    /// Rebuilds the table from an opened file's records.
    ///
    /// # Errors
    ///
    /// The first record that does not decode or breaks the rules: the
    /// history is damaged.
    pub fn replay(file: JournalFile, records: &[Vec<u8>]) -> Result<Self, String> {
        let mut table = KeyTable::default();
        for (index, payload) in records.iter().enumerate() {
            let record: JournalRecord = serde_json::from_slice(payload)
                .map_err(|error| format!("job_journal.decode: record {index}: {error}"))?;
            table.apply(&record).map_err(|error| error.to_string())?;
        }
        Ok(Self { file, table })
    }

    /// A journal with no record yet.
    #[must_use]
    pub fn empty(file: JournalFile) -> Self {
        Self {
            file,
            table: KeyTable::default(),
        }
    }

    /// The keys.
    #[must_use]
    pub fn table(&self) -> &KeyTable {
        &self.table
    }

    /// The journal's epoch.
    #[must_use]
    pub fn epoch(&self) -> JournalEpoch {
        self.file.epoch()
    }

    /// The file, for a test's fault hook.
    pub fn file_mut(&mut self) -> &mut JournalFile {
        &mut self.file
    }

    /// Whether an append could not be rolled back.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.file.is_poisoned()
    }

    /// Records `event` for `key`: checks the move, appends the record and
    /// syncs it, and only then changes the table.
    ///
    /// # Errors
    ///
    /// [`JournalWriteError`]: the move is not allowed, or the record is not
    /// on disk. The table is unchanged either way.
    pub fn record(
        &mut self,
        key: &str,
        issuer: EntityId,
        boot_id: &str,
        at_ms: u64,
        event: JournalEvent,
    ) -> Result<&NodeKey, JournalWriteError> {
        let record = JournalRecord {
            seq: self.table.last_seq + 1,
            boot_id: boot_id.to_owned(),
            at_ms,
            key: key.to_owned(),
            issuer,
            event,
        };
        let next = self.table.check(&record)?;
        let payload = serde_json::to_vec(&record)
            .map_err(|error| JournalWriteError::Encode(error.to_string()))?;
        self.file.append(&payload)?;
        self.table.last_seq = record.seq;
        self.table.keys.insert(record.key.clone(), next);
        Ok(self
            .table
            .keys
            .get(key)
            .expect("the key was inserted by this record"))
    }
}
