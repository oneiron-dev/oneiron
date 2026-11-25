//! The issuer's two rows per dispatched key (pass 33, 5.1): `JOB_DISPATCH`, what it sent and
//! where the key stands, written before the first network call; and `JOB_OBSERVATION`, the
//! newest forward receipt the machine returned. The signed messages are oneiron-server's
//! `gpu_execution_node::wire` types; these rows hold their exact codec bytes, so every re-send
//! repeats the bytes first signed and a receipt keeps the signature it arrived with.
use serde::{Deserialize, Serialize};

use crate::gpu_job::{GpuJobTerminal, MeterVerdict};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

const JOB_DISPATCHES: SideTable<String, JobDispatch, Named> =
    SideTable::new(&side_table::JOB_DISPATCH);
const JOB_OBSERVATIONS: SideTable<String, JobObservation, Named> =
    SideTable::new(&side_table::JOB_OBSERVATION);

/// Where a dispatched key stands on the issuer. It only moves forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchPhase {
    /// The row is written; no `Held` receipt is stored yet.
    Reserving,
    /// The node's `Held` receipt is stored: it journaled the key.
    Reserved,
    /// The node accepted the submit.
    Submitted,
    /// The issuer asked the node to stop the key, and holds no terminal receipt yet.
    Closing,
    /// The key is closed for good: nothing is sent again.
    Closed,
}

/// A moment on the issuer: its boot, the boot clock (`CLOCK_BOOTTIME`, which counts suspend)
/// inside that boot, and the wall clock. Two marks of one boot give an interval no wall-clock
/// step can move.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootMark {
    /// This boot's id; empty where the system names none.
    pub boot_id: String,
    pub boot_ns: u64,
    pub wall_ms: u64,
}

/// Why the issuer closed a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "why", rename_all = "snake_case")]
pub enum DispatchClose {
    /// The engine ended the chunk: a cancel, its maximum, or the end of its run.
    Ended,
    /// A Grant, the approval or the workload was revoked after the reservation (EN-4): the
    /// refusal's code.
    Revoked { code: String },
    /// The start window passed before the node accepted the submit.
    StartWindowPassed,
    /// The live recheck refused before anything was sent: the refusal's code.
    RefusedBeforeSend { code: String },
    /// The node wrote its refusal down: the key's `Ended { Refused }` receipt, with its reason.
    NodeRefused { reason: String },
    /// The owner wrote the job off (door 10, row R4): nothing is sent again, and a receipt that
    /// arrives later is evidence only.
    WrittenOff {
        at_ms: u64,
        /// The node's terminal receipt that arrived after the write-off, as signed: kept, never
        /// settled.
        #[serde(default)]
        late_receipt: Option<Vec<u8>>,
    },
}

/// What the issuer sent a vault machine for one chunk, and where the key stands. Written before
/// the first network call; the target is the job's `inputs.machine`, fixed by its quote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobDispatch {
    /// The chunk's idempotency key: the row's key.
    pub key: String,
    /// The issuer's `GPU_JOB` row.
    pub job: EntityId,
    pub chunk: u32,
    /// The workload digest the submit names.
    pub workload: String,
    /// The node that runs the key.
    pub machine: EntityId,
    /// The exact signed submit, in the job protocol's codec: every re-send repeats these bytes.
    pub submit: Vec<u8>,
    pub issued_at_ms: u64,
    /// The end of the start window: no reserve or submit is sent after it.
    pub not_after_ms: u64,
    pub phase: DispatchPhase,
    /// The node's signed `Held` receipt for the reserve, in the codec: proof it journaled the
    /// key. Once it is stored, an absent key means the node's journal is gone.
    #[serde(default)]
    pub held: Option<Vec<u8>>,
    /// When the issuer first sent the submit, on its boot clock: the start of the bracket.
    #[serde(default)]
    pub sent_boot: Option<BootMark>,
    /// Why the issuer closed the key, once it is `Closing` or `Closed`.
    #[serde(default)]
    pub closed: Option<DispatchClose>,
    /// When the issuer found the node's journal gone for this key (an absent key after a `Held`
    /// receipt, `HistoryLost`, or a receipt older than one it holds). Nothing is sent again.
    #[serde(default)]
    pub history_lost_at_ms: Option<u64>,
}

impl JobDispatch {
    /// The resource the engine names this key by: `<machine hex>#<key>`. The issuer forms it
    /// before any network call.
    #[must_use]
    pub fn resource(&self) -> String {
        format!("{}#{}", self.machine.to_hex(), self.key)
    }
}

/// The newest forward receipt the issuer holds for one dispatched key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobObservation {
    pub key: String,
    pub machine: EntityId,
    pub device_id: Option<String>,
    /// The node's signed receipt, in the job protocol's codec.
    pub receipt: Vec<u8>,
    /// The receipt's journal epoch and sequence: a later receipt of the key under the same
    /// epoch has a higher one.
    pub epoch: String,
    pub seq: u64,
    /// The newest occupied seconds any receipt of the key carried: what a lost key's end
    /// reports as last seen.
    #[serde(default)]
    pub last_measured_secs: Option<u64>,
    /// The issuer's wall clock when the receipt arrived.
    pub observed_at_ms: u64,
    /// When the terminal receipt arrived, on the issuer's boot clock: the end of the bracket.
    #[serde(default)]
    pub end_seen: Option<BootMark>,
    /// How the billed seconds were found, once the end is confirmed.
    #[serde(default)]
    pub meter: Option<MeterVerdict>,
    /// The typed terminal the issuer built from the terminal receipt at the confirmed end.
    #[serde(default)]
    pub terminal: Option<GpuJobTerminal>,
    /// Whether a receipt of the key showed its workload process running, or ended after it
    /// ran: the node's own word that the attempt started (pass 34, 14.2: `orders.wait` with
    /// `until: "started"`). Once true it stays true. A row written before the field reads
    /// false.
    #[serde(default)]
    pub started: bool,
}

impl Vault {
    /// The dispatch row of `key`, if the issuer wrote one.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn job_dispatch(&self, key: &str) -> crate::Result<Option<JobDispatch>> {
        let txn = self.store.env.read_txn()?;
        JOB_DISPATCHES.get(&self.store, &txn, &key.to_owned())
    }

    /// [`Vault::job_dispatch`] in the caller's transaction.
    pub(crate) fn job_dispatch_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        key: &str,
    ) -> crate::Result<Option<JobDispatch>> {
        JOB_DISPATCHES.get(&self.store, txn, &key.to_owned())
    }

    /// Writes `row` unless a dispatch row of its key exists, durably, and answers the row that
    /// stands: the first write of a key wins, so a second create under the key re-sends the
    /// bytes first signed.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn insert_job_dispatch(&self, row: JobDispatch) -> crate::Result<JobDispatch> {
        self.with_write_txn(|txn| {
            if let Some(stored) = JOB_DISPATCHES.get(&self.store, txn, &row.key)? {
                return Ok(stored);
            }
            JOB_DISPATCHES.put(&self.store, txn, &row.key, &row)?;
            Ok(row)
        })
    }

    /// Changes the dispatch row of `key` by `change` in one durable write, and answers the row
    /// as written; `None` when there is no row.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn update_job_dispatch(
        &self,
        key: &str,
        change: impl FnOnce(&mut JobDispatch),
    ) -> crate::Result<Option<JobDispatch>> {
        let key = key.to_owned();
        self.with_write_txn(|txn| {
            let Some(mut row) = JOB_DISPATCHES.get(&self.store, txn, &key)? else {
                return Ok(None);
            };
            change(&mut row);
            JOB_DISPATCHES.put(&self.store, txn, &key, &row)?;
            Ok(Some(row))
        })
    }

    /// The observation of `key`, if a receipt arrived.
    ///
    /// # Errors
    ///
    /// A store read failure.
    pub fn job_observation(&self, key: &str) -> crate::Result<Option<JobObservation>> {
        let txn = self.store.env.read_txn()?;
        self.job_observation_in_txn(&txn, key)
    }

    /// [`Vault::job_observation`] in the caller's transaction.
    pub(crate) fn job_observation_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        key: &str,
    ) -> crate::Result<Option<JobObservation>> {
        JOB_OBSERVATIONS.get(&self.store, txn, &key.to_owned())
    }

    /// Writes the observation of `row.key` in one durable write, replacing the one it held.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn put_job_observation(&self, row: &JobObservation) -> crate::Result<()> {
        self.with_write_txn(|txn| JOB_OBSERVATIONS.put(&self.store, txn, &row.key, row))
    }

    /// Changes the dispatch row of `key` and its observation in one durable write. `change`
    /// gets the row and the stored observation as they stand inside the write, changes the
    /// row, and answers the observation to write (`None` keeps the stored one) beside its own
    /// verdict. A receipt judged here is judged against the newest rows, so a slower call never
    /// writes over a newer receipt, and the row's `Held` mark lands in the same write as the
    /// receipt that proves it. `None` when there is no row.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub fn update_job_dispatch_and_observation<T>(
        &self,
        key: &str,
        change: impl FnOnce(&mut JobDispatch, Option<JobObservation>) -> (Option<JobObservation>, T),
    ) -> crate::Result<Option<(JobDispatch, T)>> {
        let key = key.to_owned();
        self.with_write_txn(|txn| {
            let Some(mut row) = JOB_DISPATCHES.get(&self.store, txn, &key)? else {
                return Ok(None);
            };
            let stored = JOB_OBSERVATIONS.get(&self.store, txn, &key)?;
            let (observation, verdict) = change(&mut row, stored);
            JOB_DISPATCHES.put(&self.store, txn, &key, &row)?;
            if let Some(observation) = observation {
                JOB_OBSERVATIONS.put(&self.store, txn, &key, &observation)?;
            }
            Ok(Some((row, verdict)))
        })
    }
}
