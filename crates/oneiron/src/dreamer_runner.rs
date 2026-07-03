//! Private Dreamer runner store plus atomic admission.
//!
//! Durable Dreamer milestones are ordinary vault claims. Live runner state
//! (queue leases, local run-tree rows, parked rows, and budget counters) stays
//! in private LMDB rows and is not sync materialized as vault entities.

use std::io::Cursor;

use rmpv::Value;

use crate::Vault;
use crate::claim::ClaimSubject;
use crate::error::{Error, Result};
use crate::job_queue::{
    ClaimJob, ClaimOutcome, EnqueueJob, EnqueueOutcome, JobId, JobQueue, JobRecord,
};
use crate::types::{ClaimCandidate, EntityId, TimeRange, WriteEnvelope};

/// Generic [`JobQueue`] kind used by Dreamer runner jobs.
pub const DREAMER_RUNNER_JOB_KIND: &str = "dreamer";
/// Current pinned Dreamer job payload schema version.
pub const DREAMER_JOB_PAYLOAD_SCHEMA_VERSION: u64 = 1;
/// Pinned on-disk MessagePack key set for Dreamer job payloads.
pub const DREAMER_JOB_PAYLOAD_KEYS: [&str; 4] =
    ["schema_version", "job_type", "input", "parent_job"];
/// Claim predicate used for durable Dreamer job milestones.
pub const DREAMER_MILESTONE_PREDICATE: &str = "dreamer.job_milestone";
/// Current pinned Dreamer milestone claim value schema version.
pub const DREAMER_MILESTONE_VALUE_SCHEMA_VERSION: u64 = 1;
/// Pinned on-disk MessagePack key set for Dreamer milestone claim values.
pub const DREAMER_MILESTONE_VALUE_KEYS: [&str; 4] = ["schema_version", "job_id", "milestone", "at"];
/// Default fan-out reservation for one Dreamer child, in token-like units.
pub const DEFAULT_DREAMER_CHILD_RESERVE_UNITS: u64 = 8_000;

const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_JOB_TYPE: &str = "job_type";
const KEY_INPUT: &str = "input";
const KEY_PARENT_JOB: &str = "parent_job";
const KEY_JOB_ID: &str = "job_id";
const KEY_MILESTONE: &str = "milestone";
const KEY_AT: &str = "at";
const KEY_BUDGET_ID: &str = "budget_id";
const KEY_TOTAL_UNITS: &str = "total_units";
const KEY_REMAINING_UNITS: &str = "remaining_units";
const KEY_RESERVED_UNITS: &str = "reserved_units";
const KEY_UPDATED_AT: &str = "updated_at";
const KEY_CREATED_AT: &str = "created_at";
const KEY_REASON: &str = "reason";
const KEY_PARKED_AT: &str = "parked_at";
const DREAMER_BUDGET_SCHEMA_VERSION: u64 = 1;
const DREAMER_BUDGET_RESERVATION_SCHEMA_VERSION: u64 = 1;
const DREAMER_RUN_TREE_SCHEMA_VERSION: u64 = 1;
const DREAMER_PARKED_SCHEMA_VERSION: u64 = 1;
const DREAMER_BUDGET_KEYS: [&str; 6] = [
    KEY_SCHEMA_VERSION,
    KEY_BUDGET_ID,
    KEY_TOTAL_UNITS,
    KEY_REMAINING_UNITS,
    KEY_RESERVED_UNITS,
    KEY_UPDATED_AT,
];
const DREAMER_BUDGET_RESERVATION_KEYS: [&str; 6] = [
    KEY_SCHEMA_VERSION,
    KEY_BUDGET_ID,
    KEY_JOB_ID,
    KEY_RESERVED_UNITS,
    KEY_CREATED_AT,
    KEY_UPDATED_AT,
];
const DREAMER_RUN_TREE_KEYS: [&str; 4] = [
    KEY_SCHEMA_VERSION,
    KEY_JOB_ID,
    KEY_PARENT_JOB,
    KEY_CREATED_AT,
];
const DREAMER_PARKED_KEYS: [&str; 4] = [KEY_SCHEMA_VERSION, KEY_JOB_ID, KEY_REASON, KEY_PARKED_AT];
const DREAMER_PRIVATE_BUDGET_PREFIX: &[u8] = b"dreamer:budget:";
const DREAMER_PRIVATE_BUDGET_RESERVATION_PREFIX: &[u8] = b"dreamer:budget_reservation:";
const DREAMER_PRIVATE_RUN_TREE_PREFIX: &[u8] = b"dreamer:run_tree:";
const DREAMER_PRIVATE_PARKED_PREFIX: &[u8] = b"dreamer:parked:";
const MAX_DREAMER_JOB_TYPE_LEN: usize = 128;
const MAX_DREAMER_BUDGET_ID_LEN: usize = 128;
const MAX_DREAMER_PARK_REASON_LEN: usize = 512;

/// Typed Dreamer job payload stored in the generic queue row.
#[derive(Debug, Clone, PartialEq)]
pub struct DreamerJobPayload {
    pub job_type: String,
    pub input: Value,
    pub parent_job: Option<JobId>,
}

/// Input for enqueueing a Dreamer job into the private runner queue.
#[derive(Debug, Clone, PartialEq)]
pub struct EnqueueDreamerJob {
    pub job_type: String,
    pub input: Value,
    pub parent_job: Option<JobId>,
    pub dedupe_key: Option<String>,
    pub run_id: Option<String>,
    pub now: u64,
}

/// Decoded Dreamer job plus its backing generic queue row.
#[derive(Debug, Clone, PartialEq)]
pub struct DreamerJobStatus {
    pub job: JobRecord,
    pub payload: DreamerJobPayload,
}

/// Typed enqueue outcome for Dreamer jobs.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum EnqueueDreamerJobOutcome {
    Enqueued(DreamerJobStatus),
    Existing(DreamerJobStatus),
}

/// Pinned milestone vocabulary for durable Dreamer progress claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DreamerMilestoneKind {
    Created,
    Started,
    CheckpointReached,
    Done,
    Failed,
}

impl DreamerMilestoneKind {
    /// Stable string stored in `dreamer.job_milestone` claim values.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Started => "started",
            Self::CheckpointReached => "checkpoint-reached",
            Self::Done => "done",
            Self::Failed => "failed",
        }
    }

    /// Parses the pinned milestone string form.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "created" => Some(Self::Created),
            "started" => Some(Self::Started),
            "checkpoint-reached" => Some(Self::CheckpointReached),
            "done" => Some(Self::Done),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Durable milestone claim material to write with an admission transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct DreamerMilestoneClaim {
    pub claim_id: EntityId,
    pub subject: EntityId,
    pub kind: DreamerMilestoneKind,
    pub envelope: WriteEnvelope,
    pub occurred: TimeRange,
    pub learned_at: u64,
}

/// Private wake-budget counter row used only by the local Dreamer runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerBudgetRecord {
    pub budget_id: String,
    pub total_units: u64,
    pub remaining_units: u64,
    pub reserved_units: u64,
    pub updated_at: u64,
}

/// Wake-budget fan-out policy knobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DreamerWakeBudgetConfig {
    pub child_reserve_units: u64,
}

impl Default for DreamerWakeBudgetConfig {
    fn default() -> Self {
        Self {
            child_reserve_units: DEFAULT_DREAMER_CHILD_RESERVE_UNITS,
        }
    }
}

impl DreamerWakeBudgetConfig {
    /// Validates budget policy knobs before they are used for admission.
    pub fn validate(self) -> Result<()> {
        if self.child_reserve_units == 0 {
            return Err(invalid_dreamer_runner(
                "dreamer child reserve units must be > 0",
            ));
        }
        Ok(())
    }
}

/// Private per-child reservation row used to reconcile completion or abort.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerBudgetReservation {
    pub budget_id: String,
    pub job_id: JobId,
    pub reserved_units: u64,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Explicit reserve input for callers that already have a child job id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveDreamerBudget {
    pub budget_id: String,
    pub child_job: JobId,
    /// Initial local budget total when no private row exists yet. Existing
    /// rows keep their stored total.
    pub budget_total_units: u64,
    pub reserve_units: u64,
    pub now: u64,
}

/// Reserve result for a private wake-budget counter.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DreamerBudgetReserveOutcome {
    BudgetExhausted(DreamerBudgetRecord),
    AlreadyReserved(DreamerBudgetReservation),
    Reserved(Box<DreamerReservedBudget>),
}

/// A newly reserved child budget and the counter row after reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerReservedBudget {
    pub budget: DreamerBudgetRecord,
    pub reservation: DreamerBudgetReservation,
}

/// Completion-time budget settlement for a previously reserved child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettleDreamerBudget {
    pub budget_id: String,
    pub child_job: JobId,
    pub actual_units: u64,
    pub now: u64,
}

/// Abort-time refund for a previously reserved child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbortDreamerBudgetReservation {
    pub budget_id: String,
    pub child_job: JobId,
    pub now: u64,
}

/// Settlement result for a child budget reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DreamerBudgetSettlementOutcome {
    NoReservation,
    Settled(DreamerBudgetSettlement),
}

/// Counter reconciliation after completion or abort.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerBudgetSettlement {
    pub budget: DreamerBudgetRecord,
    pub reservation: DreamerBudgetReservation,
    pub actual_units: u64,
    pub refunded_units: u64,
    pub over_reserved_units: u64,
}

/// Input for the atomic Dreamer admission step.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmitDreamerJob {
    pub lease_owner: String,
    pub now: u64,
    pub budget_id: String,
    /// Initial local budget total when no private row exists yet. Existing
    /// rows keep their stored total.
    pub budget_total_units: u64,
    /// Units to move from remaining to reserved if admission succeeds.
    pub reserve_units: u64,
    /// Optional durable started milestone claim to co-commit with admission.
    pub started_milestone: Option<DreamerMilestoneClaim>,
}

/// Atomic admission result.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum DreamerAdmissionOutcome {
    Empty,
    BudgetExhausted(DreamerBudgetRecord),
    Admitted(Box<DreamerAdmittedJob>),
}

/// A leased Dreamer job plus the private budget row after admission.
#[derive(Debug, Clone, PartialEq)]
pub struct DreamerAdmittedJob {
    pub status: DreamerJobStatus,
    pub budget: DreamerBudgetRecord,
    pub reservation: DreamerBudgetReservation,
}

/// Private run-tree row keyed by job id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerRunTreeRecord {
    pub job_id: JobId,
    pub parent_job: Option<JobId>,
    pub created_at: u64,
}

/// Input for parking a Dreamer job in local runner state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParkDreamerJob {
    pub job_id: JobId,
    pub reason: String,
    pub now: u64,
}

/// Private parked-job row keyed by job id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamerParkedJobRecord {
    pub job_id: JobId,
    pub reason: String,
    pub parked_at: u64,
}

/// Private Dreamer runner store over an already-open vault.
pub struct DreamerRunnerStore<'a> {
    vault: &'a Vault,
    jobs: JobQueue<'a>,
}

impl<'a> DreamerRunnerStore<'a> {
    /// Opens a Dreamer runner store over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            jobs: JobQueue::new(vault),
        }
    }

    /// Enqueues a Dreamer job and records its private run-tree parent row in
    /// the same LMDB write transaction.
    pub fn enqueue(&self, input: EnqueueDreamerJob) -> Result<EnqueueDreamerJobOutcome> {
        validate_job_type(&input.job_type)?;
        let payload = DreamerJobPayload {
            job_type: input.job_type,
            input: input.input,
            parent_job: input.parent_job,
        };
        let encoded_payload = encode_dreamer_job_payload(&payload)?;

        let mut wtxn = self.vault.store.env.write_txn()?;
        let outcome = self.jobs.enqueue_in_txn(
            &mut wtxn,
            EnqueueJob {
                kind: DREAMER_RUNNER_JOB_KIND.to_owned(),
                payload: encoded_payload,
                dedupe_key: input.dedupe_key,
                run_id: input.run_id,
                now: input.now,
            },
        )?;

        let (was_enqueued, status) = match outcome {
            EnqueueOutcome::Enqueued(record) => {
                put_run_tree_record_in_txn(
                    self.vault,
                    &mut wtxn,
                    &DreamerRunTreeRecord {
                        job_id: record.id,
                        parent_job: payload.parent_job,
                        created_at: record.created_at,
                    },
                )?;
                (true, decode_dreamer_job_status(record)?)
            }
            EnqueueOutcome::Existing(record) => {
                ensure_run_tree_record_in_txn(self.vault, &mut wtxn, &record)?;
                (false, decode_dreamer_job_status(record)?)
            }
        };
        wtxn.commit()?;

        if was_enqueued {
            Ok(EnqueueDreamerJobOutcome::Enqueued(status))
        } else {
            Ok(EnqueueDreamerJobOutcome::Existing(status))
        }
    }

    /// Atomically admits the next queued Dreamer job.
    ///
    /// A successful admission leases one queue row, mutates the private budget
    /// counter, and optionally writes a durable started milestone claim before
    /// committing. Budget denial commits only queue scan repairs, leaving the
    /// job queued and the budget row unchanged.
    pub fn admit_next(&self, input: AdmitDreamerJob) -> Result<DreamerAdmissionOutcome> {
        validate_budget_id(&input.budget_id)?;
        if input.reserve_units == 0 {
            return Err(invalid_dreamer_runner(
                "dreamer admission reserve_units must be > 0",
            ));
        }
        if input
            .started_milestone
            .as_ref()
            .is_some_and(|milestone| milestone.kind != DreamerMilestoneKind::Started)
        {
            return Err(invalid_dreamer_runner(
                "dreamer admission milestone must be started",
            ));
        }

        let mut wtxn = self.vault.store.env.write_txn()?;
        let Some(candidate_job_id) =
            self.jobs
                .ready_kind_candidate_in_txn(&mut wtxn, DREAMER_RUNNER_JOB_KIND, input.now)?
        else {
            wtxn.commit()?;
            return Ok(DreamerAdmissionOutcome::Empty);
        };

        let mut budget = read_or_initialize_budget_in_txn(
            self.vault,
            &wtxn,
            &input.budget_id,
            input.budget_total_units,
            input.now,
        )?;
        let existing_reservation =
            read_budget_reservation_in_txn(self.vault, &wtxn, &input.budget_id, candidate_job_id)?;
        if let Some(reservation) = existing_reservation.as_ref() {
            if reservation.reserved_units > budget.reserved_units {
                return Err(invalid_dreamer_runner(
                    "dreamer budget reservation exceeds reserved units",
                ));
            }
        } else if input.reserve_units > budget.remaining_units {
            wtxn.commit()?;
            return Ok(DreamerAdmissionOutcome::BudgetExhausted(budget));
        }

        let claim = self.jobs.claim_kind_in_txn(
            &mut wtxn,
            DREAMER_RUNNER_JOB_KIND,
            ClaimJob {
                lease_owner: input.lease_owner,
                now: input.now,
            },
        )?;
        let ClaimOutcome::Claimed(job) = claim else {
            wtxn.commit()?;
            return Ok(DreamerAdmissionOutcome::Empty);
        };
        if job.id != candidate_job_id {
            return Err(invalid_dreamer_runner(
                "dreamer admission claimed unexpected ready job",
            ));
        }

        let reservation = if let Some(reservation) = existing_reservation {
            reservation
        } else {
            let reservation = DreamerBudgetReservation {
                budget_id: input.budget_id,
                job_id: job.id,
                reserved_units: input.reserve_units,
                created_at: input.now,
                updated_at: input.now,
            };
            reserve_budget_for_child_in_txn(self.vault, &mut wtxn, &mut budget, &reservation)?;
            reservation
        };

        if let Some(milestone) = input.started_milestone {
            apply_milestone_claim_in_txn(self.vault, &mut wtxn, job.id, milestone)?;
        }

        let status = decode_dreamer_job_status(job)?;
        wtxn.commit()?;

        Ok(DreamerAdmissionOutcome::Admitted(Box::new(
            DreamerAdmittedJob {
                status,
                budget,
                reservation,
            },
        )))
    }

    /// Reserves wake-budget units for a known child job.
    ///
    /// `admit_next` is the normal spawn path because it co-commits queue
    /// leasing and reservation. This method exists for runner call sites that
    /// already have a child id and still need the same private counter rules.
    pub fn reserve_budget(
        &self,
        input: ReserveDreamerBudget,
    ) -> Result<DreamerBudgetReserveOutcome> {
        validate_budget_id(&input.budget_id)?;
        if input.reserve_units == 0 {
            return Err(invalid_dreamer_runner("dreamer reserve_units must be > 0"));
        }

        let mut wtxn = self.vault.store.env.write_txn()?;
        if let Some(reservation) =
            read_budget_reservation_in_txn(self.vault, &wtxn, &input.budget_id, input.child_job)?
        {
            return Ok(DreamerBudgetReserveOutcome::AlreadyReserved(reservation));
        }

        let mut budget = read_or_initialize_budget_in_txn(
            self.vault,
            &wtxn,
            &input.budget_id,
            input.budget_total_units,
            input.now,
        )?;
        if input.reserve_units > budget.remaining_units {
            wtxn.commit()?;
            return Ok(DreamerBudgetReserveOutcome::BudgetExhausted(budget));
        }

        let reservation = DreamerBudgetReservation {
            budget_id: input.budget_id,
            job_id: input.child_job,
            reserved_units: input.reserve_units,
            created_at: input.now,
            updated_at: input.now,
        };
        reserve_budget_for_child_in_txn(self.vault, &mut wtxn, &mut budget, &reservation)?;
        wtxn.commit()?;

        Ok(DreamerBudgetReserveOutcome::Reserved(Box::new(
            DreamerReservedBudget {
                budget,
                reservation,
            },
        )))
    }

    /// Settles a child reservation with actual usage and refunds any unspent
    /// reservation.
    pub fn settle_budget(
        &self,
        input: SettleDreamerBudget,
    ) -> Result<DreamerBudgetSettlementOutcome> {
        validate_budget_id(&input.budget_id)?;
        let mut wtxn = self.vault.store.env.write_txn()?;
        let reservation_key = budget_reservation_key(&input.budget_id, input.child_job)?;
        let Some(reservation) =
            read_budget_reservation_in_txn(self.vault, &wtxn, &input.budget_id, input.child_job)?
        else {
            return Ok(DreamerBudgetSettlementOutcome::NoReservation);
        };

        let budget_key = budget_key(&input.budget_id)?;
        let Some(raw_budget) = self.vault.store.vault_meta.get(&wtxn, &budget_key)? else {
            return Err(invalid_dreamer_runner(
                "dreamer budget reservation missing counter",
            ));
        };
        let mut budget = decode_budget_record(raw_budget)?;
        if budget.budget_id != input.budget_id {
            return Err(invalid_dreamer_runner("dreamer budget key/body mismatch"));
        }

        let settlement =
            settle_budget_for_child(&mut budget, reservation, input.actual_units, input.now)?;
        put_budget_record_in_txn(self.vault, &mut wtxn, &settlement.budget)?;
        self.vault
            .store
            .vault_meta
            .delete(&mut wtxn, &reservation_key)?;
        wtxn.commit()?;

        Ok(DreamerBudgetSettlementOutcome::Settled(settlement))
    }

    /// Refunds a child reservation when the child aborts before spending any
    /// budget units.
    pub fn abort_budget_reservation(
        &self,
        input: AbortDreamerBudgetReservation,
    ) -> Result<DreamerBudgetSettlementOutcome> {
        self.settle_budget(SettleDreamerBudget {
            budget_id: input.budget_id,
            child_job: input.child_job,
            actual_units: 0,
            now: input.now,
        })
    }

    /// Reads one Dreamer job by queue id.
    pub fn status(&self, id: JobId) -> Result<Option<DreamerJobStatus>> {
        self.jobs
            .get(id)?
            .map(decode_dreamer_job_status)
            .transpose()
    }

    /// Reads a private Dreamer budget row.
    pub fn budget(&self, budget_id: &str) -> Result<Option<DreamerBudgetRecord>> {
        validate_budget_id(budget_id)?;
        let rtxn = self.vault.store.env.read_txn()?;
        let key = budget_key(budget_id)?;
        let Some(raw) = self.vault.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_budget_record(raw).map(Some)
    }

    /// Reads the remaining units in a private Dreamer budget row.
    pub fn remaining_budget(&self, budget_id: &str) -> Result<Option<u64>> {
        self.budget(budget_id)
            .map(|budget| budget.map(|record| record.remaining_units))
    }

    /// Reads a private child reservation row.
    pub fn budget_reservation(
        &self,
        budget_id: &str,
        child_job: JobId,
    ) -> Result<Option<DreamerBudgetReservation>> {
        validate_budget_id(budget_id)?;
        let rtxn = self.vault.store.env.read_txn()?;
        let key = budget_reservation_key(budget_id, child_job)?;
        let Some(raw) = self.vault.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_budget_reservation(raw).map(Some)
    }

    /// Reads a private Dreamer run-tree row.
    pub fn run_tree(&self, job_id: JobId) -> Result<Option<DreamerRunTreeRecord>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let key = run_tree_key(job_id);
        let Some(raw) = self.vault.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_run_tree_record(raw).map(Some)
    }

    /// Parks a Dreamer job in private runner state without changing the
    /// generic queue row.
    pub fn park_job(&self, input: ParkDreamerJob) -> Result<DreamerParkedJobRecord> {
        validate_park_reason(&input.reason)?;
        if self.status(input.job_id)?.is_none() {
            return Err(invalid_dreamer_runner("dreamer parked job must exist"));
        }

        let record = DreamerParkedJobRecord {
            job_id: input.job_id,
            reason: input.reason,
            parked_at: input.now,
        };
        let encoded = encode_parked_record(&record)?;
        let key = parked_key(record.job_id);
        let mut wtxn = self.vault.store.env.write_txn()?;
        self.vault.store.vault_meta.put(&mut wtxn, &key, &encoded)?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Reads a private parked-job row.
    pub fn parked_job(&self, job_id: JobId) -> Result<Option<DreamerParkedJobRecord>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let key = parked_key(job_id);
        let Some(raw) = self.vault.store.vault_meta.get(&rtxn, &key)? else {
            return Ok(None);
        };
        decode_parked_record(raw).map(Some)
    }
}

/// Encodes a Dreamer job payload in canonical MessagePack field order.
pub fn encode_dreamer_job_payload(payload: &DreamerJobPayload) -> Result<Vec<u8>> {
    validate_job_type(&payload.job_type)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_JOB_PAYLOAD_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_JOB_TYPE),
            Value::from(payload.job_type.as_str()),
        ),
        (Value::from(KEY_INPUT), payload.input.clone()),
        (
            Value::from(KEY_PARENT_JOB),
            encode_optional_job_id(payload.parent_job),
        ),
    ]);
    encode_value(&value, "dreamer job payload MessagePack encode failed")
}

/// Decodes and validates a Dreamer job payload.
pub fn decode_dreamer_job_payload(bytes: &[u8]) -> Result<DreamerJobPayload> {
    let value = decode_value(bytes)?;
    decode_dreamer_job_payload_value(&value)
}

fn decode_dreamer_job_status(record: JobRecord) -> Result<DreamerJobStatus> {
    if record.kind != DREAMER_RUNNER_JOB_KIND {
        return Err(invalid_dreamer_runner("job is not a Dreamer runner job"));
    }
    let payload = decode_dreamer_job_payload(&record.payload)?;
    Ok(DreamerJobStatus {
        job: record,
        payload,
    })
}

fn decode_dreamer_job_payload_value(value: &Value) -> Result<DreamerJobPayload> {
    let entries = expect_map(value, "dreamer job payload must be a MessagePack map")?;
    let mut schema_version = None;
    let mut job_type = None;
    let mut input = None;
    let mut parent_job = None;
    let mut seen = [false; DREAMER_JOB_PAYLOAD_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer job payload keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_JOB_PAYLOAD_KEYS).ok_or(
            invalid_dreamer_runner("dreamer job payload key is not pinned"),
        )?;
        if seen[index] {
            return Err(invalid_dreamer_runner("duplicate dreamer job payload key"));
        }
        seen[index] = true;

        match DREAMER_JOB_PAYLOAD_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer job payload schema_version must be an integer",
                )?);
            }
            KEY_JOB_TYPE => {
                let parsed = expect_string(value, "dreamer job_type must be a string")?;
                validate_job_type(&parsed)?;
                job_type = Some(parsed);
            }
            KEY_INPUT => input = Some(value.clone()),
            KEY_PARENT_JOB => parent_job = Some(decode_optional_job_id(value)?),
            _ => unreachable!("index resolved from DREAMER_JOB_PAYLOAD_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer job payload schema_version",
    ))?;
    if schema_version != DREAMER_JOB_PAYLOAD_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer job payload schema_version",
        ));
    }

    Ok(DreamerJobPayload {
        job_type: job_type.ok_or(invalid_dreamer_runner("missing dreamer job_type"))?,
        input: input.ok_or(invalid_dreamer_runner("missing dreamer job input"))?,
        parent_job: parent_job.ok_or(invalid_dreamer_runner("missing dreamer parent_job"))?,
    })
}

fn ensure_run_tree_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &JobRecord,
) -> Result<()> {
    let key = run_tree_key(record.id);
    if vault.store.vault_meta.get(&*wtxn, &key)?.is_some() {
        return Ok(());
    }
    let status = decode_dreamer_job_status(record.clone())?;
    put_run_tree_record_in_txn(
        vault,
        wtxn,
        &DreamerRunTreeRecord {
            job_id: status.job.id,
            parent_job: status.payload.parent_job,
            created_at: status.job.created_at,
        },
    )
}

fn put_run_tree_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &DreamerRunTreeRecord,
) -> Result<()> {
    let encoded = encode_run_tree_record(record)?;
    let key = run_tree_key(record.job_id);
    vault.store.vault_meta.put(wtxn, &key, &encoded)?;
    Ok(())
}

fn read_or_initialize_budget_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    budget_id: &str,
    budget_total_units: u64,
    now: u64,
) -> Result<DreamerBudgetRecord> {
    let key = budget_key(budget_id)?;
    let Some(raw) = vault.store.vault_meta.get(wtxn, &key)? else {
        return Ok(DreamerBudgetRecord {
            budget_id: budget_id.to_owned(),
            total_units: budget_total_units,
            remaining_units: budget_total_units,
            reserved_units: 0,
            updated_at: now,
        });
    };
    let record = decode_budget_record(raw)?;
    if record.budget_id != budget_id {
        return Err(invalid_dreamer_runner("dreamer budget key/body mismatch"));
    }
    Ok(record)
}

fn put_budget_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &DreamerBudgetRecord,
) -> Result<()> {
    let encoded = encode_budget_record(record)?;
    let key = budget_key(&record.budget_id)?;
    vault.store.vault_meta.put(wtxn, &key, &encoded)?;
    Ok(())
}

fn read_budget_reservation_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    budget_id: &str,
    child_job: JobId,
) -> Result<Option<DreamerBudgetReservation>> {
    let reservation_key = budget_reservation_key(budget_id, child_job)?;
    let Some(raw) = vault.store.vault_meta.get(txn, &reservation_key)? else {
        return Ok(None);
    };
    let reservation = decode_budget_reservation(raw)?;
    if reservation.budget_id != budget_id || reservation.job_id != child_job {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation key/body mismatch",
        ));
    }
    Ok(Some(reservation))
}

fn reserve_budget_for_child_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    budget: &mut DreamerBudgetRecord,
    reservation: &DreamerBudgetReservation,
) -> Result<()> {
    validate_budget_reservation(reservation)?;
    if reservation.budget_id != budget.budget_id {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation targets a different counter",
        ));
    }
    let reservation_key = budget_reservation_key(&reservation.budget_id, reservation.job_id)?;
    if vault
        .store
        .vault_meta
        .get(&*wtxn, &reservation_key)?
        .is_some()
    {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation already exists",
        ));
    }
    if reservation.reserved_units > budget.remaining_units {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation exceeds remaining units",
        ));
    }

    budget.remaining_units -= reservation.reserved_units;
    budget.reserved_units = budget
        .reserved_units
        .checked_add(reservation.reserved_units)
        .ok_or(Error::ArithmeticOverflow("dreamer budget reserved units"))?;
    budget.updated_at = reservation.updated_at;
    put_budget_record_in_txn(vault, wtxn, budget)?;

    let encoded = encode_budget_reservation(reservation)?;
    vault
        .store
        .vault_meta
        .put(wtxn, &reservation_key, &encoded)?;
    Ok(())
}

fn settle_budget_for_child(
    budget: &mut DreamerBudgetRecord,
    reservation: DreamerBudgetReservation,
    actual_units: u64,
    now: u64,
) -> Result<DreamerBudgetSettlement> {
    validate_budget_reservation(&reservation)?;
    if reservation.budget_id != budget.budget_id {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation targets a different counter",
        ));
    }
    if reservation.reserved_units > budget.reserved_units {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation exceeds reserved units",
        ));
    }

    let refunded_units = reservation.reserved_units.saturating_sub(actual_units);
    let over_reserved_units = actual_units.saturating_sub(reservation.reserved_units);
    let remaining_after_refund = budget
        .remaining_units
        .checked_add(refunded_units)
        .ok_or(Error::ArithmeticOverflow("dreamer budget refund units"))?;
    if over_reserved_units > remaining_after_refund {
        return Err(invalid_dreamer_runner(
            "dreamer budget settlement exceeds remaining units",
        ));
    }

    budget.reserved_units -= reservation.reserved_units;
    budget.remaining_units = remaining_after_refund - over_reserved_units;
    budget.updated_at = now;
    validate_budget_record(budget)?;

    Ok(DreamerBudgetSettlement {
        budget: budget.clone(),
        reservation,
        actual_units,
        refunded_units,
        over_reserved_units,
    })
}

fn apply_milestone_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    job_id: JobId,
    milestone: DreamerMilestoneClaim,
) -> Result<()> {
    let value = encode_milestone_value(job_id, milestone.kind, milestone.occurred.start);
    let candidate = ClaimCandidate::new(
        DREAMER_MILESTONE_PREDICATE,
        ClaimSubject::Entity(milestone.subject),
        value,
        1.0,
    );
    vault
        .batch_in()
        .claim_candidate(
            &milestone.claim_id,
            candidate,
            &milestone.envelope,
            milestone.occurred,
            milestone.learned_at,
        )
        .apply(wtxn)
}

fn encode_milestone_value(job_id: JobId, kind: DreamerMilestoneKind, at: u64) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_MILESTONE_VALUE_SCHEMA_VERSION),
        ),
        (Value::from(KEY_JOB_ID), encode_job_id(job_id)),
        (Value::from(KEY_MILESTONE), Value::from(kind.as_str())),
        (Value::from(KEY_AT), Value::from(at)),
    ])
}

fn encode_budget_record(record: &DreamerBudgetRecord) -> Result<Vec<u8>> {
    validate_budget_id(&record.budget_id)?;
    validate_budget_record(record)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_BUDGET_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_BUDGET_ID),
            Value::from(record.budget_id.as_str()),
        ),
        (
            Value::from(KEY_TOTAL_UNITS),
            Value::from(record.total_units),
        ),
        (
            Value::from(KEY_REMAINING_UNITS),
            Value::from(record.remaining_units),
        ),
        (
            Value::from(KEY_RESERVED_UNITS),
            Value::from(record.reserved_units),
        ),
        (Value::from(KEY_UPDATED_AT), Value::from(record.updated_at)),
    ]);
    encode_value(&value, "dreamer budget MessagePack encode failed")
}

fn decode_budget_record(bytes: &[u8]) -> Result<DreamerBudgetRecord> {
    let value = decode_value(bytes)?;
    let entries = expect_map(&value, "dreamer budget must be a MessagePack map")?;
    let mut schema_version = None;
    let mut budget_id = None;
    let mut total_units = None;
    let mut remaining_units = None;
    let mut reserved_units = None;
    let mut updated_at = None;
    let mut seen = [false; DREAMER_BUDGET_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer budget keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_BUDGET_KEYS)
            .ok_or(invalid_dreamer_runner("dreamer budget key is not pinned"))?;
        if seen[index] {
            return Err(invalid_dreamer_runner("duplicate dreamer budget key"));
        }
        seen[index] = true;

        match DREAMER_BUDGET_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer budget schema_version must be an integer",
                )?);
            }
            KEY_BUDGET_ID => {
                let parsed = expect_string(value, "dreamer budget_id must be a string")?;
                validate_budget_id(&parsed)?;
                budget_id = Some(parsed);
            }
            KEY_TOTAL_UNITS => {
                total_units = Some(expect_u64(value, "dreamer total_units must be an integer")?);
            }
            KEY_REMAINING_UNITS => {
                remaining_units = Some(expect_u64(
                    value,
                    "dreamer remaining_units must be an integer",
                )?);
            }
            KEY_RESERVED_UNITS => {
                reserved_units = Some(expect_u64(
                    value,
                    "dreamer reserved_units must be an integer",
                )?);
            }
            KEY_UPDATED_AT => {
                updated_at = Some(expect_u64(value, "dreamer updated_at must be an integer")?);
            }
            _ => unreachable!("index resolved from DREAMER_BUDGET_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer budget schema_version",
    ))?;
    if schema_version != DREAMER_BUDGET_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer budget schema_version",
        ));
    }

    let record = DreamerBudgetRecord {
        budget_id: budget_id.ok_or(invalid_dreamer_runner("missing dreamer budget_id"))?,
        total_units: total_units.ok_or(invalid_dreamer_runner("missing dreamer total_units"))?,
        remaining_units: remaining_units
            .ok_or(invalid_dreamer_runner("missing dreamer remaining_units"))?,
        reserved_units: reserved_units
            .ok_or(invalid_dreamer_runner("missing dreamer reserved_units"))?,
        updated_at: updated_at.ok_or(invalid_dreamer_runner("missing dreamer updated_at"))?,
    };
    validate_budget_record(&record)?;
    Ok(record)
}

fn encode_budget_reservation(record: &DreamerBudgetReservation) -> Result<Vec<u8>> {
    validate_budget_reservation(record)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_BUDGET_RESERVATION_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_BUDGET_ID),
            Value::from(record.budget_id.as_str()),
        ),
        (Value::from(KEY_JOB_ID), encode_job_id(record.job_id)),
        (
            Value::from(KEY_RESERVED_UNITS),
            Value::from(record.reserved_units),
        ),
        (Value::from(KEY_CREATED_AT), Value::from(record.created_at)),
        (Value::from(KEY_UPDATED_AT), Value::from(record.updated_at)),
    ]);
    encode_value(
        &value,
        "dreamer budget reservation MessagePack encode failed",
    )
}

fn decode_budget_reservation(bytes: &[u8]) -> Result<DreamerBudgetReservation> {
    let value = decode_value(bytes)?;
    let entries = expect_map(
        &value,
        "dreamer budget reservation must be a MessagePack map",
    )?;
    let mut schema_version = None;
    let mut budget_id = None;
    let mut job_id = None;
    let mut reserved_units = None;
    let mut created_at = None;
    let mut updated_at = None;
    let mut seen = [false; DREAMER_BUDGET_RESERVATION_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer budget reservation keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_BUDGET_RESERVATION_KEYS).ok_or(
            invalid_dreamer_runner("dreamer budget reservation key is not pinned"),
        )?;
        if seen[index] {
            return Err(invalid_dreamer_runner(
                "duplicate dreamer budget reservation key",
            ));
        }
        seen[index] = true;

        match DREAMER_BUDGET_RESERVATION_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer budget reservation schema_version must be an integer",
                )?);
            }
            KEY_BUDGET_ID => {
                let parsed = expect_string(value, "dreamer budget_id must be a string")?;
                validate_budget_id(&parsed)?;
                budget_id = Some(parsed);
            }
            KEY_JOB_ID => {
                job_id = Some(decode_job_id(value)?);
            }
            KEY_RESERVED_UNITS => {
                reserved_units = Some(expect_u64(
                    value,
                    "dreamer reserved_units must be an integer",
                )?);
            }
            KEY_CREATED_AT => {
                created_at = Some(expect_u64(value, "dreamer created_at must be an integer")?);
            }
            KEY_UPDATED_AT => {
                updated_at = Some(expect_u64(value, "dreamer updated_at must be an integer")?);
            }
            _ => unreachable!("index resolved from DREAMER_BUDGET_RESERVATION_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer budget reservation schema_version",
    ))?;
    if schema_version != DREAMER_BUDGET_RESERVATION_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer budget reservation schema_version",
        ));
    }

    let record = DreamerBudgetReservation {
        budget_id: budget_id.ok_or(invalid_dreamer_runner("missing dreamer budget_id"))?,
        job_id: job_id.ok_or(invalid_dreamer_runner("missing dreamer job_id"))?,
        reserved_units: reserved_units
            .ok_or(invalid_dreamer_runner("missing dreamer reserved_units"))?,
        created_at: created_at.ok_or(invalid_dreamer_runner("missing dreamer created_at"))?,
        updated_at: updated_at.ok_or(invalid_dreamer_runner("missing dreamer updated_at"))?,
    };
    validate_budget_reservation(&record)?;
    Ok(record)
}

fn encode_run_tree_record(record: &DreamerRunTreeRecord) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_RUN_TREE_SCHEMA_VERSION),
        ),
        (Value::from(KEY_JOB_ID), encode_job_id(record.job_id)),
        (
            Value::from(KEY_PARENT_JOB),
            encode_optional_job_id(record.parent_job),
        ),
        (Value::from(KEY_CREATED_AT), Value::from(record.created_at)),
    ]);
    encode_value(&value, "dreamer run-tree MessagePack encode failed")
}

fn decode_run_tree_record(bytes: &[u8]) -> Result<DreamerRunTreeRecord> {
    let value = decode_value(bytes)?;
    let entries = expect_map(&value, "dreamer run-tree row must be a MessagePack map")?;
    let mut schema_version = None;
    let mut job_id = None;
    let mut parent_job = None;
    let mut created_at = None;
    let mut seen = [false; DREAMER_RUN_TREE_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer run-tree keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_RUN_TREE_KEYS)
            .ok_or(invalid_dreamer_runner("dreamer run-tree key is not pinned"))?;
        if seen[index] {
            return Err(invalid_dreamer_runner("duplicate dreamer run-tree key"));
        }
        seen[index] = true;

        match DREAMER_RUN_TREE_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer run-tree schema_version must be an integer",
                )?);
            }
            KEY_JOB_ID => job_id = Some(decode_job_id(value)?),
            KEY_PARENT_JOB => parent_job = Some(decode_optional_job_id(value)?),
            KEY_CREATED_AT => {
                created_at = Some(expect_u64(
                    value,
                    "dreamer run-tree created_at must be an integer",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_RUN_TREE_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer run-tree schema_version",
    ))?;
    if schema_version != DREAMER_RUN_TREE_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer run-tree schema_version",
        ));
    }

    Ok(DreamerRunTreeRecord {
        job_id: job_id.ok_or(invalid_dreamer_runner("missing dreamer run-tree job_id"))?,
        parent_job: parent_job.ok_or(invalid_dreamer_runner(
            "missing dreamer run-tree parent_job",
        ))?,
        created_at: created_at.ok_or(invalid_dreamer_runner(
            "missing dreamer run-tree created_at",
        ))?,
    })
}

fn encode_parked_record(record: &DreamerParkedJobRecord) -> Result<Vec<u8>> {
    validate_park_reason(&record.reason)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_PARKED_SCHEMA_VERSION),
        ),
        (Value::from(KEY_JOB_ID), encode_job_id(record.job_id)),
        (Value::from(KEY_REASON), Value::from(record.reason.as_str())),
        (Value::from(KEY_PARKED_AT), Value::from(record.parked_at)),
    ]);
    encode_value(&value, "dreamer parked row MessagePack encode failed")
}

fn decode_parked_record(bytes: &[u8]) -> Result<DreamerParkedJobRecord> {
    let value = decode_value(bytes)?;
    let entries = expect_map(&value, "dreamer parked row must be a MessagePack map")?;
    let mut schema_version = None;
    let mut job_id = None;
    let mut reason = None;
    let mut parked_at = None;
    let mut seen = [false; DREAMER_PARKED_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer parked row keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_PARKED_KEYS).ok_or(invalid_dreamer_runner(
            "dreamer parked row key is not pinned",
        ))?;
        if seen[index] {
            return Err(invalid_dreamer_runner("duplicate dreamer parked row key"));
        }
        seen[index] = true;

        match DREAMER_PARKED_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer parked row schema_version must be an integer",
                )?);
            }
            KEY_JOB_ID => job_id = Some(decode_job_id(value)?),
            KEY_REASON => {
                let parsed = expect_string(value, "dreamer parked reason must be a string")?;
                validate_park_reason(&parsed)?;
                reason = Some(parsed);
            }
            KEY_PARKED_AT => {
                parked_at = Some(expect_u64(value, "dreamer parked_at must be an integer")?);
            }
            _ => unreachable!("index resolved from DREAMER_PARKED_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer parked row schema_version",
    ))?;
    if schema_version != DREAMER_PARKED_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer parked row schema_version",
        ));
    }

    Ok(DreamerParkedJobRecord {
        job_id: job_id.ok_or(invalid_dreamer_runner("missing dreamer parked job_id"))?,
        reason: reason.ok_or(invalid_dreamer_runner("missing dreamer parked reason"))?,
        parked_at: parked_at.ok_or(invalid_dreamer_runner("missing dreamer parked_at"))?,
    })
}

fn encode_value(value: &Value, reason: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(reason))?;
    Ok(out)
}

fn decode_value(bytes: &[u8]) -> Result<Value> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid_dreamer_runner("dreamer runner row is not valid MessagePack"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_dreamer_runner(
            "trailing bytes after dreamer runner row",
        ));
    }
    Ok(value)
}

fn encode_job_id(job_id: JobId) -> Value {
    Value::Binary(job_id.as_bytes().to_vec())
}

fn decode_job_id(value: &Value) -> Result<JobId> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_dreamer_runner("dreamer job id must be binary"));
    };
    JobId::from_bytes(bytes)
}

fn encode_optional_job_id(job_id: Option<JobId>) -> Value {
    job_id.map_or(Value::Nil, encode_job_id)
}

fn decode_optional_job_id(value: &Value) -> Result<Option<JobId>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    decode_job_id(value).map(Some)
}

fn expect_map<'a>(value: &'a Value, reason: &'static str) -> Result<&'a [(Value, Value)]> {
    let Value::Map(entries) = value else {
        return Err(invalid_dreamer_runner(reason));
    };
    Ok(entries)
}

fn expect_key<'a>(value: &'a Value, reason: &'static str) -> Result<&'a str> {
    value.as_str().ok_or(invalid_dreamer_runner(reason))
}

fn expect_string(value: &Value, reason: &'static str) -> Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(invalid_dreamer_runner(reason))
}

fn expect_u64(value: &Value, reason: &'static str) -> Result<u64> {
    value.as_u64().ok_or(invalid_dreamer_runner(reason))
}

fn pinned_key_index(key: &str, keys: &[&str]) -> Option<usize> {
    keys.iter().position(|known| *known == key)
}

fn budget_key(budget_id: &str) -> Result<Vec<u8>> {
    validate_budget_id(budget_id)?;
    let mut out = Vec::with_capacity(DREAMER_PRIVATE_BUDGET_PREFIX.len() + budget_id.len());
    out.extend_from_slice(DREAMER_PRIVATE_BUDGET_PREFIX);
    out.extend_from_slice(budget_id.as_bytes());
    Ok(out)
}

fn budget_reservation_key(budget_id: &str, job_id: JobId) -> Result<Vec<u8>> {
    validate_budget_id(budget_id)?;
    let budget_id_len = u16::try_from(budget_id.len())
        .map_err(|_| invalid_dreamer_runner("dreamer budget_id exceeds 128 bytes"))?;
    let mut out = Vec::with_capacity(
        DREAMER_PRIVATE_BUDGET_RESERVATION_PREFIX.len() + 2 + budget_id.len() + 16,
    );
    out.extend_from_slice(DREAMER_PRIVATE_BUDGET_RESERVATION_PREFIX);
    out.extend_from_slice(&budget_id_len.to_be_bytes());
    out.extend_from_slice(budget_id.as_bytes());
    out.extend_from_slice(job_id.as_bytes());
    Ok(out)
}

fn run_tree_key(job_id: JobId) -> Vec<u8> {
    let mut out = Vec::with_capacity(DREAMER_PRIVATE_RUN_TREE_PREFIX.len() + 16);
    out.extend_from_slice(DREAMER_PRIVATE_RUN_TREE_PREFIX);
    out.extend_from_slice(job_id.as_bytes());
    out
}

fn parked_key(job_id: JobId) -> Vec<u8> {
    let mut out = Vec::with_capacity(DREAMER_PRIVATE_PARKED_PREFIX.len() + 16);
    out.extend_from_slice(DREAMER_PRIVATE_PARKED_PREFIX);
    out.extend_from_slice(job_id.as_bytes());
    out
}

fn validate_job_type(job_type: &str) -> Result<()> {
    if job_type.is_empty() {
        return Err(invalid_dreamer_runner("dreamer job_type must not be empty"));
    }
    if job_type.len() > MAX_DREAMER_JOB_TYPE_LEN {
        return Err(invalid_dreamer_runner("dreamer job_type exceeds 128 bytes"));
    }
    Ok(())
}

fn validate_budget_id(budget_id: &str) -> Result<()> {
    if budget_id.is_empty() {
        return Err(invalid_dreamer_runner(
            "dreamer budget_id must not be empty",
        ));
    }
    if budget_id.len() > MAX_DREAMER_BUDGET_ID_LEN {
        return Err(invalid_dreamer_runner(
            "dreamer budget_id exceeds 128 bytes",
        ));
    }
    Ok(())
}

fn validate_park_reason(reason: &str) -> Result<()> {
    if reason.is_empty() {
        return Err(invalid_dreamer_runner(
            "dreamer parked reason must not be empty",
        ));
    }
    if reason.len() > MAX_DREAMER_PARK_REASON_LEN {
        return Err(invalid_dreamer_runner(
            "dreamer parked reason exceeds 512 bytes",
        ));
    }
    Ok(())
}

fn validate_budget_record(record: &DreamerBudgetRecord) -> Result<()> {
    validate_budget_id(&record.budget_id)?;
    if record.remaining_units > record.total_units || record.reserved_units > record.total_units {
        return Err(invalid_dreamer_runner(
            "dreamer budget counters exceed total",
        ));
    }
    let used = record
        .remaining_units
        .checked_add(record.reserved_units)
        .ok_or(Error::ArithmeticOverflow("dreamer budget counters"))?;
    if used > record.total_units {
        return Err(invalid_dreamer_runner(
            "dreamer budget counters exceed total",
        ));
    }
    Ok(())
}

fn validate_budget_reservation(record: &DreamerBudgetReservation) -> Result<()> {
    validate_budget_id(&record.budget_id)?;
    if record.reserved_units == 0 {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation must reserve > 0 units",
        ));
    }
    if record.updated_at < record.created_at {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation updated_at precedes created_at",
        ));
    }
    Ok(())
}

const fn invalid_dreamer_runner(reason: &'static str) -> Error {
    Error::InvalidJobQueueRecord(reason)
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::thread;

    use crate::claim::{ClaimApprovalStatus, ClaimSource};
    use crate::job_queue::{CleanupJobLeases, JobState};
    use crate::types::{
        ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK, EdgeActorClass, VaultConfig, WriteActor,
        WriteProvenance,
    };

    use super::*;

    fn open_vault() -> (tempfile::TempDir, Vault) {
        crate::test_util::open_test_vault_with(VaultConfig::device())
    }

    fn occurred(at: u64) -> TimeRange {
        TimeRange { start: at, end: at }
    }

    fn enqueue_job(
        runner: &DreamerRunnerStore<'_>,
        name: &str,
        now: u64,
    ) -> Result<DreamerJobStatus> {
        match runner.enqueue(EnqueueDreamerJob {
            job_type: name.to_owned(),
            input: Value::from(format!("input:{name}")),
            parent_job: None,
            dedupe_key: None,
            run_id: None,
            now,
        })? {
            EnqueueDreamerJobOutcome::Enqueued(status)
            | EnqueueDreamerJobOutcome::Existing(status) => Ok(status),
        }
    }

    fn test_ready_key(ready_at: u64, id: JobId) -> [u8; 24] {
        let mut key = [0_u8; 24];
        key[..8].copy_from_slice(&ready_at.to_be_bytes());
        key[8..].copy_from_slice(id.as_bytes());
        key
    }

    fn job_dedupe_points_to(vault: &Vault, id: JobId) -> Result<bool> {
        let rtxn = vault.store.env.read_txn()?;
        for row in vault.store.job_dedupe.iter(&rtxn)? {
            let (_key, value) = row?;
            if value == id.as_bytes() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn milestone_fixture(
        vault: &Vault,
        claim_id: EntityId,
        at: u64,
    ) -> Result<DreamerMilestoneClaim> {
        let actor = EntityId::now();
        let subject = EntityId::now();
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(at), at, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_TASK, occurred(at), at, b"subject")?;
        let envelope = WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from("dreamer-runner-test"))?,
            ClaimApprovalStatus::Approved,
        );
        Ok(DreamerMilestoneClaim {
            claim_id,
            subject,
            kind: DreamerMilestoneKind::Started,
            envelope,
            occurred: occurred(at),
            learned_at: at,
        })
    }

    #[cfg(feature = "sync")]
    fn write_dreamer_boundary_claim(
        vault: &Vault,
        claim_id: EntityId,
        predicate: &'static str,
        at: u64,
    ) -> Result<()> {
        let actor = EntityId::now();
        let subject = EntityId::now();
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(at), at, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_TASK, occurred(at), at, b"subject")?;
        let envelope = WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from("dreamer-sync-boundary-test"))?,
            ClaimApprovalStatus::Approved,
        );
        let candidate = crate::types::ClaimCandidate::new(
            predicate,
            ClaimSubject::Entity(subject),
            Value::from(predicate),
            1.0,
        );
        vault
            .batch()
            .claim_candidate(&claim_id, candidate, &envelope, occurred(at), at)
            .commit()
    }

    #[test]
    fn dreamer_payload_round_trips_with_pinned_keys() -> Result<()> {
        let payload = DreamerJobPayload {
            job_type: "expand".to_owned(),
            input: Value::from("seed"),
            parent_job: None,
        };
        let encoded = encode_dreamer_job_payload(&payload)?;
        let decoded = decode_dreamer_job_payload(&encoded)?;
        assert_eq!(decoded, payload);
        assert_eq!(
            DREAMER_JOB_PAYLOAD_KEYS,
            ["schema_version", "job_type", "input", "parent_job"]
        );
        Ok(())
    }

    #[test]
    fn dreamer_admission_claims_job_reserves_budget_and_writes_started_milestone_atomically()
    -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queued = enqueue_job(&runner, "expand", 10)?;
        let claim_id = EntityId::now();
        let milestone = milestone_fixture(&vault, claim_id, 20)?;
        let milestone_subject = milestone.subject;

        let admitted = runner.admit_next(AdmitDreamerJob {
            lease_owner: "dreamer-worker".to_owned(),
            now: 20,
            budget_id: "wake".to_owned(),
            budget_total_units: 10,
            reserve_units: 4,
            started_milestone: Some(milestone),
        })?;

        let DreamerAdmissionOutcome::Admitted(admitted) = admitted else {
            panic!("expected admitted Dreamer job");
        };
        assert_eq!(admitted.status.job.id, queued.job.id);
        assert_eq!(admitted.status.job.state, JobState::Leased);
        assert_eq!(
            admitted.status.job.lease_owner.as_deref(),
            Some("dreamer-worker")
        );
        assert_eq!(admitted.status.job.attempt_count, 1);
        assert_eq!(admitted.budget.remaining_units, 6);
        assert_eq!(admitted.budget.reserved_units, 4);
        assert_eq!(admitted.reservation.budget_id, "wake");
        assert_eq!(admitted.reservation.job_id, queued.job.id);
        assert_eq!(admitted.reservation.reserved_units, 4);

        let stored_budget = runner.budget("wake")?.expect("budget row");
        assert_eq!(stored_budget, admitted.budget);
        assert_eq!(runner.remaining_budget("wake")?, Some(6));
        assert_eq!(
            runner.budget_reservation("wake", queued.job.id)?,
            Some(admitted.reservation)
        );
        let stored_claim = vault
            .get_claim(&claim_id)?
            .expect("started milestone claim");
        assert_eq!(stored_claim.predicate, DREAMER_MILESTONE_PREDICATE);
        assert_eq!(
            stored_claim.subject,
            ClaimSubject::Entity(milestone_subject)
        );
        assert_eq!(stored_claim.approval, ClaimApprovalStatus::Approved);

        let Value::Map(entries) = stored_claim.value else {
            panic!("milestone value must be a map");
        };
        assert!(entries.iter().any(|(key, value)| {
            key.as_str() == Some(KEY_MILESTONE)
                && value.as_str() == Some(DreamerMilestoneKind::Started.as_str())
        }));
        assert!(entries.iter().any(|(key, value)| {
            key.as_str() == Some(KEY_JOB_ID)
                && matches!(value, Value::Binary(bytes) if bytes.as_slice() == queued.job.id.as_bytes())
        }));

        Ok(())
    }

    #[test]
    fn dreamer_admission_budget_denial_does_not_lease_or_persist_budget() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let stale = match runner.enqueue(EnqueueDreamerJob {
            job_type: "stale".to_owned(),
            input: Value::from("stale"),
            parent_job: None,
            dedupe_key: Some("stale-dedupe".to_owned()),
            run_id: None,
            now: 5,
        })? {
            EnqueueDreamerJobOutcome::Enqueued(status)
            | EnqueueDreamerJobOutcome::Existing(status) => status,
        };
        let queued = enqueue_job(&runner, "expand", 10)?;
        let stale_ready_key = test_ready_key(5, stale.job.id);
        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .job_records
                .delete(&mut wtxn, stale.job.id.as_bytes())?;
            wtxn.commit()?;
        }
        assert!(
            job_dedupe_points_to(&vault, stale.job.id)?,
            "fixture must leave a stale dedupe index before denial"
        );

        let denied = runner.admit_next(AdmitDreamerJob {
            lease_owner: "dreamer-worker".to_owned(),
            now: 20,
            budget_id: "wake".to_owned(),
            budget_total_units: 3,
            reserve_units: 4,
            started_milestone: None,
        })?;

        let DreamerAdmissionOutcome::BudgetExhausted(budget) = denied else {
            panic!("expected budget denial");
        };
        assert_eq!(budget.remaining_units, 3);
        assert_eq!(budget.reserved_units, 0);
        assert!(
            runner.budget("wake")?.is_none(),
            "denied admission must not commit an initialized budget row"
        );
        assert!(
            runner.budget_reservation("wake", queued.job.id)?.is_none(),
            "denied admission must not commit a child reservation row"
        );
        let status = runner.status(queued.job.id)?.expect("queued job");
        assert_eq!(status.job.state, JobState::Queued);
        assert_eq!(status.job.attempt_count, 0);
        assert!(status.job.lease_owner.is_none());
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .job_ready
                .get(&rtxn, &stale_ready_key)?
                .is_none(),
            "budget denial must commit stale ready-row repairs"
        );
        drop(rtxn);
        assert!(
            !job_dedupe_points_to(&vault, stale.job.id)?,
            "budget denial must commit stale dedupe cleanup"
        );

        Ok(())
    }

    #[test]
    fn dreamer_private_rows_stay_out_of_vault_entities_while_milestones_are_claims() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queued = enqueue_job(&runner, "expand", 10)?;
        let claim_id = EntityId::now();
        let milestone = milestone_fixture(&vault, claim_id, 20)?;

        runner.admit_next(AdmitDreamerJob {
            lease_owner: "dreamer-worker".to_owned(),
            now: 20,
            budget_id: "wake".to_owned(),
            budget_total_units: 10,
            reserve_units: 4,
            started_milestone: Some(milestone),
        })?;
        let parked = runner.park_job(ParkDreamerJob {
            job_id: queued.job.id,
            reason: "waiting for wake budget settle".to_owned(),
            now: 30,
        })?;
        assert_eq!(runner.parked_job(queued.job.id)?, Some(parked));

        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, &budget_key("wake")?)?
                .is_some()
        );
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, &budget_reservation_key("wake", queued.job.id)?)?
                .is_some()
        );
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, &run_tree_key(queued.job.id))?
                .is_some()
        );
        assert!(
            vault
                .store
                .vault_meta
                .get(&rtxn, &parked_key(queued.job.id))?
                .is_some()
        );
        assert!(
            vault
                .store
                .job_records
                .get(&rtxn, queued.job.id.as_bytes())?
                .is_some()
        );
        assert!(
            vault
                .store
                .entities
                .get(&rtxn, queued.job.id.as_bytes())?
                .is_none(),
            "job ids and local runner rows must not become vault entities"
        );
        assert!(
            vault
                .store
                .entities
                .get(&rtxn, claim_id.as_bytes())?
                .is_some(),
            "milestone claims are the durable vault claim surface"
        );

        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn dreamer_sync_boundary_exports_claims_not_runner_private_rows() -> Result<()> {
        use crate::sync::bridge::Materializer;
        use crate::sync::loro_support::map_get_bytes;
        use crate::sync::schema::create_window_doc;
        use crate::sync::types::WindowKey;
        use crate::sync::window;
        use loro::{ExportMode, LoroDoc};

        let learned_at = 1_772_000_000;
        let window_key = WindowKey::from_timestamp(learned_at);
        let (_dir_a, vault_a) = open_vault();
        let runner_a = DreamerRunnerStore::new(&vault_a);
        let queued = enqueue_job(&runner_a, "expand", learned_at)?;
        let milestone_id = EntityId::now();
        let milestone = milestone_fixture(&vault_a, milestone_id, learned_at)?;

        runner_a.admit_next(AdmitDreamerJob {
            lease_owner: "dreamer-worker".to_owned(),
            now: learned_at,
            budget_id: "wake".to_owned(),
            budget_total_units: 10,
            reserve_units: 4,
            started_milestone: Some(milestone),
        })?;
        runner_a.park_job(ParkDreamerJob {
            job_id: queued.job.id,
            reason: "waiting for wake budget settle".to_owned(),
            now: learned_at + 1,
        })?;

        let consent_id = EntityId::now();
        let effect_id = EntityId::now();
        let checkpoint_id = EntityId::now();
        write_dreamer_boundary_claim(&vault_a, consent_id, "dreamer.consent", learned_at)?;
        write_dreamer_boundary_claim(&vault_a, effect_id, "dreamer.effect", learned_at)?;
        write_dreamer_boundary_claim(&vault_a, checkpoint_id, "dreamer.checkpoint", learned_at)?;

        let durable_claims = [milestone_id, consent_id, effect_id, checkpoint_id];
        let doc_a = create_window_doc("node-a", &window_key);
        let mirrored = window::reverse_rematerialize(&vault_a, &doc_a, &window_key)?;
        assert!(
            mirrored >= durable_claims.len() as u32,
            "reverse rematerialize must mirror durable Dreamer claims"
        );

        let entities = doc_a.get_map("entities");
        for claim_id in durable_claims {
            assert_eq!(
                map_get_bytes(&entities, claim_id.to_hex().as_str()).as_deref(),
                vault_a.get_raw(&claim_id)?.as_deref(),
                "durable Dreamer claim must be present in the sync doc"
            );
        }

        let queued_as_entity = EntityId::from_bytes(*queued.job.id.as_bytes())?;
        assert!(
            map_get_bytes(&entities, queued_as_entity.to_hex().as_str()).is_none(),
            "queue job rows and leases must not be emitted as sync entities"
        );
        assert!(
            map_get_bytes(&entities, "dreamer:budget:wake").is_none(),
            "private runner keys must not be emitted into the sync entity map"
        );
        assert!(
            map_get_bytes(&entities, "dreamer:budget_reservation:wake").is_none(),
            "private child budget reservations must not be emitted into the sync entity map"
        );

        let snapshot = doc_a.export(ExportMode::Snapshot).unwrap();
        let doc_b = LoroDoc::from_snapshot(&snapshot).unwrap();
        let (_dir_b, vault_b) = open_vault();
        let materializer = Materializer::new();
        let restored = window::forward_rematerialize(&vault_b, &doc_b, &materializer, &window_key)?;
        assert!(
            restored >= durable_claims.len() as u32,
            "forward rematerialize must restore durable Dreamer claims"
        );
        for claim_id in durable_claims {
            assert!(
                vault_b.get_claim(&claim_id)?.is_some(),
                "durable Dreamer claim must survive CRDT sync"
            );
        }

        let rtxn = vault_b.store.env.read_txn()?;
        assert!(
            vault_b
                .store
                .job_records
                .get(&rtxn, queued.job.id.as_bytes())?
                .is_none(),
            "queue leases must remain private to the runner store"
        );
        assert!(
            vault_b
                .store
                .vault_meta
                .get(&rtxn, &budget_key("wake")?)?
                .is_none(),
            "private budget rows must not sync"
        );
        assert!(
            vault_b
                .store
                .vault_meta
                .get(&rtxn, &budget_reservation_key("wake", queued.job.id)?)?
                .is_none(),
            "private budget reservation rows must not sync"
        );
        assert!(
            vault_b
                .store
                .vault_meta
                .get(&rtxn, &run_tree_key(queued.job.id))?
                .is_none(),
            "private run-tree rows must not sync"
        );
        assert!(
            vault_b
                .store
                .vault_meta
                .get(&rtxn, &parked_key(queued.job.id))?
                .is_none(),
            "private parked rows must not sync"
        );

        Ok(())
    }

    #[test]
    fn dreamer_concurrent_admission_cannot_overspend_private_budget() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let config = DreamerWakeBudgetConfig::default();
        config.validate()?;
        assert_eq!(
            config.child_reserve_units,
            DEFAULT_DREAMER_CHILD_RESERVE_UNITS
        );
        let first = enqueue_job(&runner, "first", 10)?;
        let second = enqueue_job(&runner, "second", 11)?;
        let third = enqueue_job(&runner, "third", 12)?;
        let barrier = Barrier::new(3);

        let (left, middle, right) = thread::scope(|scope| {
            let left = scope.spawn(|| {
                barrier.wait();
                runner.admit_next(AdmitDreamerJob {
                    lease_owner: "left-worker".to_owned(),
                    now: 20,
                    budget_id: "wake".to_owned(),
                    budget_total_units: config.child_reserve_units * 2,
                    reserve_units: config.child_reserve_units,
                    started_milestone: None,
                })
            });
            let middle = scope.spawn(|| {
                barrier.wait();
                runner.admit_next(AdmitDreamerJob {
                    lease_owner: "middle-worker".to_owned(),
                    now: 20,
                    budget_id: "wake".to_owned(),
                    budget_total_units: config.child_reserve_units * 2,
                    reserve_units: config.child_reserve_units,
                    started_milestone: None,
                })
            });
            let right = scope.spawn(|| {
                barrier.wait();
                runner.admit_next(AdmitDreamerJob {
                    lease_owner: "right-worker".to_owned(),
                    now: 20,
                    budget_id: "wake".to_owned(),
                    budget_total_units: config.child_reserve_units * 2,
                    reserve_units: config.child_reserve_units,
                    started_milestone: None,
                })
            });
            (
                left.join().expect("left join"),
                middle.join().expect("middle join"),
                right.join().expect("right join"),
            )
        });

        let outcomes = [left?, middle?, right?];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, DreamerAdmissionOutcome::Admitted(_)))
                .count(),
            2
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, DreamerAdmissionOutcome::BudgetExhausted(_)))
                .count(),
            1
        );
        let budget = runner.budget("wake")?.expect("committed budget");
        assert_eq!(budget.remaining_units, 0);
        assert_eq!(budget.reserved_units, config.child_reserve_units * 2);

        let first_status = runner.status(first.job.id)?.expect("first status");
        let second_status = runner.status(second.job.id)?.expect("second status");
        let third_status = runner.status(third.job.id)?.expect("third status");
        let leased = [
            first_status.job.state,
            second_status.job.state,
            third_status.job.state,
        ]
        .into_iter()
        .filter(|state| *state == JobState::Leased)
        .count();
        let queued = [
            first_status.job.state,
            second_status.job.state,
            third_status.job.state,
        ]
        .into_iter()
        .filter(|state| *state == JobState::Queued)
        .count();
        assert_eq!(leased, 2);
        assert_eq!(queued, 1);

        Ok(())
    }

    #[test]
    fn dreamer_settle_reconciles_actual_usage_and_refund() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queued = enqueue_job(&runner, "settle", 10)?;

        let DreamerAdmissionOutcome::Admitted(admitted) = runner.admit_next(AdmitDreamerJob {
            lease_owner: "dreamer-worker".to_owned(),
            now: 20,
            budget_id: "wake".to_owned(),
            budget_total_units: 20,
            reserve_units: 8,
            started_milestone: None,
        })?
        else {
            panic!("expected admitted Dreamer job");
        };
        assert_eq!(admitted.reservation.job_id, queued.job.id);
        assert_eq!(admitted.budget.remaining_units, 12);
        assert_eq!(admitted.budget.reserved_units, 8);

        let DreamerBudgetSettlementOutcome::Settled(settlement) =
            runner.settle_budget(SettleDreamerBudget {
                budget_id: "wake".to_owned(),
                child_job: queued.job.id,
                actual_units: 5,
                now: 30,
            })?
        else {
            panic!("expected settlement");
        };
        assert_eq!(settlement.actual_units, 5);
        assert_eq!(settlement.refunded_units, 3);
        assert_eq!(settlement.over_reserved_units, 0);
        assert_eq!(settlement.budget.remaining_units, 15);
        assert_eq!(settlement.budget.reserved_units, 0);
        assert_eq!(
            runner.budget("wake")?.expect("settled budget"),
            settlement.budget
        );
        assert!(runner.budget_reservation("wake", queued.job.id)?.is_none());

        let second = enqueue_job(&runner, "settle-over-reserve", 40)?;
        let DreamerBudgetReserveOutcome::Reserved(reserved) =
            runner.reserve_budget(ReserveDreamerBudget {
                budget_id: "wake".to_owned(),
                child_job: second.job.id,
                budget_total_units: 20,
                reserve_units: 8,
                now: 50,
            })?
        else {
            panic!("expected explicit reserve");
        };
        assert_eq!(reserved.budget.remaining_units, 7);
        assert_eq!(reserved.budget.reserved_units, 8);

        let DreamerBudgetSettlementOutcome::Settled(over) =
            runner.settle_budget(SettleDreamerBudget {
                budget_id: "wake".to_owned(),
                child_job: second.job.id,
                actual_units: 10,
                now: 60,
            })?
        else {
            panic!("expected over-reserve settlement");
        };
        assert_eq!(over.refunded_units, 0);
        assert_eq!(over.over_reserved_units, 2);
        assert_eq!(over.budget.remaining_units, 5);
        assert_eq!(over.budget.reserved_units, 0);

        Ok(())
    }

    #[test]
    fn dreamer_settle_rejects_actual_usage_beyond_remaining_budget() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queued = enqueue_job(&runner, "settle-overspend", 10)?;

        let DreamerAdmissionOutcome::Admitted(admitted) = runner.admit_next(AdmitDreamerJob {
            lease_owner: "dreamer-worker".to_owned(),
            now: 20,
            budget_id: "wake".to_owned(),
            budget_total_units: 10,
            reserve_units: 8,
            started_milestone: None,
        })?
        else {
            panic!("expected admitted Dreamer job");
        };
        assert_eq!(admitted.budget.remaining_units, 2);
        assert_eq!(admitted.budget.reserved_units, 8);

        let result = runner.settle_budget(SettleDreamerBudget {
            budget_id: "wake".to_owned(),
            child_job: queued.job.id,
            actual_units: 11,
            now: 30,
        });
        assert!(matches!(
            result,
            Err(Error::InvalidJobQueueRecord(
                "dreamer budget settlement exceeds remaining units"
            ))
        ));
        assert_eq!(
            runner.budget("wake")?.expect("unchanged budget"),
            admitted.budget
        );
        assert_eq!(
            runner.budget_reservation("wake", queued.job.id)?,
            Some(admitted.reservation)
        );

        Ok(())
    }

    #[test]
    fn dreamer_admission_reuses_existing_reservation_after_lease_timeout_requeue() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queue = JobQueue::new(&vault);
        let queued = enqueue_job(&runner, "requeued", 10)?;

        let DreamerAdmissionOutcome::Admitted(first) = runner.admit_next(AdmitDreamerJob {
            lease_owner: "first-worker".to_owned(),
            now: 20,
            budget_id: "wake".to_owned(),
            budget_total_units: 10,
            reserve_units: 8,
            started_milestone: None,
        })?
        else {
            panic!("expected first admission");
        };
        assert_eq!(first.status.job.id, queued.job.id);
        assert_eq!(first.status.job.attempt_count, 1);
        assert_eq!(first.budget.remaining_units, 2);
        assert_eq!(first.budget.reserved_units, 8);
        let first_budget = first.budget.clone();
        let first_reservation = first.reservation.clone();

        let report = queue.cleanup_leases(CleanupJobLeases {
            now: 40,
            lease_timeout_secs: 10,
        })?;
        assert_eq!(report.stale_requeued, 1);
        let requeued = runner.status(queued.job.id)?.expect("requeued job");
        assert_eq!(requeued.job.state, JobState::Queued);
        assert_eq!(requeued.job.last_error.as_deref(), Some("lease_timeout"));

        let DreamerAdmissionOutcome::Admitted(second) = runner.admit_next(AdmitDreamerJob {
            lease_owner: "second-worker".to_owned(),
            now: 50,
            budget_id: "wake".to_owned(),
            budget_total_units: 10,
            reserve_units: 8,
            started_milestone: None,
        })?
        else {
            panic!("expected second admission");
        };
        assert_eq!(second.status.job.id, queued.job.id);
        assert_eq!(second.status.job.state, JobState::Leased);
        assert_eq!(second.status.job.attempt_count, 2);
        assert_eq!(
            second.status.job.lease_owner.as_deref(),
            Some("second-worker")
        );
        assert_eq!(second.budget, first_budget);
        assert_eq!(second.reservation, first_reservation);
        assert_eq!(
            runner.budget("wake")?.expect("unchanged budget"),
            first_budget
        );
        assert_eq!(
            runner.budget_reservation("wake", queued.job.id)?,
            Some(first_reservation)
        );

        Ok(())
    }

    #[test]
    fn dreamer_abort_refunds_unspent_child_reservation() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queued = enqueue_job(&runner, "abort", 10)?;

        let DreamerAdmissionOutcome::Admitted(admitted) = runner.admit_next(AdmitDreamerJob {
            lease_owner: "dreamer-worker".to_owned(),
            now: 20,
            budget_id: "wake".to_owned(),
            budget_total_units: 10,
            reserve_units: 8,
            started_milestone: None,
        })?
        else {
            panic!("expected admitted Dreamer job");
        };
        assert_eq!(admitted.budget.remaining_units, 2);
        assert_eq!(admitted.budget.reserved_units, 8);

        let DreamerBudgetSettlementOutcome::Settled(aborted) =
            runner.abort_budget_reservation(AbortDreamerBudgetReservation {
                budget_id: "wake".to_owned(),
                child_job: queued.job.id,
                now: 30,
            })?
        else {
            panic!("expected abort refund");
        };
        assert_eq!(aborted.actual_units, 0);
        assert_eq!(aborted.refunded_units, 8);
        assert_eq!(aborted.over_reserved_units, 0);
        assert_eq!(aborted.budget.remaining_units, 10);
        assert_eq!(aborted.budget.reserved_units, 0);
        assert!(runner.budget_reservation("wake", queued.job.id)?.is_none());
        assert_eq!(
            runner.abort_budget_reservation(AbortDreamerBudgetReservation {
                budget_id: "wake".to_owned(),
                child_job: queued.job.id,
                now: 40,
            })?,
            DreamerBudgetSettlementOutcome::NoReservation
        );

        Ok(())
    }
}
