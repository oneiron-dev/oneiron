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
const DREAMER_RUN_TREE_KEYS: [&str; 4] = [
    KEY_SCHEMA_VERSION,
    KEY_JOB_ID,
    KEY_PARENT_JOB,
    KEY_CREATED_AT,
];
const DREAMER_PARKED_KEYS: [&str; 4] = [KEY_SCHEMA_VERSION, KEY_JOB_ID, KEY_REASON, KEY_PARKED_AT];
const DREAMER_PRIVATE_BUDGET_PREFIX: &[u8] = b"dreamer:budget:";
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
    /// committing. Budget denial drops the transaction, leaving the job queued
    /// and the budget row unchanged.
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

        let mut budget = read_or_initialize_budget_in_txn(
            self.vault,
            &wtxn,
            &input.budget_id,
            input.budget_total_units,
            input.now,
        )?;
        if input.reserve_units > budget.remaining_units {
            return Ok(DreamerAdmissionOutcome::BudgetExhausted(budget));
        }

        budget.remaining_units -= input.reserve_units;
        budget.reserved_units = budget
            .reserved_units
            .checked_add(input.reserve_units)
            .ok_or(Error::ArithmeticOverflow("dreamer budget reserved units"))?;
        budget.updated_at = input.now;
        put_budget_record_in_txn(self.vault, &mut wtxn, &budget)?;

        if let Some(milestone) = input.started_milestone {
            apply_milestone_claim_in_txn(self.vault, &mut wtxn, job.id, milestone)?;
        }

        let status = decode_dreamer_job_status(job)?;
        wtxn.commit()?;

        Ok(DreamerAdmissionOutcome::Admitted(Box::new(
            DreamerAdmittedJob { status, budget },
        )))
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

const fn invalid_dreamer_runner(reason: &'static str) -> Error {
    Error::InvalidJobQueueRecord(reason)
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::thread;

    use crate::claim::{ClaimApprovalStatus, ClaimSource};
    use crate::job_queue::JobState;
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

    fn milestone_fixture(
        vault: &Vault,
        claim_id: EntityId,
        at: u64,
    ) -> Result<DreamerMilestoneClaim> {
        let actor = EntityId::now();
        let subject = EntityId::now();
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(1), 1, b"actor")?;
        vault.put_entity(&subject, ENTITY_TYPE_TASK, occurred(1), 1, b"subject")?;
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

        let stored_budget = runner.budget("wake")?.expect("budget row");
        assert_eq!(stored_budget, admitted.budget);
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
        let queued = enqueue_job(&runner, "expand", 10)?;

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
        let status = runner.status(queued.job.id)?.expect("queued job");
        assert_eq!(status.job.state, JobState::Queued);
        assert_eq!(status.job.attempt_count, 0);
        assert!(status.job.lease_owner.is_none());

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

    #[test]
    fn dreamer_concurrent_admission_cannot_overspend_private_budget() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let first = enqueue_job(&runner, "first", 10)?;
        let second = enqueue_job(&runner, "second", 11)?;
        let barrier = Barrier::new(2);

        let (left, right) = thread::scope(|scope| {
            let left = scope.spawn(|| {
                barrier.wait();
                runner.admit_next(AdmitDreamerJob {
                    lease_owner: "left-worker".to_owned(),
                    now: 20,
                    budget_id: "wake".to_owned(),
                    budget_total_units: 5,
                    reserve_units: 3,
                    started_milestone: None,
                })
            });
            let right = scope.spawn(|| {
                barrier.wait();
                runner.admit_next(AdmitDreamerJob {
                    lease_owner: "right-worker".to_owned(),
                    now: 20,
                    budget_id: "wake".to_owned(),
                    budget_total_units: 5,
                    reserve_units: 3,
                    started_milestone: None,
                })
            });
            (
                left.join().expect("left join"),
                right.join().expect("right join"),
            )
        });

        let outcomes = [left?, right?];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, DreamerAdmissionOutcome::Admitted(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, DreamerAdmissionOutcome::BudgetExhausted(_)))
                .count(),
            1
        );
        let budget = runner.budget("wake")?.expect("committed budget");
        assert_eq!(budget.remaining_units, 2);
        assert_eq!(budget.reserved_units, 3);

        let first_status = runner.status(first.job.id)?.expect("first status");
        let second_status = runner.status(second.job.id)?.expect("second status");
        let leased = [first_status.job.state, second_status.job.state]
            .into_iter()
            .filter(|state| *state == JobState::Leased)
            .count();
        let queued = [first_status.job.state, second_status.job.state]
            .into_iter()
            .filter(|state| *state == JobState::Queued)
            .count();
        assert_eq!(leased, 1);
        assert_eq!(queued, 1);

        Ok(())
    }
}
