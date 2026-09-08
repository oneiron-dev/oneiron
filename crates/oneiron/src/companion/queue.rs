//! Durable companion task queue over AttemptQueue with payload codec and dedupe keys.

use super::codec::{
    decode_scope, decode_subject, encode_scope, encode_subject, invalid_companion_task,
};
use super::keys::{
    COMPANION_TASK_ATTEMPT_KIND, COMPANION_TASK_PAYLOAD_KEYS,
    COMPANION_TASK_PAYLOAD_SCHEMA_VERSION, ERR_INVALID_COMPANION_TASK_PAYLOAD, KEY_TASK,
    KEY_TASK_SCHEMA_VERSION, KEY_TASK_SCOPE, KEY_TASK_SUBJECT,
};
use super::model::{CompanionRecord, CompanionRecordKey, CompanionScope, CompanionSubject};
use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt,
    CompleteOutcome, EnqueueAttempt, EnqueueOutcome, FailAttempt, FailOutcome, RetryAttempt,
    RetryOutcome,
};
use crate::error::{Error, Result};
use rmpv::Value;
use std::io::Cursor;

/// Companion background task family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CompanionTaskKind {
    /// Rebuild or refresh context assembly state for a companion record.
    Context,
    /// Refresh derived profile/persona state for a companion record.
    Profile,
    /// Consolidate companion memory material for a companion record.
    Memory,
    /// Generate a goodbye artifact after an amicable relationship ending.
    GoodbyeArtifact,
}

impl CompanionTaskKind {
    /// Returns the pinned payload string for this companion task kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Context => "context",
            Self::Profile => "profile",
            Self::Memory => "memory",
            Self::GoodbyeArtifact => "goodbye_artifact",
        }
    }

    /// Parses a pinned companion task kind string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "context" => Some(Self::Context),
            "profile" => Some(Self::Profile),
            "memory" => Some(Self::Memory),
            "goodbye_artifact" => Some(Self::GoodbyeArtifact),
            _ => None,
        }
    }
}

/// Inputs controlling relationship-ending teardown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndCompanionRelationship {
    pub ended_at: u64,
    pub ended_badly: bool,
    pub run_id: Option<String>,
}

/// Result of relationship-ending teardown.
#[derive(Debug, Clone, PartialEq)]
pub struct EndCompanionRelationshipOutcome {
    pub record: CompanionRecord,
    pub goodbye_artifact: Option<EnqueueCompanionTaskOutcome>,
    pub already_ended: bool,
}

/// Typed payload stored on durable companion task attempt rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionTask {
    pub kind: CompanionTaskKind,
    pub key: CompanionRecordKey,
}

impl CompanionTask {
    /// Constructs a companion task, validating the referenced companion key.
    pub fn new(kind: CompanionTaskKind, key: CompanionRecordKey) -> Result<Self> {
        key.validate()?;
        Ok(Self { kind, key })
    }

    /// Stable advisory dedupe key for this task target.
    #[must_use]
    pub fn dedupe_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.kind.as_str(),
            companion_scope_dedupe_key(&self.key.scope),
            companion_subject_dedupe_key(&self.key.subject)
        )
    }
}

/// Decoded companion task plus its backing durable AttemptQueue row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionTaskStatus {
    pub attempt: AttemptRecord,
    pub task: CompanionTask,
}

/// Input for enqueuing a companion task through the generic AttemptQueue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnqueueCompanionTask {
    pub task: CompanionTask,
    pub run_id: Option<String>,
    pub now: u64,
}

/// Typed companion enqueue outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnqueueCompanionTaskOutcome {
    Enqueued(CompanionTaskStatus),
    Existing(CompanionTaskStatus),
}

/// Input for claiming the next queued companion task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimCompanionTask {
    pub lease_owner: String,
    pub now: u64,
}

/// Typed companion claim outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimCompanionTaskOutcome {
    Empty,
    Claimed(Box<CompanionTaskStatus>),
}

/// Input for completing a leased companion task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteCompanionTask {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub now: u64,
}

/// Typed companion complete outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompleteCompanionTaskOutcome {
    Completed(CompanionTaskStatus),
    AlreadyCompleted(CompanionTaskStatus),
}

/// Input for terminally failing a leased companion task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailCompanionTask {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub reason: String,
    pub now: u64,
}

/// Typed companion fail outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailCompanionTaskOutcome {
    Failed(CompanionTaskStatus),
    AlreadyFailed(CompanionTaskStatus),
}

/// Input for requeuing a leased companion task after a retryable failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryCompanionTask {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub backoff_until: u64,
    pub last_error: Option<String>,
    pub now: u64,
}

/// Typed companion retry outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryCompanionTaskOutcome {
    Retried(CompanionTaskStatus),
}

/// Companion-specific facade over the generic durable AttemptQueue.
pub struct CompanionQueue<'a> {
    attempts: AttemptQueue<'a>,
}

impl<'a> CompanionQueue<'a> {
    /// Opens a companion queue handle over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self {
            attempts: AttemptQueue::new(vault),
        }
    }

    /// Enqueues a companion task as a generic durable attempt row.
    pub fn enqueue(&self, input: EnqueueCompanionTask) -> Result<EnqueueCompanionTaskOutcome> {
        let payload = encode_companion_task_payload(&input.task)?;
        let outcome = self.attempts.enqueue(EnqueueAttempt {
            kind: COMPANION_TASK_ATTEMPT_KIND.to_owned(),
            payload,
            dedupe_key: Some(input.task.dedupe_key()),
            run_id: input.run_id,
            now: input.now,
        })?;
        match outcome {
            EnqueueOutcome::Enqueued(record) => {
                decode_companion_task_status(record).map(EnqueueCompanionTaskOutcome::Enqueued)
            }
            EnqueueOutcome::Existing(record) => {
                decode_companion_task_status(record).map(EnqueueCompanionTaskOutcome::Existing)
            }
        }
    }

    /// Claims the oldest queued companion task without leasing unrelated attempts.
    pub fn claim(&self, input: ClaimCompanionTask) -> Result<ClaimCompanionTaskOutcome> {
        loop {
            match self.attempts.claim_kind(
                COMPANION_TASK_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: input.lease_owner.clone(),
                    now: input.now,
                },
            )? {
                ClaimOutcome::Empty => return Ok(ClaimCompanionTaskOutcome::Empty),
                ClaimOutcome::Claimed(record) => match decode_companion_task_status(record.clone())
                {
                    Ok(status) => return Ok(ClaimCompanionTaskOutcome::Claimed(Box::new(status))),
                    Err(_) => {
                        self.fail_undecodable_claimed_task(&record, &input.lease_owner, input.now)?;
                    }
                },
            }
        }
    }

    /// Completes a leased companion task through the generic AttemptQueue.
    pub fn complete(&self, input: CompleteCompanionTask) -> Result<CompleteCompanionTaskOutcome> {
        self.ensure_companion_attempt_id(input.id)?;
        let outcome = self.attempts.complete(CompleteAttempt {
            id: input.id,
            lease_owner: input.lease_owner,
            attempt_count: input.attempt_count,
            now: input.now,
        })?;
        match outcome {
            CompleteOutcome::Completed(record) => {
                decode_companion_task_status(record).map(CompleteCompanionTaskOutcome::Completed)
            }
            CompleteOutcome::AlreadyCompleted(record) => decode_companion_task_status(record)
                .map(CompleteCompanionTaskOutcome::AlreadyCompleted),
        }
    }

    /// Terminally fails a leased companion task through the generic AttemptQueue.
    pub fn fail(&self, input: FailCompanionTask) -> Result<FailCompanionTaskOutcome> {
        self.ensure_companion_attempt_id(input.id)?;
        let outcome = self.attempts.fail(FailAttempt {
            id: input.id,
            lease_owner: input.lease_owner,
            attempt_count: input.attempt_count,
            reason: input.reason,
            now: input.now,
        })?;
        match outcome {
            FailOutcome::Failed(record) => {
                decode_companion_task_status(record).map(FailCompanionTaskOutcome::Failed)
            }
            FailOutcome::AlreadyFailed(record) => {
                decode_companion_task_status(record).map(FailCompanionTaskOutcome::AlreadyFailed)
            }
        }
    }

    /// Requeues a leased companion task after a retryable failure.
    pub fn retry(&self, input: RetryCompanionTask) -> Result<RetryCompanionTaskOutcome> {
        self.ensure_companion_attempt_id(input.id)?;
        let outcome = self.attempts.retry(RetryAttempt {
            id: input.id,
            lease_owner: input.lease_owner,
            attempt_count: input.attempt_count,
            backoff_until: input.backoff_until,
            last_error: input.last_error,
            now: input.now,
        })?;
        match outcome {
            RetryOutcome::Retried(record) => {
                decode_companion_task_status(record).map(RetryCompanionTaskOutcome::Retried)
            }
        }
    }

    /// Reads and decodes companion task status by durable attempt id.
    pub fn status(&self, id: AttemptId) -> Result<Option<CompanionTaskStatus>> {
        self.attempts
            .get(id)?
            .map(decode_companion_task_status)
            .transpose()
    }

    fn ensure_companion_attempt_id(&self, id: AttemptId) -> Result<()> {
        let _ = self.status(id)?;
        Ok(())
    }

    fn fail_undecodable_claimed_task(
        &self,
        record: &AttemptRecord,
        lease_owner: &str,
        now: u64,
    ) -> Result<()> {
        match self.attempts.fail(FailAttempt {
            id: record.id,
            lease_owner: lease_owner.to_owned(),
            attempt_count: record.attempt_count,
            reason: ERR_INVALID_COMPANION_TASK_PAYLOAD.to_owned(),
            now,
        })? {
            FailOutcome::Failed(_) | FailOutcome::AlreadyFailed(_) => Ok(()),
        }
    }
}

/// Encodes a companion task payload in canonical MessagePack field order.
pub fn encode_companion_task_payload(task: &CompanionTask) -> Result<Vec<u8>> {
    task.key.validate()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_TASK_SCHEMA_VERSION),
            Value::from(COMPANION_TASK_PAYLOAD_SCHEMA_VERSION),
        ),
        (Value::from(KEY_TASK), Value::from(task.kind.as_str())),
        (Value::from(KEY_TASK_SCOPE), encode_scope(&task.key.scope)),
        (
            Value::from(KEY_TASK_SUBJECT),
            encode_subject(&task.key.subject),
        ),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("companion task MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes and validates a companion task payload.
pub fn decode_companion_task_payload(bytes: &[u8]) -> Result<CompanionTask> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid_companion_task("companion task payload is not valid MessagePack"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_companion_task(
            "trailing bytes after companion task payload",
        ));
    }

    decode_companion_task_payload_value(&value)
}

fn decode_companion_task_status(record: AttemptRecord) -> Result<CompanionTaskStatus> {
    if record.kind != COMPANION_TASK_ATTEMPT_KIND {
        return Err(invalid_companion_task("attempt is not a companion task"));
    }
    let task = decode_companion_task_payload(&record.payload)?;
    Ok(CompanionTaskStatus {
        attempt: record,
        task,
    })
}

fn decode_companion_task_payload_value(value: &Value) -> Result<CompanionTask> {
    let Value::Map(entries) = value else {
        return Err(invalid_companion_task(
            "companion task payload must be a MessagePack map",
        ));
    };

    let mut schema_version: Option<u64> = None;
    let mut task_kind: Option<CompanionTaskKind> = None;
    let mut scope: Option<CompanionScope> = None;
    let mut subject: Option<CompanionSubject> = None;
    let mut seen = [false; COMPANION_TASK_PAYLOAD_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(invalid_companion_task(
                "companion task payload keys must be strings",
            ));
        };
        let Some(index) = COMPANION_TASK_PAYLOAD_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(invalid_companion_task(
                "companion task payload key is not in the pinned set",
            ));
        };
        if seen[index] {
            return Err(invalid_companion_task(
                "duplicate companion task payload key",
            ));
        }
        seen[index] = true;

        match COMPANION_TASK_PAYLOAD_KEYS[index] {
            KEY_TASK_SCHEMA_VERSION => {
                schema_version = Some(value.as_u64().ok_or(invalid_companion_task(
                    "companion task schema_version must be an integer",
                ))?);
            }
            KEY_TASK => {
                task_kind = Some(value.as_str().and_then(CompanionTaskKind::parse).ok_or(
                    invalid_companion_task(
                        "companion task must be context|profile|memory|goodbye_artifact",
                    ),
                )?);
            }
            KEY_TASK_SCOPE => scope = Some(decode_scope(value)?),
            KEY_TASK_SUBJECT => subject = Some(decode_subject(value)?),
            _ => unreachable!("index resolved from COMPANION_TASK_PAYLOAD_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_companion_task(
        "missing required companion task field schema_version",
    ))?;
    if schema_version != COMPANION_TASK_PAYLOAD_SCHEMA_VERSION {
        return Err(invalid_companion_task(
            "unsupported companion task schema_version",
        ));
    }
    let key = CompanionRecordKey {
        scope: scope.ok_or(invalid_companion_task(
            "missing required companion task field scope",
        ))?,
        subject: subject.ok_or(invalid_companion_task(
            "missing required companion task field subject",
        ))?,
    };
    CompanionTask::new(
        task_kind.ok_or(invalid_companion_task(
            "missing required companion task field task",
        ))?,
        key,
    )
}

fn companion_scope_dedupe_key(scope: &CompanionScope) -> String {
    match scope {
        CompanionScope::Neutral => "neutral".to_owned(),
        CompanionScope::Personal { person_ref } => format!("personal:{}", person_ref.to_hex()),
        CompanionScope::SharedVault { vault_id } => format!("shared_vault:{vault_id}"),
    }
}

fn companion_subject_dedupe_key(subject: &CompanionSubject) -> String {
    match subject {
        CompanionSubject::Persona { persona_ref } => format!("persona:{}", persona_ref.to_hex()),
        CompanionSubject::Relationship {
            source_ref,
            target_ref,
        } => format!(
            "relationship:{}:{}",
            source_ref.to_hex(),
            target_ref.to_hex()
        ),
    }
}
