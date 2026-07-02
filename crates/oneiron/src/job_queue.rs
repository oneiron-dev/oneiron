//! Generic LMDB-backed background job queue.
//!
//! This is intentionally mechanical storage state only: enqueue and claim
//! transition LMDB rows atomically, while execution policy, retry, completion,
//! failure handling, and timeout cleanup stay outside this module.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Vault;
use crate::error::{Error, Result};
use crate::store::Store;

const JOB_RECORD_VERSION: u8 = 1;
const READY_KEY_LEN: usize = 24;
const MAX_KIND_LEN: usize = 128;
const MAX_DEDUPE_KEY_LEN: usize = 512;
const MAX_LEASE_OWNER_LEN: usize = 128;
const MAX_RUN_ID_LEN: usize = 128;
const ERR_EMPTY_KIND: &str = "kind must not be empty";
const ERR_KIND_TOO_LONG: &str = "kind exceeds 128 bytes";
const ERR_DEDUPE_KEY_EMPTY: &str = "dedupe key must not be empty";
const ERR_DEDUPE_KEY_TOO_LONG: &str = "dedupe key exceeds 512 bytes";
const ERR_LEASE_OWNER_EMPTY: &str = "lease owner must not be empty";
const ERR_LEASE_OWNER_TOO_LONG: &str = "lease owner exceeds 128 bytes";
const ERR_RUN_ID_EMPTY: &str = "run id must not be empty";
const ERR_RUN_ID_TOO_LONG: &str = "run id exceeds 128 bytes";
const ERR_JOB_ID_LEN: &str = "job id must be 16 bytes";
#[cfg(test)]
const ERR_READY_KEY_LEN: &str = "ready index key must be 24 bytes";

/// Stable identifier for a queued job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId {
    bytes: [u8; 16],
}

impl JobId {
    /// Creates a new time-sortable v7 UUID-backed job id.
    #[must_use]
    pub fn now() -> Self {
        Self {
            bytes: Uuid::now_v7().into_bytes(),
        }
    }

    /// Returns the raw 16-byte storage key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }

    /// Parses a raw 16-byte storage key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 16] = bytes
            .try_into()
            .map_err(|_| Error::InvalidJobQueueRecord(ERR_JOB_ID_LEN))?;
        Ok(Self { bytes })
    }
}

/// Durable lifecycle state persisted on each job row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum JobState {
    Queued,
    Leased,
}

/// Durable job row stored in LMDB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    pub id: JobId,
    pub kind: String,
    pub payload: Vec<u8>,
    pub state: JobState,
    pub lease_owner: Option<String>,
    pub attempt_count: u32,
    pub run_id: Option<String>,
    pub dedupe_key: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Input for enqueueing a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnqueueJob {
    pub kind: String,
    pub payload: Vec<u8>,
    pub dedupe_key: Option<String>,
    pub run_id: Option<String>,
    pub now: u64,
}

/// Typed enqueue outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnqueueOutcome {
    Enqueued(JobRecord),
    Existing(JobRecord),
}

/// Input for atomically claiming the next queued job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimJob {
    pub lease_owner: String,
    pub now: u64,
}

/// Typed claim outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimOutcome {
    Empty,
    Claimed(JobRecord),
}

/// Queue handle over a vault store.
pub struct JobQueue<'a> {
    store: &'a Store,
}

impl<'a> JobQueue<'a> {
    /// Opens a queue handle over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self {
            store: &vault.store,
        }
    }

    /// Enqueues a job, returning an existing row when the caller-supplied
    /// dedupe key already maps to a job.
    pub fn enqueue(&self, input: EnqueueJob) -> Result<EnqueueOutcome> {
        validate_kind(&input.kind)?;
        validate_optional_dedupe(input.dedupe_key.as_deref())?;
        validate_optional_run_id(input.run_id.as_deref())?;

        let mut wtxn = self.store.env.write_txn()?;
        if let Some(dedupe_key) = input.dedupe_key.as_deref()
            && let Some(existing_id) = self.store.job_dedupe.get(&wtxn, dedupe_key.as_bytes())?
        {
            let id = JobId::from_bytes(existing_id)?;
            let record = self.read_record_in_txn(&wtxn, id)?;
            wtxn.commit()?;
            return Ok(EnqueueOutcome::Existing(record));
        }

        let record = JobRecord {
            id: JobId::now(),
            kind: input.kind,
            payload: input.payload,
            state: JobState::Queued,
            lease_owner: None,
            attempt_count: 0,
            run_id: input.run_id,
            dedupe_key: input.dedupe_key,
            created_at: input.now,
            updated_at: input.now,
        };

        let encoded = encode_record(&record)?;
        self.store
            .job_records
            .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
        let ready_key = ready_key(record.created_at, record.id);
        self.store
            .job_ready
            .put(&mut wtxn, &ready_key, record.id.as_bytes())?;
        if let Some(dedupe_key) = record.dedupe_key.as_deref() {
            self.store
                .job_dedupe
                .put(&mut wtxn, dedupe_key.as_bytes(), record.id.as_bytes())?;
        }
        wtxn.commit()?;

        Ok(EnqueueOutcome::Enqueued(record))
    }

    /// Atomically claims the oldest queued job under LMDB's single-writer
    /// invariant.
    pub fn claim(&self, input: ClaimJob) -> Result<ClaimOutcome> {
        validate_lease_owner(&input.lease_owner)?;

        let mut wtxn = self.store.env.write_txn()?;
        let mut stale_ready_keys = Vec::new();
        let mut claimed = None;
        for row in self.store.job_ready.iter(&wtxn)? {
            let (key, value) = row?;
            let id = JobId::from_bytes(value)?;
            let Some(raw_record) = self.store.job_records.get(&wtxn, id.as_bytes())? else {
                stale_ready_keys.push(key.to_vec());
                continue;
            };
            let mut record = decode_record(raw_record)?;
            if record.state != JobState::Queued {
                stale_ready_keys.push(key.to_vec());
                continue;
            }
            record.state = JobState::Leased;
            record.lease_owner = Some(input.lease_owner.clone());
            record.attempt_count = record
                .attempt_count
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("job attempt count"))?;
            record.updated_at = input.now;
            claimed = Some((key.to_vec(), record));
            break;
        }

        for key in stale_ready_keys {
            self.store.job_ready.delete(&mut wtxn, &key)?;
        }

        let Some((ready_key, record)) = claimed else {
            wtxn.commit()?;
            return Ok(ClaimOutcome::Empty);
        };

        self.store.job_ready.delete(&mut wtxn, &ready_key)?;
        let encoded = encode_record(&record)?;
        self.store
            .job_records
            .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
        wtxn.commit()?;

        Ok(ClaimOutcome::Claimed(record))
    }

    /// Reads a job by id.
    pub fn get(&self, id: JobId) -> Result<Option<JobRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.job_records.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        decode_record(raw).map(Some)
    }

    fn read_record_in_txn(&self, txn: &heed::RwTxn<'_>, id: JobId) -> Result<JobRecord> {
        let raw =
            self.store
                .job_records
                .get(txn, id.as_bytes())?
                .ok_or(Error::InvalidJobQueueRecord(
                    "dedupe index points at a missing job",
                ))?;
        decode_record(raw)
    }
}

fn validate_kind(kind: &str) -> Result<()> {
    if kind.is_empty() {
        return Err(Error::InvalidJobQueueRecord(ERR_EMPTY_KIND));
    }
    if kind.len() > MAX_KIND_LEN {
        return Err(Error::InvalidJobQueueRecord(ERR_KIND_TOO_LONG));
    }
    Ok(())
}

fn validate_optional_dedupe(dedupe_key: Option<&str>) -> Result<()> {
    if let Some(dedupe_key) = dedupe_key {
        if dedupe_key.is_empty() {
            return Err(Error::InvalidJobQueueRecord(ERR_DEDUPE_KEY_EMPTY));
        }
        if dedupe_key.len() > MAX_DEDUPE_KEY_LEN {
            return Err(Error::InvalidJobQueueRecord(ERR_DEDUPE_KEY_TOO_LONG));
        }
    }
    Ok(())
}

fn validate_optional_run_id(run_id: Option<&str>) -> Result<()> {
    if let Some(run_id) = run_id {
        if run_id.is_empty() {
            return Err(Error::InvalidJobQueueRecord(ERR_RUN_ID_EMPTY));
        }
        if run_id.len() > MAX_RUN_ID_LEN {
            return Err(Error::InvalidJobQueueRecord(ERR_RUN_ID_TOO_LONG));
        }
    }
    Ok(())
}

fn validate_lease_owner(lease_owner: &str) -> Result<()> {
    if lease_owner.is_empty() {
        return Err(Error::InvalidJobQueueRecord(ERR_LEASE_OWNER_EMPTY));
    }
    if lease_owner.len() > MAX_LEASE_OWNER_LEN {
        return Err(Error::InvalidJobQueueRecord(ERR_LEASE_OWNER_TOO_LONG));
    }
    Ok(())
}

fn ready_key(created_at: u64, id: JobId) -> [u8; READY_KEY_LEN] {
    let mut key = [0_u8; READY_KEY_LEN];
    key[..8].copy_from_slice(&created_at.to_be_bytes());
    key[8..].copy_from_slice(id.as_bytes());
    key
}

#[cfg(test)]
fn decode_ready_key(bytes: &[u8]) -> Result<(u64, JobId)> {
    if bytes.len() != READY_KEY_LEN {
        return Err(Error::InvalidJobQueueRecord(ERR_READY_KEY_LEN));
    }
    let mut created_at = [0_u8; 8];
    created_at.copy_from_slice(&bytes[..8]);
    Ok((
        u64::from_be_bytes(created_at),
        JobId::from_bytes(&bytes[8..])?,
    ))
}

fn encode_record(record: &JobRecord) -> Result<Vec<u8>> {
    let mut encoded = vec![JOB_RECORD_VERSION];
    let mut body = rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvalidJobQueueRecord("failed to encode job record"))?;
    encoded.append(&mut body);
    Ok(encoded)
}

fn decode_record(raw: &[u8]) -> Result<JobRecord> {
    let Some((&version, body)) = raw.split_first() else {
        return Err(Error::InvalidJobQueueRecord("missing job record version"));
    };
    if version != JOB_RECORD_VERSION {
        return Err(Error::InvalidJobQueueRecord(
            "unsupported job record version",
        ));
    }
    let record: JobRecord = rmp_serde::from_slice(body)
        .map_err(|_| Error::InvalidJobQueueRecord("failed to decode job record"))?;
    validate_kind(&record.kind)?;
    validate_optional_dedupe(record.dedupe_key.as_deref())?;
    validate_optional_run_id(record.run_id.as_deref())?;
    if let Some(lease_owner) = record.lease_owner.as_deref() {
        validate_lease_owner(lease_owner)?;
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Vault, VaultConfig};

    fn open_queue() -> (tempfile::TempDir, Vault) {
        crate::test_util::open_test_vault_with(VaultConfig::device())
    }

    fn enqueue(kind: &str, dedupe_key: Option<&str>, now: u64) -> EnqueueJob {
        EnqueueJob {
            kind: kind.to_owned(),
            payload: format!("payload-{now}").into_bytes(),
            dedupe_key: dedupe_key.map(str::to_owned),
            run_id: Some(format!("run-{now}")),
            now,
        }
    }

    #[test]
    fn job_queue_enqueue_persists_required_fields() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = JobQueue::new(&vault);

        let EnqueueOutcome::Enqueued(job) =
            queue.enqueue(enqueue("claim_extraction", Some("turn:1"), 10))?
        else {
            panic!("expected new job");
        };

        let persisted = queue.get(job.id)?.expect("persisted job");
        assert_eq!(persisted.kind, "claim_extraction");
        assert_eq!(persisted.payload, b"payload-10");
        assert_eq!(persisted.state, JobState::Queued);
        assert_eq!(persisted.lease_owner, None);
        assert_eq!(persisted.attempt_count, 0);
        assert_eq!(persisted.run_id.as_deref(), Some("run-10"));
        assert_eq!(persisted.dedupe_key.as_deref(), Some("turn:1"));
        assert_eq!(persisted.created_at, 10);
        assert_eq!(persisted.updated_at, 10);

        Ok(())
    }

    #[test]
    fn job_queue_enqueue_is_idempotent_for_dedupe_key() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = JobQueue::new(&vault);

        let EnqueueOutcome::Enqueued(first) =
            queue.enqueue(enqueue("claim_extraction", Some("same"), 10))?
        else {
            panic!("expected first enqueue");
        };
        let EnqueueOutcome::Existing(second) =
            queue.enqueue(enqueue("claim_extraction", Some("same"), 20))?
        else {
            panic!("expected existing enqueue");
        };

        assert_eq!(second.id, first.id);
        assert_eq!(second.payload, first.payload);
        assert_eq!(second.created_at, 10);

        Ok(())
    }

    #[test]
    fn job_queue_claim_is_atomic_and_returns_typed_states() -> Result<()> {
        let (_dir, vault) = open_queue();
        let queue = JobQueue::new(&vault);

        assert_eq!(
            queue.claim(ClaimJob {
                lease_owner: "worker-a".to_owned(),
                now: 10,
            })?,
            ClaimOutcome::Empty
        );

        let EnqueueOutcome::Enqueued(first) = queue.enqueue(enqueue("first", None, 10))? else {
            panic!("expected first enqueue");
        };
        let EnqueueOutcome::Enqueued(second) = queue.enqueue(enqueue("second", None, 20))? else {
            panic!("expected second enqueue");
        };

        let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
            lease_owner: "worker-a".to_owned(),
            now: 30,
        })?
        else {
            panic!("expected claimed job");
        };
        assert_eq!(claimed.id, first.id);
        assert_eq!(claimed.state, JobState::Leased);
        assert_eq!(claimed.lease_owner.as_deref(), Some("worker-a"));
        assert_eq!(claimed.attempt_count, 1);
        assert_eq!(claimed.updated_at, 30);

        let persisted = queue.get(first.id)?.expect("claimed job persisted");
        assert_eq!(persisted, claimed);

        let ClaimOutcome::Claimed(next) = queue.claim(ClaimJob {
            lease_owner: "worker-b".to_owned(),
            now: 40,
        })?
        else {
            panic!("expected second claimed job");
        };
        assert_eq!(next.id, second.id);

        assert_eq!(
            queue.claim(ClaimJob {
                lease_owner: "worker-c".to_owned(),
                now: 50,
            })?,
            ClaimOutcome::Empty
        );

        Ok(())
    }

    #[test]
    fn ready_key_round_trips() -> Result<()> {
        let id = JobId::now();
        let key = ready_key(42, id);
        assert_eq!(decode_ready_key(&key)?, (42, id));
        Ok(())
    }
}
