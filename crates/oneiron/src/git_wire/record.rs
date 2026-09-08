//! Durable journal row: record state machine, key builders, MessagePack codec, stored conversions.

use serde::{Deserialize, Serialize};

use super::failure::invalid;
use super::{
    GIT_WIRE_DOMAIN, GIT_WIRE_RECORD_KEY_PREFIX, GIT_WIRE_SCHEMA_VERSION, GitOid,
    GitRefExpectation, GitRefName, GitRefPublication, GitWireFailureClass, GitWireOperation,
    GitWireRepo, GitWireRepoIdentity, ObservedGitRef,
};
use crate::error::{Error, Result};

/// The lifecycle of a durable GitWire record. `Applied` and `Failed` are
/// terminal and can never be overwritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitWireRecordState {
    Prepared,
    Applied,
    Failed,
}

impl GitWireRecordState {
    /// Stable wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Applied => "applied",
            Self::Failed => "failed",
        }
    }

    /// Whether the state can no longer change.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Applied | Self::Failed)
    }

    pub(super) fn parse(value: &str) -> Result<Self> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "applied" => Ok(Self::Applied),
            "failed" => Ok(Self::Failed),
            _ => Err(invalid("unknown git wire record state")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredObservedRef {
    name: String,
    oid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredPublication {
    name: String,
    expected: Option<String>,
    next: Option<String>,
}

/// The durable row of one journaled effect.
///
/// It carries only validated minimal replay values — ref names, object ids,
/// state, and a failure class. No stdout, no stderr, no payload bytes, and no
/// filesystem path ever reaches this row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredGitWireRecord {
    schema_version: u8,
    pub(super) record_key: [u8; 32],
    repo_identity: [u8; 32],
    pub(super) operation: String,
    pub(super) state: String,
    pub(super) publications: Vec<StoredPublication>,
    observed_before: Vec<StoredObservedRef>,
    pub(super) observed_after: Vec<StoredObservedRef>,
    pub(super) keep_refs: Vec<String>,
    /// Hash of the worktree handle this record owns, for worktree effects.
    pub(super) worktree_scope: Option<[u8; 32]>,
    pub(super) failure: Option<String>,
    started_at: u64,
    finished_at: Option<u64>,
}

impl StoredGitWireRecord {
    /// The identity a capability is issued against.
    ///
    /// It covers exactly the fields that are fixed when the record is created —
    /// never the mutable state, outcome, or timing — so a handle stays valid
    /// across the record's own lifecycle while still failing closed if the row
    /// is replaced by a different intent or is gone.
    pub(super) fn capability_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hash_field(&mut hasher, GIT_WIRE_DOMAIN);
        hash_field(&mut hasher, b"capability");
        hash_field(&mut hasher, &self.record_key);
        hash_field(&mut hasher, &self.repo_identity);
        hash_field(&mut hasher, self.operation.as_bytes());
        for publication in &self.publications {
            hash_field(&mut hasher, publication.name.as_bytes());
            hash_field(
                &mut hasher,
                publication.expected.as_deref().unwrap_or("*").as_bytes(),
            );
            hash_field(
                &mut hasher,
                publication.next.as_deref().unwrap_or("-").as_bytes(),
            );
        }
        for observed in &self.observed_before {
            hash_field(&mut hasher, observed.name.as_bytes());
            hash_field(
                &mut hasher,
                observed.oid.as_deref().unwrap_or("-").as_bytes(),
            );
        }
        for keep in &self.keep_refs {
            hash_field(&mut hasher, keep.as_bytes());
        }
        hash_field(&mut hasher, &self.started_at.to_be_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// The public view of a durable record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitWireReceipt {
    pub record_key: [u8; 32],
    pub repo_identity: GitWireRepoIdentity,
    pub operation: GitWireOperation,
    pub state: GitWireRecordState,
    pub publications: Vec<GitRefPublication>,
    pub observed_before: Vec<ObservedGitRef>,
    pub observed_after: Vec<ObservedGitRef>,
    pub failure: Option<GitWireFailureClass>,
    pub started_at: u64,
    pub finished_at: Option<u64>,
}

/// An unforgeable handle to a durable `Prepared` record.
///
/// The handle carries no effect values of its own: commit and recovery always
/// re-read the durable row and act on that. The capability hash pins the exact
/// intent the handle was issued against, so a forged handle has no record and a
/// stale one cannot commit a record that has since been replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitWirePrepared {
    pub(super) record_key: [u8; 32],
    pub(super) repo_identity: GitWireRepoIdentity,
    pub(super) capability_hash: [u8; 32],
}

impl GitWirePrepared {
    /// The durable record this capability refers to.
    pub const fn record_key(&self) -> &[u8; 32] {
        &self.record_key
    }

    /// The object store this capability is bound to.
    pub const fn repo_identity(&self) -> GitWireRepoIdentity {
        self.repo_identity
    }
}

/// Why an effect did not apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitWireRejection {
    /// A guarded ref no longer carries the value the effect was decided
    /// against.
    RefMoved,
    /// A published object set is not fully present in the object store.
    ObjectsUnavailable,
    /// The effect could not be confirmed to have happened, and the record is
    /// terminally void rather than silently claimed.
    EffectUnconfirmed,
}

impl GitWireRejection {
    pub(super) const fn as_failure(self) -> GitWireFailureClass {
        match self {
            Self::RefMoved => GitWireFailureClass::RefMismatch,
            Self::ObjectsUnavailable => GitWireFailureClass::Missing,
            Self::EffectUnconfirmed => GitWireFailureClass::Unknown,
        }
    }
}

/// The result of applying or replaying a journaled ref effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitWireCommitOutcome {
    /// The publication transaction ran now.
    Applied(GitWireReceipt),
    /// A durable terminal record answered without launching git.
    Replayed(GitWireReceipt),
    /// The effect is terminally void; no ref was moved by this call.
    Rejected {
        receipt: GitWireReceipt,
        reason: GitWireRejection,
    },
}

impl GitWireCommitOutcome {
    /// The durable record behind the outcome.
    pub fn receipt(&self) -> &GitWireReceipt {
        match self {
            Self::Applied(receipt) | Self::Replayed(receipt) => receipt,
            Self::Rejected { receipt, .. } => receipt,
        }
    }

    /// Whether the outcome came from a durable record without launching git.
    pub const fn is_replayed(&self) -> bool {
        matches!(self, Self::Replayed(_))
    }

    /// Whether the refs now carry the intended values.
    pub const fn is_applied(&self) -> bool {
        matches!(self, Self::Applied(_) | Self::Replayed(_))
    }
}

pub(super) fn record_row_prefix(identity: GitWireRepoIdentity) -> Vec<u8> {
    let mut key = Vec::with_capacity(GIT_WIRE_RECORD_KEY_PREFIX.len() + 66);
    key.extend_from_slice(GIT_WIRE_RECORD_KEY_PREFIX);
    key.extend_from_slice(identity.as_hex().as_bytes());
    key.push(b':');
    key
}

pub(super) fn record_row_key(identity: GitWireRepoIdentity, record_key: &[u8; 32]) -> Vec<u8> {
    let mut key = record_row_prefix(identity);
    key.extend_from_slice(hex_lower(record_key).as_bytes());
    key
}

pub(super) fn ref_record_key(
    identity: GitWireRepoIdentity,
    publications: &[GitRefPublication],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_DOMAIN);
    hash_field(&mut hasher, b"ref-effect");
    hash_field(&mut hasher, identity.as_bytes());
    for publication in publications {
        hash_field(&mut hasher, publication.name.as_str().as_bytes());
        match publication.expected() {
            GitRefExpectation::Absent => hash_field(&mut hasher, b"absent"),
            GitRefExpectation::Value(oid) => hash_field(&mut hasher, oid.as_str().as_bytes()),
            GitRefExpectation::Any => hash_field(&mut hasher, b"any"),
        }
        match publication.next() {
            Some(oid) => hash_field(&mut hasher, oid.as_str().as_bytes()),
            None => hash_field(&mut hasher, b"delete"),
        }
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn stage_record_key(identity: GitWireRepoIdentity, plan_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_DOMAIN);
    hash_field(&mut hasher, b"stage");
    hash_field(&mut hasher, identity.as_bytes());
    hash_field(&mut hasher, plan_hash);
    *hasher.finalize().as_bytes()
}

pub(super) fn worktree_record_key(
    identity: GitWireRepoIdentity,
    operation: GitWireOperation,
    scope: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, GIT_WIRE_DOMAIN);
    hash_field(&mut hasher, b"worktree");
    hash_field(&mut hasher, identity.as_bytes());
    hash_field(&mut hasher, operation.as_str().as_bytes());
    hash_field(&mut hasher, scope);
    *hasher.finalize().as_bytes()
}

pub(super) fn new_record(
    repo: &GitWireRepo,
    record_key: [u8; 32],
    operation: GitWireOperation,
    publications: &[GitRefPublication],
    observed_before: &[ObservedGitRef],
    now: u64,
) -> StoredGitWireRecord {
    StoredGitWireRecord {
        schema_version: GIT_WIRE_SCHEMA_VERSION,
        record_key,
        repo_identity: *repo.identity().as_bytes(),
        operation: operation.as_str().to_owned(),
        state: GitWireRecordState::Prepared.as_str().to_owned(),
        publications: publications.iter().map(stored_publication).collect(),
        observed_before: observed_before.iter().map(stored_observed).collect(),
        observed_after: Vec::new(),
        keep_refs: Vec::new(),
        worktree_scope: None,
        failure: None,
        started_at: now,
        finished_at: None,
    }
}

pub(super) fn finish_state(
    mut record: StoredGitWireRecord,
    state: GitWireRecordState,
    observed_after: Vec<ObservedGitRef>,
    now: u64,
) -> StoredGitWireRecord {
    record.state = state.as_str().to_owned();
    record.observed_after = observed_after.iter().map(stored_observed).collect();
    record.finished_at = Some(now);
    record
}

fn stored_observed(observed: &ObservedGitRef) -> StoredObservedRef {
    StoredObservedRef {
        name: observed.name.as_str().to_owned(),
        oid: observed.oid.as_ref().map(|oid| oid.as_str().to_owned()),
    }
}

pub(super) fn observed_from_stored(rows: &[StoredObservedRef]) -> Result<Vec<ObservedGitRef>> {
    let mut observed = Vec::with_capacity(rows.len());
    for row in rows {
        observed.push(ObservedGitRef {
            name: GitRefName::parse_full(row.name.clone())?,
            oid: row
                .oid
                .as_ref()
                .map(|oid| GitOid::parse_hex(oid.clone()))
                .transpose()?,
        });
    }
    Ok(observed)
}

fn stored_publication(publication: &GitRefPublication) -> StoredPublication {
    StoredPublication {
        name: publication.name.as_str().to_owned(),
        expected: publication.expected.wire(),
        next: publication.next.as_ref().map(|oid| oid.as_str().to_owned()),
    }
}

pub(super) fn publications_from_stored(
    rows: &[StoredPublication],
) -> Result<Vec<GitRefPublication>> {
    let mut publications = Vec::with_capacity(rows.len());
    for row in rows {
        publications.push(GitRefPublication {
            name: GitRefName::parse_full(row.name.clone())?,
            expected: GitRefExpectation::from_wire(row.expected.as_ref())?,
            next: row
                .next
                .as_ref()
                .map(|oid| GitOid::parse_hex(oid.clone()))
                .transpose()?,
        });
    }
    Ok(publications)
}

pub(super) fn receipt_from_stored(stored: &StoredGitWireRecord) -> Result<GitWireReceipt> {
    if stored.schema_version != GIT_WIRE_SCHEMA_VERSION {
        return Err(invalid("unsupported git wire record schema version"));
    }
    Ok(GitWireReceipt {
        record_key: stored.record_key,
        repo_identity: GitWireRepoIdentity(stored.repo_identity),
        operation: GitWireOperation::parse(&stored.operation)?,
        state: GitWireRecordState::parse(&stored.state)?,
        publications: publications_from_stored(&stored.publications)?,
        observed_before: observed_from_stored(&stored.observed_before)?,
        observed_after: observed_from_stored(&stored.observed_after)?,
        failure: stored
            .failure
            .as_ref()
            .map(|class| GitWireFailureClass::parse(class.as_str()))
            .transpose()?,
        started_at: stored.started_at,
        finished_at: stored.finished_at,
    })
}

pub(super) fn prepared_from_stored(stored: &StoredGitWireRecord) -> GitWirePrepared {
    GitWirePrepared {
        record_key: stored.record_key,
        repo_identity: GitWireRepoIdentity(stored.repo_identity),
        capability_hash: stored.capability_hash(),
    }
}

pub(super) fn rejection_from_stored(stored: &StoredGitWireRecord) -> Result<GitWireRejection> {
    let class = stored
        .failure
        .as_ref()
        .map(|value| GitWireFailureClass::parse(value.as_str()))
        .transpose()?;
    match class {
        Some(GitWireFailureClass::Missing) => Ok(GitWireRejection::ObjectsUnavailable),
        Some(GitWireFailureClass::RefMismatch) => Ok(GitWireRejection::RefMoved),
        _ => Ok(GitWireRejection::EffectUnconfirmed),
    }
}

pub(super) fn encode_record(record: &StoredGitWireRecord) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record)
        .map_err(|_| Error::InvariantViolation("git wire record encode failed"))
}

pub(super) fn decode_record(bytes: &[u8]) -> Result<StoredGitWireRecord> {
    rmp_serde::from_slice(bytes).map_err(|_| invalid("git wire record row is not MessagePack"))
}

pub(super) fn hash_field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    hasher.update(&length.to_be_bytes());
    hasher.update(bytes);
}

pub(super) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}
