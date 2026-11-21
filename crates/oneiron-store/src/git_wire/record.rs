//! Durable journal row: record state machine, key builders, MessagePack codec, stored conversions.

use serde::{Deserialize, Serialize};

use crate::git_wire::config::GIT_WIRE_DOMAIN;
use crate::git_wire::config::GIT_WIRE_SCHEMA_VERSION;
use crate::git_wire::failure::GitWireFailureClass;
use crate::git_wire::failure::invalid;
use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefExpectation;
use crate::git_wire::ids::GitRefName;
use crate::git_wire::ids::GitRefPublication;
use crate::git_wire::ids::ObservedGitRef;
use crate::git_wire::operation::GitWireOperation;
use crate::git_wire::repo::GitWireRepo;
use crate::git_wire::repo::GitWireRepoIdentity;
use oneiron_base::error::Result;
use oneiron_contracts::fingerprint::{LegacyDigest, purposes};

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

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "applied" => Ok(Self::Applied),
            "failed" => Ok(Self::Failed),
            _ => Err(invalid("unknown git wire record state")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredObservedRef {
    name: String,
    oid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPublication {
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
pub struct StoredGitWireRecord {
    schema_version: u8,
    pub record_key: [u8; 32],
    repo_identity: [u8; 32],
    pub operation: String,
    pub state: String,
    pub publications: Vec<StoredPublication>,
    observed_before: Vec<StoredObservedRef>,
    pub observed_after: Vec<StoredObservedRef>,
    pub keep_refs: Vec<String>,
    /// Hash of the worktree handle this record owns, for worktree effects.
    pub worktree_scope: Option<[u8; 32]>,
    /// Commit the worktree add must resolve even after crash recovery. An
    /// absent value on a legacy prepared row cannot certify an add.
    #[serde(default)]
    pub worktree_commit: Option<String>,
    /// Digest of the admitted non-executable config that must survive in the
    /// created registration. Recovery cannot certify a different meaning.
    #[serde(default)]
    pub worktree_settings_hash: Option<[u8; 32]>,
    pub failure: Option<String>,
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
    ///
    /// A capability handed out before an upgrade must still match its row, so
    /// it keeps its bytes (K, PLAN-UC-04 3.3): each field framed by its length
    /// as a u32 big-endian.
    pub fn capability_hash(&self) -> [u8; 32] {
        let mut digest = LegacyDigest::new(purposes::git_wire::CAPABILITY);
        for field in [
            GIT_WIRE_DOMAIN,
            b"capability".as_slice(),
            self.record_key.as_slice(),
            self.repo_identity.as_slice(),
            self.operation.as_bytes(),
        ] {
            digest.len_u32_be_saturating(field.len()).raw(field);
        }
        for publication in &self.publications {
            for field in [
                publication.name.as_str(),
                publication.expected.as_deref().unwrap_or("*"),
                publication.next.as_deref().unwrap_or("-"),
            ] {
                digest
                    .len_u32_be_saturating(field.len())
                    .raw(field.as_bytes());
            }
        }
        for observed in &self.observed_before {
            for field in [
                observed.name.as_str(),
                observed.oid.as_deref().unwrap_or("-"),
            ] {
                digest
                    .len_u32_be_saturating(field.len())
                    .raw(field.as_bytes());
            }
        }
        for keep in &self.keep_refs {
            digest
                .len_u32_be_saturating(keep.len())
                .raw(keep.as_bytes());
        }
        let started_at = self.started_at.to_be_bytes();
        for field in [
            self.worktree_commit.as_deref().unwrap_or("-").as_bytes(),
            self.worktree_settings_hash
                .as_ref()
                .map_or(b"-".as_slice(), |hash| hash.as_slice()),
            started_at.as_slice(),
        ] {
            digest.len_u32_be_saturating(field.len()).raw(field);
        }
        digest.finish()
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
    pub record_key: [u8; 32],
    pub repo_identity: GitWireRepoIdentity,
    pub capability_hash: [u8; 32],
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
    /// The source the effect was decided for no longer holds the authority
    /// to apply it. This judges that source, not the move: a later attempt at
    /// the same move decides again.
    Unauthorized,
}

impl GitWireRejection {
    pub const fn as_failure(self) -> GitWireFailureClass {
        match self {
            Self::RefMoved => GitWireFailureClass::RefMismatch,
            Self::ObjectsUnavailable => GitWireFailureClass::Missing,
            Self::EffectUnconfirmed => GitWireFailureClass::Unknown,
            Self::Unauthorized => GitWireFailureClass::Unauthorized,
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

/// A ref publication's journal key. Rows are stored under it, so it keeps its
/// bytes (K, PLAN-UC-04 3.3): each field framed by its length as a u32
/// big-endian.
pub fn ref_record_key(
    identity: GitWireRepoIdentity,
    publications: &[GitRefPublication],
) -> [u8; 32] {
    let mut digest = LegacyDigest::new(purposes::git_wire::REF_RECORD_KEY);
    for field in [
        GIT_WIRE_DOMAIN,
        b"ref-effect".as_slice(),
        identity.as_bytes().as_slice(),
    ] {
        digest.len_u32_be_saturating(field.len()).raw(field);
    }
    for publication in publications {
        let expected = match publication.expected() {
            GitRefExpectation::Absent => b"absent".as_slice(),
            GitRefExpectation::Value(oid) => oid.as_str().as_bytes(),
            GitRefExpectation::Any => b"any".as_slice(),
        };
        let next = match publication.next() {
            Some(oid) => oid.as_str().as_bytes(),
            None => b"delete".as_slice(),
        };
        for field in [publication.name.as_str().as_bytes(), expected, next] {
            digest.len_u32_be_saturating(field.len()).raw(field);
        }
    }
    digest.finish()
}

/// A staged plan's journal key. Rows are stored under it, so it keeps its
/// bytes (K, PLAN-UC-04 3.3): each field framed by its length as a u32
/// big-endian.
pub fn stage_record_key(identity: GitWireRepoIdentity, plan_hash: &[u8; 32]) -> [u8; 32] {
    let mut digest = LegacyDigest::new(purposes::git_wire::STAGE_RECORD_KEY);
    for field in [
        GIT_WIRE_DOMAIN,
        b"stage".as_slice(),
        identity.as_bytes().as_slice(),
        plan_hash.as_slice(),
    ] {
        digest.len_u32_be_saturating(field.len()).raw(field);
    }
    digest.finish()
}

/// A worktree effect's journal key. Rows are stored under it, so it keeps its
/// bytes (K, PLAN-UC-04 3.3): each field framed by its length as a u32
/// big-endian.
pub fn worktree_record_key(
    identity: GitWireRepoIdentity,
    operation: GitWireOperation,
    scope: &[u8; 32],
) -> [u8; 32] {
    let mut digest = LegacyDigest::new(purposes::git_wire::WORKTREE_RECORD_KEY);
    for field in [
        GIT_WIRE_DOMAIN,
        b"worktree".as_slice(),
        identity.as_bytes().as_slice(),
        operation.as_str().as_bytes(),
        scope.as_slice(),
    ] {
        digest.len_u32_be_saturating(field.len()).raw(field);
    }
    digest.finish()
}

pub fn new_record(
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
        worktree_commit: None,
        worktree_settings_hash: None,
        failure: None,
        started_at: now,
        finished_at: None,
    }
}

pub fn finish_state(
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

pub fn observed_from_stored(rows: &[StoredObservedRef]) -> Result<Vec<ObservedGitRef>> {
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

pub fn publications_from_stored(rows: &[StoredPublication]) -> Result<Vec<GitRefPublication>> {
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

pub fn receipt_from_stored(stored: &StoredGitWireRecord) -> Result<GitWireReceipt> {
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

pub fn prepared_from_stored(stored: &StoredGitWireRecord) -> GitWirePrepared {
    GitWirePrepared {
        record_key: stored.record_key,
        repo_identity: GitWireRepoIdentity(stored.repo_identity),
        capability_hash: stored.capability_hash(),
    }
}

pub fn rejection_from_stored(stored: &StoredGitWireRecord) -> Result<GitWireRejection> {
    let class = stored
        .failure
        .as_ref()
        .map(|value| GitWireFailureClass::parse(value.as_str()))
        .transpose()?;
    match class {
        Some(GitWireFailureClass::Missing) => Ok(GitWireRejection::ObjectsUnavailable),
        Some(GitWireFailureClass::RefMismatch) => Ok(GitWireRejection::RefMoved),
        Some(GitWireFailureClass::Unauthorized) => Ok(GitWireRejection::Unauthorized),
        _ => Ok(GitWireRejection::EffectUnconfirmed),
    }
}

pub fn hex_lower(bytes: &[u8]) -> String {
    oneiron_hex::encode(bytes)
}
