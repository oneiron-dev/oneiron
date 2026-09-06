//! The origin publication protocol (ARCH-0068 RA2–RA5, ONE-1910).
//!
//! One publication couples ONE typed LEDGER claim to ONE compare-and-swap git
//! ref advance under one crash-consistent protocol. Nothing else in this crate
//! may advance a served ref, and nothing else may decide what the origin
//! advertises.
//!
//! # Visibility is a derived proof, never a flag
//!
//! [`Vault::published_origin_refs`] is the ONLY advertisement projection. A ref
//! appears there while — and only while — a `Published` journal row's live ref
//! still equals its `new_oid` and all required Git and LFS objects remain
//! readable. There is no "visible" boolean anybody could set by hand. The
//! objects are proved before the ref moves and rechecked by the projection;
//! missing bytes or a live-ref mismatch hide the row without granting raw refs
//! any advertisement authority.
//!
//! # Single writer, by CAS and nothing else
//!
//! Every ref advance goes through [`crate::git_wire::GitWire::update_ref_cas`]
//! against the exact value the publication was decided against. A rejected
//! compare-and-swap ([`GitWireRejection::RefMoved`]) is a durable `Conflicted`
//! record and is NEVER retried — retrying is precisely how a second writer
//! would silently overwrite the first. That makes split-brain impossible
//! without any coordination service (RA2).
//!
//! # Physical roots and logical owners (RA4)
//!
//! An object is pinned by ONE physical keep-ref — the landed
//! [`GIT_WIRE_KEEP_REF_PREFIX`]`object/<oid>` shape, written only through
//! GitWire — and by as many LOGICAL owner rows as there are reasons to keep it
//! ([`OriginKeepRefKind`]). The physical root is deleted only when the owner
//! count reaches zero, so a publication releasing its own pin can never
//! unpin an object a change index, a conflict tree, a recovery or a snapshot
//! still needs.
//!
//! # The crash windows
//!
//! Objects and LFS bytes stage BEFORE the LMDB critical section. Three windows
//! exist and each has exactly one durable disposition, all reached through the
//! same code path [`Vault::reconcile_origin_publications`] drives:
//!
//! | Window | Observation | Disposition |
//! |---|---|---|
//! | after `Prepared`, before CAS | live ref == `expected_old_oid` and every object present | [`OriginCensusDisposition::RetriedAndPublished`] |
//! | after `Prepared`, before CAS | anything else | `MarkedFailed` / `MarkedConflicted`, ref unmoved |
//! | after CAS, before finalize | live ref == `new_oid` | `FinalizedPublished`, ref NOT moved again |
//! | after finalize, before cleanup | `Published` + live-ref proof | owner dropped; `NoChange` |
//!
//! An interrupted cleanup is a SAFE LEAK: a keep-ref with no owner keeps bytes
//! alive and costs one ref, and the next census removes it. Losing a root that
//! something still references would not be recoverable, so the protocol always
//! errs toward the leak.
//!
//! # Where the transaction boundary really is
//!
//! T1 commits Prepared plus the CAS intent before the public-ref effect.
//! GitWire then commits its own intent and runs CAS, outside publication's
//! transactions. After an Applied/Replayed outcome and a fresh live-ref proof,
//! T2 atomically writes the claim, Published and the visible-ref row. T2 reads
//! its journal row inside the transaction: terminal states always win.
//!
//! Pinning, runner, census and retirement share GitWire's re-entrant repository
//! coordinator. It is acquired BEFORE any LMDB writer. No GitWire call, Vault
//! read or subprocess runs inside T1 or T2. Keeping this coordinator across
//! pinning and zero-owner retirement prevents deletion beneath a new owner.
//!
//! # One authority for "did the ref move"
//!
//! This module never decides a compare-and-swap for itself. It hands the
//! decided-against value to [`GitWire::update_ref_cas`] and reads the verdict
//! back, because GitWire already owns the journal, the roll-forward of an
//! interrupted effect, the whole-graph object proof and the replay of a
//! terminal record. A second implementation of that decision here would be a
//! second thing to keep in agreement with the repository, and the two would
//! disagree exactly when it mattered.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::codebase::entity_id_from_hash_material;
use crate::edge::EdgeKind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::git_wire::{
    GIT_WIRE_KEEP_REF_PREFIX, GitOid, GitRefName, GitWire, GitWireCommitOutcome, GitWireRejection,
    GitWireRepo, lock_repository,
};
use crate::origin::lfs::LfsOid;
use crate::temporal::TimeRange;

// ---------------------------------------------------------------------------
// Pinned protocol constants
// ---------------------------------------------------------------------------

/// Schema version of every `vault_meta` row family below.
pub const ORIGIN_PUBLICATION_SCHEMA_VERSION: u8 = 1;

/// The LEDGER predicate one successful publication asserts.
///
/// Well-formed and unreserved under the D17 grammar, so it rides the generic
/// claim door; the append-only predicate registry needs no edit.
pub const ORIGIN_PUBLICATION_PREDICATE: &str = "repo.publication";

/// Publication journal family: `prefix ++ 16B publication_id`.
///
/// The prefix ends in the version separator `v1:` so a future `v10:` can never
/// be a prefix-scan of `v1` (`store::short_id_alias` prefix law).
pub const ORIGIN_PUBLICATION_RECORD_KEY_PREFIX: &[u8] = b"origin:publication:v1:";

/// One in-flight owner of `(repo, ref, expected, new)`, independent of provenance.
pub const ORIGIN_CAS_INTENT_KEY_PREFIX: &[u8] = b"origin:cas_intent:v1:";

/// Advertisement family: `prefix ++ 16B repo_id ++ 0x00 ++ ref_name`.
///
/// Repo-scoped because two served repositories both carry `refs/heads/main`
/// and their advertisements are different facts.
pub const ORIGIN_VISIBLE_REF_KEY_PREFIX: &[u8] = b"origin:visible_ref:v1:";

/// Logical keep-owner family:
/// `prefix ++ 16B repo_id ++ 0x00 ++ oid ++ 0x00 ++ kind ++ 0x00 ++ owner_key`.
pub const ORIGIN_KEEP_OWNER_KEY_PREFIX: &[u8] = b"origin:keep_owner:v1:";

/// The pinned key vocabulary of the `repo.publication` claim value.
pub const ORIGIN_PUBLICATION_VALUE_KEYS: [&str; 10] = [
    "schema_version",
    "publication_id",
    "ref_name",
    "expected_old_oid",
    "new_oid",
    "provenance_claim_id",
    "required_objects",
    "required_lfs_oids",
    "actor_id",
    "created_at",
];

/// Domain separator for the deterministic publication id.
pub const ORIGIN_PUBLICATION_ID_DOMAIN: &[u8] = b"oneiron:origin-publication:v1";

/// Domain separator for the deterministic `repo.publication` claim id.
pub const ORIGIN_PUBLICATION_CLAIM_ID_DOMAIN: &[u8] = b"oneiron:origin-publication-claim:v1";

/// Domain separator for the commit-keyed subject anchor (RA5).
pub const ORIGIN_PUBLICATION_COMMIT_ID_DOMAIN: &[u8] = b"oneiron:origin-publication-commit:v1";

/// Longest bounded failure text a record may carry.
pub const ORIGIN_PUBLICATION_MAX_FAILURE_BYTES: usize = 512;

/// Largest required-object set one publication may name.
pub const ORIGIN_PUBLICATION_MAX_REQUIRED_OBJECTS: usize = 4096;

/// Largest number of journal rows a single scan will walk before refusing.
pub const ORIGIN_PUBLICATION_MAX_ROWS: usize = 100_000;

/// Field separator inside a composite key. Neither a ref name nor a lower-hex
/// object id can carry a NUL, so every field stays unambiguously framed.
const ORIGIN_KEY_SEPARATOR: u8 = 0;

// ---------------------------------------------------------------------------
// Protocol types
// ---------------------------------------------------------------------------

/// Where one publication stands. Deliberately its OWN axis: the queued
/// repo-mutation status is a different protocol with different crash windows,
/// and overloading it would make two lifecycles share one vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OriginPublicationStatus {
    /// A durable intent exists. The external ref effect may have happened.
    Prepared,
    /// The claim, the ref advance and the advertisement row all landed.
    Published,
    /// Bounded failure. The public ref is unchanged.
    Failed,
    /// A compare-and-swap found another writer's value. Never retried.
    Conflicted,
}

impl OriginPublicationStatus {
    /// The pinned on-disk spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Published => "published",
            Self::Failed => "failed",
            Self::Conflicted => "conflicted",
        }
    }

    /// Parses the pinned on-disk spelling.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "published" => Ok(Self::Published),
            "failed" => Ok(Self::Failed),
            "conflicted" => Ok(Self::Conflicted),
            _ => Err(Error::CorruptedIndex("origin publication status")),
        }
    }

    /// Whether no further transition is possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Prepared)
    }
}

/// Why an object is kept alive. One physical keep-ref, many logical owners:
/// the kinds exist so a publication releasing its own reason cannot unpin an
/// object another plane still needs (RA4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OriginKeepRefKind {
    /// A publication holds the object until its ref advance is proved.
    Publication,
    /// A change index entry references the object.
    Change,
    /// A conflict tree references the object.
    Conflict,
    /// A recovery pass is holding the object.
    Recovery,
    /// A snapshot references the object.
    Snapshot,
}

impl OriginKeepRefKind {
    /// Every kind, in the order the shared-count law walks them.
    pub const ALL: [Self; 5] = [
        Self::Publication,
        Self::Change,
        Self::Conflict,
        Self::Recovery,
        Self::Snapshot,
    ];

    /// The pinned on-disk spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Publication => "publication",
            Self::Change => "change",
            Self::Conflict => "conflict",
            Self::Recovery => "recovery",
            Self::Snapshot => "snapshot",
        }
    }

    /// Parses the pinned on-disk spelling.
    pub fn parse(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.as_str() == value)
            .ok_or(Error::CorruptedIndex("origin keep owner kind"))
    }
}

/// The one durable disposition a census gave one partial publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OriginCensusDisposition {
    /// The intent was replayed and the ref advanced.
    RetriedAndPublished,
    /// The ref was already at `new_oid`; the record was finalized without
    /// moving it again.
    FinalizedPublished,
    /// Bounded failure recorded; the public ref is unchanged.
    MarkedFailed,
    /// Another writer holds the ref; recorded and never retried.
    MarkedConflicted,
    /// Nothing to decide. Cleanup of an already-terminal row may still have
    /// run, because dropping a leaked owner is not a state change.
    NoChange,
}

impl OriginCensusDisposition {
    /// The pinned reporting spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RetriedAndPublished => "retried-and-published",
            Self::FinalizedPublished => "finalized-published",
            Self::MarkedFailed => "marked-failed",
            Self::MarkedConflicted => "marked-conflicted",
            Self::NoChange => "no-change",
        }
    }
}

/// One requested publication: a ref advance plus everything that must be
/// locally readable before it may become visible.
#[derive(Debug, Clone)]
pub struct OriginPublicationRequest {
    /// The repository this publication belongs to.
    pub repo_id: EntityId,
    /// The proven repository handle the ref advance runs against.
    pub repo: GitWireRepo,
    /// The full ref being advanced.
    pub ref_name: GitRefName,
    /// The value the advance was decided against; `None` means "must not
    /// exist yet".
    pub expected_old_oid: Option<GitOid>,
    /// The value the ref must carry afterwards.
    pub new_oid: GitOid,
    /// Git objects that must be present before the ref may be advertised.
    /// `new_oid` is always checked and need not be repeated here.
    pub required_objects: Vec<GitOid>,
    /// `(object id, declared size)` pairs that must be locally readable.
    pub required_lfs_oids: Vec<(LfsOid, u64)>,
    /// The durable provenance anchor this publication descends from.
    pub provenance_claim_id: EntityId,
    /// The authenticated principal behind the advance.
    pub actor_id: EntityId,
    /// Valid time of the publication.
    pub occurred: TimeRange,
    /// Transaction time of the publication.
    pub learned_at: u64,
}

/// The durable journal row for one publication.
///
/// It carries `repo_id` rather than a [`GitWireRepo`]: that handle exists only
/// as the result of a live correspondence proof and has no field constructor,
/// so it can be passed to a call but never restored from disk. The caller
/// supplies the proven handle; the row supplies the identity.
#[derive(Debug, Clone, PartialEq)]
pub struct OriginPublicationRecord {
    /// Deterministic id of this publication.
    pub publication_id: EntityId,
    /// The repository the publication belongs to.
    pub repo_id: EntityId,
    /// The full ref being advanced.
    pub ref_name: GitRefName,
    /// The value the advance was decided against.
    pub expected_old_oid: Option<GitOid>,
    /// The value the ref carries once published.
    pub new_oid: GitOid,
    /// Git objects required for visibility.
    pub required_objects: Vec<GitOid>,
    /// LFS `(object id, size)` pairs required for visibility.
    pub required_lfs_oids: Vec<(LfsOid, u64)>,
    /// The durable provenance anchor.
    pub provenance_claim_id: EntityId,
    /// The `repo.publication` claim, once it exists.
    pub publication_claim_id: Option<EntityId>,
    /// The authenticated principal behind the advance.
    pub actor_id: EntityId,
    /// Where the publication stands.
    pub status: OriginPublicationStatus,
    /// Bounded failure text, when the publication did not land.
    pub failure: Option<String>,
    /// Valid time carried into the claim, so a census can finalize it.
    pub occurred: TimeRange,
    /// When the intent became durable.
    pub created_at: u64,
    /// When the record reached a terminal state.
    pub finished_at: Option<u64>,
}

/// What one [`Vault::publish_origin_ref`] call decided.
#[derive(Debug, Clone, PartialEq)]
pub struct OriginPublicationReceipt {
    /// The durable record as it now stands.
    pub record: OriginPublicationRecord,
    /// The physical keep-ref this publication pinned its object with.
    pub physical_keep_ref: GitRefName,
    /// Whether the repository already carried `new_oid` before this call, so
    /// no ref had to move — a re-push, or a crash recovered after the CAS.
    pub ref_was_already_applied: bool,
    /// What the git wire said about the ref effect this call drove.
    ///
    /// `None` when no CAS was driven at all, which is only the terminally
    /// REFUSED record: a `Failed` or `Conflicted` publication is never retried,
    /// so re-asking for it re-drives nothing.
    ///
    /// A `Published` record whose live ref has since moved answers
    /// [`GitWireCommitOutcome::Rejected`] here while the record still reads
    /// `Published`, and both are true: the publication did land, and this
    /// re-drive of it was refused because the repository moved on. The
    /// advertisement projection already omits such a row.
    pub wire: Option<GitWireCommitOutcome>,
}

impl OriginPublicationReceipt {
    /// Whether the git wire answered from a durable record without re-running
    /// the effect.
    #[must_use]
    pub fn wire_replayed(&self) -> bool {
        self.wire
            .as_ref()
            .is_some_and(GitWireCommitOutcome::is_replayed)
    }

    /// Why the ref effect was refused, when it was.
    #[must_use]
    pub fn wire_rejection(&self) -> Option<GitWireRejection> {
        match &self.wire {
            Some(GitWireCommitOutcome::Rejected { reason, .. }) => Some(*reason),
            _ => None,
        }
    }
}

/// The honest recovery surface: one durable disposition per partial state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OriginCensusReport {
    /// Every publication the census looked at, and what it decided.
    pub items: Vec<(EntityId, OriginCensusDisposition)>,
}

impl OriginCensusReport {
    /// How many rows the census actually moved.
    #[must_use]
    pub fn changed(&self) -> usize {
        self.items
            .iter()
            .filter(|(_, disposition)| *disposition != OriginCensusDisposition::NoChange)
            .count()
    }
}

// ---------------------------------------------------------------------------
// Keys and rows
// ---------------------------------------------------------------------------

/// The physical keep-ref that pins one object.
///
/// The spelling follows the LANDED [`GIT_WIRE_KEEP_REF_PREFIX`] shape that
/// [`GitWire::write_keep_ref`] writes, because the physical root must be the
/// one GitWire owns rather than a second name meaning the same thing.
pub fn origin_keep_ref_name(oid: &GitOid) -> Result<GitRefName> {
    GitRefName::parse_full(format!("{GIT_WIRE_KEEP_REF_PREFIX}object/{}", oid.as_str()))
}

fn publication_key(publication_id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(ORIGIN_PUBLICATION_RECORD_KEY_PREFIX.len() + ENTITY_ID_LEN);
    key.extend_from_slice(ORIGIN_PUBLICATION_RECORD_KEY_PREFIX);
    key.extend_from_slice(publication_id.as_bytes());
    key
}

fn cas_intent_key(record: &OriginPublicationRecord) -> Vec<u8> {
    let mut key = ORIGIN_CAS_INTENT_KEY_PREFIX.to_vec();
    key.extend_from_slice(record.repo_id.as_bytes());
    for field in [
        record.ref_name.as_str(),
        record.expected_old_oid.as_ref().map_or("", GitOid::as_str),
        record.new_oid.as_str(),
    ] {
        key.push(ORIGIN_KEY_SEPARATOR);
        key.extend_from_slice(field.as_bytes());
    }
    key
}

fn visible_ref_prefix(repo_id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(ORIGIN_VISIBLE_REF_KEY_PREFIX.len() + ENTITY_ID_LEN + 1);
    key.extend_from_slice(ORIGIN_VISIBLE_REF_KEY_PREFIX);
    key.extend_from_slice(repo_id.as_bytes());
    key.push(ORIGIN_KEY_SEPARATOR);
    key
}

fn visible_ref_key(repo_id: &EntityId, ref_name: &GitRefName) -> Vec<u8> {
    let mut key = visible_ref_prefix(repo_id);
    key.extend_from_slice(ref_name.as_str().as_bytes());
    key
}

fn keep_owner_oid_prefix(repo_id: &EntityId, oid: &GitOid) -> Vec<u8> {
    let mut key = Vec::with_capacity(ORIGIN_KEEP_OWNER_KEY_PREFIX.len() + ENTITY_ID_LEN + 44);
    key.extend_from_slice(ORIGIN_KEEP_OWNER_KEY_PREFIX);
    key.extend_from_slice(repo_id.as_bytes());
    key.push(ORIGIN_KEY_SEPARATOR);
    key.extend_from_slice(oid.as_str().as_bytes());
    key.push(ORIGIN_KEY_SEPARATOR);
    key
}

fn keep_owner_key(
    repo_id: &EntityId,
    oid: &GitOid,
    kind: OriginKeepRefKind,
    owner_key: &str,
) -> Vec<u8> {
    let mut key = keep_owner_oid_prefix(repo_id, oid);
    key.extend_from_slice(kind.as_str().as_bytes());
    key.push(ORIGIN_KEY_SEPARATOR);
    key.extend_from_slice(owner_key.as_bytes());
    key
}

/// The wire shape of a publication journal row.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OriginPublicationRow {
    schema_version: u8,
    publication_id: [u8; ENTITY_ID_LEN],
    repo_id: [u8; ENTITY_ID_LEN],
    ref_name: String,
    expected_old_oid: Option<String>,
    new_oid: String,
    required_objects: Vec<String>,
    required_lfs_oids: Vec<(String, u64)>,
    provenance_claim_id: [u8; ENTITY_ID_LEN],
    publication_claim_id: Option<[u8; ENTITY_ID_LEN]>,
    actor_id: [u8; ENTITY_ID_LEN],
    status: String,
    failure: Option<String>,
    occurred_start: u64,
    occurred_end: u64,
    created_at: u64,
    finished_at: Option<u64>,
}

fn encode_publication_row(record: &OriginPublicationRecord) -> Result<Vec<u8>> {
    let row = OriginPublicationRow {
        schema_version: ORIGIN_PUBLICATION_SCHEMA_VERSION,
        publication_id: *record.publication_id.as_bytes(),
        repo_id: *record.repo_id.as_bytes(),
        ref_name: record.ref_name.as_str().to_owned(),
        expected_old_oid: record
            .expected_old_oid
            .as_ref()
            .map(|oid| oid.as_str().to_owned()),
        new_oid: record.new_oid.as_str().to_owned(),
        required_objects: record
            .required_objects
            .iter()
            .map(|oid| oid.as_str().to_owned())
            .collect(),
        required_lfs_oids: record
            .required_lfs_oids
            .iter()
            .map(|(oid, size)| (oid.to_hex(), *size))
            .collect(),
        provenance_claim_id: *record.provenance_claim_id.as_bytes(),
        publication_claim_id: record.publication_claim_id.map(|id| *id.as_bytes()),
        actor_id: *record.actor_id.as_bytes(),
        status: record.status.as_str().to_owned(),
        failure: record.failure.clone(),
        occurred_start: record.occurred.start,
        occurred_end: record.occurred.end,
        created_at: record.created_at,
        finished_at: record.finished_at,
    };
    rmp_serde::to_vec_named(&row)
        .map_err(|_| Error::InvariantViolation("origin publication row does not encode"))
}

fn decode_publication_row(raw: &[u8]) -> Result<OriginPublicationRecord> {
    let row: OriginPublicationRow =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("origin publication row"))?;
    if row.schema_version != ORIGIN_PUBLICATION_SCHEMA_VERSION {
        return Err(Error::CorruptedIndex("origin publication schema version"));
    }
    let mut required_objects = Vec::with_capacity(row.required_objects.len());
    for oid in row.required_objects {
        required_objects.push(GitOid::parse_hex(oid)?);
    }
    let mut required_lfs_oids = Vec::with_capacity(row.required_lfs_oids.len());
    for (oid, size) in row.required_lfs_oids {
        required_lfs_oids.push((LfsOid::parse_hex(&oid)?, size));
    }
    Ok(OriginPublicationRecord {
        publication_id: row_entity_id(row.publication_id)?,
        repo_id: row_entity_id(row.repo_id)?,
        ref_name: GitRefName::parse_full(row.ref_name)?,
        expected_old_oid: row.expected_old_oid.map(GitOid::parse_hex).transpose()?,
        new_oid: GitOid::parse_hex(row.new_oid)?,
        required_objects,
        required_lfs_oids,
        provenance_claim_id: row_entity_id(row.provenance_claim_id)?,
        publication_claim_id: row.publication_claim_id.map(row_entity_id).transpose()?,
        actor_id: row_entity_id(row.actor_id)?,
        status: OriginPublicationStatus::parse(&row.status)?,
        failure: row.failure,
        occurred: TimeRange {
            start: row.occurred_start,
            end: row.occurred_end,
        },
        created_at: row.created_at,
        finished_at: row.finished_at,
    })
}

fn row_entity_id(bytes: [u8; ENTITY_ID_LEN]) -> Result<EntityId> {
    EntityId::from_bytes(bytes).map_err(|_| Error::CorruptedIndex("origin publication entity id"))
}

/// Truncates failure text to the pinned bound on a character boundary.
fn bounded_failure(text: impl Into<String>) -> String {
    let mut text = text.into();
    if text.len() <= ORIGIN_PUBLICATION_MAX_FAILURE_BYTES {
        return text;
    }
    let mut cut = ORIGIN_PUBLICATION_MAX_FAILURE_BYTES;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    text
}

// ---------------------------------------------------------------------------
// Deterministic identities
// ---------------------------------------------------------------------------

/// The deterministic id of one publication.
///
/// Derived from everything that makes the advance the SAME advance, so an
/// identical replay addresses the identical row instead of minting a second
/// publication of one push.
pub fn origin_publication_id(request: &OriginPublicationRequest) -> Result<EntityId> {
    let expected = request.expected_old_oid.as_ref().map_or("", GitOid::as_str);
    entity_id_from_hash_material(
        ORIGIN_PUBLICATION_ID_DOMAIN,
        &[
            request.repo_id.as_bytes(),
            request.ref_name.as_str().as_bytes(),
            expected.as_bytes(),
            request.new_oid.as_str().as_bytes(),
            request.provenance_claim_id.as_bytes(),
        ],
    )
}

/// The deterministic id of the `repo.publication` claim one record asserts.
///
/// Deterministic on purpose: a census finalizing a crashed publication writes
/// the SAME claim id the first attempt would have, so "exactly one active
/// claim per publication" survives recovery.
pub fn origin_publication_claim_id(publication_id: &EntityId) -> Result<EntityId> {
    entity_id_from_hash_material(
        ORIGIN_PUBLICATION_CLAIM_ID_DOMAIN,
        &[publication_id.as_bytes()],
    )
}

/// The commit-keyed entity one publication's claim is anchored on (RA5).
pub fn origin_published_commit_id(oid: &GitOid) -> Result<EntityId> {
    entity_id_from_hash_material(
        ORIGIN_PUBLICATION_COMMIT_ID_DOMAIN,
        &[oid.as_str().as_bytes()],
    )
}

/// The claim body one successful publication asserts.
///
/// The subject is the commit-keyed EdgeRef `commit -PartOf-> repo`, which is
/// the RA5 anchor that needs no entity row to exist: a repository receiving its
/// first push has no durable entity yet, and a protocol that minted one would
/// be inventing an identity it does not own. `sensitivity: public` is stamped
/// because an advertised ref IS public repository metadata; leaving it
/// unstamped would read as band 2 at the write gate and refuse the push for a
/// reason that has nothing to do with publication.
fn publication_claim_body(record: &OriginPublicationRecord) -> Result<ClaimBody> {
    let mut body = ClaimBody::new(
        ORIGIN_PUBLICATION_PREDICATE,
        ClaimSubject::Edge {
            source: origin_published_commit_id(&record.new_oid)?,
            kind: EdgeKind::PartOf,
            target: record.repo_id,
        },
        publication_claim_value(record),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.scope = Some(Value::Map(vec![(
        Value::from("sensitivity"),
        Value::from("public"),
    )]));
    Ok(body)
}

fn publication_claim_value(record: &OriginPublicationRecord) -> Value {
    let expected = record
        .expected_old_oid
        .as_ref()
        .map_or(Value::Nil, |oid| Value::from(oid.as_str()));
    let objects = record
        .required_objects
        .iter()
        .map(|oid| Value::from(oid.as_str()))
        .collect::<Vec<_>>();
    let lfs = record
        .required_lfs_oids
        .iter()
        .map(|(oid, size)| Value::Array(vec![Value::from(oid.to_hex()), Value::from(*size)]))
        .collect::<Vec<_>>();
    let fields: [Value; 10] = [
        Value::from(u32::from(ORIGIN_PUBLICATION_SCHEMA_VERSION)),
        Value::from(record.publication_id.to_hex()),
        Value::from(record.ref_name.as_str()),
        expected,
        Value::from(record.new_oid.as_str()),
        Value::from(record.provenance_claim_id.to_hex()),
        Value::Array(objects),
        Value::Array(lfs),
        Value::from(record.actor_id.to_hex()),
        Value::from(record.created_at),
    ];
    Value::Map(
        ORIGIN_PUBLICATION_VALUE_KEYS
            .into_iter()
            .zip(fields)
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// The public protocol surface
// ---------------------------------------------------------------------------

impl Vault {
    /// Pins one git object behind a physical keep-ref and one logical owner.
    ///
    /// Crate-local inherent impl in the feature module: `vault.rs` is never
    /// edited to add a feature's entry points (the blob-artifact and vault-LFS
    /// precedent).
    ///
    /// The PHYSICAL root is written first and the LOGICAL owner second, so a
    /// crash between them leaves a keep-ref nobody claims — a safe leak the
    /// census removes. The other order would leave an owner row claiming a
    /// root that does not exist, and the object it thinks it is protecting
    /// could be collected out from under it.
    pub fn pin_origin_object(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        kind: OriginKeepRefKind,
        owner_key: &str,
        oid: &GitOid,
        learned_at: u64,
    ) -> Result<GitRefName> {
        // Hold the same coordinator as retirement until BOTH the physical
        // root and its logical owner exist. Otherwise a concurrent last-owner
        // release could delete the root between these two writes.
        let _guard = lock_repository(repo.common_dir())?;
        let name = origin_keep_ref_name(oid)?;
        let outcome = git.write_keep_ref(repo, oid, learned_at)?;
        if !outcome.is_applied() {
            return Err(Error::InvariantViolation(
                "origin keep-ref could not be written",
            ));
        }
        let repo_id = self.origin_repo_id_for(repo)?;
        let key = keep_owner_key(&repo_id, oid, kind, owner_key);
        self.with_write_txn(|wtxn| {
            self.store
                .vault_meta
                .put(wtxn, &key, &learned_at.to_le_bytes())?;
            Ok(())
        })?;
        Ok(name)
    }

    /// Releases one logical owner and, at zero owners, the physical root.
    ///
    /// The owner row goes first and the keep-ref second, for the same reason
    /// [`Vault::pin_origin_object`] writes them the other way round: an
    /// interrupted release leaves an unclaimed keep-ref, never a claim with no
    /// root. Deletion happens ONLY when no publication, change, conflict,
    /// recovery or snapshot owner still references the object.
    pub fn unpin_origin_object(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        kind: OriginKeepRefKind,
        owner_key: &str,
        oid: &GitOid,
        learned_at: u64,
    ) -> Result<()> {
        // Serialize owner removal, the zero-owner proof and physical deletion
        // with pinning, including callers outside the receive-pack door.
        let _guard = lock_repository(repo.common_dir())?;
        let repo_id = self.origin_repo_id_for(repo)?;
        let key = keep_owner_key(&repo_id, oid, kind, owner_key);
        self.with_write_txn(|wtxn| {
            self.store.vault_meta.delete(wtxn, &key)?;
            Ok(())
        })?;
        if self.origin_keep_owner_count(&repo_id, oid)? == 0
            && !git.delete_keep_ref(repo, oid, learned_at)?.is_applied()
        {
            return Err(Error::InvariantViolation(
                "origin keep-ref could not be deleted",
            ));
        }
        Ok(())
    }

    /// Runs the whole publication protocol for one ref advance.
    ///
    /// An identical replay is idempotent: the publication id is derived from
    /// the advance itself, so a second call addresses the same row and writes
    /// no second claim.
    ///
    /// Terminal refusals never retry. Published replay uses the original CAS
    /// expectation and proves the live ref again before reporting success.
    pub fn publish_origin_ref(
        &self,
        git: &GitWire<'_>,
        request: OriginPublicationRequest,
    ) -> Result<OriginPublicationReceipt> {
        validate_origin_publication_request(&request)?;
        self.validate_origin_repo(request.repo_id, &request.repo)?;
        let _guard = lock_repository(request.repo.common_dir())?;
        let publication_id = origin_publication_id(&request)?;
        let existing = self.origin_publication(publication_id)?;
        if existing.as_ref().is_some_and(|record| {
            record.repo_id != request.repo_id
                || record.actor_id != request.actor_id
                || record.required_objects != request.required_objects
                || record.required_lfs_oids != request.required_lfs_oids
        }) {
            return Err(Error::InvariantViolation(
                "origin publication replay changed its availability or attribution",
            ));
        }
        let record = match existing {
            Some(record) if record.status == OriginPublicationStatus::Published => {
                return self.redrive_published_origin_ref(
                    git,
                    &request.repo,
                    record,
                    request.learned_at,
                );
            }
            Some(record) if record.status.is_terminal() => {
                return origin_receipt(record, false, None);
            }
            Some(record) => record,
            None => self.stage_origin_publication(git, &request, publication_id)?,
        };
        if record.status.is_terminal() {
            return origin_receipt(record, false, None);
        }
        let advance = self.advance_prepared_origin_publication(
            git,
            &request.repo,
            record,
            request.learned_at,
        )?;
        if advance.record.status == OriginPublicationStatus::Prepared {
            return Err(Error::ConcurrentWrite(
                "origin publication awaits readable objects",
            ));
        }
        origin_receipt(advance.record, advance.already_applied, advance.wire)
    }

    /// The post-crash census: exactly one durable disposition per partial
    /// state, and a leak sweep for the rows that already reached a terminal
    /// one.
    pub fn reconcile_origin_publications(
        &self,
        git: &GitWire<'_>,
        repo_id: EntityId,
        repo: &GitWireRepo,
        learned_at: u64,
    ) -> Result<OriginCensusReport> {
        self.validate_origin_repo(repo_id, repo)?;
        let _guard = lock_repository(repo.common_dir())?;
        let mut items = Vec::new();
        for record in self.origin_publication_rows(Some(repo_id))? {
            let publication_id = record.publication_id;
            let disposition = if record.status == OriginPublicationStatus::Prepared {
                self.advance_prepared_origin_publication(git, repo, record, learned_at)?
                    .disposition
            } else {
                // Terminal already. The only thing left to do is the leak
                // sweep, and sweeping is not a state change.
                self.release_origin_publication_pin(git, repo, &record, learned_at)?;
                OriginCensusDisposition::NoChange
            };
            items.push((publication_id, disposition));
        }
        self.sweep_orphan_origin_publication_owners(git, repo_id, repo, learned_at)?;
        Ok(OriginCensusReport { items })
    }

    /// The durable record for one publication id.
    pub fn origin_publication(
        &self,
        publication_id: EntityId,
    ) -> Result<Option<OriginPublicationRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self
            .store
            .vault_meta
            .get(&rtxn, &publication_key(&publication_id))?
        else {
            return Ok(None);
        };
        decode_publication_row(&raw).map(Some)
    }

    /// Lists durable publication ids for read-only diagnostics, in every status.
    ///
    /// `None` includes every repository. The scan refuses after
    /// [`ORIGIN_PUBLICATION_MAX_ROWS`] rows rather than returning a partial list.
    /// Use [`Vault::origin_publication`] to inspect a record. This list is not
    /// advertisement authority; only [`Vault::published_origin_refs`] proves
    /// that a ref may be served.
    pub fn origin_publication_ids(&self, repo_id: Option<EntityId>) -> Result<Vec<EntityId>> {
        Ok(self
            .origin_publication_rows(repo_id)?
            .into_iter()
            .map(|record| record.publication_id)
            .collect())
    }

    /// THE advertisement projection, and the only one.
    ///
    /// A row survives here when its publication is `Published` AND the
    /// repository's live ref still carries exactly `new_oid`. Raw repository
    /// refs are never consulted as an authority: they are consulted only to
    /// DISPROVE a row this journal already claims. That asymmetry is the whole
    /// invariant — an unpublished ref cannot appear by existing, and a
    /// published one disappears the moment the repository disagrees.
    pub fn published_origin_refs(
        &self,
        git: &GitWire<'_>,
        repo_id: EntityId,
        repo: &GitWireRepo,
    ) -> Result<Vec<(GitRefName, GitOid)>> {
        self.validate_origin_repo(repo_id, repo)?;
        let _guard = lock_repository(repo.common_dir())?;
        let mut advertised = Vec::new();
        for publication_id in self.origin_visible_ref_rows(&repo_id)? {
            let Some(record) = self.origin_publication(publication_id)? else {
                continue;
            };
            if record.repo_id != repo_id || record.status != OriginPublicationStatus::Published {
                continue;
            }
            if git.read_ref(repo, &record.ref_name)?.as_ref() != Some(&record.new_oid)
                || self
                    .origin_availability_failure(git, repo, &record)?
                    .is_some()
            {
                continue;
            }
            advertised.push((record.ref_name, record.new_oid));
        }
        advertised.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(advertised)
    }

    /// How many publications for one repository are still `Prepared`.
    pub fn prepared_origin_publication_count(&self, repo_id: EntityId) -> Result<u64> {
        let prepared = self
            .origin_publication_rows(Some(repo_id))?
            .into_iter()
            .filter(|record| record.status == OriginPublicationStatus::Prepared)
            .count();
        u64::try_from(prepared)
            .map_err(|_| Error::ArithmeticOverflow("prepared origin publication count"))
    }
}

// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

impl Vault {
    /// Exposes the real Prepared boundary to the sibling smart-HTTP crash test.
    #[cfg(test)]
    pub(super) fn prepare_origin_publication_for_test(
        &self,
        git: &GitWire<'_>,
        request: &OriginPublicationRequest,
    ) -> Result<OriginPublicationRecord> {
        validate_origin_publication_request(request)?;
        self.validate_origin_repo(request.repo_id, &request.repo)?;
        let _guard = lock_repository(request.repo.common_dir())?;
        let publication_id = origin_publication_id(request)?;
        self.stage_origin_publication(git, request, publication_id)
    }

    /// Stages the objects and makes the intent durable. No public ref moves.
    fn stage_origin_publication(
        &self,
        git: &GitWire<'_>,
        request: &OriginPublicationRequest,
        publication_id: EntityId,
    ) -> Result<OriginPublicationRecord> {
        let _guard = lock_repository(request.repo.common_dir())?;
        let provenance =
            self.get_claim(&request.provenance_claim_id)?
                .ok_or(Error::InvariantViolation(
                    "origin publication requires a durable provenance claim",
                ))?;
        if provenance.lifecycle != ClaimLifecycleStatus::Active
            || provenance.predicate == ORIGIN_PUBLICATION_PREDICATE
        {
            return Err(Error::InvariantViolation(
                "origin publication provenance is not an active source claim",
            ));
        }
        if provenance.predicate == super::smart_http::RECEIVE_PACK_ADMISSION_PREDICATE {
            return Err(Error::InvariantViolation(
                "receive-pack admission alone is not outcome evidence",
            ));
        }
        if provenance.predicate == super::smart_http::RECEIVE_PACK_OUTCOME_PREDICATE
            || self.has_receive_pack_evidence(request.provenance_claim_id)?
        {
            self.validate_receive_pack_publication(request)?;
        }
        let record = OriginPublicationRecord {
            publication_id,
            repo_id: request.repo_id,
            ref_name: request.ref_name.clone(),
            expected_old_oid: request.expected_old_oid.clone(),
            new_oid: request.new_oid.clone(),
            required_objects: request.required_objects.clone(),
            required_lfs_oids: request.required_lfs_oids.clone(),
            provenance_claim_id: request.provenance_claim_id,
            publication_claim_id: None,
            actor_id: request.actor_id,
            status: OriginPublicationStatus::Prepared,
            failure: None,
            occurred: request.occurred,
            created_at: request.learned_at,
            finished_at: None,
        };
        // Reconcile a colliding owner before creating anything for this caller.
        // Completed Published rows retain the consumed triple after T2 removes
        // the in-flight index. A different provenance is not a second effect.
        let intent_key = cas_intent_key(&record);
        let owner = {
            let rtxn = self.store.env.read_txn()?;
            self.store
                .vault_meta
                .get(&rtxn, &intent_key)?
                .map(|raw| {
                    let bytes = raw
                        .as_ref()
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("origin CAS intent owner"))?;
                    row_entity_id(bytes)
                })
                .transpose()?
        };
        if let Some(owner) = owner {
            let previous = self
                .origin_publication(owner)?
                .ok_or(Error::CorruptedIndex(
                    "origin CAS intent has no publication",
                ))?;
            if previous.status == OriginPublicationStatus::Prepared {
                self.advance_prepared_origin_publication(
                    git,
                    &request.repo,
                    previous,
                    request.learned_at,
                )?;
            }
            if self.origin_publication(owner)?.is_some_and(|row| {
                matches!(
                    row.status,
                    OriginPublicationStatus::Prepared | OriginPublicationStatus::Published
                )
            }) {
                return Err(Error::ConcurrentWrite("origin CAS intent already owned"));
            }
        }
        if self
            .origin_publication_rows(Some(record.repo_id))?
            .iter()
            .any(|row| {
                row.publication_id != publication_id
                    && row.status == OriginPublicationStatus::Published
                    && cas_intent_key(row) == intent_key
            })
        {
            return Err(Error::ConcurrentWrite(
                "origin CAS intent already published",
            ));
        }
        // A missing tip cannot be pinned. Still commit an intent, then refuse
        // through the same terminal transaction as every other missing object.
        if git.reachable_objects_present(&request.repo, &request.new_oid, &[])? {
            self.pin_origin_object(
                git,
                &request.repo,
                OriginKeepRefKind::Publication,
                &publication_id.to_hex(),
                &request.new_oid,
                request.learned_at,
            )?;
        }
        let key = publication_key(&publication_id);
        let row = encode_publication_row(&record)?;
        self.with_write_txn(|wtxn| {
            if self.store.vault_meta.get(wtxn, &intent_key)?.is_some()
                || self.store.vault_meta.get(wtxn, &key)?.is_some()
            {
                return Err(Error::ConcurrentWrite("origin CAS intent already owned"));
            }
            self.store
                .vault_meta
                .put(wtxn, &intent_key, publication_id.as_bytes())?;
            self.store.vault_meta.put(wtxn, &key, &row)?;
            Ok(())
        })?;
        Ok(record)
    }

    /// Drives one `Prepared` record to a terminal state.
    ///
    /// This is the SAME path a first attempt and a census recovery take, which
    /// is what makes "every crash window has exactly one disposition" true
    /// rather than aspirational: there is no second implementation that could
    /// decide differently.
    fn advance_prepared_origin_publication(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        record: OriginPublicationRecord,
        learned_at: u64,
    ) -> Result<OriginAdvance> {
        let _guard = lock_repository(repo.common_dir())?;
        let record = self
            .origin_publication(record.publication_id)?
            .ok_or(Error::CorruptedIndex("origin publication disappeared"))?;
        if record.status.is_terminal() {
            return Ok(OriginAdvance {
                record,
                already_applied: true,
                wire: None,
                disposition: OriginCensusDisposition::NoChange,
            });
        }
        let live = git.read_ref(repo, &record.ref_name)?;
        let already_applied = live.as_ref() == Some(&record.new_oid);
        if !already_applied && live != record.expected_old_oid {
            return self.refuse_origin_publication(
                git,
                repo,
                record,
                OriginPublicationStatus::Conflicted,
                "live ref no longer equals the expected value",
                learned_at,
            );
        }
        if let Some(failure) = self.origin_availability_failure(git, repo, &record)? {
            if already_applied {
                // The effect may have happened. Missing bytes cannot prove it
                // failed; retain intent and protection, and do not advertise.
                return Ok(OriginAdvance {
                    record,
                    already_applied,
                    wire: None,
                    disposition: OriginCensusDisposition::NoChange,
                });
            }
            return self.refuse_origin_publication(
                git,
                repo,
                record,
                OriginPublicationStatus::Failed,
                &failure,
                learned_at,
            );
        }
        self.compare_and_swap_origin_ref(git, repo, record, already_applied, learned_at)
    }

    /// The one ref advance, and the one place a conflict is decided.
    fn compare_and_swap_origin_ref(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        record: OriginPublicationRecord,
        already_applied: bool,
        learned_at: u64,
    ) -> Result<OriginAdvance> {
        let outcome = git.update_ref_cas(
            repo,
            &record.ref_name,
            record.expected_old_oid.as_ref(),
            &record.new_oid,
            learned_at,
        )?;
        self.finish_origin_cas_outcome(git, repo, record, already_applied, learned_at, outcome)
    }

    /// The effect is external. A receipt is not a substitute for the live-ref
    /// proof, including when GitWire answered from its own durable journal.
    fn finish_origin_cas_outcome(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        record: OriginPublicationRecord,
        already_applied: bool,
        learned_at: u64,
        outcome: GitWireCommitOutcome,
    ) -> Result<OriginAdvance> {
        let _guard = lock_repository(repo.common_dir())?;
        // A moved ref is another writer, and another writer is a conflict.
        // Retrying it is exactly how the second writer would clobber the first,
        // so neither arm below ever loops.
        if let GitWireCommitOutcome::Rejected { reason, .. } = outcome {
            let (status, failure) = match reason {
                GitWireRejection::RefMoved => (
                    OriginPublicationStatus::Conflicted,
                    "compare-and-swap found a value on the ref that nobody decided against"
                        .to_owned(),
                ),
                GitWireRejection::ObjectsUnavailable => (
                    OriginPublicationStatus::Failed,
                    "the git wire found required objects unavailable".to_owned(),
                ),
                GitWireRejection::EffectUnconfirmed => {
                    return Err(Error::ConcurrentWrite("origin CAS effect is uncertain"));
                }
            };
            let mut refused =
                self.refuse_origin_publication(git, repo, record, status, &failure, learned_at)?;
            refused.wire = Some(outcome);
            return Ok(refused);
        }
        // Never certify a sticky or stale GitWire receipt as live evidence.
        if git.read_ref(repo, &record.ref_name)?.as_ref() != Some(&record.new_oid) {
            return Err(Error::ConcurrentWrite(
                "origin CAS live-ref proof is uncertain",
            ));
        }
        let record = self.finalize_origin_publication(record, learned_at)?;
        // Publication is already durable. Cleanup failure is a safe leak for
        // census, not a reason to report a landed ref as a rejected push.
        let _ = self.release_origin_publication_pin(git, repo, &record, learned_at);
        Ok(OriginAdvance {
            record,
            already_applied,
            wire: Some(outcome),
            disposition: if already_applied {
                OriginCensusDisposition::FinalizedPublished
            } else {
                OriginCensusDisposition::RetriedAndPublished
            },
        })
    }

    /// Re-drives the ref effect of an already-`Published` publication.
    ///
    /// The record is not restated — it is already durable and already true.
    /// What runs again is the git wire's own journaled effect, which replays
    /// when the repository agrees, rolls a crash-interrupted advance forward
    /// when it is merely behind, and refuses when the repository carries a
    /// value nobody decided against.
    fn redrive_published_origin_ref(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        record: OriginPublicationRecord,
        learned_at: u64,
    ) -> Result<OriginPublicationReceipt> {
        let already_applied =
            git.read_ref(repo, &record.ref_name)?.as_ref() == Some(&record.new_oid);
        if self
            .origin_availability_failure(git, repo, &record)?
            .is_some()
        {
            return Err(Error::InvariantViolation(
                "published origin ref no longer has its required objects",
            ));
        }
        let outcome = git.update_ref_cas(
            repo,
            &record.ref_name,
            record.expected_old_oid.as_ref(),
            &record.new_oid,
            learned_at,
        )?;
        if outcome.is_applied()
            && git.read_ref(repo, &record.ref_name)?.as_ref() != Some(&record.new_oid)
        {
            return Err(Error::ConcurrentWrite(
                "origin replay live-ref proof is uncertain",
            ));
        }
        if outcome.is_applied() {
            // Both a fresh advance and a replay can finish leaked cleanup.
            // Failure here keeps a safe root for census; it does not undo the
            // already-durable publication or reject a successful landing.
            let _ = self.release_origin_publication_pin(git, repo, &record, learned_at);
        }
        if matches!(
            outcome,
            GitWireCommitOutcome::Rejected {
                reason: GitWireRejection::EffectUnconfirmed,
                ..
            }
        ) {
            return Err(Error::ConcurrentWrite("origin replay effect is uncertain"));
        }
        origin_receipt(record, already_applied, Some(outcome))
    }

    /// The finalize transaction: the claim, the `Published` mark and the
    /// advertisement row are ONE atomic write or none of them.
    fn finalize_origin_publication(
        &self,
        record: OriginPublicationRecord,
        learned_at: u64,
    ) -> Result<OriginPublicationRecord> {
        let claim_id = origin_publication_claim_id(&record.publication_id)?;
        let mut published = record;
        published.status = OriginPublicationStatus::Published;
        published.publication_claim_id = Some(claim_id);
        published.failure = None;
        published.finished_at = Some(learned_at);
        self.finish_origin_publication(published, learned_at)
    }

    /// T2: read-check-write using only this transaction. No external calls.
    fn finish_origin_publication(
        &self,
        terminal: OriginPublicationRecord,
        learned_at: u64,
    ) -> Result<OriginPublicationRecord> {
        if !terminal.status.is_terminal() {
            return Err(Error::InvariantViolation(
                "origin finalize requires a terminal state",
            ));
        }
        let record_key = publication_key(&terminal.publication_id);
        let intent_key = cas_intent_key(&terminal);
        let owner_key = keep_owner_key(
            &terminal.repo_id,
            &terminal.new_oid,
            OriginKeepRefKind::Publication,
            &terminal.publication_id.to_hex(),
        );
        self.with_write_txn(|wtxn| {
            let raw = self
                .store
                .vault_meta
                .get(wtxn, &record_key)?
                .ok_or(Error::CorruptedIndex("origin finalize has no prepared row"))?;
            let current = decode_publication_row(&raw)?;
            if current.status.is_terminal() {
                if current.status == terminal.status {
                    return Ok(current);
                }
                return Err(Error::InvariantViolation(
                    "origin finalize cannot overwrite terminal state",
                ));
            }
            let mut expected = terminal.clone();
            expected.status = current.status;
            expected.publication_claim_id = current.publication_claim_id;
            expected.failure = current.failure.clone();
            expected.finished_at = current.finished_at;
            if expected != current {
                return Err(Error::InvariantViolation(
                    "origin finalize changed prepared intent",
                ));
            }
            let owner = self
                .store
                .vault_meta
                .get(wtxn, &intent_key)?
                .ok_or(Error::CorruptedIndex("origin finalize has no CAS intent"))?;
            if owner.as_ref() != terminal.publication_id.as_bytes() {
                return Err(Error::InvariantViolation(
                    "origin finalize does not own CAS intent",
                ));
            }
            if terminal.status == OriginPublicationStatus::Published {
                let claim_id = terminal
                    .publication_claim_id
                    .ok_or(Error::InvariantViolation(
                        "origin publication has no claim id",
                    ))?;
                let body = publication_claim_body(&terminal)?;
                self.put_claim_in_txn(wtxn, &claim_id, &body, terminal.occurred, learned_at)?;
                self.store.vault_meta.put(
                    wtxn,
                    &visible_ref_key(&terminal.repo_id, &terminal.ref_name),
                    terminal.publication_id.as_bytes(),
                )?;
            }
            self.store
                .vault_meta
                .put(wtxn, &record_key, &encode_publication_row(&terminal)?)?;
            self.store.vault_meta.delete(wtxn, &intent_key)?;
            self.store.vault_meta.delete(wtxn, &owner_key)?;
            Ok(terminal)
        })
    }

    /// Records a bounded refusal. The public ref is left exactly as it was.
    fn refuse_origin_publication(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        record: OriginPublicationRecord,
        status: OriginPublicationStatus,
        failure: &str,
        learned_at: u64,
    ) -> Result<OriginAdvance> {
        let mut refused = record;
        refused.status = status;
        refused.failure = Some(bounded_failure(failure));
        refused.finished_at = Some(learned_at);
        let refused = self.finish_origin_publication(refused, learned_at)?;
        // A terminal refusal remains a refusal even if physical cleanup leaks.
        let _ = self.release_origin_publication_pin(git, repo, &refused, learned_at);
        Ok(OriginAdvance {
            record: refused,
            already_applied: false,
            wire: None,
            disposition: if status == OriginPublicationStatus::Conflicted {
                OriginCensusDisposition::MarkedConflicted
            } else {
                OriginCensusDisposition::MarkedFailed
            },
        })
    }

    /// Why this publication may not become visible, or `None` when it may.
    ///
    /// The tip is proved WHOLE, not merely present: a commit whose tree or
    /// parent is missing is a head that fails checkout, which is the one
    /// outcome the advertisement invariant forbids. Historical publications are
    /// not exclusions: object loss or corruption can invalidate an older proof.
    fn origin_availability_failure(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        record: &OriginPublicationRecord,
    ) -> Result<Option<String>> {
        // A past publication is not evidence that its objects are still
        // readable. Walk the whole graph, including on replay and advertisement.
        if !git.reachable_objects_present(repo, &record.new_oid, &[])? {
            return Ok(Some(format!(
                "the object graph reachable from {} is not whole in this object store",
                record.new_oid.as_str()
            )));
        }
        for oid in &record.required_objects {
            if !git.object_exists(repo, oid)? {
                return Ok(Some(format!(
                    "required git object {} is not present in this object store",
                    oid.as_str()
                )));
            }
        }
        for (oid, size) in &record.required_lfs_oids {
            if !self.has_lfs_object(*oid, *size)? {
                return Ok(Some(format!(
                    "required lfs object {} at {size} bytes is not stored in this vault",
                    oid.to_hex()
                )));
            }
            match self.verify_lfs_object(*oid, *size) {
                Ok(true) => {}
                Ok(false) | Err(Error::CorruptedIndex(_)) => {
                    return Ok(Some(format!(
                        "required lfs object {} is not locally readable at {size} bytes",
                        oid.to_hex()
                    )));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    /// T2 already removed the logical owner. Retry physical retirement after
    /// commit, under the same coordinator used by pinning. Never delete a root
    /// while another logical owner exists.
    fn release_origin_publication_pin(
        &self,
        git: &GitWire<'_>,
        repo: &GitWireRepo,
        record: &OriginPublicationRecord,
        learned_at: u64,
    ) -> Result<()> {
        if record.status == OriginPublicationStatus::Prepared {
            return Ok(());
        }
        self.unpin_origin_object(
            git,
            repo,
            OriginKeepRefKind::Publication,
            &record.publication_id.to_hex(),
            &record.new_oid,
            learned_at,
        )
    }

    /// A crash after pinning but before T1 has an owner but no journal row.
    /// The coordinator spans both stage operations, so a missing row cannot
    /// belong to a live runner paused between pinning and T1.
    fn sweep_orphan_origin_publication_owners(
        &self,
        git: &GitWire<'_>,
        repo_id: EntityId,
        repo: &GitWireRepo,
        learned_at: u64,
    ) -> Result<()> {
        let _guard = lock_repository(repo.common_dir())?;
        let mut prefix = ORIGIN_KEEP_OWNER_KEY_PREFIX.to_vec();
        prefix.extend_from_slice(repo_id.as_bytes());
        prefix.push(ORIGIN_KEY_SEPARATOR);
        let owners = {
            let rtxn = self.store.env.read_txn()?;
            let mut owners = Vec::new();
            for (index, entry) in self
                .store
                .vault_meta
                .prefix_iter(&rtxn, &prefix)?
                .enumerate()
            {
                if index >= ORIGIN_PUBLICATION_MAX_ROWS {
                    return Err(Error::IndexOverflow("origin keep owner rows"));
                }
                let (key, _) = entry?;
                let suffix = std::str::from_utf8(&key[prefix.len()..])
                    .map_err(|_| Error::CorruptedIndex("origin keep owner key"))?;
                let fields = suffix.splitn(3, '\0').collect::<Vec<_>>();
                if fields.len() != 3 || fields[1] != OriginKeepRefKind::Publication.as_str() {
                    continue;
                }
                // Only publication-id owners belong to this journal. Other
                // callers of the general pin door keep their own owner keys.
                let Ok(id) = EntityId::from_hex(fields[2]) else {
                    continue;
                };
                if self
                    .store
                    .vault_meta
                    .get(&rtxn, &publication_key(&id))?
                    .is_none()
                {
                    owners.push((GitOid::parse_hex(fields[0])?, fields[2].to_owned()));
                }
            }
            owners
        };
        for (oid, owner) in owners {
            self.unpin_origin_object(
                git,
                repo,
                OriginKeepRefKind::Publication,
                &owner,
                &oid,
                learned_at,
            )?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Journal access
// ---------------------------------------------------------------------------

impl Vault {
    /// The repository identity publication rows are scoped to.
    ///
    /// The same derivation the LFS attachment plane already uses, so one served
    /// repository has ONE repo id across both origin planes.
    fn origin_repo_id_for(&self, repo: &GitWireRepo) -> Result<EntityId> {
        crate::origin::lfs::lfs_repo_id(&repo.identity().as_hex())
    }

    fn validate_origin_repo(&self, repo_id: EntityId, repo: &GitWireRepo) -> Result<()> {
        if self.origin_repo_id_for(repo)? != repo_id {
            return Err(Error::InvariantViolation(
                "origin publication repository identity does not match its handle",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn put_origin_publication_record(&self, record: &OriginPublicationRecord) -> Result<()> {
        let key = publication_key(&record.publication_id);
        let row = encode_publication_row(record)?;
        self.with_write_txn(|wtxn| {
            self.store.vault_meta.put(wtxn, &key, &row)?;
            Ok(())
        })
    }

    pub(crate) fn origin_publication_rows(
        &self,
        repo_id: Option<EntityId>,
    ) -> Result<Vec<OriginPublicationRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        let mut seen = 0_usize;
        for entry in self
            .store
            .vault_meta
            .prefix_iter(&rtxn, ORIGIN_PUBLICATION_RECORD_KEY_PREFIX)?
        {
            seen += 1;
            if seen > ORIGIN_PUBLICATION_MAX_ROWS {
                return Err(Error::IndexOverflow("origin publication rows"));
            }
            let (_, raw) = entry?;
            let record = decode_publication_row(&raw)?;
            if repo_id.is_none_or(|scope| scope == record.repo_id) {
                rows.push(record);
            }
        }
        Ok(rows)
    }

    fn origin_visible_ref_rows(&self, repo_id: &EntityId) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let prefix = visible_ref_prefix(repo_id);
        let mut rows = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
            if rows.len() >= ORIGIN_PUBLICATION_MAX_ROWS {
                return Err(Error::IndexOverflow("origin visible ref rows"));
            }
            let (_, raw) = entry?;
            let bytes: [u8; ENTITY_ID_LEN] = raw
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("origin visible ref row"))?;
            rows.push(row_entity_id(bytes)?);
        }
        Ok(rows)
    }

    /// Whether this repository's publication protocol has ever published this
    /// ref name.
    ///
    /// An O(1) ownership read, not an alternative advertisement authority.
    /// A missing row does not permit serving a raw ref. Even an owned ref must
    /// also survive [`Vault::published_origin_refs`] before it is advertised.
    pub(crate) fn origin_publication_manages_ref(
        &self,
        repo_id: EntityId,
        ref_name: &GitRefName,
    ) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        let key = visible_ref_key(&repo_id, ref_name);
        Ok(self.store.vault_meta.get(&rtxn, &key)?.is_some())
    }

    /// How many logical owners still reference one object in one repository.
    fn origin_keep_owner_count(&self, repo_id: &EntityId, oid: &GitOid) -> Result<u64> {
        let rtxn = self.store.env.read_txn()?;
        let prefix = keep_owner_oid_prefix(repo_id, oid);
        let mut count = 0_u64;
        for entry in self.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
            entry?;
            count = count.saturating_add(1);
        }
        Ok(count)
    }
}

/// What one drive of the state machine did.
struct OriginAdvance {
    record: OriginPublicationRecord,
    already_applied: bool,
    wire: Option<GitWireCommitOutcome>,
    disposition: OriginCensusDisposition,
}

fn origin_receipt(
    record: OriginPublicationRecord,
    ref_was_already_applied: bool,
    wire: Option<GitWireCommitOutcome>,
) -> Result<OriginPublicationReceipt> {
    Ok(OriginPublicationReceipt {
        physical_keep_ref: origin_keep_ref_name(&record.new_oid)?,
        record,
        ref_was_already_applied,
        wire,
    })
}

/// Refuses a request the protocol must never turn into a durable row.
fn validate_origin_publication_request(request: &OriginPublicationRequest) -> Result<()> {
    if request
        .ref_name
        .as_str()
        .starts_with(GIT_WIRE_KEEP_REF_PREFIX)
    {
        return Err(Error::InvariantViolation(
            "origin publication must not publish into the keep-ref namespace",
        ));
    }
    if request.required_objects.len() > ORIGIN_PUBLICATION_MAX_REQUIRED_OBJECTS
        || request.required_lfs_oids.len() > ORIGIN_PUBLICATION_MAX_REQUIRED_OBJECTS
    {
        return Err(Error::InvariantViolation(
            "origin publication requires an unbounded object set",
        ));
    }
    if request.occurred.end < request.occurred.start {
        return Err(Error::InvariantViolation(
            "origin publication occurred range is inverted",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codebase::RepoRef;
    use crate::test_util::{embedding_test_config, open_test_vault_with};
    use std::path::{Path, PathBuf};
    use std::process::Command as StdCommand;

    const LEARNED_AT: u64 = 1_700_000_000;

    fn occurred() -> TimeRange {
        TimeRange {
            start: LEARNED_AT,
            end: LEARNED_AT,
        }
    }

    fn test_vault() -> (tempfile::TempDir, Vault) {
        open_test_vault_with(embedding_test_config())
    }

    fn git(repo: &Path, args: &[&str]) -> String {
        let output = StdCommand::new("git")
            .current_dir(repo)
            .args(args)
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn commit(root: &Path, message: &str, body: &str) -> GitOid {
        std::fs::write(root.join("README.md"), body).expect("write readme");
        git(root, &["add", "--", "README.md"]);
        git(
            root,
            &[
                "-c",
                "user.name=Oneiron",
                "-c",
                "user.email=oneiron@example.invalid",
                "commit",
                "-m",
                message,
            ],
        );
        GitOid::parse_hex(git(root, &["rev-parse", "--verify", "HEAD"])).expect("head oid")
    }

    /// A repository with one commit on `refs/heads/main`.
    fn seeded_repo() -> (tempfile::TempDir, PathBuf, GitOid) {
        let dir = tempfile::tempdir().expect("repo tempdir");
        let root = dir.path().canonicalize().expect("canonical repo root");
        git(&root, &["init", "--initial-branch=main"]);
        let head = commit(&root, "initial", "base\n");
        (dir, root, head)
    }

    fn open_repo(wire: &GitWire<'_>, root: &Path, pin: &GitOid) -> GitWireRepo {
        let path = root.to_str().expect("utf-8 repo path");
        let repo_ref = RepoRef::parse(&format!("local:{path}#{}", pin.as_str())).expect("repo ref");
        wire.open_repo(repo_ref, root).expect("open repo")
    }

    fn main_ref() -> GitRefName {
        GitRefName::parse_full("refs/heads/main").expect("ref name")
    }

    fn fixture_provenance(vault: &Vault, repo_id: EntityId) -> EntityId {
        let id = EntityId::now();
        let mut body = ClaimBody::new(
            "test.publication_source",
            ClaimSubject::Edge {
                source: id,
                kind: EdgeKind::PartOf,
                target: repo_id,
            },
            Value::from("test fixture source, not authentication evidence"),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.scope = Some(Value::Map(vec![(
            Value::from("sensitivity"),
            Value::from("public"),
        )]));
        vault
            .put_claim(&id, &body, occurred(), LEARNED_AT)
            .expect("durable fixture provenance");
        id
    }

    fn request(
        vault: &Vault,
        repo: &GitWireRepo,
        repo_id: EntityId,
        expected_old_oid: Option<GitOid>,
        new_oid: GitOid,
    ) -> OriginPublicationRequest {
        OriginPublicationRequest {
            repo_id,
            repo: repo.clone(),
            ref_name: main_ref(),
            expected_old_oid,
            new_oid,
            required_objects: Vec::new(),
            required_lfs_oids: Vec::new(),
            provenance_claim_id: fixture_provenance(vault, repo_id),
            actor_id: EntityId::now(),
            occurred: occurred(),
            learned_at: LEARNED_AT,
        }
    }

    /// The repo id the protocol itself derives, so a fixture and the code
    /// under test always agree about which repository a row belongs to.
    fn repo_id_of(vault: &Vault, repo: &GitWireRepo) -> EntityId {
        vault.origin_repo_id_for(repo).expect("repo id")
    }

    /// Rewinds `refs/heads/main` behind the protocol's back, which is what a
    /// crash before the CAS looks like from the journal's point of view.
    fn force_ref(root: &Path, oid: &GitOid) {
        git(root, &["update-ref", "refs/heads/main", oid.as_str()]);
    }

    #[test]
    fn publication_happy_path_single_claim_single_ref_advance() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "second", "second\n");
        force_ref(&root, &base);

        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let wrong_repo_id = EntityId::now();
        assert!(
            vault
                .publish_origin_ref(
                    &wire,
                    request(
                        &vault,
                        &repo,
                        wrong_repo_id,
                        Some(base.clone()),
                        next.clone()
                    ),
                )
                .is_err(),
            "a caller-chosen repository id cannot redirect publication or keep accounting"
        );
        assert!(
            vault
                .published_origin_refs(&wire, wrong_repo_id, &repo)
                .is_err()
        );
        assert!(
            vault
                .reconcile_origin_publications(&wire, wrong_repo_id, &repo, LEARNED_AT)
                .is_err()
        );

        let receipt = vault
            .publish_origin_ref(
                &wire,
                request(&vault, &repo, repo_id, Some(base), next.clone()),
            )
            .expect("publish");

        assert_eq!(receipt.record.status, OriginPublicationStatus::Published);
        assert!(
            !receipt.ref_was_already_applied,
            "the publication moved the ref itself"
        );
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("read ref"),
            Some(next.clone()),
            "exactly one ref advanced from expected to new oid"
        );

        // Exactly one active repo.publication claim.
        let claim_id = receipt
            .record
            .publication_claim_id
            .expect("published record carries its claim");
        let body = vault
            .get_claim(&claim_id)
            .expect("read claim")
            .expect("claim exists");
        assert_eq!(body.predicate, ORIGIN_PUBLICATION_PREDICATE);
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
        assert_eq!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise"),
            vec![(main_ref(), next)],
        );
        assert_eq!(
            vault
                .prepared_origin_publication_count(repo_id)
                .expect("prepared count"),
            0,
        );
    }

    #[test]
    fn publication_finalize_txn_atomic() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "second", "second\n");
        force_ref(&root, &base);

        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let ask = request(&vault, &repo, repo_id, Some(base), next.clone());

        let first = vault
            .publish_origin_ref(&wire, ask.clone())
            .expect("publish");
        let claim_id = first.record.publication_claim_id.expect("claim id");
        // CAS precedes finalize. T2 atomically writes claim and Published,
        // and identical replay must not invoke the claim writer a second time.
        // The claim and the Published mark are one transaction: a record that
        // says Published always has a claim behind it.
        assert!(
            vault.get_claim(&claim_id).expect("read claim").is_some(),
            "the finalize transaction wrote both halves"
        );

        let mut altered = ask.clone();
        altered
            .required_objects
            .push(GitOid::parse_hex("d".repeat(40)).expect("missing oid"));
        assert!(
            vault.publish_origin_ref(&wire, altered).is_err(),
            "replay cannot replace the availability set behind an existing claim"
        );
        let replay = vault.publish_origin_ref(&wire, ask).expect("replay");
        assert_eq!(replay.record.publication_id, first.record.publication_id);
        assert_eq!(replay.record.publication_claim_id, Some(claim_id));
        assert!(
            replay.ref_was_already_applied,
            "an identical replay moves no ref"
        );
        let commit_anchor = origin_published_commit_id(&next).expect("commit anchor");
        assert_eq!(
            vault
                .claims_for_subject(&commit_anchor)
                .expect("claims for subject")
                .len(),
            0,
            "an EdgeRef subject writes no claim_of edge, so the anchor is not an entity subject"
        );
        assert_eq!(
            vault
                .origin_publication_rows(Some(repo_id))
                .expect("rows")
                .len(),
            1,
            "an identical replay is one publication, not two"
        );
    }

    #[test]
    fn publication_advertisement_gated_on_object_and_lfs_availability() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "second", "second\n");
        force_ref(&root, &base);

        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);

        // A required git object this store does not carry.
        let mut missing_object = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        missing_object.required_objects =
            vec![GitOid::parse_hex("b".repeat(40)).expect("absent oid")];
        let refused = vault
            .publish_origin_ref(&wire, missing_object)
            .expect("publish refuses rather than errors");
        assert_eq!(refused.record.status, OriginPublicationStatus::Failed);
        assert!(
            refused
                .record
                .failure
                .as_deref()
                .expect("bounded failure text")
                .contains("not present"),
        );
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("read ref"),
            Some(base.clone()),
            "a refused publication leaves the public ref unchanged"
        );
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise")
                .is_empty(),
            "the advertisement omits a row that never published"
        );

        // A missing tip must also produce a bounded durable refusal, even
        // though GitWire cannot create a keep-ref for it.
        let absent = GitOid::parse_hex("d".repeat(40)).expect("missing tip");
        let missing_tip = request(&vault, &repo, repo_id, Some(base.clone()), absent);
        let refused = vault
            .publish_origin_ref(&wire, missing_tip)
            .expect("missing tip refusal");
        assert_eq!(refused.record.status, OriginPublicationStatus::Failed);
        assert!(
            refused.record.failure.as_ref().expect("failure").len()
                <= ORIGIN_PUBLICATION_MAX_FAILURE_BYTES
        );
        assert_eq!(
            vault
                .origin_publication(refused.record.publication_id)
                .expect("read refusal"),
            Some(refused.record)
        );

        // A row with the right length is not evidence that its bytes still
        // exist. Delete only the ASSET body to model corruption after upload.
        let bytes = b"publication lfs content";
        let oid = LfsOid::digest(bytes);
        let size = u64::try_from(bytes.len()).expect("size");
        let object = vault
            .put_lfs_object(oid, bytes, occurred(), LEARNED_AT)
            .expect("upload")
            .object;
        vault
            .with_write_txn(|wtxn| {
                vault
                    .store
                    .entities
                    .delete(wtxn, object.asset_id.as_bytes())?;
                Ok(())
            })
            .expect("lose asset body");
        assert!(vault.has_lfs_object(oid, size).expect("metadata remains"));
        let mut corrupt_lfs = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        corrupt_lfs.required_lfs_oids = vec![(oid, size)];
        let refused = vault
            .publish_origin_ref(&wire, corrupt_lfs)
            .expect("corrupt lfs refusal");
        assert_eq!(refused.record.status, OriginPublicationStatus::Failed);
        assert!(
            refused
                .record
                .failure
                .expect("failure")
                .contains("not locally readable")
        );

        // An LFS pointer whose bytes this vault does not hold.
        let mut missing_lfs = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        missing_lfs.required_lfs_oids =
            vec![(LfsOid::parse_hex(&"c".repeat(64)).expect("lfs oid"), 11)];
        let refused = vault
            .publish_origin_ref(&wire, missing_lfs)
            .expect("publish refuses rather than errors");
        assert_eq!(refused.record.status, OriginPublicationStatus::Failed);
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("read ref"),
            Some(base.clone()),
            "a missing lfs object never moves the public ref"
        );
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &next)
                .expect("released owner"),
            0
        );
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise")
                .is_empty(),
        );

        let bytes = b"lfs bytes lost after publication";
        let oid = LfsOid::digest(bytes);
        let object = vault
            .put_lfs_object(oid, bytes, occurred(), LEARNED_AT)
            .expect("upload readable bytes")
            .object;
        let mut ask = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        ask.required_lfs_oids = vec![(oid, u64::try_from(bytes.len()).expect("size"))];
        let published = vault
            .publish_origin_ref(&wire, ask.clone())
            .expect("publish with lfs");
        assert_eq!(published.record.status, OriginPublicationStatus::Published);
        assert_eq!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("visible"),
            vec![(main_ref(), next)]
        );
        vault
            .with_write_txn(|wtxn| {
                vault
                    .store
                    .entities
                    .delete(wtxn, object.asset_id.as_bytes())?;
                Ok(())
            })
            .expect("lose published bytes");
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("projection")
                .is_empty()
        );
        force_ref(&root, &base);
        assert!(
            vault.publish_origin_ref(&wire, ask).is_err(),
            "replay must not move a ref onto unavailable LFS bytes"
        );
        assert_eq!(wire.read_ref(&repo, &main_ref()).expect("ref"), Some(base));
    }

    #[test]
    fn publication_cas_mismatch_records_conflicted() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let other_writer = commit(&root, "other writer", "other\n");
        let mine = commit(&root, "mine", "mine\n");
        // The repository carries the OTHER writer's value; this publication was
        // decided against `base`.
        force_ref(&root, &other_writer);

        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &other_writer);
        let repo_id = repo_id_of(&vault, &repo);

        let ask = request(&vault, &repo, repo_id, Some(base.clone()), mine);
        let receipt = vault
            .publish_origin_ref(&wire, ask.clone())
            .expect("publish");
        assert_eq!(receipt.record.status, OriginPublicationStatus::Conflicted);
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("read ref"),
            Some(other_writer),
            "the other writer's ref is intact"
        );
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise")
                .is_empty(),
        );
        // Never retried: a second call answers from the durable record.
        assert_eq!(
            vault
                .origin_publication(receipt.record.publication_id)
                .expect("record")
                .expect("row")
                .status,
            OriginPublicationStatus::Conflicted,
        );
        // Even if the old precondition becomes true again, a terminal conflict
        // must not be retried as a fresh CAS.
        force_ref(&root, &base);
        let replay = vault
            .publish_origin_ref(&wire, ask)
            .expect("replay conflict");
        assert_eq!(replay.record, receipt.record);
        assert!(
            replay.wire.is_none(),
            "a conflicted publication never reaches GitWire again"
        );
        assert_eq!(wire.read_ref(&repo, &main_ref()).expect("ref"), Some(base));
    }

    #[test]
    fn publication_keep_ref_shape_and_shared_owner_counting() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);

        let name = vault
            .pin_origin_object(
                &wire,
                &repo,
                OriginKeepRefKind::Publication,
                "owner-a",
                &base,
                LEARNED_AT,
            )
            .expect("pin");
        assert_eq!(
            name.as_str(),
            format!("{GIT_WIRE_KEEP_REF_PREFIX}object/{}", base.as_str()),
            "the physical root is the landed keep-ref shape"
        );
        assert_eq!(
            wire.read_ref(&repo, &name).expect("read keep ref"),
            Some(base.clone()),
        );

        // A second, DIFFERENT logical reason for the same object.
        vault
            .pin_origin_object(
                &wire,
                &repo,
                OriginKeepRefKind::Change,
                "owner-b",
                &base,
                LEARNED_AT,
            )
            .expect("pin change owner");
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &base)
                .expect("owner count"),
            2,
        );

        vault
            .unpin_origin_object(
                &wire,
                &repo,
                OriginKeepRefKind::Publication,
                "owner-a",
                &base,
                LEARNED_AT,
            )
            .expect("unpin publication owner");
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &base)
                .expect("owner count"),
            1,
        );
        assert_eq!(
            wire.read_ref(&repo, &name).expect("read keep ref"),
            Some(base.clone()),
            "the physical root survives while another owner references it"
        );

        vault
            .unpin_origin_object(
                &wire,
                &repo,
                OriginKeepRefKind::Change,
                "owner-b",
                &base,
                LEARNED_AT,
            )
            .expect("unpin change owner");
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &base)
                .expect("owner count"),
            0,
        );
        assert_eq!(
            wire.read_ref(&repo, &name).expect("read keep ref"),
            None,
            "the physical root is retired only at zero owners"
        );

        for kind in OriginKeepRefKind::ALL {
            vault
                .pin_origin_object(&wire, &repo, kind, "shared-key", &base, LEARNED_AT)
                .expect("pin each owner kind");
        }
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &base)
                .expect("count"),
            5
        );
        for (index, kind) in OriginKeepRefKind::ALL.into_iter().enumerate() {
            vault
                .unpin_origin_object(&wire, &repo, kind, "shared-key", &base, LEARNED_AT)
                .expect("unpin each owner kind");
            assert_eq!(
                wire.read_ref(&repo, &name).expect("root"),
                (index < 4).then(|| base.clone()),
                "all five kinds participate in zero-owner retirement"
            );
        }
    }

    #[test]
    fn publication_crash_after_prepared_retries_safely() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "second", "second\n");
        force_ref(&root, &base);

        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let ask = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        let publication_id = origin_publication_id(&ask).expect("publication id");

        // The crash: a durable Prepared row and nothing else.
        vault
            .stage_origin_publication(&wire, &ask, publication_id)
            .expect("stage");
        assert_eq!(
            vault
                .prepared_origin_publication_count(repo_id)
                .expect("prepared count"),
            1,
        );
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("read ref"),
            Some(base.clone()),
            "no public ref moved before the census ran"
        );

        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 1)
            .expect("census");
        assert_eq!(
            report.items,
            vec![(publication_id, OriginCensusDisposition::RetriedAndPublished)],
        );
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("read ref"),
            Some(next),
        );

        // The other half of the window: the live ref no longer matches the
        // expected old oid, so the retry refuses instead of clobbering.
        let third = commit(&root, "third", "third\n");
        let stale = request(&vault, &repo, repo_id, Some(base.clone()), third);
        let stale_id = origin_publication_id(&stale).expect("stale id");
        force_ref(&root, &base);
        vault
            .stage_origin_publication(&wire, &stale, stale_id)
            .expect("stage stale");
        let moved_on = commit(&root, "fourth", "fourth\n");
        force_ref(&root, &moved_on);
        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 2)
            .expect("census");
        assert!(
            report
                .items
                .contains(&(stale_id, OriginCensusDisposition::MarkedConflicted)),
        );
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("read ref"),
            Some(moved_on.clone()),
            "a refused retry moves no ref"
        );

        let fifth = commit(&root, "fifth", "fifth\n");
        force_ref(&root, &moved_on);
        std::fs::write(root.join("extra-object"), "detached dependency\n").expect("extra object");
        let extra = GitOid::parse_hex(git(&root, &["hash-object", "-w", "--", "extra-object"]))
            .expect("extra oid");
        let mut unavailable = request(&vault, &repo, repo_id, Some(moved_on.clone()), fifth);
        unavailable.required_objects = vec![extra.clone()];
        let unavailable_id = origin_publication_id(&unavailable).expect("publication id");
        vault
            .stage_origin_publication(&wire, &unavailable, unavailable_id)
            .expect("stage");
        std::fs::remove_file(
            root.join(".git/objects")
                .join(&extra.as_str()[..2])
                .join(&extra.as_str()[2..]),
        )
        .expect("lose dependency");
        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 3)
            .expect("census with missing dependency");
        assert!(
            report
                .items
                .contains(&(unavailable_id, OriginCensusDisposition::MarkedFailed))
        );
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("ref"),
            Some(moved_on)
        );
    }

    #[test]
    fn publication_crash_after_cas_before_finalize_recovers() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "second", "second\n");
        force_ref(&root, &base);

        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let ask = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        let publication_id = origin_publication_id(&ask).expect("publication id");

        // The crash: Prepared is durable and the real GitWire CAS happened,
        // but the publication finalize transaction never committed.
        vault
            .stage_origin_publication(&wire, &ask, publication_id)
            .expect("stage");
        assert!(
            wire.update_ref_cas(&repo, &main_ref(), Some(&base), &next, LEARNED_AT)
                .expect("CAS before crash")
                .is_applied()
        );
        let log = reflog(&root);
        assert_eq!(claim_count(&vault), 0);

        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 1)
            .expect("census");
        assert_eq!(
            report.items,
            vec![(publication_id, OriginCensusDisposition::FinalizedPublished)],
        );
        let record = vault
            .origin_publication(publication_id)
            .expect("record")
            .expect("row");
        assert_eq!(record.status, OriginPublicationStatus::Published);
        assert!(record.publication_claim_id.is_some());
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("read ref"),
            Some(next),
            "the census finalized without moving the ref again"
        );

        // The same window through the ordinary door reports the receipt flag.
        let receipt = vault.publish_origin_ref(&wire, ask).expect("publish");
        assert!(receipt.ref_was_already_applied);
        assert!(
            receipt.wire_replayed(),
            "the GitWire effect was not run again"
        );
        assert_eq!(receipt.record.publication_id, publication_id);
        assert_eq!(claim_count(&vault), 1);
        assert_eq!(reflog(&root), log);
    }

    #[test]
    fn publication_crash_after_finalize_cleanup_leak_safe() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "second", "second\n");
        force_ref(&root, &base);

        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let ask = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        let publication_id = origin_publication_id(&ask).expect("publication id");

        // The crash: finalize committed, cleanup never ran. Reconstructed by
        // staging the pin and committing T2 without physical retirement.
        vault
            .stage_origin_publication(&wire, &ask, publication_id)
            .expect("stage");
        assert!(
            wire.update_ref_cas(&repo, &main_ref(), Some(&base), &next, LEARNED_AT)
                .expect("CAS before T2")
                .is_applied()
        );
        let record = vault
            .origin_publication(publication_id)
            .expect("record")
            .expect("row");
        let published = vault
            .finalize_origin_publication(record, LEARNED_AT)
            .expect("finalize");
        assert_eq!(published.status, OriginPublicationStatus::Published);

        // A second, independent owner of the same object: the leak sweep must
        // not retire a root somebody else still references.
        vault
            .pin_origin_object(
                &wire,
                &repo,
                OriginKeepRefKind::Snapshot,
                "snapshot-owner",
                &next,
                LEARNED_AT,
            )
            .expect("snapshot pin");
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &next)
                .expect("owner count"),
            1,
            "T2 already removed the publication owner atomically",
        );

        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 1)
            .expect("census");
        assert_eq!(
            report.items,
            vec![(publication_id, OriginCensusDisposition::NoChange)],
            "cleanup is not a state change"
        );
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &next)
                .expect("owner count"),
            1,
            "the census dropped the publication owner after the live-ref proof"
        );
        let keep = origin_keep_ref_name(&next).expect("keep name");
        assert_eq!(
            wire.read_ref(&repo, &keep).expect("read keep ref"),
            Some(next.clone()),
            "the physical root survives while the snapshot owner references it"
        );

        // The interrupted-cleanup leak: a later census removes it.
        vault
            .unpin_origin_object(
                &wire,
                &repo,
                OriginKeepRefKind::Snapshot,
                "snapshot-owner",
                &next,
                LEARNED_AT + 2,
            )
            .expect("unpin snapshot");
        assert_eq!(
            wire.read_ref(&repo, &keep).expect("read keep ref"),
            None,
            "a later pass removes the leaked root at zero owners"
        );
        wire.write_keep_ref(&repo, &next, LEARNED_AT + 3)
            .expect("restore leaked root");
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &next)
                .expect("count"),
            0
        );
        let lock = root.join(".git").join(format!("{}.lock", keep.as_str()));
        std::fs::write(&lock, b"held by another operation").expect("block keep cleanup");
        let replay = vault
            .publish_origin_ref(&wire, ask)
            .expect("cleanup leak is not rejection");
        assert_eq!(replay.record.status, OriginPublicationStatus::Published);
        assert_eq!(
            wire.read_ref(&repo, &keep).expect("leaked root"),
            Some(next.clone())
        );
        std::fs::remove_file(lock).expect("unblock cleanup");
        vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 4)
            .expect("sweep an ownerless physical root");
        assert_eq!(
            wire.read_ref(&repo, &keep).expect("root after census"),
            None
        );
        assert_eq!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise"),
            vec![(main_ref(), next)],
            "cleanup never disturbs the advertisement"
        );
    }

    #[test]
    fn published_origin_refs_is_the_only_advertisement_projection() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "second", "second\n");
        force_ref(&root, &base);

        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);

        // A raw repository ref that no publication ever produced.
        git(&root, &["update-ref", "refs/heads/raw", base.as_str()]);
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise")
                .is_empty(),
            "a raw repository ref is never an advertisement authority"
        );

        // A non-Published row is omitted.
        let ask = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        let publication_id = origin_publication_id(&ask).expect("publication id");
        vault
            .stage_origin_publication(&wire, &ask, publication_id)
            .expect("stage");
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise")
                .is_empty(),
            "a Prepared row is not advertisable"
        );

        // Published and live: advertised.
        let receipt = vault.publish_origin_ref(&wire, ask).expect("publish");
        assert_eq!(receipt.record.status, OriginPublicationStatus::Published);
        assert_eq!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise"),
            vec![(main_ref(), next)],
        );

        // Live-ref mismatch: the row is omitted the moment the repository
        // disagrees with it, without any journal write.
        force_ref(&root, &base);
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("advertise")
                .is_empty(),
            "a Published row whose live ref moved is not advertisable"
        );
    }

    fn claim_count(vault: &Vault) -> usize {
        let txn = vault.store.env.read_txn().expect("read claims");
        vault
            .store
            .entities
            .iter(&txn)
            .expect("entities")
            .filter(|entry| {
                let (_, raw) = entry.as_ref().expect("entity");
                let Some(header) = crate::batch::EntityMetadataHeader::parse(raw) else {
                    return false;
                };
                header.entity_type == crate::registry::ENTITY_TYPE_CLAIM
                    && crate::claim::decode_claim_body(
                        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                        true,
                    )
                    .is_ok_and(|body| body.predicate == ORIGIN_PUBLICATION_PREDICATE)
            })
            .count()
    }

    fn reflog(root: &Path) -> String {
        git(
            root,
            &["reflog", "show", "--format=%H %gs", "refs/heads/main"],
        )
    }

    #[test]
    fn publication_terminal_wins_and_duplicate_finalize_is_inert() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "next", "next\n");
        force_ref(&root, &base);
        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let ask = request(&vault, &repo, repo_id_of(&vault, &repo), Some(base), next);
        let id = origin_publication_id(&ask).expect("id");
        let prepared = vault.stage_origin_publication(&wire, &ask, id).expect("T1");
        let mut conflicted = prepared.clone();
        conflicted.status = OriginPublicationStatus::Conflicted;
        conflicted.finished_at = Some(LEARNED_AT);
        vault
            .put_origin_publication_record(&conflicted)
            .expect("competing terminal write");
        assert!(
            vault
                .finalize_origin_publication(prepared.clone(), LEARNED_AT + 1)
                .is_err()
        );
        assert_eq!(
            vault.origin_publication(id).expect("row"),
            Some(conflicted.clone())
        );
        assert_eq!(claim_count(&vault), 0);
        assert!(
            vault
                .finish_origin_publication(prepared, LEARNED_AT + 1)
                .is_err()
        );
        assert_eq!(vault.origin_publication(id).expect("row"), Some(conflicted));

        // A distinct ref proves duplicate Published T2 is a byte-preserving no-op.
        let mut second = ask;
        second.ref_name = GitRefName::parse_full("refs/heads/other").expect("ref");
        second.expected_old_oid = None;
        let landed = vault
            .publish_origin_ref(&wire, second)
            .expect("publish")
            .record;
        let raw = vault
            .get_raw(&landed.publication_claim_id.expect("claim"))
            .expect("claim bytes");
        assert_eq!(
            vault
                .finalize_origin_publication(landed.clone(), LEARNED_AT + 2)
                .expect("same terminal"),
            landed
        );
        assert_eq!(
            vault
                .get_raw(&landed.publication_claim_id.expect("claim"))
                .expect("claim bytes"),
            raw
        );
        assert_eq!(claim_count(&vault), 1);
    }

    #[test]
    fn publication_duplicate_intent_reconciles_without_second_claim() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "next", "next\n");
        force_ref(&root, &base);
        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let first = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        let id = origin_publication_id(&first).expect("id");
        vault
            .stage_origin_publication(&wire, &first, id)
            .expect("T1");
        let mut duplicate = first.clone();
        duplicate.provenance_claim_id = fixture_provenance(&vault, repo_id);
        let duplicate_id = origin_publication_id(&duplicate).expect("duplicate id");
        assert!(vault.publish_origin_ref(&wire, duplicate.clone()).is_err());
        assert_eq!(
            vault
                .origin_publication(id)
                .expect("owner")
                .expect("row")
                .status,
            OriginPublicationStatus::Published
        );
        assert!(
            vault
                .origin_publication(duplicate_id)
                .expect("no duplicate row")
                .is_none()
        );
        let log = reflog(&root);
        assert!(vault.publish_origin_ref(&wire, duplicate).is_err());
        let replay = vault
            .publish_origin_ref(&wire, first.clone())
            .expect("identical replay");
        assert!(replay.ref_was_already_applied);
        assert_eq!(claim_count(&vault), 1);
        assert_eq!(
            vault
                .origin_visible_ref_rows(&repo_id)
                .expect("visible rows"),
            vec![id]
        );
        assert_eq!(reflog(&root), log);
        force_ref(&root, &base);
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("hidden")
                .is_empty()
        );
        let replay = vault
            .publish_origin_ref(&wire, first)
            .expect("CAS replay from expected");
        assert!(replay.wire.as_ref().expect("wire proof").is_applied());
        assert_eq!(wire.read_ref(&repo, &main_ref()).expect("ref"), Some(next));
        assert_eq!(claim_count(&vault), 1);
    }

    #[test]
    fn publication_stale_applied_outcome_cannot_finalize_without_live_ref() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "next", "next\n");
        force_ref(&root, &base);
        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let ask = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        let id = origin_publication_id(&ask).expect("id");
        let prepared = vault.stage_origin_publication(&wire, &ask, id).expect("T1");
        let outcome = wire
            .update_ref_cas(&repo, &main_ref(), Some(&base), &next, LEARNED_AT)
            .expect("real applied outcome");
        assert!(outcome.is_applied());
        // An external Git writer does not obey the engine's advisory lock.
        force_ref(&root, &base);
        assert!(
            vault
                .finish_origin_cas_outcome(
                    &wire,
                    &repo,
                    prepared.clone(),
                    false,
                    LEARNED_AT,
                    outcome
                )
                .is_err()
        );
        assert_eq!(vault.origin_publication(id).expect("row"), Some(prepared));
        assert_eq!(claim_count(&vault), 0);
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("hidden")
                .is_empty()
        );
        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 1)
            .expect("retry same triple through GitWire");
        assert_eq!(
            report.items,
            vec![(id, OriginCensusDisposition::RetriedAndPublished)]
        );
        assert_eq!(claim_count(&vault), 1);
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("live proof"),
            Some(next)
        );
    }

    #[test]
    fn publication_uncertain_git_error_keeps_intent_for_census() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "next", "next\n");
        force_ref(&root, &base);
        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let ask = request(&vault, &repo, repo_id, Some(base.clone()), next.clone());
        let id = origin_publication_id(&ask).expect("id");
        let prepared = vault.stage_origin_publication(&wire, &ask, id).expect("T1");
        // A real Git lockfile failure, not a process/coordinator proof. Unlike
        // chmod this also fails when the test runner has elevated privileges.
        let blocked = root.join(".git/refs/heads/main.lock");
        std::fs::write(&blocked, b"another git ref transaction").expect("block CAS");
        let mut duplicate = ask.clone();
        duplicate.provenance_claim_id = fixture_provenance(&vault, repo_id);
        let duplicate_id = origin_publication_id(&duplicate).expect("duplicate id");
        assert!(vault.publish_origin_ref(&wire, duplicate).is_err());
        assert!(
            vault
                .origin_publication(duplicate_id)
                .expect("no new owner")
                .is_none()
        );
        assert!(vault.publish_origin_ref(&wire, ask).is_err());
        assert_eq!(vault.origin_publication(id).expect("row"), Some(prepared));
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("unchanged"),
            Some(base)
        );
        assert_eq!(claim_count(&vault), 0);
        std::fs::remove_file(blocked).expect("unblock CAS");
        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 1)
            .expect("retry uncertainty");
        assert_eq!(
            report.items,
            vec![(id, OriginCensusDisposition::RetriedAndPublished)]
        );
        assert_eq!(claim_count(&vault), 1);
        assert_eq!(
            wire.read_ref(&repo, &main_ref()).expect("published"),
            Some(next)
        );
    }

    #[test]
    fn publication_live_ref_missing_data_stays_prepared_and_orphan_owner_is_swept() {
        let (_vault_dir, vault) = test_vault();
        let (_repo_dir, root, base) = seeded_repo();
        let next = commit(&root, "next", "next\n");
        force_ref(&root, &base);
        let wire = GitWire::new(&vault).expect("wire");
        let repo = open_repo(&wire, &root, &base);
        let repo_id = repo_id_of(&vault, &repo);
        let orphan = EntityId::now().to_hex();
        vault
            .pin_origin_object(
                &wire,
                &repo,
                OriginKeepRefKind::Publication,
                &orphan,
                &next,
                LEARNED_AT,
            )
            .expect("pin before T1 crash");
        vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT)
            .expect("sweep");
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &next)
                .expect("owners"),
            0
        );
        assert_eq!(
            wire.read_ref(&repo, &origin_keep_ref_name(&next).expect("keep"))
                .expect("root"),
            None
        );

        let bytes = b"recoverable lfs";
        let oid = LfsOid::digest(bytes);
        let size = bytes.len() as u64;
        let mut ask = request(&vault, &repo, repo_id, Some(base), next.clone());
        ask.required_lfs_oids = vec![(oid, size)];
        let id = origin_publication_id(&ask).expect("id");
        vault.stage_origin_publication(&wire, &ask, id).expect("T1");
        // Model a crash after the Git subprocess, before its journal transition.
        // Census must use GitWire's already-published path, not infer a claim.
        force_ref(&root, &next);
        let log = reflog(&root);
        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT)
            .expect("census missing bytes");
        assert_eq!(report.items, vec![(id, OriginCensusDisposition::NoChange)]);
        assert_eq!(claim_count(&vault), 0);
        assert_eq!(
            vault
                .origin_keep_owner_count(&repo_id, &next)
                .expect("owner"),
            1
        );
        assert!(
            vault
                .published_origin_refs(&wire, repo_id, &repo)
                .expect("hidden")
                .is_empty()
        );
        vault
            .put_lfs_object(oid, bytes, occurred(), LEARNED_AT)
            .expect("restore bytes");
        let report = vault
            .reconcile_origin_publications(&wire, repo_id, &repo, LEARNED_AT + 1)
            .expect("census readable bytes");
        assert_eq!(
            report.items,
            vec![(id, OriginCensusDisposition::FinalizedPublished)]
        );
        assert_eq!(claim_count(&vault), 1);
        assert_eq!(reflog(&root), log);
    }

    /// Static guard: this module touches only the surfaces the claim allows.
    ///
    /// The forbidden spellings are assembled at compile time from fragments, so
    /// the guard's own source does not contain the strings it refuses and the
    /// scan cannot trip over itself.
    #[test]
    fn origin_publication_module_isolation_guard() {
        let source = include_str!("publication.rs");
        let forbidden: [&str; 7] = [
            concat!("repo_", "mutation"),
            concat!("RepoMutation", "Status"),
            concat!("sync_", "state"),
            concat!("refs/", "jj/keep"),
            concat!("change_", "index"),
            concat!("conflict_", "tree"),
            concat!("origin::", "residence"),
        ];
        for spelling in forbidden {
            assert!(
                !source.contains(spelling),
                "publication module must not reference {spelling}"
            );
        }
        for required in [
            "published_origin_refs",
            "update_ref_cas",
            "has_lfs_object",
            "put_claim_in_txn",
            "write_keep_ref",
            "delete_keep_ref",
        ] {
            assert!(
                source.contains(required),
                "publication module must ride {required}"
            );
        }
    }
}
