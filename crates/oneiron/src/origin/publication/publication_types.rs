//! Pinned constants, protocol enums with string tables, and request/record/receipt/report types.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefName, GitWireCommitOutcome, GitWireRejection, GitWireRepo};
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

/// Explicit, target-bound source for callers outside the receive-pack observer.
pub const ORIGIN_PUBLICATION_INTENT_PREDICATE: &str = "repo.publication_intent";

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
pub(super) const ORIGIN_KEY_SEPARATOR: u8 = 0;

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
