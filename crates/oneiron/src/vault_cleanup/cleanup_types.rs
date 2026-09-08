//! Pinned cleanup vocabulary: wire strings, enums, and proposal/digest/report structs.

use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;

// ---------------------------------------------------------------------------
// Pinned vocabulary
// ---------------------------------------------------------------------------

/// `vault_meta` key holding the cleanup posture flag.
///
/// Absent means [`CleanupPosture::ProposeFirst`] — the safe default is the
/// ABSENCE of a decision, so a vault that never heard of this feature cannot
/// be auto-archiving.
pub const VAULT_CLEANUP_POSTURE_KEY: &[u8] = b"vault_cleanup.posture.v1";

/// `vault_meta` key prefix for open cleanup proposals.
pub(super) const PROPOSAL_PREFIX: &[u8] = b"vault_cleanup.proposal.v1:";

/// `vault_meta` key prefix for cleanup run digests (the receipt substrate).
pub(super) const DIGEST_PREFIX: &[u8] = b"vault_cleanup.digest.v1:";

/// Receipt-id prefix that discriminates this projector's rows inside the
/// shared `Gate` family.
pub const VAULT_CLEANUP_RECEIPT_PREFIX: &str = "vault_cleanup:";

/// Actor recorded on a cleanup digest receipt. The cron is the engine acting
/// on its own maintenance schedule; naming it plainly keeps a reader from
/// reading an archive as something a person did.
pub const VAULT_CLEANUP_ACTOR: &str = "engine:vault_cleanup";

pub(super) const PROPOSAL_ROW_LABEL: &str = "vault cleanup proposal";

pub(super) const DIGEST_ROW_LABEL: &str = "vault cleanup digest";

pub(super) const PROPOSAL_SCHEMA_VERSION: u64 = 1;

pub(super) const DIGEST_SCHEMA_VERSION: u64 = 1;

pub(super) const KEY_SCHEMA_VERSION: &str = "schema_version";

pub(super) const KEY_ATTEMPT: &str = "attempt";

pub(super) const KEY_CREATED_AT: &str = "created_at";

pub(super) const KEY_CANDIDATES: &str = "candidates";

pub(super) const KEY_ENTITY: &str = "entity";

pub(super) const KEY_KIND: &str = "kind";

pub(super) const KEY_PROPOSAL: &str = "proposal";

pub(super) const KEY_DECISION: &str = "decision";

pub(super) const KEY_POSTURE: &str = "posture";

pub(super) const KEY_ARCHIVED: &str = "archived";

pub(super) const KEY_SKIPPED: &str = "skipped";

pub(super) const KEY_AT: &str = "at";

/// Receipt field names. Strings, because the receipt family's field ABI is
/// `BTreeMap<String, String>`; counts are decimal numerals so a reader can
/// compare them.
pub const FIELD_CLEANUP_PHASE: &str = "phase";

pub const FIELD_CLEANUP_DECISION: &str = "cleanup_decision";

pub const FIELD_CLEANUP_POSTURE: &str = "cleanup_posture";

pub const FIELD_CLEANUP_ARCHIVED_COUNT: &str = "cleanup_archived_count";

pub const FIELD_CLEANUP_SKIPPED_COUNT: &str = "cleanup_skipped_count";

pub const FIELD_CLEANUP_ARCHIVED_IDS: &str = "cleanup_archived_ids";

pub const FIELD_CLEANUP_SKIPPED_IDS: &str = "cleanup_skipped_ids";

pub const FIELD_CLEANUP_PROPOSAL: &str = "cleanup_proposal";

pub const FIELD_CLEANUP_TOMBSTONE_REASON: &str = "cleanup_tombstone_reason";

/// The value of [`FIELD_CLEANUP_PHASE`] on every row this projector mints.
pub const CLEANUP_PHASE: &str = "cleanup";

/// Ceiling on rows one run will EXAMINE per entity type.
///
/// A cron that walks an unbounded index holds a read transaction for an
/// unbounded time. Stopping early is safe in a way that stopping early on a
/// deletion never is: the rows not examined are simply not archived this run,
/// and the next run starts over.
pub(super) const MAX_CLEANUP_SCAN_ROWS: usize = 50_000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Which ratified emptiness arm matched a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CleanupKind {
    /// An extraction-minted PERSON row with no live claim about it.
    ClaimlessExtractionPerson,
    /// A SUMMARY row with no live members or references.
    EmptySummary,
}

impl CleanupKind {
    /// The pinned on-disk string for this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaimlessExtractionPerson => "claimless_extraction_person",
            Self::EmptySummary => "empty_summary",
        }
    }

    /// Parses the pinned on-disk string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "claimless_extraction_person" => Some(Self::ClaimlessExtractionPerson),
            "empty_summary" => Some(Self::EmptySummary),
            _ => None,
        }
    }
}

/// One row the tripwire tripped on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupCandidate {
    pub entity: EntityId,
    pub kind: CleanupKind,
}

/// Whether the cron proposes archives or performs them.
///
/// Engine config (`vault_meta`), flipped only by owner action. Default
/// [`Self::ProposeFirst`] while ARCH-0066 teeth #5/#9 are open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum CleanupPosture {
    /// Emit a proposal; archive nothing until the owner accepts.
    #[default]
    ProposeFirst,
    /// Archive directly, then say so once per run (after-notice digest).
    AutoWithDigest,
}

impl CleanupPosture {
    /// The pinned on-disk string for this posture.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProposeFirst => "propose_first",
            Self::AutoWithDigest => "auto_with_digest",
        }
    }

    /// Parses the pinned on-disk string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "propose_first" => Some(Self::ProposeFirst),
            "auto_with_digest" => Some(Self::AutoWithDigest),
            _ => None,
        }
    }
}

/// What a cleanup decision did, as recorded on its digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CleanupDecision {
    /// The auto posture archived directly.
    AutoArchived,
    /// The owner accepted a proposal and the accept re-ran the tripwire.
    ProposalAccepted,
}

impl CleanupDecision {
    /// The pinned on-disk string for this decision.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutoArchived => "auto_archived",
            Self::ProposalAccepted => "proposal_accepted",
        }
    }

    /// Parses the pinned on-disk string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto_archived" => Some(Self::AutoArchived),
            "proposal_accepted" => Some(Self::ProposalAccepted),
            _ => None,
        }
    }
}

/// The bulk-purge door's impact preview, which for an archive batch IS the
/// proposal body: how many rows, of which kind, and exactly which ids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupImpactPreview {
    pub total: usize,
    pub claimless_persons: usize,
    pub empty_summaries: usize,
    pub entities: Vec<EntityId>,
}

/// An open archive proposal awaiting an owner decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupProposal {
    pub id: EntityId,
    pub attempt: AttemptId,
    pub created_at: u64,
    pub candidates: Vec<CleanupCandidate>,
}

impl CleanupProposal {
    /// The impact preview this proposal carries.
    #[must_use]
    pub fn impact_preview(&self) -> CleanupImpactPreview {
        CleanupImpactPreview {
            total: self.candidates.len(),
            claimless_persons: self
                .candidates
                .iter()
                .filter(|c| c.kind == CleanupKind::ClaimlessExtractionPerson)
                .count(),
            empty_summaries: self
                .candidates
                .iter()
                .filter(|c| c.kind == CleanupKind::EmptySummary)
                .count(),
            entities: self.candidates.iter().map(|c| c.entity).collect(),
        }
    }
}

/// One recorded cleanup decision — the row the digest receipt projects from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupDigest {
    pub id: EntityId,
    pub attempt: Option<AttemptId>,
    pub proposal: Option<EntityId>,
    pub decision: CleanupDecision,
    pub posture: CleanupPosture,
    pub at: u64,
    pub archived: Vec<EntityId>,
    /// Candidates that were NOT archived because the re-check found them no
    /// longer empty. The stale-candidate guard's audit trail.
    pub skipped: Vec<EntityId>,
}

/// What one cron pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupRunReport {
    pub attempt: AttemptId,
    pub posture: CleanupPosture,
    pub candidates: Vec<CleanupCandidate>,
    /// The proposal this run opened, under [`CleanupPosture::ProposeFirst`].
    pub proposal: Option<EntityId>,
    /// Ids archived by this run, under [`CleanupPosture::AutoWithDigest`].
    pub archived: Vec<EntityId>,
    /// The one digest this run recorded, if it archived anything.
    pub digest: Option<EntityId>,
}

/// What accepting a proposal did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupAcceptOutcome {
    pub proposal: EntityId,
    pub archived: Vec<EntityId>,
    pub skipped: Vec<EntityId>,
    pub digest: EntityId,
}

/// An archived row, flagged as archived.
///
/// "Resolver-visible" in the ARCH-0024 sense: the data is REACHABLE, not
/// hidden. The row still answers `entities_by_type`; this query says which of
/// those rows are archived and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedEntity {
    pub entity: EntityId,
    /// Unix seconds the archive was applied.
    pub archived_at: u64,
    /// The archive request UUID, for correlating with the run digest.
    pub request_id: Option<String>,
}
