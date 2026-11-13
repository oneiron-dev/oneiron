//! Pinned cleanup vocabulary: wire strings, enums, and proposal/digest/report structs.

use serde::{Deserialize, Serialize};

use crate::attempt_id::AttemptId;
use oneiron_contracts::entity_id::EntityId;

// ---------------------------------------------------------------------------
// Pinned vocabulary
// ---------------------------------------------------------------------------

/// `vault_meta` key holding the cleanup posture flag.
///
/// Absent means [`CleanupPosture::AutoWithDigest`]: a vault cleans up
/// automatically from birth, takes a snapshot first, tells the owner
/// afterwards, and the owner can revert any run (owner 2026-10-18,
/// ARCH-0073 #arm-ruled; DEC-0006: no grant step, no holdout). The owner may
/// store [`CleanupPosture::ProposeFirst`] instead. A value that does not
/// parse reads as `ProposeFirst`, the safe reading of a damaged row.
pub const VAULT_CLEANUP_POSTURE_KEY: &[u8] = b"vault_cleanup.posture.v1";

/// Receipt-id prefix that discriminates this projector's rows inside the
/// shared `Gate` family.
pub const VAULT_CLEANUP_RECEIPT_PREFIX: &str = "vault_cleanup:";

/// Actor recorded on a cleanup digest receipt. The cron is the engine acting
/// on its own maintenance schedule; naming it plainly keeps a reader from
/// reading an archive as something a person did.
pub const VAULT_CLEANUP_ACTOR: &str = "engine:vault_cleanup";

pub const PROPOSAL_ROW_LABEL: &str = "vault cleanup proposal";

pub const DIGEST_ROW_LABEL: &str = "vault cleanup digest";

pub const PROPOSAL_SCHEMA_VERSION: u64 = 1;

pub const DIGEST_SCHEMA_VERSION: u64 = 1;

pub const KEY_SCHEMA_VERSION: &str = "schema_version";

pub const KEY_ATTEMPT: &str = "attempt";

pub const KEY_CREATED_AT: &str = "created_at";

pub const KEY_CANDIDATES: &str = "candidates";

pub const KEY_ENTITY: &str = "entity";

pub const KEY_KIND: &str = "kind";

pub const KEY_PROPOSAL: &str = "proposal";

pub const KEY_DECISION: &str = "decision";

pub const KEY_POSTURE: &str = "posture";

pub const KEY_ARCHIVED: &str = "archived";

pub const KEY_SKIPPED: &str = "skipped";

/// The digest key of the slots a mixed decision rejected; absent on every
/// other digest.
pub const KEY_REJECTED: &str = "rejected";

/// The digest key of an automatic run's integrity-teeth badge, a map of
/// [`KEY_READ_FOLD_COVERAGE_CLOSED`] and [`KEY_OS_SEPARATION_CLOSED`] to
/// booleans; absent on every other digest.
pub const KEY_INTEGRITY_TEETH: &str = "integrity_teeth";

pub const KEY_READ_FOLD_COVERAGE_CLOSED: &str = "read_fold_coverage_closed";

pub const KEY_OS_SEPARATION_CLOSED: &str = "os_separation_closed";

pub const KEY_AT: &str = "at";

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

/// How many candidates the owner rejected in a mixed decision; present only
/// when he rejected one.
pub const FIELD_CLEANUP_REJECTED_COUNT: &str = "cleanup_rejected_count";

/// The ids the owner rejected in a mixed decision, comma-joined; present
/// only when he rejected one.
pub const FIELD_CLEANUP_REJECTED_IDS: &str = "cleanup_rejected_ids";

pub const FIELD_CLEANUP_PROPOSAL: &str = "cleanup_proposal";

pub const FIELD_CLEANUP_TOMBSTONE_REASON: &str = "cleanup_tombstone_reason";

/// ARCH-0066 tooth #5 (read/fold verification coverage) as it stood when an
/// automatic run archived: `open` or `closed`. Present only on an automatic
/// run's receipt.
pub const FIELD_CLEANUP_TOOTH_READ_FOLD_COVERAGE: &str = "cleanup_tooth_read_fold_coverage";

/// ARCH-0066 tooth #9 (OS-level separation of the vault's files) as it stood
/// when an automatic run archived: `open` or `closed`. Present only on an
/// automatic run's receipt.
pub const FIELD_CLEANUP_TOOTH_OS_SEPARATION: &str = "cleanup_tooth_os_separation";

/// The value of [`FIELD_CLEANUP_PHASE`] on every row this projector mints.
pub const CLEANUP_PHASE: &str = "cleanup";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Which ratified emptiness arm matched a row.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CleanupKind {
    /// An extraction-minted PERSON row with no live claim about it.
    ClaimlessExtractionPerson,
    /// A SUMMARY row with no live members or references.
    EmptySummary,
    /// A completed TASK older than the owner-set retention period.
    CompletedTask,
    /// A completed private attempt older than the retention period.
    CompletedAttempt,
    /// A NOTE whose kind keeps it a set number of days, born longer ago.
    RetainedNote,
}

impl CleanupKind {
    /// The pinned on-disk string for this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaimlessExtractionPerson => "claimless_extraction_person",
            Self::EmptySummary => "empty_summary",
            Self::CompletedTask => "completed_task",
            Self::CompletedAttempt => "completed_attempt",
            Self::RetainedNote => "retained_note",
        }
    }

    /// Parses the pinned on-disk string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "claimless_extraction_person" => Some(Self::ClaimlessExtractionPerson),
            "empty_summary" => Some(Self::EmptySummary),
            "completed_task" => Some(Self::CompletedTask),
            "completed_attempt" => Some(Self::CompletedAttempt),
            "retained_note" => Some(Self::RetainedNote),
            _ => None,
        }
    }
}

/// One row the tripwire tripped on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CleanupCandidate {
    pub entity: EntityId,
    pub kind: CleanupKind,
}

/// Whether the cron proposes archives or performs them.
///
/// Engine config (`vault_meta`), set only by owner action. Default
/// [`Self::AutoWithDigest`], the reading of a vault with no stored posture
/// (see [`VAULT_CLEANUP_POSTURE_KEY`]).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CleanupPosture {
    /// Emit a proposal; archive nothing until the owner accepts.
    ProposeFirst,
    /// Archive directly, then say so once per run (after-notice digest).
    #[default]
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
    /// Each candidate in proposal order; `None` is one an erase reached since
    /// the proposal opened, which names no one and which an accept skips
    /// (FIX 7517).
    pub candidates: Vec<Option<CleanupCandidate>>,
}

impl CleanupProposal {
    /// The impact preview this proposal carries. `total` counts every slot,
    /// an erased one too; the kind counts and the ids are the live ones, the
    /// ones an accept can archive.
    #[must_use]
    pub fn impact_preview(&self) -> CleanupImpactPreview {
        CleanupImpactPreview {
            total: self.candidates.len(),
            claimless_persons: self
                .candidates
                .iter()
                .flatten()
                .filter(|c| c.kind == CleanupKind::ClaimlessExtractionPerson)
                .count(),
            empty_summaries: self
                .candidates
                .iter()
                .flatten()
                .filter(|c| c.kind == CleanupKind::EmptySummary)
                .count(),
            entities: self.candidates.iter().flatten().map(|c| c.entity).collect(),
        }
    }
}

/// The proof badge on an automatic run's digest: ARCH-0066 teeth #5 and #9
/// as they stood when the run archived.
///
/// The automatic posture does not wait on these teeth (owner 2026-10-18,
/// DEC-0006); the badge says which proofs stood behind each run. Each flag
/// flips in the PR that closes its tooth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupIntegrityTeeth {
    /// Tooth #5: read/fold verification coverage at consumption.
    pub read_fold_coverage_closed: bool,
    /// Tooth #9: OS-level separation of the vault's files.
    pub os_separation_closed: bool,
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
    /// The ids the decision archived; `None` is one an erase reached since,
    /// kept in its place so the count stays (FIX 7517).
    pub archived: Vec<Option<EntityId>>,
    /// Candidates that were NOT archived because the re-check found them no
    /// longer empty. The stale-candidate guard's audit trail. `None` as in
    /// `archived`.
    pub skipped: Vec<Option<EntityId>>,
    /// Candidates the owner rejected in a mixed per-item decision: nothing
    /// was looked up or archived for them, and none is pinned (FIX 1758).
    /// Empty for every other decision. `None` as in `archived`.
    pub rejected: Vec<Option<EntityId>>,
    /// The integrity-teeth badge of an automatic run; `None` on an accepted
    /// proposal, and on a digest recorded before the badge.
    pub integrity_teeth: Option<CleanupIntegrityTeeth>,
}

/// What one cron pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupRunReport {
    pub attempt: AttemptId,
    pub posture: CleanupPosture,
    /// What the run found, in scan order; `None` is a candidate an erase
    /// reached since the run recorded it (FIX 7517). A run just made holds
    /// none.
    pub candidates: Vec<Option<CleanupCandidate>>,
    /// The proposal this run opened, under [`CleanupPosture::ProposeFirst`].
    pub proposal: Option<EntityId>,
    /// Ids archived by this run, under [`CleanupPosture::AutoWithDigest`];
    /// `None` as in `candidates`.
    pub archived: Vec<Option<EntityId>>,
    /// The one digest this run recorded, if it archived anything.
    pub digest: Option<EntityId>,
}

/// What accepting a proposal did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupAcceptOutcome {
    pub proposal: EntityId,
    pub archived: Vec<EntityId>,
    pub skipped: Vec<EntityId>,
    /// How many of the proposal's candidates an erase reached before the
    /// accept: they name no one, and nothing was looked up or archived for
    /// them (FIX 7517).
    pub erased: usize,
    pub digest: EntityId,
}

/// `items` as slots, each live.
pub fn live_slots<T>(items: Vec<T>) -> Vec<Option<T>> {
    items.into_iter().map(Some).collect()
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
