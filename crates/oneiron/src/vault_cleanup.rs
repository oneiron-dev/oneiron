//! ARCH-0073 vault auto-cleanup: the Dreamer ARCHIVE cron (ONE-1931).
//!
//! # What this is
//!
//! A vault accumulates rows that carry nothing: a PERSON an extraction pass
//! minted and never learned a single fact about, a SUMMARY whose members are
//! all gone. They are not wrong, they are EMPTY, and deleting them is not
//! what anyone wants — the owner may mention that person tomorrow. So the
//! cron ARCHIVES them, and archive is reversible.
//!
//! # The archive verb is a tombstone reason, not a state machine
//!
//! There is no Archive state in this engine and this ticket does not mint one.
//! `DeleteReason::ArchivedByCleanup` (wire byte 5) is the soft-reversible twin
//! of `user_delete`: it keeps the 25 B shell, purges nothing, queues no sweep,
//! and mints no per-entity receipt — the ratified contracts row
//! (`archived_by_cleanup`: `activeStoreHardPurgeV1 = false`,
//! `historicalSweepQueued = false`, `receipt = false`) IS the spec. It is also
//! the one reason that publishes no CRDT tombstone, because an archive is
//! local hygiene rather than a deletion intent peers must obey; see
//! `DeleteReason::publishes_crdt_tombstone`.
//!
//! **Hard deletion is NEVER automatic.** Nothing in this module hard-erases,
//! purges, or enqueues a historical sweep. Its transaction-composable archive
//! door accepts only `DeleteReason::ArchivedByCleanup`, whose behavior matrix
//! is false on every destructive row.
//!
//! # The tripwire is closed-form
//!
//! [`zero_live_members`] is a TRIPWIRE, not a score. It answers from row
//! shape and edge presence alone — no thresholds, no weights, no ranking, no
//! "probably". Two arms ship, held in the const [`CLEANUP_CHECKS`] table so a
//! third is one line:
//!
//! * Extraction-minted `PERSON` (byte 4) with zero live claims about it.
//! * `SUMMARY` (byte 8) with zero live claims about it and no member or
//!   reference edge in either direction.
//!
//! ARC_THREAD is named by the canon but **has no entity-type byte in this
//! engine**, and this ticket does not mint one. When that kind lands, its arm
//! is one row in [`CLEANUP_CHECKS`].
//!
//! ## Extraction-minted PERSON provenance
//!
//! Claim absence is not evidence of minting provenance. The trusted Core
//! extraction writer uses [`Vault::put_extraction_minted_person`] to mint a
//! PERSON with atomic, revision-bound source evidence. Only the
//! [`MACHINE_MINTED_CLAIM_SOURCES`] class is eligible. Ordinary PERSON rows,
//! replaced revisions, and missing or unreadable evidence are never candidates.
//!
//! # Posture: propose-first today, auto later
//!
//! ARCH-0066 teeth #5 (sync re-gating) and #9 (OS sandbox) are OPEN, so the
//! default posture is [`CleanupPosture::ProposeFirst`]: a run emits ONE
//! proposal carrying the impact preview (counts + ids — the preview IS the
//! proposal body) and archives nothing. Accepting RE-RUNS the tripwire per
//! entity and archives only the ones still empty; a candidate that gained a
//! live claim between proposal and accept is SKIPPED, and the skip is on the
//! run's digest receipt. Rejecting archives nothing and leaves no receipt.
//!
//! [`CleanupPosture::AutoWithDigest`] is the post-teeth path, built now and
//! reachable only by an owner flipping the `vault_meta` posture flag. It
//! archives directly and emits ONE digest receipt per run listing the ids —
//! job-level, never per-entity.
//!
//! # Not in this ticket
//!
//! * **Forgetting-window routing is OPEN/deferred** (deletion design
//!   session). This module has no interaction with forgetting windows, by
//!   decision rather than omission.
//! * **The ARCH-0024 resolver/matcher is UNBUILT.** This ticket ships the two
//!   halves that belong to the vault — an archived-aware query
//!   ([`Vault::archived_entities`]) and the restore door
//!   ([`Vault::restore_archived`]) — and records the
//!   "re-mention restores, never duplicates" contract on the door. The
//!   resolver-side hook is that program's ticket.

use std::collections::BTreeMap;

use rmpv::Value;
use uuid::Uuid;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ClaimSource;
use crate::deletion::{
    ARCHIVE_TOMBSTONE_PREFIX, DeleteReason, TombstoneReason, entity_id_from_archive_tombstone_key,
};
use crate::edge::EdgeKind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::receipt::{
    MAX_RECEIPT_QUERY_SCAN, ReceiptKind, ReceiptQuery, ReceiptRecord, hex_lower,
    retain_newest_receipt,
};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SUMMARY};
use crate::vault::{LiveEntityRow, edge_kind_prefix, live_entity_row_in_txn};

mod person_provenance;

#[cfg(test)]
mod repair_tests;
#[cfg(test)]
mod tests;

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
const PROPOSAL_PREFIX: &[u8] = b"vault_cleanup.proposal.v1:";
/// `vault_meta` key prefix for cleanup run digests (the receipt substrate).
const DIGEST_PREFIX: &[u8] = b"vault_cleanup.digest.v1:";

/// Receipt-id prefix that discriminates this projector's rows inside the
/// shared `Gate` family.
pub const VAULT_CLEANUP_RECEIPT_PREFIX: &str = "vault_cleanup:";

/// Actor recorded on a cleanup digest receipt. The cron is the engine acting
/// on its own maintenance schedule; naming it plainly keeps a reader from
/// reading an archive as something a person did.
pub const VAULT_CLEANUP_ACTOR: &str = "engine:vault_cleanup";

const PROPOSAL_ROW_LABEL: &str = "vault cleanup proposal";
const DIGEST_ROW_LABEL: &str = "vault cleanup digest";
const PROPOSAL_SCHEMA_VERSION: u64 = 1;
const DIGEST_SCHEMA_VERSION: u64 = 1;

const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_ATTEMPT: &str = "attempt";
const KEY_CREATED_AT: &str = "created_at";
const KEY_CANDIDATES: &str = "candidates";
const KEY_ENTITY: &str = "entity";
const KEY_KIND: &str = "kind";
const KEY_PROPOSAL: &str = "proposal";
const KEY_DECISION: &str = "decision";
const KEY_POSTURE: &str = "posture";
const KEY_ARCHIVED: &str = "archived";
const KEY_SKIPPED: &str = "skipped";
const KEY_AT: &str = "at";

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

/// Rows read per candidate-scan page. The scan is paged rather than
/// materialized so a vault with more PERSON rows than
/// `MAX_TYPE_QUERY_RESULTS` gets a cleanup pass instead of an overflow error.
const CLEANUP_SCAN_PAGE: usize = 1024;

/// Ceiling on rows one run will EXAMINE per entity type.
///
/// A cron that walks an unbounded index holds a read transaction for an
/// unbounded time. Stopping early is safe in a way that stopping early on a
/// deletion never is: the rows not examined are simply not archived this run,
/// and the next run starts over.
const MAX_CLEANUP_SCAN_ROWS: usize = 50_000;

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

// ---------------------------------------------------------------------------
// The tripwire
// ---------------------------------------------------------------------------

/// Claim sources treated as machine-minted.
///
/// The mint-time provenance writer and PERSON predicate share this allowlist.
/// Source evidence is necessary, but never overrides a live claim.
pub const MACHINE_MINTED_CLAIM_SOURCES: [ClaimSource; 2] =
    [ClaimSource::Generated, ClaimSource::ToolOutput];

/// Whether `source` is in the const machine-minted class.
#[must_use]
pub fn claim_source_is_machine_minted(source: ClaimSource) -> bool {
    MACHINE_MINTED_CLAIM_SOURCES.contains(&source)
}

/// Edge kinds that make a SUMMARY non-empty.
///
/// A SUMMARY body carries text, not a member list (its serialized field set
/// is `txt`/`lvl`/`at`/`src`), so "members and refs" can only be read off the
/// graph. The list is deliberately WIDE and checked in BOTH directions: every
/// kind added here can only ever REFUSE to archive, so being generous costs
/// nothing but a few rows left alone.
const SUMMARY_MEMBER_EDGE_KINDS: [EdgeKind; 7] = [
    EdgeKind::PartOf,
    EdgeKind::DerivedFrom,
    EdgeKind::About,
    EdgeKind::Mentions,
    EdgeKind::BelongsTo,
    EdgeKind::Attached,
    EdgeKind::ChildOf,
];

/// A closed-form emptiness predicate for one entity type.
type EmptinessPredicate = fn(&Vault, &heed::RoTxn<'_>, &EntityId) -> Result<bool>;

/// The ratified checker table: `(entity type byte, kind, predicate)`.
///
/// The extension point the canon asks for. ARC_THREAD activates by adding one
/// row here once that kind has an engine byte — no other edit, and nothing
/// about the two shipped arms moves.
const CLEANUP_CHECKS: [(u8, CleanupKind, EmptinessPredicate); 2] = [
    (
        ENTITY_TYPE_PERSON,
        CleanupKind::ClaimlessExtractionPerson,
        person_is_claimless,
    ),
    (
        ENTITY_TYPE_SUMMARY,
        CleanupKind::EmptySummary,
        summary_is_empty,
    ),
];

/// The tripwire: which cleanup arm, if any, `entity` trips.
///
/// `Ok(None)` for a row that is not a candidate — wrong type, absent,
/// already archived or deleted, or simply not empty. Closed-form: the answer
/// is a function of the row's type byte, its liveness, its inbound claims and
/// its edges, and nothing else. There is no score anywhere on this path.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unparseable entity header.
pub fn zero_live_members(vault: &Vault, entity: &EntityId) -> Result<Option<CleanupKind>> {
    let rtxn = vault.store.env.read_txn()?;
    zero_live_members_in_txn(vault, &rtxn, entity)
}

/// Transaction-composable [`zero_live_members`].
///
/// This is the form the accept path re-runs: passing `&*wtxn` reads the
/// caller's own uncommitted view, so a candidate that a concurrent write made
/// non-empty cannot slip past the re-check.
pub(crate) fn zero_live_members_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    entity: &EntityId,
) -> Result<Option<CleanupKind>> {
    let Some(raw) = vault.store.entities.get(rtxn, entity.as_bytes())? else {
        return Ok(None);
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity metadata"))?;
    // Never overwrite an archive marker, even if a replacement body exists.
    // Unknown/reserved marker bytes remain fail-closed and unrestorable.
    if vault.archive_tombstone_in_txn(rtxn, entity)?.is_some() {
        return Ok(None);
    }
    // Already a shell — archived by an earlier run, or deleted outright.
    // Either way there is nothing here to archive, so the pass is idempotent
    // and never re-archives its own output.
    if raw.len() == ENTITY_METADATA_HEADER_LEN
        && vault
            .store
            .entity_deletion_present_in_txn(rtxn, entity, header.learned_at)?
    {
        return Ok(None);
    }
    for (type_byte, kind, predicate) in CLEANUP_CHECKS {
        if type_byte != header.entity_type {
            continue;
        }
        return Ok(predicate(vault, rtxn, entity)?.then_some(kind));
    }
    Ok(None)
}

/// A PERSON needs positive mint-time provenance AND no live claims.
/// ONE live claim of ANY source disqualifies even an extraction-minted row.
fn person_is_claimless(vault: &Vault, rtxn: &heed::RoTxn<'_>, person: &EntityId) -> Result<bool> {
    Ok(
        person_provenance::is_extraction_minted_person_in_txn(vault, rtxn, person)?
            && !has_live_claim(vault, rtxn, person)?,
    )
}

/// A SUMMARY is a candidate exactly when nothing points at it and it points
/// at nothing: no live claim about it, and no member/reference edge in either
/// direction.
fn summary_is_empty(vault: &Vault, rtxn: &heed::RoTxn<'_>, summary: &EntityId) -> Result<bool> {
    if has_live_claim(vault, rtxn, summary)? {
        return Ok(false);
    }
    for kind in SUMMARY_MEMBER_EDGE_KINDS {
        if has_any_edge_in_txn(vault, rtxn, EdgeDirection::In, summary, kind)?
            || has_any_edge_in_txn(vault, rtxn, EdgeDirection::Out, summary, kind)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether any LIVE claim names `subject`.
///
/// A tombstoned claim leaves a 25 B shell that still answers the `claim_of`
/// edge index, so presence in that index is not liveness; the canonical
/// [`live_entity_row_in_txn`] resolver decides. An edge pointing at a row
/// that is gone is not evidence either.
fn has_live_claim(vault: &Vault, rtxn: &heed::RoTxn<'_>, subject: &EntityId) -> Result<bool> {
    for claim in vault.claims_for_subject_in_txn(rtxn, subject)? {
        if matches!(
            live_entity_row_in_txn(&vault.store, rtxn, &claim)?,
            LiveEntityRow::Live { .. }
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

enum EdgeDirection {
    In,
    Out,
}

/// Whether `id` has at least ONE edge of `kind` in `direction`.
///
/// A PRESENCE probe, not a query: it reads the first key under the
/// `(id, kind)` prefix and stops. The materializing edge readers cap at
/// `MAX_EDGE_QUERY_RESULTS` and raise `IndexOverflow` past it, which would
/// turn "this summary has far too many members to be empty" into a failed
/// cron pass. Asking only whether the first row exists cannot overflow.
fn has_any_edge_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    direction: EdgeDirection,
    id: &EntityId,
    kind: EdgeKind,
) -> Result<bool> {
    let db = match direction {
        EdgeDirection::In => &vault.store.edges_in,
        EdgeDirection::Out => &vault.store.edges_out,
    };
    let prefix = edge_kind_prefix(id, kind);
    Ok(db.prefix_iter(rtxn, &prefix)?.next().transpose()?.is_some())
}

/// Every current cleanup candidate in the vault, in checker-table order.
///
/// Paged and capped ([`MAX_CLEANUP_SCAN_ROWS`] rows examined per type): a
/// maintenance scan that cannot finish is worse than one that does part of
/// the work and leaves the rest for the next wake.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn scan_cleanup_candidates(vault: &Vault) -> Result<Vec<CleanupCandidate>> {
    let mut candidates = Vec::new();
    for (type_byte, _, _) in CLEANUP_CHECKS {
        let mut after: Option<EntityId> = None;
        let mut examined = 0_usize;
        loop {
            let page = vault.entities_by_type_page(type_byte, after.as_ref(), CLEANUP_SCAN_PAGE)?;
            if page.is_empty() {
                break;
            }
            after = page.last().copied();
            let full_page = page.len() == CLEANUP_SCAN_PAGE;
            for entity in page {
                examined += 1;
                if let Some(kind) = zero_live_members(vault, &entity)? {
                    candidates.push(CleanupCandidate { entity, kind });
                }
            }
            if !full_page || examined >= MAX_CLEANUP_SCAN_ROWS {
                break;
            }
        }
    }
    Ok(candidates)
}

// ---------------------------------------------------------------------------
// Posture flag
// ---------------------------------------------------------------------------

/// The vault's current cleanup posture.
///
/// An absent or unreadable flag reads as [`CleanupPosture::ProposeFirst`]:
/// the auto posture is a decision, and a decision nobody can read was never
/// made.
///
/// # Errors
///
/// Storage errors.
pub fn cleanup_posture(vault: &Vault) -> Result<CleanupPosture> {
    let rtxn = vault.store.env.read_txn()?;
    cleanup_posture_in_txn(vault, &rtxn)
}

fn cleanup_posture_in_txn(vault: &Vault, rtxn: &heed::RoTxn<'_>) -> Result<CleanupPosture> {
    let Some(raw) = vault
        .store
        .vault_meta
        .get(rtxn, VAULT_CLEANUP_POSTURE_KEY)?
    else {
        return Ok(CleanupPosture::ProposeFirst);
    };
    Ok(std::str::from_utf8(&raw)
        .ok()
        .and_then(CleanupPosture::parse)
        .unwrap_or(CleanupPosture::ProposeFirst))
}

/// Sets the cleanup posture. OWNER ACTION ONLY — the teeth-closing tickets
/// flip this flag; the cron never writes it.
///
/// # Errors
///
/// Storage errors.
pub fn set_cleanup_posture(vault: &Vault, posture: CleanupPosture) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, VAULT_CLEANUP_POSTURE_KEY, posture.as_str().as_bytes())?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// The job body
// ---------------------------------------------------------------------------

/// One vault-cleanup pass, as the Dreamer's `dreamer.vault_cleanup` attempt
/// runs it.
///
/// Under [`CleanupPosture::ProposeFirst`] this archives NOTHING: it scans,
/// applies the tripwire, and — if anything tripped — opens one proposal
/// carrying the impact preview. Under [`CleanupPosture::AutoWithDigest`] it
/// archives the candidates and records ONE digest listing the ids.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn run_vault_cleanup(vault: &Vault, attempt: &AttemptId) -> Result<CleanupRunReport> {
    let candidates = scan_cleanup_candidates(vault)?;
    // Read the owner's posture under the same writer lock as the decision.
    vault.with_write_txn(|wtxn| run_cleanup_candidates_in_txn(vault, wtxn, attempt, candidates))
}

fn run_cleanup_candidates_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: &AttemptId,
    candidates: Vec<CleanupCandidate>,
) -> Result<CleanupRunReport> {
    let posture = cleanup_posture_in_txn(vault, wtxn)?;
    let now = crate::unix_seconds_now();

    if candidates.is_empty() {
        return Ok(CleanupRunReport {
            attempt: *attempt,
            posture,
            candidates,
            proposal: None,
            archived: Vec::new(),
            digest: None,
        });
    }

    match posture {
        CleanupPosture::ProposeFirst => {
            let proposal = CleanupProposal {
                id: fresh_row_id()?,
                attempt: *attempt,
                created_at: now,
                candidates: candidates.clone(),
            };
            put_proposal_in_txn(vault, wtxn, &proposal)?;
            Ok(CleanupRunReport {
                attempt: *attempt,
                posture,
                candidates,
                proposal: Some(proposal.id),
                archived: Vec::new(),
                digest: None,
            })
        }
        CleanupPosture::AutoWithDigest => {
            let applied = apply_archives_in_txn(vault, wtxn, &candidates)?;
            let digest = CleanupDigest {
                id: fresh_row_id()?,
                attempt: Some(*attempt),
                proposal: None,
                decision: CleanupDecision::AutoArchived,
                posture,
                at: now,
                archived: applied.archived.clone(),
                skipped: applied.skipped,
            };
            put_digest_in_txn(vault, wtxn, &digest)?;
            Ok(CleanupRunReport {
                attempt: *attempt,
                posture,
                candidates,
                proposal: None,
                archived: applied.archived,
                digest: Some(digest.id),
            })
        }
    }
}

struct AppliedArchives {
    archived: Vec<EntityId>,
    skipped: Vec<EntityId>,
}

/// Re-checks each candidate and archives the ones still empty.
///
/// THE STALE-CANDIDATE GUARD. Between a proposal and its accept — or between
/// a scan and its archive — a candidate can gain a live claim, and a row that
/// gained a fact is no longer empty by the only definition this module has.
/// So the tripwire is re-run per entity immediately before that entity's
/// archive, and a candidate that changed is SKIPPED and named on the digest.
///
/// The caller owns ONE write transaction for re-checks, archive markers,
/// the digest, and proposal consumption. A failure rolls back the whole batch.
fn apply_archives_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    candidates: &[CleanupCandidate],
) -> Result<AppliedArchives> {
    let mut archived = Vec::new();
    let mut skipped = Vec::new();
    for candidate in candidates {
        let still_empty = zero_live_members_in_txn(vault, wtxn, &candidate.entity)?;
        if still_empty != Some(candidate.kind) {
            skipped.push(candidate.entity);
            continue;
        }
        let tombstone = crate::deletion::TombstoneValueV2 {
            reason: DeleteReason::ArchivedByCleanup.into(),
            deleted_at: crate::unix_seconds_now(),
            request_id: Uuid::now_v7().into_bytes(),
        };
        if vault.archive_cleanup_candidate_in_txn(wtxn, &candidate.entity, &tombstone)? {
            archived.push(candidate.entity);
        } else {
            skipped.push(candidate.entity);
        }
    }
    Ok(AppliedArchives { archived, skipped })
}

// ---------------------------------------------------------------------------
// Propose lane
// ---------------------------------------------------------------------------

/// Every open cleanup proposal, oldest first.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn cleanup_proposals(vault: &Vault) -> Result<Vec<CleanupProposal>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&rtxn, PROPOSAL_PREFIX)? {
        let (key, raw) = row?;
        out.push(decode_proposal(&key, &raw)?);
    }
    Ok(out)
}

/// One open proposal by id.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn cleanup_proposal(vault: &Vault, proposal: &EntityId) -> Result<Option<CleanupProposal>> {
    let rtxn = vault.store.env.read_txn()?;
    let key = proposal_key(proposal);
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &key)? else {
        return Ok(None);
    };
    decode_proposal(&key, &raw).map(Some)
}

/// Accepts an archive proposal: re-runs the tripwire per candidate, archives
/// the ones still empty, skips the rest, and records ONE digest.
///
/// The proposal row is consumed whichever way each candidate went — an
/// accepted proposal is answered, and a skipped candidate is a fact about
/// THIS accept, recorded on the digest, not a proposal left half-open.
///
/// # Errors
///
/// [`Error::VaultCleanupProposalNotFound`] when no such proposal is open;
/// storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn accept_cleanup_proposal(vault: &Vault, proposal: &EntityId) -> Result<CleanupAcceptOutcome> {
    vault.with_write_txn(|wtxn| accept_cleanup_proposal_in_txn(vault, wtxn, proposal))
}

fn accept_cleanup_proposal_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    proposal: &EntityId,
) -> Result<CleanupAcceptOutcome> {
    let key = proposal_key(proposal);
    let Some(raw) = vault.store.vault_meta.get(wtxn, &key)? else {
        return Err(Error::VaultCleanupProposalNotFound {
            proposal: proposal.to_hex(),
        });
    };
    let row = decode_proposal(&key, &raw)?;
    let applied = apply_archives_in_txn(vault, wtxn, &row.candidates)?;
    let digest = CleanupDigest {
        id: fresh_row_id()?,
        attempt: Some(row.attempt),
        proposal: Some(row.id),
        decision: CleanupDecision::ProposalAccepted,
        posture: cleanup_posture_in_txn(vault, wtxn)?,
        at: crate::unix_seconds_now(),
        archived: applied.archived.clone(),
        skipped: applied.skipped.clone(),
    };
    put_digest_in_txn(vault, wtxn, &digest)?;
    vault.store.vault_meta.delete(wtxn, &key)?;
    Ok(CleanupAcceptOutcome {
        proposal: row.id,
        archived: applied.archived,
        skipped: applied.skipped,
        digest: digest.id,
    })
}

/// Rejects an archive proposal. Nothing is archived and NO digest is written:
/// a refusal is not a decision anyone needs a receipt for, and the ratified
/// row's `receipt: false` is not a licence to receipt the refusal instead.
///
/// # Errors
///
/// [`Error::VaultCleanupProposalNotFound`] when no such proposal is open;
/// storage errors.
pub fn reject_cleanup_proposal(vault: &Vault, proposal: &EntityId) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        if !vault
            .store
            .vault_meta
            .delete(wtxn, &proposal_key(proposal))?
        {
            return Err(Error::VaultCleanupProposalNotFound {
                proposal: proposal.to_hex(),
            });
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Archive query + restore door
// ---------------------------------------------------------------------------

impl Vault {
    /// Every row this vault has archived, flagged as archived.
    ///
    /// ARCH-0024 :87 conformance, scoped to what exists: "resolver-visible"
    /// means the archived data is REACHABLE, not hidden. Archived rows still
    /// answer [`Vault::entities_by_type`] — this query is how a caller tells
    /// which of them are archived, and it is what a future resolver reads
    /// before deciding to restore.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn archived_entities(&self) -> Result<Vec<ArchivedEntity>> {
        let rtxn = self.store.env.read_txn()?;
        let mut out = Vec::new();
        for row in self
            .store
            .sync_state
            .prefix_iter(&rtxn, ARCHIVE_TOMBSTONE_PREFIX)?
        {
            let (key, raw) = row?;
            let Some(entity) = entity_id_from_archive_tombstone_key(&key) else {
                continue;
            };
            let decoded = crate::deletion::decode_tombstone_value(&raw);
            if decoded.reason != Some(TombstoneReason::ArchivedByCleanup) {
                continue;
            }
            out.push(ArchivedEntity {
                entity,
                archived_at: decoded.deleted_at,
                request_id: decoded
                    .request_id
                    .map(|bytes| Uuid::from_bytes(bytes).to_string()),
            });
        }
        Ok(out)
    }

    /// Whether — and when — `entity` is archived.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn archived_entity(&self, entity: &EntityId) -> Result<Option<ArchivedEntity>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(decoded) = self.archive_tombstone_in_txn(&rtxn, entity)? else {
            return Ok(None);
        };
        if decoded.reason != Some(TombstoneReason::ArchivedByCleanup) {
            return Ok(None);
        }
        Ok(Some(ArchivedEntity {
            entity: *entity,
            archived_at: decoded.deleted_at,
            request_id: decoded
                .request_id
                .map(|bytes| Uuid::from_bytes(bytes).to_string()),
        }))
    }

    /// Restores an archived row: clears its `archived_by_cleanup` marker and
    /// the shell is live again.
    ///
    /// # Scope: cleanup archives ONLY
    ///
    /// This is not an un-delete. An entity with no archive marker — a
    /// `user_delete` shell, a hard-purged id, a live row — is refused with
    /// [`Error::VaultCleanupRestoreNotArchived`], and a marker whose bytes do
    /// not read as an archive is refused with
    /// [`Error::VaultCleanupArchiveMarkerUndecodable`]. There is no path
    /// through this door to a tombstone the owner or a regulator asked for.
    ///
    /// It restores rather than withdraws because the archive published
    /// nothing: no peer ever saw the archive tombstone (see
    /// `DeleteReason::publishes_crdt_tombstone`), so reviving the shell takes
    /// nothing back from anyone. That is the whole reason the archive is
    /// local.
    ///
    /// # The contract this door carries (ARCH-0024 :87)
    ///
    /// **Re-mention restores, never duplicates.** When the ARCH-0024
    /// resolver lands, a re-mention that matches an archived row must call
    /// THIS door and get that row back — it must never mint a second entity
    /// for the same subject. This function is written so it cannot do
    /// otherwise: it creates nothing and mints no id, it only deletes a
    /// marker, so the restored entity is necessarily the same
    /// [`EntityId`] the archive kept. The resolver-side matching hook is that
    /// program's ticket, not this one; the contract is recorded here because
    /// this is the door it binds.
    ///
    /// Idempotent in effect but not in answer: restoring twice refuses the
    /// second time, because by then there is no archive to undo.
    ///
    /// # Errors
    ///
    /// [`Error::VaultCleanupRestoreNotArchived`],
    /// [`Error::VaultCleanupArchiveMarkerUndecodable`], storage errors.
    pub fn restore_archived(&self, entity: &EntityId) -> Result<()> {
        self.with_write_txn(|wtxn| {
            let Some(decoded) = self.archive_tombstone_in_txn(wtxn, entity)? else {
                return Err(Error::VaultCleanupRestoreNotArchived {
                    entity: entity.to_hex(),
                });
            };
            match decoded.reason {
                Some(TombstoneReason::ArchivedByCleanup) => {}
                Some(_) => {
                    return Err(Error::VaultCleanupArchiveMarkerUndecodable {
                        entity: entity.to_hex(),
                        reason: "marker carries a non-archive tombstone reason",
                    });
                }
                None => {
                    return Err(Error::VaultCleanupArchiveMarkerUndecodable {
                        entity: entity.to_hex(),
                        reason: "marker is legacy, reserved, unknown or malformed",
                    });
                }
            }
            self.clear_archive_tombstone_in_txn(wtxn, entity)?;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Row codecs
// ---------------------------------------------------------------------------

fn fresh_row_id() -> Result<EntityId> {
    EntityId::from_bytes(Uuid::now_v7().into_bytes())
}

fn proposal_key(id: &EntityId) -> Vec<u8> {
    prefixed_key(PROPOSAL_PREFIX, id)
}

fn digest_key(id: &EntityId) -> Vec<u8> {
    prefixed_key(DIGEST_PREFIX, id)
}

fn prefixed_key(prefix: &[u8], id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + ENTITY_ID_LEN);
    key.extend_from_slice(prefix);
    key.extend_from_slice(id.as_bytes());
    key
}

fn id_from_key(key: &[u8], prefix: &[u8], label: &'static str) -> Result<EntityId> {
    let tail = key
        .get(prefix.len()..)
        .ok_or(Error::CorruptedIndex(label))?
        .try_into()
        .map_err(|_| Error::CorruptedIndex(label))?;
    EntityId::from_bytes(tail).map_err(|_| Error::CorruptedIndex(label))
}

fn encode_row(row: &Value, label: &'static str) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, row).map_err(|_| Error::CorruptedIndex(label))?;
    Ok(encoded)
}

fn decode_row(raw: &[u8], label: &'static str) -> Result<Vec<(Value, Value)>> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| Error::CorruptedIndex(label))?;
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(Error::CorruptedIndex(label)),
    }
}

fn field<'a>(entries: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
}

fn id_list(entries: &[(Value, Value)], name: &str, label: &'static str) -> Result<Vec<EntityId>> {
    let Some(Value::Array(items)) = field(entries, name) else {
        return Err(Error::CorruptedIndex(label));
    };
    items
        .iter()
        .map(|item| {
            item.as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or(Error::CorruptedIndex(label))
        })
        .collect()
}

fn id_value_list(ids: &[EntityId]) -> Value {
    Value::Array(ids.iter().map(|id| Value::from(id.to_hex())).collect())
}

fn put_proposal_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    proposal: &CleanupProposal,
) -> Result<()> {
    let row = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(PROPOSAL_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ATTEMPT),
            Value::from(hex_lower(proposal.attempt.as_bytes())),
        ),
        (
            Value::from(KEY_CREATED_AT),
            Value::from(proposal.created_at),
        ),
        (
            Value::from(KEY_CANDIDATES),
            Value::Array(
                proposal
                    .candidates
                    .iter()
                    .map(|candidate| {
                        Value::Map(vec![
                            (
                                Value::from(KEY_ENTITY),
                                Value::from(candidate.entity.to_hex()),
                            ),
                            (Value::from(KEY_KIND), Value::from(candidate.kind.as_str())),
                        ])
                    })
                    .collect(),
            ),
        ),
    ]);
    let encoded = encode_row(&row, PROPOSAL_ROW_LABEL)?;
    vault
        .store
        .vault_meta
        .put(wtxn, &proposal_key(&proposal.id), &encoded)?;
    Ok(())
}

fn decode_proposal(key: &[u8], raw: &[u8]) -> Result<CleanupProposal> {
    let id = id_from_key(key, PROPOSAL_PREFIX, PROPOSAL_ROW_LABEL)?;
    let entries = decode_row(raw, PROPOSAL_ROW_LABEL)?;
    if field(&entries, KEY_SCHEMA_VERSION).and_then(Value::as_u64) != Some(PROPOSAL_SCHEMA_VERSION)
    {
        return Err(Error::CorruptedIndex(PROPOSAL_ROW_LABEL));
    }
    let attempt = field(&entries, KEY_ATTEMPT)
        .and_then(Value::as_str)
        .and_then(hex_to_bytes_16)
        .ok_or(Error::CorruptedIndex(PROPOSAL_ROW_LABEL))?;
    let created_at = field(&entries, KEY_CREATED_AT)
        .and_then(Value::as_u64)
        .ok_or(Error::CorruptedIndex(PROPOSAL_ROW_LABEL))?;
    let Some(Value::Array(items)) = field(&entries, KEY_CANDIDATES) else {
        return Err(Error::CorruptedIndex(PROPOSAL_ROW_LABEL));
    };
    let mut candidates = Vec::with_capacity(items.len());
    for item in items {
        let Value::Map(fields) = item else {
            return Err(Error::CorruptedIndex(PROPOSAL_ROW_LABEL));
        };
        let entity = field(fields, KEY_ENTITY)
            .and_then(Value::as_str)
            .and_then(|hex| EntityId::from_hex(hex).ok())
            .ok_or(Error::CorruptedIndex(PROPOSAL_ROW_LABEL))?;
        let kind = field(fields, KEY_KIND)
            .and_then(Value::as_str)
            .and_then(CleanupKind::parse)
            .ok_or(Error::CorruptedIndex(PROPOSAL_ROW_LABEL))?;
        candidates.push(CleanupCandidate { entity, kind });
    }
    Ok(CleanupProposal {
        id,
        attempt: AttemptId::from_bytes(&attempt)?,
        created_at,
        candidates,
    })
}

fn put_digest_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    digest: &CleanupDigest,
) -> Result<()> {
    let row = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DIGEST_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ATTEMPT),
            digest.attempt.map_or(Value::Nil, |attempt| {
                Value::from(hex_lower(attempt.as_bytes()))
            }),
        ),
        (
            Value::from(KEY_PROPOSAL),
            digest
                .proposal
                .map_or(Value::Nil, |id| Value::from(id.to_hex())),
        ),
        (
            Value::from(KEY_DECISION),
            Value::from(digest.decision.as_str()),
        ),
        (
            Value::from(KEY_POSTURE),
            Value::from(digest.posture.as_str()),
        ),
        (Value::from(KEY_AT), Value::from(digest.at)),
        (Value::from(KEY_ARCHIVED), id_value_list(&digest.archived)),
        (Value::from(KEY_SKIPPED), id_value_list(&digest.skipped)),
    ]);
    let encoded = encode_row(&row, DIGEST_ROW_LABEL)?;
    vault
        .store
        .vault_meta
        .put(wtxn, &digest_key(&digest.id), &encoded)?;
    Ok(())
}

fn decode_digest(key: &[u8], raw: &[u8]) -> Result<CleanupDigest> {
    let id = id_from_key(key, DIGEST_PREFIX, DIGEST_ROW_LABEL)?;
    let entries = decode_row(raw, DIGEST_ROW_LABEL)?;
    if field(&entries, KEY_SCHEMA_VERSION).and_then(Value::as_u64) != Some(DIGEST_SCHEMA_VERSION) {
        return Err(Error::CorruptedIndex(DIGEST_ROW_LABEL));
    }
    let attempt = match field(&entries, KEY_ATTEMPT) {
        Some(Value::Nil) | None => None,
        Some(value) => Some(AttemptId::from_bytes(
            &value
                .as_str()
                .and_then(hex_to_bytes_16)
                .ok_or(Error::CorruptedIndex(DIGEST_ROW_LABEL))?,
        )?),
    };
    let proposal = match field(&entries, KEY_PROPOSAL) {
        Some(Value::Nil) | None => None,
        Some(value) => Some(
            value
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or(Error::CorruptedIndex(DIGEST_ROW_LABEL))?,
        ),
    };
    Ok(CleanupDigest {
        id,
        attempt,
        proposal,
        decision: field(&entries, KEY_DECISION)
            .and_then(Value::as_str)
            .and_then(CleanupDecision::parse)
            .ok_or(Error::CorruptedIndex(DIGEST_ROW_LABEL))?,
        posture: field(&entries, KEY_POSTURE)
            .and_then(Value::as_str)
            .and_then(CleanupPosture::parse)
            .ok_or(Error::CorruptedIndex(DIGEST_ROW_LABEL))?,
        at: field(&entries, KEY_AT)
            .and_then(Value::as_u64)
            .ok_or(Error::CorruptedIndex(DIGEST_ROW_LABEL))?,
        archived: id_list(&entries, KEY_ARCHIVED, DIGEST_ROW_LABEL)?,
        skipped: id_list(&entries, KEY_SKIPPED, DIGEST_ROW_LABEL)?,
    })
}

fn hex_to_bytes_16(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0_u8; 16];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Every cleanup decision this vault has recorded, in decision order.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn cleanup_digests(vault: &Vault) -> Result<Vec<CleanupDigest>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&rtxn, DIGEST_PREFIX)? {
        let (key, raw) = row?;
        out.push(decode_digest(&key, &raw)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Receipts (a projector in the `Gate` family)
// ---------------------------------------------------------------------------

/// Whether a receipt is a vault-cleanup run digest.
#[must_use]
pub fn is_vault_cleanup_receipt(record: &ReceiptRecord) -> bool {
    record.receipt_kind == ReceiptKind::Gate
        && record.receipt_id.starts_with(VAULT_CLEANUP_RECEIPT_PREFIX)
}

/// The exclusive upper bound of the digest keyspace.
fn digest_key_range_end() -> Vec<u8> {
    let mut end = DIGEST_PREFIX.to_vec();
    if let Some(last) = end.last_mut() {
        *last = last.saturating_add(1);
    }
    end
}

/// Projects the cleanup digest ledger as `Gate` receipts.
///
/// The cron's decision to archive IS a gate decision — the engine ruled on
/// rows it may remove from view — so it mints no receipt kind of its own,
/// following `consent_graduation::ramp_receipts`,
/// `edit_distance::escalation` and `skill_optimize`'s verdict projector down
/// to the discriminating id prefix. Opens its own read txn, as they do.
///
/// ONE receipt per DECISION, never one per entity: the ratified contracts row
/// pins `receipt: false` for the `archived_by_cleanup` tombstone, and this is
/// the job-level record that replaces it. The archived ids ride the digest's
/// fields, so the per-entity fact is still auditable without a per-entity
/// receipt.
///
/// Bounded like its siblings: digest keys are UUIDv7-ordered, so walking them
/// newest-first under [`MAX_RECEIPT_QUERY_SCAN`] spends the work bound on the
/// decisions a reader asked for.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub(crate) fn cleanup_receipts(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let end = digest_key_range_end();
    let bounds = (
        std::ops::Bound::Included(DIGEST_PREFIX),
        std::ops::Bound::Excluded(&end[..]),
    );
    let mut out = Vec::new();
    // One row PAST the cap is reached and never decoded: it is what separates
    // a ledger holding exactly the cap from one the cap truncated.
    for (scanned, row) in vault
        .store
        .vault_meta
        .rev_range(&rtxn, &bounds)?
        .take(MAX_RECEIPT_QUERY_SCAN + 1)
        .enumerate()
    {
        if scanned == MAX_RECEIPT_QUERY_SCAN {
            tracing::warn!(
                scan_cap = MAX_RECEIPT_QUERY_SCAN,
                "vault cleanup digest scan hit the receipt-family work cap; older runs were not \
                 projected"
            );
            break;
        }
        let (key, raw) = row?;
        let record = cleanup_digest_receipt(&decode_digest(&key, &raw)?);
        if !query.matches(&record) {
            continue;
        }
        if query.job_ref.is_some() {
            out.push(record);
        } else {
            retain_newest_receipt(&mut out, record, query.limit);
        }
    }
    Ok(out)
}

fn cleanup_digest_receipt(digest: &CleanupDigest) -> ReceiptRecord {
    let mut fields = BTreeMap::from([
        (FIELD_CLEANUP_PHASE.to_owned(), CLEANUP_PHASE.to_owned()),
        (
            FIELD_CLEANUP_DECISION.to_owned(),
            digest.decision.as_str().to_owned(),
        ),
        (
            FIELD_CLEANUP_POSTURE.to_owned(),
            digest.posture.as_str().to_owned(),
        ),
        (
            FIELD_CLEANUP_ARCHIVED_COUNT.to_owned(),
            digest.archived.len().to_string(),
        ),
        (
            FIELD_CLEANUP_SKIPPED_COUNT.to_owned(),
            digest.skipped.len().to_string(),
        ),
        (
            FIELD_CLEANUP_ARCHIVED_IDS.to_owned(),
            join_ids(&digest.archived),
        ),
        (
            FIELD_CLEANUP_SKIPPED_IDS.to_owned(),
            join_ids(&digest.skipped),
        ),
        (
            FIELD_CLEANUP_TOMBSTONE_REASON.to_owned(),
            DeleteReason::ArchivedByCleanup.as_str().to_owned(),
        ),
    ]);
    if let Some(proposal) = digest.proposal {
        fields.insert(FIELD_CLEANUP_PROPOSAL.to_owned(), proposal.to_hex());
    }
    ReceiptRecord {
        receipt_id: format!("{VAULT_CLEANUP_RECEIPT_PREFIX}{}", digest.id.to_hex()),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: digest.at,
        actor: Some(VAULT_CLEANUP_ACTOR.to_owned()),
        on_behalf_of: None,
        outcome: digest.decision.as_str().to_owned(),
        job_ref: digest.attempt.map(|attempt| hex_lower(attempt.as_bytes())),
        trigger_ref: digest
            .proposal
            .map(|proposal| format!("vault_cleanup_proposal:{}", proposal.to_hex())),
        policy_trace: vec![format!("vault_cleanup.{}", digest.decision.as_str())],
        fields,
    }
}

fn join_ids(ids: &[EntityId]) -> String {
    ids.iter()
        .map(EntityId::to_hex)
        .collect::<Vec<_>>()
        .join(",")
}
