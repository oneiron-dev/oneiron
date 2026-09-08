//! Closed-form cleanup checks, the posture door, and the job body.

use super::person_provenance;
use super::rollout;
use super::scan;
use super::{
    CleanupCandidate, CleanupDecision, CleanupDigest, CleanupKind, CleanupPosture, CleanupProposal,
    CleanupRunReport, MAX_CLEANUP_SCAN_ROWS, VAULT_CLEANUP_POSTURE_KEY, fresh_row_id,
    put_digest_in_txn, put_proposal_in_txn,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ClaimSource;
use crate::deletion::DeleteReason;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SUMMARY};
use crate::vault::{LiveEntityRow, edge_kind_prefix, live_entity_row_in_txn};
use uuid::Uuid;

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
pub(super) const CLEANUP_CHECKS: [(u8, CleanupKind, EmptinessPredicate); 2] = [
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
/// Paged and capped (`MAX_CLEANUP_SCAN_ROWS` rows examined per type): a
/// maintenance scan that cannot finish is worse than one that does part of
/// the work and leaves the rest for the next wake.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn scan_cleanup_candidates(vault: &Vault) -> Result<Vec<CleanupCandidate>> {
    let txn = vault.store.env.read_txn()?;
    Ok(scan::scan_in_txn(vault, &txn, MAX_CLEANUP_SCAN_ROWS)?.candidates)
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

pub(super) fn cleanup_posture_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> Result<CleanupPosture> {
    if !rollout::auto_enabled(vault, rtxn)? {
        return Ok(CleanupPosture::ProposeFirst);
    }
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
        if posture == CleanupPosture::AutoWithDigest && !rollout::auto_enabled(vault, wtxn)? {
            return Err(Error::InvariantViolation(
                "automatic cleanup rollout blockers are open",
            ));
        }
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
    scan::run_with_limit(vault, attempt, MAX_CLEANUP_SCAN_ROWS)
}

pub(super) fn run_cleanup_candidates_in_txn(
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

pub(super) struct AppliedArchives {
    pub(super) archived: Vec<EntityId>,
    pub(super) skipped: Vec<EntityId>,
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
pub(super) fn apply_archives_in_txn(
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
