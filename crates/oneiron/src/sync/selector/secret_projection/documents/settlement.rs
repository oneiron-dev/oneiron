//! Owner settlement of a retained document-copy lineage (FIX12419, document-only).
//!
//! Native owner review and exact canonical replacement for the current retained
//! projection-copy lineage of one marked source document. No new ledger, table,
//! directive, `x:` authority gate, presence gate, or raw held stash; no fake ACK,
//! window settlement, or 12775 convergence claim.
//!
//! Review recomputes the actual ruled cause from the current canonical source,
//! the current masked copy, and the stored lineage text, without bringing the
//! lineage current (which would overwrite the proposal). It answers `Some`
//! only for a current retained nonempty lineage whose recomputed visible diff
//! is [`SealedFileEdited`](crate::origin::secret_projection::edit::RepoProjectionDiffResult::SealedFileEdited)
//! or [`ProjectionEditConflict`](crate::origin::secret_projection::edit::RepoProjectionDiffResult::ProjectionEditConflict),
//! including an `Applied` whose bytes are not UTF-8 (the same conflict the
//! import writer keeps). No mark, an unread copy, or no actual held cause
//! answers `None`, never an arbitrary force-write.
//!
//! The review token is NOT authority: [`RepoCopyEditReview::approval_for`]
//! binds the opaque revision and the exact replacement target so the setter can
//! refuse a stale review or a later edit, but the owner's authority comes only
//! from [`AuthenticatedOwner`](crate::consent::AuthenticatedOwner) revalidated
//! in the setter's own writer. See `docs/ops/repo-sync-settlement.md`.

use heed::{RoTxn, RwTxn};
use loro::VersionVector;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::origin::RepoProjectionHoldCause;
use crate::origin::secret_projection::edit::RepoProjectionDiffResult;
use crate::origin::secret_projection::index::RepoIndexMarks;

/// The sole hash domain of the settlement review and approval tokens
/// (FIX12419). Both the opaque revision and the exact-approval token derive
/// from it; every variable-length component is length-framed (`u64` BE length
/// then bytes) before hashing. No numeric policy constant is introduced.
const SETTLEMENT_REVIEW_DOMAIN: &str = "oneiron.repo-sync-settlement.review.v1";

/// The owner's review of one retained document-copy edit: the source it was
/// read from, the ruled held cause, the lineage's retained submitted text,
/// and the opaque revision the exact-approval token binds.
///
/// The submitted text is the masked copy's retained text as the lineage holds
/// it, shown so the owner can review what the peer wrote; the canonical
/// replacement the owner supplies is separate. The revision binds the source
/// id and incarnation, the source full text and canonical source version
/// vector, the current copy stamp and blob, and the exact lineage version
/// vector, submitted text, and cause. It is a token, not authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoCopyEditReview {
    source: EntityId,
    cause: RepoProjectionHoldCause,
    submitted: String,
    revision: [u8; 32],
}

impl RepoCopyEditReview {
    /// The marked source document this review was read from.
    #[must_use]
    pub fn source(&self) -> EntityId {
        self.source
    }

    /// The recomputed ruled held cause: a sealed-file edit or a projection
    /// conflict (including an applied text that is not UTF-8).
    #[must_use]
    pub fn cause(&self) -> RepoProjectionHoldCause {
        self.cause
    }

    /// The lineage's retained submitted text: the masked copy text the peer's
    /// edit left, as stored, for the owner to review.
    #[must_use]
    pub fn submitted(&self) -> &str {
        &self.submitted
    }

    /// The opaque revision this review binds: source id and incarnation,
    /// source text and canonical source vector, copy stamp and blob, lineage
    /// vector, submitted text, and cause, hashed under
    /// [`SETTLEMENT_REVIEW_DOMAIN`].
    #[must_use]
    pub fn revision(&self) -> &[u8; 32] {
        &self.revision
    }

    /// The exact-approval token for `replacement`: the revision plus the exact
    /// canonical target, hashed under [`SETTLEMENT_REVIEW_DOMAIN`] with the
    /// replacement length-framed. The setter recomputes the review in its own
    /// writer and compares this token before any write; a mismatch refuses
    /// stale. The token is NOT authority and proves no owner.
    #[must_use]
    pub fn approval_for(&self, replacement: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(SETTLEMENT_REVIEW_DOMAIN);
        hasher.update(&self.revision);
        hasher.update(&(replacement.len() as u64).to_be_bytes());
        hasher.update(replacement.as_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// The setter's opaque in-writer carry from review to finish (FIX12419):
/// the reviewed source, its copy blob, and the source's Unicode-scalar length
/// at review time. Fields stay private so callers cannot fabricate proof from
/// metadata; only the scalar-count getter is exposed, for the canonical
/// whole-text replacement (`start` 0, `delete` this length). This helper
/// performs no authority by itself.
pub(crate) struct CopySettlement {
    source: EntityId,
    blob: [u8; 32],
    delete: usize,
}

impl CopySettlement {
    /// The source text's Unicode-scalar count at review time: the `delete`
    /// of the canonical whole-text replacement.
    pub(crate) fn source_len(&self) -> usize {
        self.delete
    }
}

/// The current review of `source`'s retained copy lineage in `txn`, without
/// bringing the lineage current: `None` for no mark, an unread copy, an empty
/// lineage, or no actual held cause (unchanged or cleanly applied, including
/// an applied text that lands).
///
/// # Errors
/// A store failure, a mark that does not decode and names no blob, a failed
/// copy id derivation, or the visible diff's own failure.
pub(crate) fn review_repo_copy_edit_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    source: EntityId,
) -> Result<Option<RepoCopyEditReview>> {
    Ok(current_in_txn(vault, txn, source)?.map(|(review, _)| review))
}

/// The settlement carry for `source` in `txn`, after recomputing the current
/// review and comparing `approval` against `approval_for(replacement)`
/// before any write. No authority is checked here; the caller revalidates the
/// owner, eligibility, and the non-NOTE guard in the same writer first.
///
/// # Errors
/// [`ArtifactError::EditProposalStale`] when no held review stands now or the
/// approval does not match the recomputed review and exact replacement; a
/// store, mark, copy id, or visible diff failure otherwise.
pub(crate) fn begin_repo_copy_settlement_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    source: EntityId,
    approval: &[u8; 32],
    replacement: &str,
) -> Result<CopySettlement> {
    let Some((review, settlement)) = current_in_txn(vault, txn, source)? else {
        return Err(Error::Artifact(ArtifactError::EditProposalStale));
    };
    if review.approval_for(replacement) != *approval {
        return Err(Error::Artifact(ArtifactError::EditProposalStale));
    }
    Ok(settlement)
}

/// The post-edit half of the settlement in the same writer: reloads the ACTUAL
/// persisted source text (admission and the lift may have altered the
/// replacement), carries the reviewed copy blob's marks onto those actual
/// bytes, then refreshes the SAME lineage and mask from the actual document.
///
/// # Errors
/// A store failure, the mark carry's own failure, or the lineage refresh's
/// own failure. An [`Error::InvariantViolation`] when the settled source has
/// no text after its canonical edit.
pub(crate) fn finish_repo_copy_settlement_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    settlement: &CopySettlement,
) -> Result<()> {
    let Some(sync_text) = crate::entity_doc::sync_text_in(vault, txn, &settlement.source)? else {
        return Err(Error::InvariantViolation("settled source has no text"));
    };
    let actual = sync_text.doc.get_text(super::BODY).to_string();
    crate::origin::secret_marks::carry_repo_secret_marks_in_txn(
        vault,
        txn,
        &settlement.blob,
        actual.as_bytes(),
        settlement.source,
    )?;
    let _ = super::document_copy_in_txn(vault, txn, settlement.source, &sync_text.doc)?;
    Ok(())
}

/// The current review and its settlement carry, or `None` for no mark, an
/// unread copy, an empty lineage, or no actual held cause. Reads the current
/// source, projection, and lineage without bringing the lineage current.
fn current_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    source: EntityId,
) -> Result<Option<(RepoCopyEditReview, CopySettlement)>> {
    let marks = RepoIndexMarks::read_scoped_in_txn(vault, txn)?;
    if marks.is_empty() {
        return Ok(None);
    }
    let Some(sync_text) = crate::entity_doc::sync_text_in(vault, txn, &source)? else {
        return Ok(None);
    };
    let text = sync_text.doc.get_text(super::BODY).to_string();
    let source_vv = sync_text.doc.oplog_vv();
    let Some(copy) = super::text_copy_in_txn(vault, txn, &marks, &source, &text)? else {
        return Ok(None);
    };
    if copy.unread() {
        return Ok(None);
    }
    let id = crate::origin::secret_projection::copy_id::copy_id(&source)?;
    let lineage = super::load_lineage(vault, txn, id)?;
    let lineage_vv = lineage.oplog_vv();
    if lineage_vv.is_empty() {
        return Ok(None);
    }
    let submitted = lineage.get_text(super::BODY).to_string();
    let result = super::copy_diff_result(&text, &copy, &submitted)?;
    let cause = match result {
        RepoProjectionDiffResult::Unchanged => return Ok(None),
        RepoProjectionDiffResult::Applied(applied) => match String::from_utf8(applied) {
            Ok(_) => return Ok(None),
            Err(_) => RepoProjectionHoldCause::ProjectionEditConflict,
        },
        RepoProjectionDiffResult::SealedFileEdited => RepoProjectionHoldCause::SealedFileEdited,
        RepoProjectionDiffResult::ProjectionEditConflict => {
            RepoProjectionHoldCause::ProjectionEditConflict
        }
    };
    let incarnation = crate::entity_doc::source_incarnation_in_txn(&vault.store, txn, &source)?
        .unwrap_or_default();
    let revision = revision_hash(
        &source,
        &incarnation,
        &text,
        &source_vv,
        &copy.stamp,
        &copy.blob,
        &lineage_vv,
        &submitted,
        cause,
    );
    let delete = text.chars().count();
    let review = RepoCopyEditReview {
        source,
        cause,
        submitted,
        revision,
    };
    let settlement = CopySettlement {
        source,
        blob: copy.blob,
        delete,
    };
    Ok(Some((review, settlement)))
}

/// The opaque revision: source id and incarnation, source text and canonical
/// source vector, copy stamp and blob, lineage vector, submitted text, and
/// cause, hashed under [`SETTLEMENT_REVIEW_DOMAIN`] with every
/// variable-length component length-framed.
#[expect(
    clippy::too_many_arguments,
    reason = "the revision binds nine components in one call"
)]
fn revision_hash(
    source: &EntityId,
    incarnation: &str,
    text: &str,
    source_vv: &VersionVector,
    stamp: &[u8; 32],
    blob: &[u8; 32],
    lineage_vv: &VersionVector,
    submitted: &str,
    cause: RepoProjectionHoldCause,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SETTLEMENT_REVIEW_DOMAIN);
    hasher.update(source.as_bytes());
    hasher.update(&(incarnation.len() as u64).to_be_bytes());
    hasher.update(incarnation.as_bytes());
    hasher.update(&(text.len() as u64).to_be_bytes());
    hasher.update(text.as_bytes());
    canonical_vv(&mut hasher, source_vv);
    hasher.update(stamp);
    hasher.update(blob);
    canonical_vv(&mut hasher, lineage_vv);
    hasher.update(&(submitted.len() as u64).to_be_bytes());
    hasher.update(submitted.as_bytes());
    let cause_str = cause.as_str();
    hasher.update(&(cause_str.len() as u64).to_be_bytes());
    hasher.update(cause_str.as_bytes());
    *hasher.finalize().as_bytes()
}

/// The canonical hash of `vv`: its `(peer, counter)` pairs sorted, count then
/// each pair (`u64` then `i32`, both BE). `VersionVector::encode` ordering is
/// NOT assumed deterministic, so the pairs are sorted before hashing.
fn canonical_vv(hasher: &mut blake3::Hasher, vv: &VersionVector) {
    let mut pairs: Vec<(u64, i32)> = vv.iter().map(|(peer, counter)| (*peer, *counter)).collect();
    pairs.sort_unstable();
    hasher.update(&(pairs.len() as u64).to_be_bytes());
    for (peer, counter) in pairs {
        hasher.update(&peer.to_be_bytes());
        hasher.update(&counter.to_be_bytes());
    }
}
