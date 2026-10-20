//! Signed piece receipts applied to anonymous custody (TL-6; CALLS
//! TL6_ANON_RECEIPT_APPLICATION). Each receipt is verified against the
//! intake's receipt key ring, then matched to its row by the exact C the row
//! stores, through a map built in the writer from the rows the page names:
//! no index. In one writer, a piece takes only a strictly newer revision; an
//! exact repeat is idempotent, and a different receipt at the revision
//! applied already applies nothing and stays retryable. A signed state never
//! clears a withdrawal intent, and no receipt here names a run, so none is
//! recorded. An unsigned refusal changes nothing durable: it goes back to
//! the caller to schedule.
//!
//! The state mapping: `uploading` keeps its cursor; `accepted` records that
//! the intake holds the piece whole in quarantine, never eligibility or a V2
//! `stored`; `rejected`, `conflict` and `invalid_submission` keep their
//! reason and are sent again later; `eligible` and `refused` are the
//! re-filter's answers; `removal_pending` waits; `removed` completes the
//! remote removal; `unknown` says the intake holds nothing, so the upload
//! resumes from its start, and never stands in for `removed`. When a
//! `removed` makes the purge done (TL-5), the same writer stages the
//! training link key's retirement, finished after it commits.

use std::collections::{BTreeMap, BTreeSet};

use oneiron_vault_contract::conversation_training::{
    PieceOutcomeV1, PieceReceiptBodyV1, PieceReceiptPageV1, PieceResultV1, PieceStateV1,
};

use crate::Vault;
use crate::error::Result;

use super::super::crypto::IntakeReceiptKey;
use super::super::custody::{self, SUBMISSION, SUBMISSIONS, SubmissionCustody, put_submission_in};
use super::super::lifecycle::TrainingSubmissionId;
use super::{AnonymousCursor, AnonymousPiece, TrainingPieceState, TrainingTransport};

/// What one application did. It names submissions, never a C.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnonymousApplied {
    /// Signed receipts applied, each strictly newer than its piece's last.
    pub applied: usize,
    /// Signed receipts at or before a piece's last revision that repeat
    /// what it holds, or are older: nothing to apply.
    pub repeated: usize,
    /// Pieces a signed receipt contradicted at the revision they hold:
    /// nothing applied; ask their receipts again later.
    pub contradicted: Vec<TrainingSubmissionId>,
    /// The intake's unsigned refusals of single entries: nothing durable
    /// changed, and each is the caller's to schedule.
    pub refused: Vec<AnonymousRefusal>,
    /// Receipts no key of the ring verifies, or about another code than
    /// their entry's, and receipts and refusals that match no piece's
    /// stored C: nothing applied.
    pub unverified: usize,
}

/// The intake's unsigned refusal of one piece's entry. On
/// `recipient_refresh_required` the caller hands the piece to
/// [`Vault::anonymous_refresh_required`]; on any other error it sends the
/// entry again once `retry_after_secs` passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnonymousRefusal {
    /// The submission whose piece the entry was.
    pub id: TrainingSubmissionId,
    /// One of the window's `PIECE_ERROR_*` codes.
    pub error: String,
    /// How long the intake asked the caller to wait first, in seconds.
    pub retry_after_secs: Option<u64>,
}

/// One unsigned refusal as read, before its piece is found.
struct Refusal<'a> {
    code: &'a str,
    error: &'a str,
    retry_after_secs: Option<u64>,
}

/// One piece the writer touches: its row as read, and whether it changed.
struct Piece {
    id: TrainingSubmissionId,
    row: SubmissionCustody,
    dirty: bool,
}

/// What one signed receipt does to its piece.
enum Outcome {
    /// Strictly newer: applied.
    Applied,
    /// The revision held, unchanged, or an older one: nothing to apply.
    Repeated,
    /// A different receipt at the revision held: nothing applied.
    Contradicted,
}

impl Vault {
    /// Applies the intake's answers to one batch (TL-6): every signed
    /// receipt the `ring` verifies, a `duplicate` one by the same rules, on
    /// the piece whose stored C it names, in one writer; every unsigned
    /// refusal handed back for scheduling.
    ///
    /// # Errors
    /// Storage faults: nothing is applied.
    pub fn apply_anonymous_results(
        &self,
        results: &[PieceResultV1],
        ring: &IntakeReceiptKey,
    ) -> Result<AnonymousApplied> {
        let mut applied = AnonymousApplied::default();
        let mut signed = Vec::new();
        let mut refusals = Vec::new();
        for result in results {
            match &result.outcome {
                PieceOutcomeV1::Receipt { receipt, .. } => {
                    if receipt.body.code == result.code && ring.verify_piece_receipt(receipt) {
                        signed.push(&receipt.body);
                    } else {
                        applied.unverified += 1;
                    }
                }
                PieceOutcomeV1::Refused {
                    error,
                    retry_after_secs,
                } => refusals.push(Refusal {
                    code: result.code.as_str(),
                    error: error.as_str(),
                    retry_after_secs: *retry_after_secs,
                }),
            }
        }
        apply_in_one_writer(self, &signed, &refusals, applied)
    }

    /// Applies one page of the intake's signed receipts (TL-6): every
    /// receipt the `ring` verifies, in the order each entry lists them, on
    /// the piece whose stored C it names, in one writer.
    ///
    /// # Errors
    /// Storage faults: nothing is applied.
    pub fn apply_anonymous_receipt_page(
        &self,
        page: &PieceReceiptPageV1,
        ring: &IntakeReceiptKey,
    ) -> Result<AnonymousApplied> {
        let mut applied = AnonymousApplied::default();
        let mut signed = Vec::new();
        for entry in &page.entries {
            for receipt in &entry.receipts {
                if receipt.body.code == entry.code && ring.verify_piece_receipt(receipt) {
                    signed.push(&receipt.body);
                } else {
                    applied.unverified += 1;
                }
            }
        }
        apply_in_one_writer(self, &signed, &[], applied)
    }
}

/// Applies `signed` receipts and matches `refusals` to their pieces, in one
/// writer, staging the training link key's retirement when a `removed` made
/// the purge done; that retirement is finished after the commit.
fn apply_in_one_writer(
    vault: &Vault,
    signed: &[&PieceReceiptBodyV1],
    refusals: &[Refusal<'_>],
    mut applied: AnonymousApplied,
) -> Result<AnonymousApplied> {
    if signed.is_empty() && refusals.is_empty() {
        return Ok(applied);
    }
    let removes = signed
        .iter()
        .any(|body| body.state == PieceStateV1::Removed);
    let staged = vault.with_write_txn_grouped(|txn| {
        let wanted: BTreeSet<&str> = signed
            .iter()
            .map(|body| body.code.as_str())
            .chain(refusals.iter().map(|refusal| refusal.code))
            .collect();
        let mut pieces = pieces_named(vault, txn, &wanted)?;
        let done_before = removes && custody::purge_removed(vault, txn)?;
        for body in signed {
            let Some(piece) = pieces.get_mut(body.code.as_str()) else {
                applied.unverified += 1;
                continue;
            };
            match apply_receipt(&mut piece.row.anonymous, body) {
                Outcome::Applied => {
                    applied.applied += 1;
                    piece.dirty = true;
                }
                Outcome::Repeated => applied.repeated += 1,
                Outcome::Contradicted => {
                    if !applied.contradicted.contains(&piece.id) {
                        applied.contradicted.push(piece.id);
                    }
                }
            }
        }
        for refusal in refusals {
            match pieces.get(refusal.code) {
                Some(piece) => applied.refused.push(AnonymousRefusal {
                    id: piece.id,
                    error: refusal.error.to_owned(),
                    retry_after_secs: refusal.retry_after_secs,
                }),
                None => applied.unverified += 1,
            }
        }
        for piece in pieces.values().filter(|piece| piece.dirty) {
            put_submission_in(vault, txn, piece.id, &piece.row)?;
        }
        if !removes || done_before || !custody::purge_removed(vault, txn)? {
            return Ok(false);
        }
        // TL-5: the last piece of the purge is removed; the training link
        // key may retire. Finished after this write commits.
        let generation = custody::state(vault, txn)?.link_generation;
        vault
            .store
            .stage_training_link_retirement_in_txn(txn, generation)?;
        Ok(true)
    })?;
    if staged {
        vault.finish_training_link_retirement_after_commit();
    }
    Ok(applied)
}

/// The anonymous rows whose stored C is among `wanted`, keyed by it as the
/// wire spells it: one walk over the custody rows, no index.
fn pieces_named(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wanted: &BTreeSet<&str>,
) -> Result<BTreeMap<String, Piece>> {
    let mut pieces = BTreeMap::new();
    if wanted.is_empty() {
        return Ok(pieces);
    }
    for row in SUBMISSIONS.iter_from(&vault.store, txn, &SUBMISSION)? {
        let ((_, id), row) = row?;
        if row.transport != TrainingTransport::Anonymous {
            continue;
        }
        let code = oneiron_vault_contract::hex(&row.piece);
        if wanted.contains(code.as_str()) {
            let piece = Piece {
                id: TrainingSubmissionId(id),
                row,
                dirty: false,
            };
            pieces.insert(code, piece);
        }
    }
    Ok(pieces)
}

/// Applies one verified receipt to its piece: only a strictly newer
/// revision (or the first receipt the piece takes), by the state mapping.
/// It never touches the withdrawal intent.
fn apply_receipt(piece: &mut AnonymousPiece, body: &PieceReceiptBodyV1) -> Outcome {
    if piece.state.is_some() && body.revision <= piece.revision {
        return if body.revision < piece.revision || holds(piece, body) {
            Outcome::Repeated
        } else {
            Outcome::Contradicted
        };
    }
    piece.revision = body.revision;
    piece.state = Some(TrainingPieceState::of(&body.state));
    piece.reason = reason_of(&body.state).map(str::to_owned);
    piece.at = Some(body.at);
    match &body.state {
        PieceStateV1::Uploading { cursor } => piece.cursor = Some(AnonymousCursor::of(cursor)),
        PieceStateV1::Accepted | PieceStateV1::Eligible | PieceStateV1::Refused { .. } => {
            piece.accepted = true;
        }
        PieceStateV1::Unknown => piece.cursor = None,
        PieceStateV1::Rejected { .. }
        | PieceStateV1::Conflict
        | PieceStateV1::InvalidSubmission
        | PieceStateV1::RemovalPending
        | PieceStateV1::Removed => {}
    }
    Outcome::Applied
}

/// Whether `piece` already holds exactly what `body` says, at its revision.
fn holds(piece: &AnonymousPiece, body: &PieceReceiptBodyV1) -> bool {
    let cursor = match &body.state {
        PieceStateV1::Uploading { cursor } => piece.cursor == Some(AnonymousCursor::of(cursor)),
        _ => true,
    };
    cursor
        && piece.state == Some(TrainingPieceState::of(&body.state))
        && piece.reason.as_deref() == reason_of(&body.state)
        && piece.at == Some(body.at)
}

/// The reason a signed state carries, if it carries one.
fn reason_of(state: &PieceStateV1) -> Option<&str> {
    match state {
        PieceStateV1::Rejected { reason } | PieceStateV1::Refused { reason } => {
            Some(reason.as_str())
        }
        _ => None,
    }
}
