//! The self-host shipper's pages over anonymous custody (TL-6): the pieces
//! to upload, the codes to withdraw and the codes whose next signed state is
//! owed. Each page walks the custody rows in key order past an exclusive
//! continuation cursor, so every row is reached in rotation; a page is a
//! pace, never a cap, and the rest come on the next. While the vault's
//! "Learn from my conversations" setting is off, uploads pause, first
//! windows and later ones alike, and resume once it is back on;
//! withdrawals and receipts keep going, since switching it off stops new
//! sharing, never erasure. Nothing here logs a C.

use std::ops::Bound;

use oneiron_vault_contract::conversation_training::PieceCursorV1;

use crate::Vault;
use crate::error::Result;

use super::super::custody::{
    self, CustodyKey, SUBMISSION, SUBMISSIONS, SubmissionCustody, SubmissionState,
    put_submission_in,
};
use super::super::lifecycle::TrainingSubmissionId;
use super::{TrainingPieceState, TrainingTransport};

/// CALLS TL6_ANON_PAGE: the rows one shipper page lists, the pace the
/// shipper passes as `page`. Never a cap: the rest come on the next page.
pub const ANONYMOUS_PAGE: usize = 64;

/// One anonymous piece to upload a window of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnonymousUploadWork {
    /// The submission, whose released files carry the piece.
    pub id: TrainingSubmissionId,
    /// The piece's C, 64 lower-case hex: its only handle at the intake.
    /// Never logged.
    pub code: String,
    /// Where the intake's last signed receipt says the upload resumes;
    /// `None` from its start.
    pub cursor: Option<PieceCursorV1>,
}

/// One anonymous piece to withdraw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnonymousWithdrawalWork {
    /// The submission.
    pub id: TrainingSubmissionId,
    /// The piece's C, 64 lower-case hex. Never logged.
    pub code: String,
}

/// One anonymous piece whose next signed state is owed, for the receipts
/// ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnonymousStatusWork {
    /// The submission.
    pub id: TrainingSubmissionId,
    /// The piece's C, 64 lower-case hex. Never logged.
    pub code: String,
    /// The revision of the last signed receipt applied: ask past it.
    pub revision: u64,
}

impl Vault {
    /// One page of the anonymous pieces to upload, past `after` (from the
    /// first with none), at most `page` of them (a pace: the shipper passes
    /// [`ANONYMOUS_PAGE`]): each published piece whose files are still here,
    /// that carries no withdrawal intent, and that the intake has not yet
    /// taken whole, filtered, refused or removed; with its C and its stored
    /// cursor. Rejected, conflicting, invalid and unknown pieces are sent
    /// again. The continuation comes back while more rows may follow; `None`
    /// once the page reached the end, and the next walk starts over. While
    /// the vault's setting is off it lists nothing: uploads pause, and
    /// resume when it is back on.
    ///
    /// # Errors
    /// Storage faults, and a setting that cannot be read.
    pub fn anonymous_upload_page(
        &self,
        after: Option<TrainingSubmissionId>,
        page: usize,
    ) -> Result<(Vec<AnonymousUploadWork>, Option<TrainingSubmissionId>)> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if !fold.conversation_training_vault.on() {
            return Ok((Vec::new(), None));
        }
        anonymous_page(self, &txn, (after, page), upload_work)
    }

    /// One page of the anonymous pieces to withdraw, past `after`, at most
    /// `page` of them: each with its withdrawal intent set and its
    /// withdrawal not yet acknowledged (no signed `removal_pending` or
    /// `removed`), never-accepted and never-published ones included (the
    /// intake fences a code it never saw). With its C. A piece whose removal
    /// is pending is polled through [`Vault::anonymous_status_page`] until
    /// it reads `removed`, never sent again. It runs whatever the vault's
    /// setting.
    ///
    /// # Errors
    /// Storage faults.
    pub fn anonymous_withdrawal_page(
        &self,
        after: Option<TrainingSubmissionId>,
        page: usize,
    ) -> Result<(Vec<AnonymousWithdrawalWork>, Option<TrainingSubmissionId>)> {
        let txn = self.store.env.read_txn()?;
        anonymous_page(self, &txn, (after, page), withdrawal_work)
    }

    /// One page of the anonymous pieces whose next signed state is owed,
    /// past `after`, at most `page` of them: uploading, accepted and waiting
    /// for the re-filter, or with their removal pending. With their C and
    /// the last revision applied, for the receipts ask. It runs whatever the
    /// vault's setting.
    ///
    /// # Errors
    /// Storage faults.
    pub fn anonymous_status_page(
        &self,
        after: Option<TrainingSubmissionId>,
        page: usize,
    ) -> Result<(Vec<AnonymousStatusWork>, Option<TrainingSubmissionId>)> {
        let txn = self.store.env.read_txn()?;
        anonymous_page(self, &txn, (after, page), status_work)
    }

    /// The intake answered `recipient_refresh_required` for the piece of
    /// `id`: it holds no accepted facts for its C, and its bytes are sealed
    /// to a recipient it no longer opens. In one writer the piece's
    /// withdrawal intent is set (the intake fences an unknown C
    /// generically), its refresh asked, and the row withheld, so its files
    /// go with the next purge; at the next offer pass its source is offered
    /// anew as a new submission under a new C (CALLS TL6_ANON_REFRESH). No C
    /// is ever sealed under twice. `false`, with nothing written, for a row
    /// that is not a published anonymous piece, or one the intake ever took
    /// whole.
    ///
    /// # Errors
    /// Storage faults.
    pub fn anonymous_refresh_required(&self, id: TrainingSubmissionId) -> Result<bool> {
        self.with_write_txn_grouped(|txn| {
            let Some(mut row) = custody::submission(self, txn, id)? else {
                return Ok(false);
            };
            if row.transport != TrainingTransport::Anonymous
                || row.state != SubmissionState::Published
                || row.anonymous.accepted
            {
                return Ok(false);
            }
            row.anonymous.withdraw = true;
            row.anonymous.refresh_requested = true;
            row.state = SubmissionState::Withheld;
            put_submission_in(self, txn, id, &row)?;
            Ok(true)
        })
    }
}

/// One page of anonymous rows `work` lists, past `after`, at most `page` of
/// them (a pace; a page of 0 still lists one): the items, and the
/// continuation while another listed row follows.
fn anonymous_page<T>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (after, page): (Option<TrainingSubmissionId>, usize),
    work: impl Fn(TrainingSubmissionId, &SubmissionCustody) -> Option<T>,
) -> Result<(Vec<T>, Option<TrainingSubmissionId>)> {
    let page = page.max(1);
    let lower: Bound<CustodyKey> = after.map_or(Bound::Included((SUBMISSION, [0; 16])), |id| {
        Bound::Excluded((SUBMISSION, id.0))
    });
    let upper: Bound<CustodyKey> = Bound::Included((SUBMISSION, [u8::MAX; 16]));
    let mut items = Vec::new();
    let mut last = None;
    for row in SUBMISSIONS.iter_range(&vault.store, txn, lower.as_ref(), upper.as_ref())? {
        let ((_, id), row) = row?;
        if row.transport != TrainingTransport::Anonymous {
            continue;
        }
        let id = TrainingSubmissionId(id);
        let Some(item) = work(id, &row) else {
            continue;
        };
        if items.len() == page {
            return Ok((items, last));
        }
        items.push(item);
        last = Some(id);
    }
    Ok((items, None))
}

/// The upload work of an anonymous row, when it has any.
fn upload_work(id: TrainingSubmissionId, row: &SubmissionCustody) -> Option<AnonymousUploadWork> {
    let piece = &row.anonymous;
    let settled = matches!(
        piece.state,
        Some(
            TrainingPieceState::Accepted
                | TrainingPieceState::Eligible
                | TrainingPieceState::Refused
                | TrainingPieceState::RemovalPending
                | TrainingPieceState::Removed
        )
    );
    let due = row.state == SubmissionState::Published && row.files && !piece.withdraw && !settled;
    due.then(|| AnonymousUploadWork {
        id,
        code: oneiron_vault_contract::hex(&row.piece),
        cursor: piece.cursor(),
    })
}

/// The withdrawal work of an anonymous row, when it has any.
fn withdrawal_work(
    id: TrainingSubmissionId,
    row: &SubmissionCustody,
) -> Option<AnonymousWithdrawalWork> {
    let piece = &row.anonymous;
    let acknowledged = matches!(
        piece.state,
        Some(TrainingPieceState::RemovalPending | TrainingPieceState::Removed)
    );
    let due = piece.withdraw && !acknowledged;
    due.then(|| AnonymousWithdrawalWork {
        id,
        code: oneiron_vault_contract::hex(&row.piece),
    })
}

/// The status work of an anonymous row, when its next signed state is
/// owed.
fn status_work(id: TrainingSubmissionId, row: &SubmissionCustody) -> Option<AnonymousStatusWork> {
    let piece = &row.anonymous;
    let owed = matches!(
        piece.state,
        Some(
            TrainingPieceState::Uploading
                | TrainingPieceState::Accepted
                | TrainingPieceState::RemovalPending
        )
    );
    owed.then(|| AnonymousStatusWork {
        id,
        code: oneiron_vault_contract::hex(&row.piece),
        revision: piece.revision,
    })
}
