//! A released anonymous offer whose outbox files ship nothing (FIX 6916):
//! a manifest or chunk file the self-host shipper found missing, or not what
//! the manifest says. The shipper still reads such a piece again every pass,
//! so a restored file heals by itself, and still counts it in its code-free
//! warning; what it found also rides the piece's row, as a typed local
//! problem with when it was first found, for the owner's receipts view. It
//! is never a state the intake signed: the piece's revision, state, cursor
//! and withdrawal intent are never touched here. A later window from the
//! piece that ships clears it. Nothing here re-offers, withdraws or drops a
//! piece, and nothing names a file, a path or a code.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::Result;

use super::super::custody::{self, SubmissionCustody, put_submission_in};
use super::super::lifecycle::TrainingSubmissionId;
use super::TrainingTransport;
use super::pages::upload_due;

/// Why a released anonymous offer's outbox files ship nothing (FIX 6916):
/// a local problem the self-host shipper found, never a state the intake
/// signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PieceFilesProblem {
    /// A file is not there, or does not read.
    Missing,
    /// The manifest does not decode or names another submission, or a chunk
    /// file is not the length or the BLAKE3 the manifest gives.
    Mismatched,
}

impl PieceFilesProblem {
    /// The problem as a door spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Mismatched => "mismatched",
        }
    }
}

/// A piece's files problem as its row keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(in super::super) struct PieceFilesMark {
    /// What the shipper found.
    pub(in super::super) problem: PieceFilesProblem,
    /// When it first found it, unix seconds; a later pass that finds the
    /// same keeps it.
    pub(in super::super) since: u64,
}

/// What one shipper pass found of one released piece's outbox files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnonymousFilesSeen {
    /// The submission whose released files carry the piece.
    pub id: TrainingSubmissionId,
    /// What kept them from shipping; `None` once a window from them shipped.
    pub problem: Option<PieceFilesProblem>,
}

impl Vault {
    /// Records what the self-host shipper found of released anonymous
    /// pieces' outbox files (FIX 6916), in one writer: a problem on a piece
    /// still to upload, kept with when it was first found while the same
    /// one holds, and cleared once a later window from the piece shipped. A
    /// row that is gone, hosted, or no longer to upload takes no problem.
    /// Local and for the owner's view alone: no signed field and no
    /// withdrawal intent is touched, and nothing is re-offered or dropped.
    ///
    /// # Errors
    /// Storage faults: nothing is recorded.
    pub fn anonymous_piece_files(&self, seen: &[AnonymousFilesSeen]) -> Result<()> {
        if seen.is_empty() {
            return Ok(());
        }
        let now = crate::unix_seconds_now();
        self.with_write_txn_grouped(|txn| {
            for seen in seen {
                let Some(mut row) = custody::submission(self, txn, seen.id)? else {
                    continue;
                };
                if row.transport != TrainingTransport::Anonymous {
                    continue;
                }
                let mark = match seen.problem {
                    Some(_) if !upload_due(&row) => continue,
                    Some(problem) => Some(
                        row.anonymous
                            .files_problem
                            .filter(|held| held.problem == problem)
                            .unwrap_or(PieceFilesMark {
                                problem,
                                since: now,
                            }),
                    ),
                    None => None,
                };
                if row.anonymous.files_problem != mark {
                    row.anonymous.files_problem = mark;
                    put_submission_in(self, txn, seen.id, &row)?;
                }
            }
            Ok(())
        })
    }
}

/// The files problem `row`'s piece stands with while it is still to upload,
/// and since when; none once it left the uploads (withdrawn, settled, or its
/// files gone).
pub(in super::super) fn files_problem(row: &SubmissionCustody) -> Option<PieceFilesMark> {
    row.anonymous.files_problem.filter(|_| upload_due(row))
}
