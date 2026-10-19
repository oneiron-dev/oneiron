//! A person's own publisher training receipts (OF-420, FIX 5372): what the
//! outbox holds and what the intake answered for the submissions carrying
//! their words. Read from local custody alone: nothing here reads, filters
//! or sends conversation text.
//!
//! A person sees only rows that name them. A submission names every person
//! whose words it carries (FIX 5502: one per conversation), so each of them
//! lists it, and nobody else does; it shows its source, worlds and custody,
//! never who else is in it. This door is local and authenticated: it names
//! the raw ids this vault keeps, never the codes that left. Controls name no
//! person and are not listed; a withdrawn submission reads withdrawn on its
//! own row. Nothing says what the intake holds for anyone else.
//!
//! A page walks the submissions in key order from a cursor. It lists
//! [`RECEIPT_PAGE`] rows at most, a pace and not a cap: the rest come on the
//! next page.

use std::collections::BTreeSet;
use std::ops::Bound;

use oneiron_vault_contract::conversation_training::{
    TRAINING_WITHDRAWAL_NOTE, TrainingReceiptStatusV2, is_lower_hex,
};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::custody::{CustodyKey, SUBMISSION, SUBMISSIONS, SubmissionCustody, SubmissionState};
use super::lifecycle::TrainingSubmissionId;

/// Rows one page lists: a pace, never a cap. The rest come on the next page.
const RECEIPT_PAGE: usize = 64;
/// Lower-case hex characters of a cursor: the row's kind byte, then its id.
const CURSOR_HEX: usize = 34;

/// Where a person's next receipt page resumes: past the custody row the page
/// before listed last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrainingReceiptsCursor {
    kind: [u8; 1],
    id: [u8; 16],
}

impl TrainingReceiptsCursor {
    /// The cursor as 34 lower-case hex characters.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut bytes = [0; 17];
        bytes[0] = self.kind[0];
        bytes[1..].copy_from_slice(&self.id);
        oneiron_vault_contract::hex(&bytes)
    }

    /// The cursor `text` spells, as [`Self::to_hex`] wrote it.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        if !is_lower_hex(text, CURSOR_HEX) {
            return None;
        }
        let bytes = oneiron_vault_contract::from_hex(text)?;
        let (kind, id) = bytes.split_first()?;
        let kind = [*kind];
        let id: [u8; 16] = id.try_into().ok()?;
        (kind == SUBMISSION).then_some(Self { kind, id })
    }
}

/// One page of a person's own publisher training receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonTrainingReceipts {
    /// The person, as their proof names them.
    pub person: EntityId,
    /// The submissions carrying their words, in custody order.
    pub submissions: Vec<PersonTrainingSubmission>,
    /// Where the next page resumes; `None` when this page reached the end.
    pub next: Option<TrainingReceiptsCursor>,
}

/// One submission carrying the person's words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonTrainingSubmission {
    /// The submission.
    pub id: TrainingSubmissionId,
    /// The conversation it was selected from.
    pub source: EntityId,
    /// The worlds the selected rows sit in.
    pub worlds: BTreeSet<EntityId>,
    /// Where it stands in local custody.
    pub custody: TrainingCustody,
    /// The intake's last receipt for it; `None` while it sent none.
    pub receipt: Option<TrainingReceiptStatusV2>,
    /// The runs the intake says used it.
    pub used_runs: Vec<TrainingUsedRun>,
    /// [`TRAINING_WITHDRAWAL_NOTE`] once it is withdrawn or its removal is
    /// pending or done; `None` before.
    pub withdrawal_note: Option<&'static str>,
    /// When it was prepared, unix seconds.
    pub prepared_at: u64,
    /// When it was published, unix seconds; `None` while it never left.
    pub published_at: Option<u64>,
}

/// Where a submission stands in local custody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrainingCustody {
    /// Prepared and held, awaiting its release.
    Held,
    /// Released and published.
    Published,
    /// Its release held it back: it never left.
    Withheld,
    /// Withdrawn after it was prepared.
    Withdrawn,
}

impl TrainingCustody {
    /// The state as a door spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Published => "published",
            Self::Withheld => "withheld",
            Self::Withdrawn => "withdrawn",
        }
    }
}

/// One run the intake says used a submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrainingUsedRun {
    /// The intake's run id.
    pub run_id: String,
    /// The model or checkpoint the run made.
    pub model: String,
    /// When it used the submission, unix seconds.
    pub used_at: u64,
}

impl Vault {
    /// One page of the authenticated person's own publisher training
    /// receipts, past `after` (from the first row with none): each
    /// submission carrying their words with its custody, the intake's last
    /// receipt and the runs that used it. The person is revalidated in the
    /// reading transaction.
    ///
    /// # Errors
    /// A refusal when the proof is no longer a live person of this vault;
    /// storage faults.
    pub fn conversation_training_receipts(
        &self,
        owner: &AuthenticatedOwner,
        after: Option<TrainingReceiptsCursor>,
    ) -> Result<PersonTrainingReceipts> {
        let txn = self.store.env.read_txn()?;
        let person = owner.revalidate_person_in_txn(self, &txn)?;
        let mut page = Page {
            receipts: PersonTrainingReceipts {
                person,
                submissions: Vec::new(),
                next: None,
            },
            last: None,
        };
        if let Some((lower, upper)) = kind_range(SUBMISSION, after) {
            for row in SUBMISSIONS.iter_range(&self.store, &txn, lower.as_ref(), upper.as_ref())? {
                let ((_, id), row) = row?;
                if !row.persons.contains(&person) {
                    continue;
                }
                if !page.admits(SUBMISSION, id) {
                    return Ok(page.receipts);
                }
                page.receipts
                    .submissions
                    .push(own_submission(TrainingSubmissionId(id), row));
            }
        }
        Ok(page.receipts)
    }
}

/// A page as it fills.
struct Page {
    receipts: PersonTrainingReceipts,
    /// The custody row it listed last.
    last: Option<TrainingReceiptsCursor>,
}

impl Page {
    /// Whether the row of `kind` and `id` joins this page. Once the page
    /// holds [`RECEIPT_PAGE`] rows the next one resumes past its last, and
    /// the row waits for it.
    fn admits(&mut self, kind: [u8; 1], id: [u8; 16]) -> bool {
        if self.receipts.submissions.len() == RECEIPT_PAGE {
            self.receipts.next = self.last;
            return false;
        }
        self.last = Some(TrainingReceiptsCursor { kind, id });
        true
    }
}

/// The custody keys of `kind` a page walks: past `after` when it points into
/// `kind`, every one when it points before `kind` or there is none, and none
/// when it points past `kind`.
fn kind_range(
    kind: [u8; 1],
    after: Option<TrainingReceiptsCursor>,
) -> Option<(Bound<CustodyKey>, Bound<CustodyKey>)> {
    let lower = match after {
        Some(cursor) if cursor.kind > kind => return None,
        Some(cursor) if cursor.kind == kind => Bound::Excluded((kind, cursor.id)),
        _ => Bound::Included((kind, [0; 16])),
    };
    Some((lower, Bound::Included((kind, [u8::MAX; 16]))))
}

/// One submission carrying the person's words as they read it.
fn own_submission(id: TrainingSubmissionId, row: SubmissionCustody) -> PersonTrainingSubmission {
    let receipt = row.receipt.map(|mark| mark.status);
    let withdrawn = row.state == SubmissionState::Withdrawn
        || matches!(
            receipt,
            Some(TrainingReceiptStatusV2::RemovalPending | TrainingReceiptStatusV2::Removed)
        );
    PersonTrainingSubmission {
        id,
        source: row.source,
        worlds: row.worlds,
        custody: match row.state {
            SubmissionState::Held => TrainingCustody::Held,
            SubmissionState::Published => TrainingCustody::Published,
            SubmissionState::Withheld => TrainingCustody::Withheld,
            SubmissionState::Withdrawn => TrainingCustody::Withdrawn,
        },
        receipt,
        used_runs: row
            .used_runs
            .into_iter()
            .map(|run| TrainingUsedRun {
                run_id: run.run_id,
                model: run.model,
                used_at: run.used_at,
            })
            .collect(),
        withdrawal_note: withdrawn.then_some(TRAINING_WITHDRAWAL_NOTE),
        prepared_at: row.prepared_at,
        published_at: row.published_at,
    }
}
