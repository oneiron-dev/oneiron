//! FIX 1825 (OF-506): the one landing stamp a saved question's answer takes,
//! read from the version that asked it. Its two lands, a refresh's and a
//! standing backfill's, stamp here, and only here.
//!
//! The contract has two halves. Landing: the version's audience
//! ([`QuestionAudience`]) names who the answer is private to. Reading: the
//! asker reads it back through its own live lane
//! ([`super::question_answers_in_lane`]), and the answer itself rests only on
//! rows the version's saved lane read, so it lands no wider than them. Only
//! [`QuestionAudience::Asker`] is built: every answer lands private to the
//! question's principal. A wider audience extends this stamp and
//! `store::owned_head`, which admits the principal alone, together.
//!
//! A one-off graph ask saves no version and keeps no audience: its answer
//! (`graph_ask::answer_unit`) stays private to its asker.

use super::records::{QuestionAudience, QuestionRecord};
use crate::{ClaimCandidate, Result};

/// `candidate`, an answer to `record`'s version, stamped for the audience
/// the version names.
///
/// # Errors
/// A candidate whose scope is no map.
pub(super) fn stamp_answer(
    candidate: ClaimCandidate,
    record: &QuestionRecord,
) -> Result<ClaimCandidate> {
    match record.definition.audience {
        QuestionAudience::Asker => candidate.with_private_reader(record.principal),
    }
}
