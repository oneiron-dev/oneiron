//! FIX 9176: a standing question refreshed by hand writes its answers as the asker its
//! version keeps, as the standing pump writes them, never under the class of the
//! credential that pressed refresh; its answerer is handed the same writer. Reads, the
//! owner's alternatives and the fallback for a version that keeps no class stay as they
//! were.

use super::super::graph_ask::GraphAnswerer;
use super::super::records::{AnswerRecord, QuestionRecord, RefreshTrigger};
use super::asker::RefreshWriter;
use super::{graph_proposal, refresh_with};
use crate::{EntityId, Result, Vault, WriteActor};

/// [`super::refresh_question_with`] for `caller`'s own standing question, by hand
/// (FIX 9176): every answer is written as the loaded record's own asker when `caller`
/// is its principal, under the class that version keeps ([`RefreshWriter::Runner`]),
/// and `answerer_for` is handed that same writer with the record. A version that keeps
/// no class, or a caller other than its principal, writes as `caller`, as before. The
/// refresh's reads run as `caller`.
pub fn refresh_standing_question_with<A: GraphAnswerer>(
    vault: &Vault,
    caller: WriteActor,
    principal: EntityId,
    question: EntityId,
    now: u64,
    mut answerer_for: impl FnMut(&QuestionRecord, WriteActor) -> Result<A>,
) -> Result<Vec<AnswerRecord>> {
    let writer = RefreshWriter::Runner(caller);
    let mut answerer: Option<A> = None;
    refresh_with(
        vault,
        writer,
        principal,
        question,
        RefreshTrigger::Manual,
        now,
        &mut |record, unit, kind, body| {
            if answerer.is_none() {
                answerer = Some(answerer_for(record, writer.for_record(record))?);
            }
            let answerer = answerer.as_mut().expect("made above");
            graph_proposal(vault, record, answerer, unit, kind, body)
        },
    )
}
