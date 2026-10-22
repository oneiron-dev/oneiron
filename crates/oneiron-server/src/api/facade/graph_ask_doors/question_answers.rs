//! `vault.questions.answers` (FIX 1585, FIX 2337): the engine's one reader
//! ([`question_answers`]), as the run-host door serves it too. Without a cursor
//! it answers every graph answer receipt and every artifact ask as one bare
//! list, unpaged and uncapped; a cursor opts into pages over the question's
//! ask log.

use std::sync::Arc;

use oneiron::llm::decision::questions::question_answers;
use oneiron::memory::MemoryResult;
use oneiron::receipt::{QuestionAnswersReply, QuestionAnswersRequest};

use super::super::host_doors::support::{Listed, internal, naming};
use super::{asker, question_answer_rows};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.questions.answers`: every answer of the caller's standing
/// question, across its versions, tagged by kind: each graph answer receipt,
/// then each ask the question made of its artifacts, with where its proposal
/// stands. With a `cursor`, the page it names instead (`page_size` entries at
/// most when above 0), and the cursor of the page after it.
/// Beside it, the rows each answer it holds names
/// ([`question_answer_rows`]); an answer outside the page names none.
pub(crate) async fn vault_questions_answers(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionAnswersRequest,
) -> Listed<QuestionAnswersReply> {
    naming(
        vault_questions_answers_answer(server, auth, input).await,
        |reply| {
            let answers = match reply {
                QuestionAnswersReply::All(answers) => answers,
                QuestionAnswersReply::Page(page) => &page.answers,
            };
            answers.iter().flat_map(question_answer_rows).collect()
        },
    )
}

async fn vault_questions_answers_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionAnswersRequest,
) -> MemoryResult<QuestionAnswersReply> {
    const VERB: &str = "vault.questions.answers";
    let principal = asker(auth, server, VERB)?.entity_ref();
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || -> MemoryResult<QuestionAnswersReply> {
        Ok(question_answers(server.vault(), principal, &input)?)
    })
    .await
    .map_err(|_| internal(VERB))?
}
