//! External provider work over an explicit standing-question preparation.

use super::*;
use oneiron::llm::decision::questions::{
    GraphQuestionRef, admit_standing_answer, prepare_standing_answer,
};
use oneiron::receipt::{
    QuestionAdmitRequest, QuestionPrepareRequest, QuestionPrepared, QuestionPreparedSource,
};

pub(crate) async fn vault_questions_prepare(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionPrepareRequest,
) -> Listed<QuestionPrepared> {
    naming(prepare(server, auth, input).await, |prepared| {
        prepared
            .sources
            .iter()
            .map(|source| source.id)
            .chain(std::iter::once(prepared.principal))
            .collect()
    })
}

async fn prepare(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionPrepareRequest,
) -> MemoryResult<QuestionPrepared> {
    const VERB: &str = "vault.questions.prepare";
    let actor = asker(auth, server, VERB)?;
    let server = Arc::clone(server);
    let auth = auth.clone();
    super::super::clock_ingress::run_blocking(move || -> MemoryResult<QuestionPrepared> {
        let lane = asker_lane(server.vault(), &auth, VERB)?;
        let (record, context, source_frontier) = prepare_standing_answer(
            &lane,
            GraphQuestionRef {
                id: input.id,
                version: input.expected_version,
            },
            actor,
            &input.input,
        )?;
        Ok(QuestionPrepared {
            question: record.definition.question,
            dial: record.definition.dial,
            principal: record.principal,
            unit: context.unit,
            sources: context
                .sources
                .into_iter()
                .map(|source| QuestionPreparedSource {
                    id: source.id,
                    entity_type: source.entity_type,
                    body: source.body,
                    hash: source.hash,
                })
                .collect(),
            source_frontier,
        })
    })
    .await
    .map_err(|_| internal(VERB))?
}

pub(crate) async fn vault_questions_admit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionAdmitRequest,
) -> Listed<AnswerRecord> {
    naming(admit(server, auth, input).await, answer_rows)
}

async fn admit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: QuestionAdmitRequest,
) -> MemoryResult<AnswerRecord> {
    const VERB: &str = "vault.questions.admit";
    let actor = asker(auth, server, VERB)?;
    let server = Arc::clone(server);
    let auth = auth.clone();
    super::super::clock_ingress::run_blocking(move || -> MemoryResult<AnswerRecord> {
        let lane = asker_lane(server.vault(), &auth, VERB)?;
        Ok(admit_standing_answer(
            &lane,
            GraphQuestionRef {
                id: input.id,
                version: input.expected_version,
            },
            actor,
            input.input,
            input.source_frontier,
            input.decision,
            oneiron_vault_contract::now_ts(),
        )?)
    })
    .await
    .map_err(|_| internal(VERB))?
}
