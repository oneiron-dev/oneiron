//! The owner's quota question as a typed ask (OF-305, FIX 562). When the
//! parked call's principal is known, its question is a person-only decision
//! through the decision ladder, and the questions' rows are that ladder's
//! person queue: the ask keeps the same row it always kept, which
//! `GET /v1/ai/status` lists and `POST /v1/ai/quota/{id}` answers. With no
//! principal the row is kept directly, as before.
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::Vault;
use oneiron::llm::decision::catalogue::QUOTA_SPENT;
use oneiron::llm::decision::{
    AnswerContract, DecisionBand, DecisionBandPolicy, DecisionDial, DecisionRung, HeldLadder,
    HumanDecisionQueue, HumanDecisionRequest, ProviderPin, Reversibility,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::{EntityId, Error};

use super::{QuotaQuestion, question_key};

/// The time the ladder gives a person-only ask to queue: it reads no model,
/// so only the queue's own write spends it.
const QUEUE_BUDGET: Duration = Duration::from_secs(30);

/// The questions' rows, as the person queue of a quota question's ladder.
struct QuotaQueue {
    vault: Arc<Vault>,
}

impl HumanDecisionQueue for QuotaQueue {
    /// A quota ask always carries its question's record as its state.
    fn queue(&self, _request: HumanDecisionRequest) -> oneiron::Result<()> {
        Err(Error::InvalidConfig(
            "a quota question queues with its record".into(),
        ))
    }

    fn queue_with_state(
        &self,
        _request: HumanDecisionRequest,
        state: &serde_json::Value,
    ) -> oneiron::Result<Option<u64>> {
        let question = serde_json::from_value::<QuotaQuestion>(state.clone())
            .map_err(|_| Error::InvalidConfig("a quota ask's state is its question".into()))?;
        keep(&self.vault, &question).map(|()| None)
    }
}

/// Asks `question` of a person for `principal` through a ladder whose one
/// rung is the person, its row kept by [`QuotaQueue`].
pub(super) fn ask(
    vault: &Arc<Vault>,
    principal: EntityId,
    question: &QuotaQuestion,
) -> oneiron::Result<()> {
    let spent = serde_json::to_value(question.spent)
        .ok()
        .and_then(|spent| spent.as_str().map(str::to_owned))
        .unwrap_or_default();
    let options = question
        .choices
        .iter()
        .filter_map(|choice| serde_json::to_value(choice).ok())
        .filter_map(|choice| choice.as_str().map(str::to_owned))
        .collect();
    let typed = QUOTA_SPENT.question(
        &[question.id.as_bytes(), spent.as_bytes()],
        format!("quota:{}", question.id),
        AnswerContract::Choice { options },
    )?;
    let held = HeldLadder {
        human: Arc::new(QuotaQueue {
            vault: Arc::clone(vault),
        }),
        human_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: "models.quota_questions".into(),
            version: "1".into(),
        },
        ..HeldLadder::unstaffed()
    };
    let state = serde_json::to_value(question)
        .map_err(|_| Error::InvariantViolation("encode a quota question"))?;
    held.ladder().run(
        &typed,
        principal,
        &[],
        &state,
        DecisionDial {
            first: DecisionRung::Human,
            ceiling: DecisionRung::Human,
            band: DecisionBand::default(),
        },
        &DecisionBandPolicy::default(),
        Reversibility::OutboundEffect,
        &RetrievalDeadline::hard(Instant::now(), QUEUE_BUDGET),
    )?;
    Ok(())
}

/// Keeps `question`'s row unless a question on the same offer is still open
/// there: one still open stays as it was asked, and one whose window has
/// reset answered itself, so it is replaced, read and replaced in one write.
pub(super) fn keep(vault: &Vault, question: &QuotaQuestion) -> oneiron::Result<()> {
    let row = question_key(&question.id);
    let now = vault.now_recorded_at();
    let open = |bytes: Option<Vec<u8>>| {
        bytes
            .and_then(|bytes| rmp_serde::from_slice::<QuotaQuestion>(&bytes).ok())
            .is_some_and(|asked| asked.resets_at.is_none_or(|reset| reset > now))
    };
    let bytes = rmp_serde::to_vec_named(question)
        .map_err(|_| Error::InvariantViolation("encode a quota question"))?;
    vault.try_with_write_txn_grouped(|txn| {
        // A question another call opened meanwhile stays.
        if !open(vault.sync_state_get_in_write_txn(txn, &row)?) {
            vault.sync_state_put_in_write_txn(txn, &row, &bytes)?;
        }
        Ok::<_, Error>(())
    })
}
