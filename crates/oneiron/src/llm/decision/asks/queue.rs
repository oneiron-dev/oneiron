//! One ask queued in the caller's own write (FIX 10789): an engine record that owes the
//! owner a question keeps its row and its ask in one commit, so neither lands without the
//! other. [`Vault::queue_decision_ask_with_state`] runs the same body in a write of its
//! own.

use super::{ASKS, AskPrior, DecisionAsk, SAME_ASK_SCAN};
use crate::llm::decision::AnswerActor;
use crate::llm::decision::ladder::HumanDecisionRequest;
use crate::llm::decision::types::invalid;
use crate::{EntityId, Error, Result, Vault};

impl Vault {
    /// [`Self::queue_decision_ask_with_state`] in `txn`: the ask's arrival number, an open
    /// ask that is the same ask answering its own number and keeping the snapshot it was
    /// queued with. Waiters wake on answers, never on a queue, so nothing signals here.
    pub(crate) fn queue_decision_ask_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        request: &HumanDecisionRequest,
        state: Option<&serde_json::Value>,
    ) -> Result<u64> {
        request.question.validate()?;
        request.to.validate()?;
        let prior = match (&request.prior, &request.prior_provider) {
            (None, _) => None,
            (Some(prior), Some(provider)) => Some(AskPrior {
                answer: prior.answer.clone(),
                probability: prior.probability,
                provider: provider.clone(),
                paired: prior.paired.map(|reading| reading.bind(provider.clone())),
                person: prior.person.map(|reading| reading.bind(provider.clone())),
            }),
            (Some(_), None) => return Err(invalid("a prior without its provider")),
        };
        let asked_at = self.store.clock.now_recorded_at();
        let mut last = None;
        for row in ASKS
            .iter_rev_from(&self.store, txn, &[])?
            .take(SAME_ASK_SCAN)
        {
            let (seq, ask) = row?;
            last.get_or_insert(seq);
            if ask.is_open_for(request) {
                return Ok(seq);
            }
        }
        let seq = match last {
            None => 1,
            Some(seq) => seq
                .checked_add(1)
                .ok_or(Error::IndexOverflow("decision ask sequence"))?,
        };
        let role = self.next_ask_role_in_txn(txn, &request.to, None)?;
        let ask = DecisionAsk {
            seq,
            id: EntityId::now(),
            asked_at,
            question: request.question.clone(),
            principal: AnswerActor::Actor(request.principal),
            evidence: request.evidence.clone(),
            reason: request.reason,
            prior,
            queue_pin: request.queue_pin.clone(),
            to: request.to.clone(),
            correlation: request.correlation,
            role,
            answer: None,
            withdrawn_at: None,
            pack_state: state.cloned(),
        };
        ASKS.put(&self.store, txn, &seq, &ask)?;
        Ok(seq)
    }
}
