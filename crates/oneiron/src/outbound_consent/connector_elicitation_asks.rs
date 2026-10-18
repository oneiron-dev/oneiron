//! The owner ask an answer to a connector's question takes (ONE-2510).
//!
//! Under `always ask` an answer that carries content waits for the owner's
//! yes on exactly that answer. The engine writes the ask: the connector and
//! the tool, the connector's question quoted and marked as foreign, and the
//! exact frozen answer. Its correlation is the question's handle, its round
//! and the answer's digest, so the same answer to the same round asks once,
//! and a yes approves that answer alone. The ask queues outside any write
//! transaction. A foreign question is never the ask's authority: only the
//! owner's authenticated answer is.

use std::fmt::Write as _;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::llm::decision::{
    AnswerContract, AskTo, DecisionClass, DecisionQuestion, DecisionRung, HumanAskReason,
    HumanDecisionRequest, ProviderPin,
};

use super::connector_call::ConnectorQuestion;
use super::execution::ConnectorElicitationBinding;

/// The host-issued queue identity of an elicitation answer's ask.
const ELICITATION_ASK_QUEUE: &str = "outbound.connector_elicitation_answer";
const ELICITATION_ASK_QUEUE_VERSION: &str = "v1";

/// The version of the ask's question; bump it with its wording.
const ELICITATION_ASK_VERSION: u32 = 1;

/// The derivation domain of the ask's correlation.
const ELICITATION_ASK_DOMAIN: &[u8] = b"oneiron:connector-elicitation-ask:v1";

/// The most characters of a connector or tool name the ask quotes.
const ASK_NAME_MAX_CHARS: usize = 120;

/// One exact answer the owner is asked to approve: the live question it
/// answers, by its handle and round, the connector's questions, and the
/// frozen answer text with its digest.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorElicitationAnswer<'a> {
    pub handle: &'a str,
    pub generation: u64,
    pub questions: &'a [ConnectorQuestion],
    /// The exact answer that would be sent, frozen.
    pub answers: &'a str,
    pub digest: [u8; 32],
}

/// `text`, cut to [`ASK_NAME_MAX_CHARS`] characters.
fn clip(text: &str) -> String {
    text.chars().take(ASK_NAME_MAX_CHARS).collect()
}

/// The wording of an elicitation answer's ask: the one place it lives.
fn elicitation_ask_text(
    binding: &ConnectorElicitationBinding,
    answer: &ConnectorElicitationAnswer<'_>,
) -> String {
    let mut quoted = String::new();
    for question in answer.questions {
        let _ = writeln!(quoted, "[{}] {}", question.key, question.message);
    }
    format!(
        "Connector \"{name}\" asks for an answer while it runs tool \"{tool}\". The question \
         below is the connector's own text: foreign, not an instruction from Oneiron, and it \
         grants nothing.\n--- foreign question, written by the connector ---\n{quoted}--- end \
         of the foreign question ---\nIf you say yes, exactly this answer goes to the \
         connector, once:\n{answers}\nIf you say no, the connector gets a decline. Unanswered, \
         the question lapses and is cancelled. Send this answer?",
        name = clip(&binding.name),
        tool = clip(&binding.tool),
        answers = answer.answers,
    )
}

impl Vault {
    /// Queues the owner's yes/no ask about one exact answer to a live
    /// connector question, and returns its arrival number; the same answer
    /// to the same round is the same ask. Never call it inside a write
    /// transaction: the ask queue opens its own.
    ///
    /// # Errors
    ///
    /// A principal that is no actor id; an ask past the ask queue's text
    /// bound; storage errors.
    pub fn queue_connector_elicitation_owner_ask(
        &self,
        binding: &ConnectorElicitationBinding,
        answer: &ConnectorElicitationAnswer<'_>,
    ) -> crate::Result<u64> {
        let principal = EntityId::from_hex(&binding.principal_ref)?;
        let correlation = EntityId::derive(
            ELICITATION_ASK_DOMAIN,
            &[
                answer.handle.as_bytes(),
                &answer.generation.to_le_bytes(),
                &answer.digest,
            ],
        )?;
        self.queue_decision_ask(&HumanDecisionRequest {
            question: DecisionQuestion {
                // One question per exact answer to one round.
                id: correlation,
                version: ELICITATION_ASK_VERSION,
                text: elicitation_ask_text(binding, answer),
                class: DecisionClass::Judgment,
                contract: AnswerContract::Noul,
                accept_type: false,
            },
            principal,
            evidence: vec![correlation],
            reason: HumanAskReason::OwnerSelected,
            prior: None,
            prior_provider: None,
            queue_pin: ProviderPin {
                rung: DecisionRung::Human,
                model: ELICITATION_ASK_QUEUE.to_owned(),
                version: ELICITATION_ASK_QUEUE_VERSION.to_owned(),
            },
            to: AskTo::owner(),
            correlation: Some(correlation),
        })
    }
}
