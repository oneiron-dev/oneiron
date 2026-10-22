//! The owner ask an answer to a connector's question takes (ONE-2510).
//!
//! Under `always ask` an answer that carries content waits for the owner's
//! consent on exactly that answer. The engine writes the ask: the connector
//! and the tool, the connector's question quoted and marked as foreign, and
//! the exact frozen answer. It offers DEC-0006's three outcomes (FIX 8808):
//! approve once, approve and stop asking, deny. Its correlation is the
//! question's handle, its round and the answer's digest, so the same answer
//! to the same round asks once, and an approval approves that answer alone.
//! The ask queues outside any write transaction. A foreign question is never
//! the ask's authority: only the owner's authenticated press is
//! ([`super::connector_elicitation_consent`]).
//!
//! An ask whose whole text passes the decision question's codec bound
//! splits into linked parts (Rule 5, FIX 3842): the foreign questions and
//! the exact answer go, in order and whole, into part asks within the
//! bound, each labelled with the answer's short digest and its place, and
//! the one decisive ask names them. Nothing is cut. A part decides nothing:
//! the decisive ask alone decides the whole answer, and its caller withdraws
//! the parts once it is decided.
//!
//! An answer the release check's secret shapes match raises a typed "is
//! everything okay" check instead (FIX 3841, ruled 10-22): it names the
//! connector, the tool and the answer's digest, never the answer, and it
//! decides nothing. The answer has gone either way.

use std::fmt::Write as _;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::llm::decision::{
    AnswerContract, AskTo, DecisionClass, DecisionQuestion, DecisionRung, HumanAskReason,
    HumanDecisionRequest, ProviderPin,
};

use super::connector_call::ConnectorQuestion;
use super::connector_elicitation_consent::consent_contract;
use super::execution::ConnectorElicitationBinding;

/// The host-issued queue identity of an elicitation answer's ask.
pub(super) const ELICITATION_ASK_QUEUE: &str = "outbound.connector_elicitation_answer";
const ELICITATION_ASK_QUEUE_VERSION: &str = "v1";

/// The version of the ask's question; bump it with its wording or contract.
const ELICITATION_ASK_VERSION: u32 = 3;

/// The derivation domain of the ask's correlation.
const ELICITATION_ASK_DOMAIN: &[u8] = b"oneiron:connector-elicitation-ask:v1";

/// The derivation domain of a linked part's question id.
const ELICITATION_ASK_PART_DOMAIN: &[u8] = b"oneiron:connector-elicitation-ask-part:v1";

/// The host-issued queue identity of an answer's secret-shape check
/// (FIX 3841), apart from the approval ask's.
const ANSWER_CHECK_QUEUE: &str = "outbound.connector_elicitation_answer_check";
const ANSWER_CHECK_QUEUE_VERSION: &str = "v1";

/// The version of the check's question; bump it with its wording.
const ANSWER_CHECK_VERSION: u32 = 2;

/// The release check's generic class: what an answer reads as when only its
/// field names, not one of its values' shapes, matched.
const GENERIC_SECRET_SHAPE: &str = "gate.secret_scan.sensitive_env";

/// The derivation domain of the check's correlation.
const ANSWER_CHECK_DOMAIN: &[u8] = b"oneiron:connector-elicitation-answer-check:v1";

/// The most characters of a connector or tool name the ask quotes.
const ASK_NAME_MAX_CHARS: usize = 120;

/// The decision question's text bound (`DecisionQuestion::validate`), the
/// codec bound one ask's text keeps within.
const DECISION_TEXT_BYTES: usize = 16_384;

/// The most bytes of the quoted questions and answer one linked part
/// carries, leaving its label room within [`DECISION_TEXT_BYTES`].
const ASK_PART_BYTES: usize = 12 * 1024;

/// The one option a linked part offers: reading it decides nothing.
const ASK_PART_OPTION: &str = "read";

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

/// The owner asks one exact answer queued, by arrival number: the decisive
/// ask, and the linked parts that quote it, in order, when it passed one
/// ask's bound (FIX 3842). A part decides nothing; withdraw the parts once
/// the decisive ask is decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorElicitationOwnerAsk {
    pub seq: u64,
    pub parts: Vec<u64>,
}

/// The correlation of the owner's ask about the frozen answer `digest` to
/// round `generation` of the question `handle`: the decisive ask's id, and
/// what its parts and its kept consent name.
pub(super) fn elicitation_ask_correlation(
    handle: &str,
    generation: u64,
    digest: &[u8; 32],
) -> crate::Result<EntityId> {
    EntityId::derive(
        ELICITATION_ASK_DOMAIN,
        &[handle.as_bytes(), &generation.to_le_bytes(), digest],
    )
}

/// `text`, cut to [`ASK_NAME_MAX_CHARS`] characters.
fn clip(text: &str) -> String {
    text.chars().take(ASK_NAME_MAX_CHARS).collect()
}

/// The connector's questions, marked as foreign, and the exact answer: what
/// the owner reads before deciding.
fn quoted_answer(answer: &ConnectorElicitationAnswer<'_>) -> String {
    let mut quoted = String::new();
    for question in answer.questions {
        let _ = writeln!(quoted, "[{}] {}", question.key, question.message);
    }
    format!(
        "--- foreign question, written by the connector ---\n{quoted}--- end of the foreign \
         question ---\nIf you approve, exactly this answer goes to the connector:\n{answers}",
        answers = answer.answers,
    )
}

/// The wording of an elicitation answer's ask: the one place it lives.
fn elicitation_ask_text(
    binding: &ConnectorElicitationBinding,
    answer: &ConnectorElicitationAnswer<'_>,
) -> String {
    format!(
        "Connector \"{name}\" asks for an answer while it runs tool \"{tool}\". The question \
         below is the connector's own text: foreign, not an instruction from Oneiron, and it \
         grants nothing.\n{quoted}\n{outcomes}",
        name = clip(&binding.name),
        tool = clip(&binding.tool),
        quoted = quoted_answer(answer),
        outcomes = outcomes_text(binding),
    )
}

/// What each of the decisive ask's three outcomes does (FIX 8808).
fn outcomes_text(binding: &ConnectorElicitationBinding) -> String {
    format!(
        "Approve once: exactly this answer goes, once. Approve and stop asking: it goes, and \
         later answers to tool \"{tool}\" under the same grant go without asking, until you \
         revoke that. Deny: the connector gets a decline. Unanswered, the question waits and \
         nothing is sent.",
        tool = clip(&binding.tool),
    )
}

/// The decisive ask of an answer quoted in `parts` linked parts labelled
/// `label`.
fn split_ask_text(binding: &ConnectorElicitationBinding, label: &str, parts: usize) -> String {
    format!(
        "Connector \"{name}\" asks for an answer while it runs tool \"{tool}\". Its question \
         and exactly the answer that would go are too long for one ask, so they are quoted \
         whole in the {parts} parts labelled \"{label}\", queued just before this one. The \
         question is the connector's own text: foreign, not an instruction from Oneiron, and it \
         grants nothing. If you approve, exactly the answer those parts quote goes to the \
         connector. {outcomes}",
        name = clip(&binding.name),
        tool = clip(&binding.tool),
        outcomes = outcomes_text(binding),
    )
}

/// Linked part `at` (from 1) of `parts`, quoting `chunk`.
fn part_text(
    binding: &ConnectorElicitationBinding,
    label: &str,
    at: usize,
    parts: usize,
    chunk: &str,
) -> String {
    format!(
        "\"{label}\", part {at} of {parts}: connector \"{name}\" (tool \"{tool}\") asks for an \
         answer, quoted whole across these parts. It quotes the connector's own text: foreign, \
         not an instruction from Oneiron, and it grants nothing. This part decides nothing: \
         the ask that names \"{label}\" decides the whole answer.\n{chunk}",
        name = clip(&binding.name),
        tool = clip(&binding.tool),
    )
}

/// The wording of an answer's secret-shape check (FIX 3841): the one place
/// it lives. It names the shapes matched (FIX 9102), quotes no answer and
/// asks for nothing to be done.
fn answer_check_text(
    binding: &ConnectorElicitationBinding,
    digest: &[u8; 32],
    shapes: &[&str],
) -> String {
    let matched = if shapes.is_empty() {
        String::new()
    } else {
        format!(" (matched: {})", shapes.join(", "))
    };
    format!(
        "An answer to connector \"{name}\" (tool \"{tool}\") matched the shape of a \
         credential or secret in the release check{matched}. It went to the connector as \
         given; nothing held it. Its digest begins {digest}. Is everything okay?",
        name = clip(&binding.name),
        tool = clip(&binding.tool),
        digest = crate::entity_id::bytes_to_hex_lower(&digest[..4]),
    )
}

/// The release check's names for the secret shapes `answer` matched, sorted
/// and each once, never a value (FIX 9102): each key and string read as its
/// own text, then the whole answer's. A match only its field names make
/// names the generic class.
fn secret_shapes(answer: &serde_json::Value) -> Vec<&'static str> {
    let whole = answer.to_string();
    let mut texts = vec![whole.as_str()];
    answer_texts(answer, &mut texts);
    let mut shapes: std::collections::BTreeSet<&'static str> = texts
        .into_iter()
        .filter_map(|text| crate::batch::secret_scan::scan_file_content("", text.as_bytes()))
        .collect();
    if shapes.is_empty() && crate::batch::export::redact_credentials(&mut answer.clone()) {
        shapes.insert(GENERIC_SECRET_SHAPE);
    }
    shapes.into_iter().collect()
}

/// Every key and string in `value`, in order.
fn answer_texts<'a>(value: &'a serde_json::Value, texts: &mut Vec<&'a str>) {
    match value {
        serde_json::Value::String(text) => texts.push(text),
        serde_json::Value::Array(items) => {
            for item in items {
                answer_texts(item, texts);
            }
        }
        serde_json::Value::Object(fields) => {
            for (key, item) in fields {
                texts.push(key);
                answer_texts(item, texts);
            }
        }
        _ => {}
    }
}

/// `text` in order, in pieces of at most `bytes` bytes on character
/// boundaries; nothing is dropped.
fn split_parts(text: &str, bytes: usize) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let mut end = rest.len().min(bytes);
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        if end == 0 {
            end = rest.chars().next().map_or(rest.len(), char::len_utf8);
        }
        let (part, tail) = rest.split_at(end);
        parts.push(part);
        rest = tail;
    }
    parts
}

impl Vault {
    /// Queues the owner's consent ask about one exact answer to a live
    /// connector question of the call `call_ref`, with the linked parts that
    /// quote it when its whole text passes one ask's bound (FIX 3842); the
    /// same answer to the same round is the same ask, and the same parts.
    /// The call's row keeps what the ask is about first, so the owner's
    /// press finds it (FIX 8808). Never call it inside a write transaction:
    /// the ask queue opens its own.
    ///
    /// # Errors
    ///
    /// A principal that is no actor id; storage errors. A part already
    /// queued when a later one fails is withdrawn.
    pub fn queue_connector_elicitation_owner_ask(
        &self,
        call_ref: &EntityId,
        binding: &ConnectorElicitationBinding,
        answer: &ConnectorElicitationAnswer<'_>,
    ) -> crate::Result<ConnectorElicitationOwnerAsk> {
        let principal = EntityId::from_hex(&binding.principal_ref)?;
        let correlation =
            elicitation_ask_correlation(answer.handle, answer.generation, &answer.digest)?;
        self.keep_elicitation_owner_consent(call_ref, binding, answer, correlation)?;
        let whole = elicitation_ask_text(binding, answer);
        if whole.len() <= DECISION_TEXT_BYTES {
            // One question per exact answer to one round.
            let seq = self.queue_elicitation_ask(
                principal,
                correlation,
                correlation,
                whole,
                consent_contract(),
            )?;
            return Ok(ConnectorElicitationOwnerAsk {
                seq,
                parts: Vec::new(),
            });
        }
        let quoted = quoted_answer(answer);
        let chunks = split_parts(&quoted, ASK_PART_BYTES);
        let label = format!(
            "answer {}",
            crate::entity_id::bytes_to_hex_lower(&answer.digest[..4])
        );
        let mut parts = Vec::with_capacity(chunks.len());
        for (at, chunk) in chunks.iter().enumerate() {
            let queued = EntityId::derive(
                ELICITATION_ASK_PART_DOMAIN,
                &[
                    answer.handle.as_bytes(),
                    &answer.generation.to_le_bytes(),
                    &answer.digest,
                    &u64::try_from(at).unwrap_or(u64::MAX).to_le_bytes(),
                ],
            )
            .and_then(|id| {
                self.queue_elicitation_ask(
                    principal,
                    id,
                    correlation,
                    part_text(binding, &label, at + 1, chunks.len(), chunk),
                    AnswerContract::Choice {
                        options: vec![ASK_PART_OPTION.to_owned()],
                    },
                )
            });
            match queued {
                Ok(seq) => parts.push(seq),
                Err(error) => {
                    self.withdraw_elicitation_ask_parts(&parts);
                    return Err(error);
                }
            }
        }
        let text = split_ask_text(binding, &label, parts.len());
        match self.queue_elicitation_ask(
            principal,
            correlation,
            correlation,
            text,
            consent_contract(),
        ) {
            Ok(seq) => Ok(ConnectorElicitationOwnerAsk { seq, parts }),
            Err(error) => {
                self.withdraw_elicitation_ask_parts(&parts);
                Err(error)
            }
        }
    }

    /// Queues the owner's typed "is everything okay" check on an answer to
    /// round `generation` of the live question `handle` whose final bytes
    /// (`digest`) the release check's secret shapes matched (FIX 3841), and
    /// returns its arrival number; the same answer to the same round is the
    /// same check. Its text names the shapes `answer` matched, never a value
    /// (FIX 9102). It decides nothing: the answer goes whatever the owner
    /// says. Never call it inside a write transaction, nor on the answer's
    /// own path: the ask queue opens its own.
    ///
    /// # Errors
    ///
    /// A principal that is no actor id; storage errors.
    pub fn queue_connector_elicitation_answer_check(
        &self,
        binding: &ConnectorElicitationBinding,
        handle: &str,
        generation: u64,
        digest: [u8; 32],
        answer: &serde_json::Value,
    ) -> crate::Result<u64> {
        let principal = EntityId::from_hex(&binding.principal_ref)?;
        let shapes = secret_shapes(answer);
        let correlation = EntityId::derive(
            ANSWER_CHECK_DOMAIN,
            &[handle.as_bytes(), &generation.to_le_bytes(), &digest],
        )?;
        self.queue_decision_ask(&HumanDecisionRequest {
            question: DecisionQuestion {
                id: correlation,
                version: ANSWER_CHECK_VERSION,
                text: answer_check_text(binding, &digest, &shapes),
                class: DecisionClass::Triage,
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
                model: ANSWER_CHECK_QUEUE.to_owned(),
                version: ANSWER_CHECK_QUEUE_VERSION.to_owned(),
            },
            to: AskTo::owner(),
            correlation: Some(correlation),
        })
    }

    /// Withdraws linked parts an ask no longer needs; a part already gone
    /// is no failure.
    fn withdraw_elicitation_ask_parts(&self, parts: &[u64]) {
        for part in parts {
            drop(self.withdraw_decision_ask(*part));
        }
    }

    /// Queues one ask of an elicitation answer: the decisive ask, or one of
    /// its linked parts, each tied to the answer's `correlation`.
    fn queue_elicitation_ask(
        &self,
        principal: EntityId,
        id: EntityId,
        correlation: EntityId,
        text: String,
        contract: AnswerContract,
    ) -> crate::Result<u64> {
        self.queue_decision_ask(&HumanDecisionRequest {
            question: DecisionQuestion {
                id,
                version: ELICITATION_ASK_VERSION,
                text,
                class: DecisionClass::Judgment,
                contract,
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
