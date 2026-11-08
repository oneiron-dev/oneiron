//! The owner Ask a parked question queues (FIX 16029, L06-A): one per
//! intent, question digest and round, naming the connector, the tool and the
//! field names only, with the options Answer, Decline and Cancel.

use serde_json::{Value, json};

use super::RemoteTaskInputRow;
use crate::EntityId;
use crate::llm::decision::{AskTo, DecisionAsk, HumanDecisionRequest};
use crate::model_decision::{
    AnswerContract, DecisionClass, DecisionQuestion, DecisionRung, HumanAskReason, ProviderPin,
};

/// The domain an Ask's question id and correlation derive under, from the
/// intent id, the question digest and the round's generation.
const ASK_DOMAIN: &[u8] = b"oneiron:outbound-remote-task-input-ask:v1";

/// The host-issued queue identity of a parked question's owner Ask.
pub(super) const ASK_QUEUE: &str = "outbound.remote_task_input";
const ASK_QUEUE_VERSION: &str = "v1";

/// The version of the Ask's question; bump it with its wording.
const ASK_VERSION: u32 = 1;

/// The Ask's options.
pub(super) const ANSWER: &str = "Answer";
pub(super) const DECLINE: &str = "Decline";
pub(super) const CANCEL: &str = "Cancel";

/// The most characters of a connector, tool or field name the Ask quotes.
const ASK_NAME_MAX_CHARS: usize = 120;

/// The most field names the Ask lists.
const ASK_MAX_FIELDS: usize = 32;

/// The id of the Ask for round `generation` of question `digest` of
/// `intent`: its question's id and its correlation.
fn ask_correlation(
    intent: &[u8; 32],
    digest: &[u8; 32],
    generation: u32,
) -> crate::Result<EntityId> {
    let generation = generation.to_be_bytes();
    EntityId::derive(
        ASK_DOMAIN,
        &[intent.as_slice(), digest.as_slice(), generation.as_slice()],
    )
}

/// The Ask's options: Answer, Decline, Cancel.
fn ask_contract() -> AnswerContract {
    AnswerContract::Choice {
        options: vec![ANSWER.to_owned(), DECLINE.to_owned(), CANCEL.to_owned()],
    }
}

/// `text`, cut to [`ASK_NAME_MAX_CHARS`] characters.
fn clip(text: &str) -> String {
    text.chars().take(ASK_NAME_MAX_CHARS).collect()
}

/// The Ask's wording: the connector, the tool and the field names, never a
/// value or the request's message.
fn ask_text(row: &RemoteTaskInputRow) -> String {
    let named = row
        .field_names
        .iter()
        .take(ASK_MAX_FIELDS)
        .map(|name| format!("\"{}\"", clip(name)))
        .collect::<Vec<_>>();
    let more = row.field_names.len().saturating_sub(named.len());
    let fields = match (named.is_empty(), more) {
        (true, _) => "no fields".to_owned(),
        (false, 0) => format!("the fields {}", named.join(", ")),
        (false, more) => format!("the fields {} and {more} more", named.join(", ")),
    };
    format!(
        "A background task on connector \"{connector}\" asks for input on tool \"{tool}\": \
         {fields}. Choose Answer to enter the values on its input form, Decline to refuse \
         it, or Cancel to dismiss it. Nothing goes to the connector until you answer.",
        connector = clip(&row.connector),
        tool = clip(&row.tool),
    )
}

/// The owner Ask of `row`, round `row.generation` of `intent`, put by
/// `principal` (the actor that admitted the send; the Ask's own id for a
/// send no actor admitted), and its metadata-only state.
pub(super) fn input_ask(
    intent: &[u8; 32],
    row: &RemoteTaskInputRow,
    principal: Option<EntityId>,
) -> crate::Result<(HumanDecisionRequest, Value)> {
    let correlation = ask_correlation(intent, &row.question_digest, row.generation)?;
    let state = json!({
        "intent_id": crate::entity_id::bytes_to_hex_lower(intent),
        "generation": row.generation,
        "question_digest": crate::entity_id::bytes_to_hex_lower(&row.question_digest),
    });
    let request = HumanDecisionRequest {
        question: DecisionQuestion {
            id: correlation,
            version: ASK_VERSION,
            text: ask_text(row),
            class: DecisionClass::Judgment,
            contract: ask_contract(),
            accept_type: false,
        },
        principal: principal.unwrap_or(correlation),
        evidence: vec![correlation],
        reason: HumanAskReason::OwnerSelected,
        prior: None,
        prior_provider: None,
        queue_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: ASK_QUEUE.to_owned(),
            version: ASK_QUEUE_VERSION.to_owned(),
        },
        to: AskTo::owner(),
        correlation: Some(correlation),
    };
    Ok((request, state))
}

/// Whether `ask` is the Ask `row` of `intent` queued, by its typed identity:
/// its number, this queue, and the question id, correlation and options of
/// that intent, question and round.
pub(super) fn ask_matches(
    intent: &[u8; 32],
    row: &RemoteTaskInputRow,
    ask: &DecisionAsk,
) -> crate::Result<bool> {
    let correlation = ask_correlation(intent, &row.question_digest, row.generation)?;
    Ok(row.ask == ask.seq
        && ask.queue_pin.model == ASK_QUEUE
        && ask.question.id == correlation
        && ask.correlation == Some(correlation)
        && ask.question.contract == ask_contract())
}

/// The intent, question and round an Ask of this queue was queued for.
pub(super) struct AskRound {
    pub(super) intent: [u8; 32],
    pub(super) question_digest: [u8; 32],
    pub(super) generation: u32,
}

/// The round `ask` was queued for, read from its metadata state and proved
/// by its typed identity: this queue, and the question id, correlation and
/// options that intent, question and round derive. `None` for an ask this
/// queue's identity does not prove its own; such an ask is left alone.
pub(super) fn ask_round(ask: &DecisionAsk) -> crate::Result<Option<AskRound>> {
    if ask.queue_pin.model != ASK_QUEUE {
        return Ok(None);
    }
    let Some(state) = ask.pack_state.as_ref() else {
        return Ok(None);
    };
    let intent = state
        .get("intent_id")
        .and_then(Value::as_str)
        .and_then(hex32);
    let question_digest = state
        .get("question_digest")
        .and_then(Value::as_str)
        .and_then(hex32);
    let generation = state
        .get("generation")
        .and_then(Value::as_u64)
        .and_then(|generation| u32::try_from(generation).ok());
    let (Some(intent), Some(question_digest), Some(generation)) =
        (intent, question_digest, generation)
    else {
        return Ok(None);
    };
    let correlation = ask_correlation(&intent, &question_digest, generation)?;
    let proved = ask.question.id == correlation
        && ask.correlation == Some(correlation)
        && ask.question.contract == ask_contract();
    Ok(proved.then_some(AskRound {
        intent,
        question_digest,
        generation,
    }))
}

/// The 32 bytes `text` spells as 64 lowercase hex digits, as the Ask's
/// state writes them.
fn hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    (crate::entity_id::bytes_to_hex_lower(&bytes) == text).then_some(bytes)
}
