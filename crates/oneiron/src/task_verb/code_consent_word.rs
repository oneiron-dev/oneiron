//! The person's word a code consent answer stands on (DOOR-079 1a).
//!
//! A code consent wait asks the vault's owner one TASK question, as the
//! caller of the held call, on a short question it witnesses itself,
//! offering canon's confirm trio. Only that owner's own Human word naming
//! one of the offered choices is admitted on it: no companion, inform,
//! executor or link word, and no generated word in a person's name. The
//! word is evidence, never approval: the consent operation reads it, under
//! the owner's authentication, and only that operation lets anything run.
//! Its ask's own settlement moves nothing.

use std::collections::BTreeMap;

use super::ask_record::{self, AskGroup};
use super::ask_types::{
    TaskAskAnswer, TaskAskDefault, TaskAskOptionId, TaskAskQuestion, TaskAskSource, TaskAskSpec,
    TaskAskTarget, TaskAskWord,
};
use super::{ConsultPayloadRef, TaskAssignee};
use crate::code_run::{
    CodeConsentChoice, CodeConsentWaitRow, attach_code_consent_ask_in_txn, offered_choices,
    read_code_consent_wait_in_txn,
};
use crate::error::Result;
use crate::memory::{
    Memory, MemoryError, MemoryResult, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use crate::{EntityId, Vault};

/// Every code consent ask's intent key: `code_consent/<wait hex>`.
const INTENT_PREFIX: &str = "code_consent/";

/// The message type of the witnessed question.
const QUESTION_TYPE: &str = "code_consent_question";

fn intent_key(wait_id: EntityId) -> String {
    format!("{INTENT_PREFIX}{}", wait_id.to_hex())
}

/// The wait a code consent intent names, read whole and in canonical form;
/// `None` for any other key.
fn intent_wait(intent_key: &str) -> Option<EntityId> {
    let wait_id = EntityId::from_hex(intent_key.strip_prefix(INTENT_PREFIX)?).ok()?;
    (intent_key == self::intent_key(wait_id)).then_some(wait_id)
}

/// Whether `intent_key` is a code consent ask's. The prefix admits nothing
/// by itself: a code consent ask is one its wait reserved.
pub(super) fn is_code_consent_ask_intent(intent_key: &str) -> bool {
    intent_key.starts_with(INTENT_PREFIX)
}

/// The label one choice's option carries. A held browser act's names the
/// act itself, its row as the page showed it (FIX 10423); a connector
/// call's speaks of the call and its tool.
fn choice_label(choice: CodeConsentChoice, row: &CodeConsentWaitRow) -> String {
    let Some(action) = row.binding.pending.browser_action() else {
        return match choice {
            CodeConsentChoice::ApproveOnce => "Approve once: this call only",
            CodeConsentChoice::ApproveAndStopAsking => {
                "Approve and stop asking: this call, and this tool no longer asks"
            }
            CodeConsentChoice::Deny => "Deny: nothing is sent",
        }
        .to_owned();
    };
    let act = format!("the click on {} \"{}\"", action.role, action.name);
    match choice {
        CodeConsentChoice::ApproveOnce | CodeConsentChoice::ApproveAndStopAsking => {
            format!("Approve once: {act}, this time only")
        }
        CodeConsentChoice::Deny => format!("Deny: {act} does not happen"),
    }
}

/// The ask a wait's question carries: to its owner, offering the wait's
/// choices, holding with no deadline of its own. The held call's own expiry
/// ends the wait, and silence never approves.
fn ask_spec(row: &CodeConsentWaitRow) -> MemoryResult<TaskAskSpec> {
    let question = &row.binding.question;
    let mut what = TaskAskQuestion::new(ConsultPayloadRef::Turn(question.turn));
    what.options = offered_choices(&row.binding)
        .into_iter()
        .map(|choice| {
            Ok((
                TaskAskOptionId::new(choice.as_str())?,
                choice_label(choice, row),
            ))
        })
        .collect::<MemoryResult<BTreeMap<_, _>>>()?;
    let mut spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::Responder(TaskAssignee::Human {
            actor_ref: question.owner,
        })),
        what,
        None,
        TaskAskDefault::Hold,
    );
    spec.intent_key = intent_key(row.binding.wait_id);
    Ok(spec)
}

/// Whether `input` is the ask a code consent wait reserved for this
/// surface's actor: the wait's original caller, with no ask open yet, the
/// wait not settled, and the very spec its row names. Such an ask takes no
/// ceiling and no launch hold: it is the engine's question to the owner.
pub(super) fn reserved_ask_in(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    input: &TaskAskSpec,
) -> MemoryResult<bool> {
    let Some(wait_id) = intent_wait(&input.intent_key) else {
        return Ok(false);
    };
    let Some(row) = read_code_consent_wait_in_txn(memory.vault(), txn, wait_id)? else {
        return Ok(false);
    };
    Ok(row.ask.is_none()
        && row.settlement.is_none()
        && row.binding.original.actor_ref == memory.actor()
        && ask_spec(&row)? == *input)
}

/// Refuses a word on a code consent ask unless it is the asked owner's own
/// Human word naming one of the wait's choices, on the node that admitted
/// the ask; any other ask passes untouched. Runs in shared word admission,
/// before the word is recorded.
pub(super) fn guard_word(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    source: TaskAskSource,
    actor: EntityId,
    word: &TaskAskWord,
) -> Result<()> {
    if !is_code_consent_ask_intent(&group.requested.intent_key) {
        return Ok(());
    }
    let wait_id = intent_wait(&group.requested.intent_key).ok_or_else(ask_record::invalid)?;
    let row =
        read_code_consent_wait_in_txn(vault, txn, wait_id)?.ok_or_else(ask_record::invalid)?;
    let offered = offered_choices(&row.binding);
    if row.ask != Some(id)
        || source != TaskAskSource::Human
        || actor != row.binding.question.owner
        || word.companion_for.is_some()
        || word.inform_for.is_some()
        || word.confirmation.is_some()
        || !word.option.as_ref().is_some_and(|option| {
            CodeConsentChoice::from_option(option.as_str())
                .is_some_and(|choice| offered.contains(&choice))
        })
        || !ask_record::owns_revision(vault, txn, id, group)?
    {
        return Err(ask_record::invalid());
    }
    Ok(())
}

/// The owner's word an answer stands on: a Human word `answerer` gave on the
/// code consent ask `ask`, naming `choice`. Evidence, never approval.
///
/// # Errors
///
/// The ask's own record error when no such word stands.
pub(crate) fn code_consent_word_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ask: EntityId,
    word_ref: EntityId,
    answerer: EntityId,
    choice: CodeConsentChoice,
) -> Result<TaskAskAnswer> {
    let group = ask_record::read_group(vault, txn, ask)?.ok_or_else(ask_record::invalid)?;
    if !is_code_consent_ask_intent(&group.requested.intent_key)
        || !ask_record::owns_revision(vault, txn, ask, &group)?
    {
        return Err(ask_record::invalid());
    }
    let entry = ask_record::evidence_in(vault, txn, ask, &group)?
        .into_iter()
        .find(|entry| entry.answer.word_ref == word_ref)
        .ok_or_else(ask_record::invalid)?;
    if entry.source != TaskAskSource::Human
        || entry.answer.actor_ref != answerer
        || entry.person_ref != answerer
        || entry.word.option.as_ref().map(TaskAskOptionId::as_str) != Some(choice.as_str())
    {
        return Err(ask_record::invalid());
    }
    Ok(entry.answer)
}

impl Memory<'_> {
    /// Opens the owner's question for code consent wait `wait_id`, as the
    /// held call's own caller: witnesses `text` as the question unless it
    /// already landed, then admits the ask with its group bound to the wait
    /// in the admission's commit. Returns the ask's group.
    pub(crate) fn ask_code_consent(&self, wait_id: EntityId, text: &str) -> MemoryResult<EntityId> {
        let vault = self.vault();
        let row = {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            read_code_consent_wait_in_txn(vault, &txn, wait_id)?
        }
        .ok_or_else(|| MemoryError::from(ask_record::invalid()))?;
        if let Some(ask) = row.ask {
            return Ok(ask);
        }
        let question = row.binding.question;
        let landed = {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            vault
                .get_entity_type_in_txn(&txn, &question.message)?
                .is_some()
        };
        if !landed {
            self.witness(&WitnessTurn {
                conversation_ref: question.conversation.to_hex(),
                turn_ref: Some(question.turn.to_hex()),
                thread_audience: None,
                messages: vec![WitnessMessage {
                    id: Some(question.message.to_hex()),
                    // The held call's caller asks; generated code speaks as
                    // the companion.
                    author: WitnessAuthor::Companion,
                    message_type: QUESTION_TYPE.to_owned(),
                    content: text.to_owned(),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at: question.at,
                assertions: Default::default(),
            })?;
        }
        let spec = ask_spec(&row)?;
        let receipt = self.tasks_ask_with_txn_effect(&spec, |txn, group| {
            Ok(attach_code_consent_ask_in_txn(vault, txn, wait_id, group)?)
        })?;
        if receipt.idempotent_replay {
            self.with_verified_actor_write_txn(|txn| {
                Ok(attach_code_consent_ask_in_txn(
                    vault,
                    txn,
                    wait_id,
                    receipt.handle.group_ref,
                )?)
            })?;
        }
        Ok(receipt.handle.group_ref)
    }
}
