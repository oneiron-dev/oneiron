//! FIX 1380 phase 2: a comm refusal raises the one widen ask to the parent.
//! ARCH-0028 :611: "Widening is one signal to the parent, approve-and-stop-
//! asking." The signal is one durable TASK ask (CALLS W1; ARCH-0079 ask:
//! "Work goes on while it waits") from the refused child to its dispatch
//! parent's agent, offering approve and decline, or for a dispatch with no
//! agent parent to the vault owner, offering the confirm trio: approve once,
//! approve and stop asking, deny (FIX 10178). The child asks in its own
//! name, on a short question it witnesses itself; the question names the
//! reach, never the refused message.
//!
//! The answer is the existing `tasks.answer` door (CALLS W2): only the asked
//! recipient's own word on its own ask moves the request, in the ask's
//! settling commit. An answer that never comes approves nothing: its round
//! closes, and the next refused send asks a fresh one.

use std::collections::BTreeMap;

use super::ask_record::{self, AskGroup};
use super::ask_types::{
    TaskAskDefault, TaskAskOptionId, TaskAskQuestion, TaskAskResult, TaskAskSettlementReason,
    TaskAskSource, TaskAskSpec, TaskAskTarget, TaskAskWord,
};
use super::highway::invalid_state;
use super::{ConsultPayloadRef, TaskAssignee};
use crate::agent_dispatch::{
    CommReach, CommWidenDecision, CommWidenQuestion, CommWidenRecipient, CommWidenRequest,
    CommWidenState, comm_widen_in, comm_widen_recipient_in_txn, put_comm_widen_in,
};
use crate::agent_inbox_lens::{
    AgentInboxItemKind, AgentInboxLensItem, AgentInboxParticipant, InboxImpact,
};
use crate::attempt_queue::AttemptId;
use crate::error::Result;
use crate::genui::ConsentConfirmOutcome;
use crate::memory::{
    Memory, MemoryError, MemoryResult, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use crate::{EdgeActorClass, EntityId, Vault};

/// Every comm widen ask's intent key starts so:
/// `comm_widen/<child attempt hex>/<needed reach>/<question turn hex>`.
const INTENT_PREFIX: &str = "comm_widen/";
/// The message type of the witnessed question.
const QUESTION_TYPE: &str = "comm_widen_question";
/// The two answers a widen ask to an agent parent offers (CALLS W1).
const APPROVE: &str = "approve";
const DECLINE: &str = "decline";
/// The confirm trio a widen ask to the owner offers (FIX 10178).
const APPROVE_ONCE: &str = "approve_once";
const APPROVE_AND_STOP_ASKING: &str = "approve_and_stop_asking";
const DENY: &str = "deny";

/// What `option` chose on a widen ask to `recipient`: one of the answers that
/// ask offers, or `None`. An agent parent's approve is once and its decline
/// a deny.
fn widen_choice(recipient: CommWidenRecipient, option: &str) -> Option<ConsentConfirmOutcome> {
    match (recipient, option) {
        (CommWidenRecipient::Agent(_), APPROVE) | (CommWidenRecipient::Owner(_), APPROVE_ONCE) => {
            Some(ConsentConfirmOutcome::ApproveOnce)
        }
        (CommWidenRecipient::Owner(_), APPROVE_AND_STOP_ASKING) => {
            Some(ConsentConfirmOutcome::ApproveAndStopAsking)
        }
        (CommWidenRecipient::Agent(_), DECLINE) | (CommWidenRecipient::Owner(_), DENY) => {
            Some(ConsentConfirmOutcome::Deny)
        }
        _ => None,
    }
}

/// What one refused send's widen signal did: the reach it asks for, the ask
/// that carries it, and where it stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CommWidenView {
    needed: CommReach,
    ask: Option<EntityId>,
    outcome: CommWidenOutcome,
}

/// Where a refused send's widen signal stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommWidenOutcome {
    /// This send asked the parent.
    Asked,
    /// An earlier send asked; the answer is awaited (no second ask).
    Pending,
    /// The parent declined this reach; that is final for it.
    Declined,
    /// The parent approved it, but an ancestor's own reach is narrower.
    Clamped,
}

impl CommWidenView {
    /// The refusal text's tail: the needed reach, the ask and its state.
    pub(crate) fn describe(&self) -> String {
        let ask = self
            .ask
            .map_or_else(|| "none".to_owned(), |ask| ask.to_hex());
        let needed = self.needed.as_str();
        match self.outcome {
            CommWidenOutcome::Asked => {
                format!("asked the parent to widen this run to {needed} (ask {ask}, state asked)")
            }
            CommWidenOutcome::Pending => {
                format!("a widen to {needed} is already asked (ask {ask}, state pending)")
            }
            CommWidenOutcome::Declined => format!(
                "the parent declined widening this run to {needed} (ask {ask}, state declined); that is final for this reach"
            ),
            CommWidenOutcome::Clamped => format!(
                "the parent approved {needed} (ask {ask}), but its own reach is narrower; it must widen first"
            ),
        }
    }

    /// The widen ask's hex ref, for the refusal's typed denial (FIX 1380).
    pub(crate) fn ask_ref(&self) -> Option<String> {
        self.ask.map(|ask| ask.to_hex())
    }

    /// The refusal's remedy.
    pub(crate) const fn suggestion(&self) -> &'static str {
        match self.outcome {
            CommWidenOutcome::Asked | CommWidenOutcome::Pending => {
                "Wait for the parent's answer on the ask, then send the message again."
            }
            CommWidenOutcome::Declined => {
                "Reach the person another way, through the parent, or without this message."
            }
            CommWidenOutcome::Clamped => {
                "Wait for the parent's own reach to widen, then send the message again."
            }
        }
    }
}

/// Whether `intent_key` is a comm widen ask's. The prefix admits nothing by
/// itself: a routed ask is one its child's reservation names.
pub(super) fn is_comm_widen_ask_intent(intent_key: &str) -> bool {
    intent_key.starts_with(INTENT_PREFIX)
}

fn attempt_hex(attempt: AttemptId) -> String {
    crate::entity_id::bytes_to_hex_lower(attempt.as_bytes())
}

fn intent_key(child: AttemptId, needed: CommReach, turn: EntityId) -> String {
    format!(
        "{INTENT_PREFIX}{}/{}/{}",
        attempt_hex(child),
        needed.as_str(),
        turn.to_hex()
    )
}

/// The tuple a comm widen intent names, read whole and in canonical form;
/// `None` for any other key.
fn intent_parts(intent_key: &str) -> Option<(AttemptId, CommReach, EntityId)> {
    let mut parts = intent_key.strip_prefix(INTENT_PREFIX)?.split('/');
    let (Some(child), Some(needed), Some(turn), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let child = AttemptId::from_bytes(EntityId::from_hex(child).ok()?.as_bytes()).ok()?;
    let needed = [
        CommReach::Parent,
        CommReach::Subtree,
        CommReach::Project,
        CommReach::Vault,
    ]
    .into_iter()
    .find(|reach| reach.as_str() == needed)?;
    let turn = EntityId::from_hex(turn).ok()?;
    (intent_key == self::intent_key(child, needed, turn)).then_some((child, needed, turn))
}

/// The ask a request's question carries: its recipient, approve or decline
/// to an agent parent and the confirm trio to the owner, holding by default.
fn ask_spec(
    child: AttemptId,
    request: &CommWidenRequest,
    turn: EntityId,
) -> MemoryResult<TaskAskSpec> {
    let mut what = TaskAskQuestion::new(ConsultPayloadRef::Turn(turn));
    let reach = request.needed.as_str();
    what.options = match request.recipient {
        CommWidenRecipient::Owner(_) => BTreeMap::from([
            (
                TaskAskOptionId::new(APPROVE_ONCE)?,
                format!("Approve once: widen this run's comm reach to {reach}"),
            ),
            (
                TaskAskOptionId::new(APPROVE_AND_STOP_ASKING)?,
                format!(
                    "Approve and stop asking: widen this run, and the runs it starts, up to {reach}"
                ),
            ),
            (TaskAskOptionId::new(DENY)?, "Deny".to_owned()),
        ]),
        CommWidenRecipient::Agent(_) | CommWidenRecipient::Erased => BTreeMap::from([
            (
                TaskAskOptionId::new(APPROVE)?,
                format!("Approve: widen its comm reach to {reach}"),
            ),
            (TaskAskOptionId::new(DECLINE)?, "Decline".to_owned()),
        ]),
    };
    let who = match request.recipient {
        CommWidenRecipient::Agent(actor_ref) => TaskAssignee::Child { actor_ref },
        CommWidenRecipient::Owner(actor_ref) => TaskAssignee::Human { actor_ref },
        // An erase takes out every pending request it names (FIX 3520).
        CommWidenRecipient::Erased => return Err(MemoryError::from(ask_record::invalid())),
    };
    let mut spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::Responder(who)),
        what,
        None,
        TaskAskDefault::Hold,
    );
    spec.intent_key = intent_key(child, request.needed, turn);
    Ok(spec)
}

/// Whether `input` is the widen ask the caller's own live run reserved: its
/// intent names the run the host bound and a pending request whose current
/// question and recipient the ask carries. Such an ask takes no ceiling and
/// no launch hold: it is the engine's signal to the approver itself.
pub(super) fn reserved_ask_in(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    input: &TaskAskSpec,
) -> MemoryResult<bool> {
    let Some((child, needed, turn)) = intent_parts(&input.intent_key) else {
        return Ok(false);
    };
    if !super::message_dispatch_in_txn(memory, txn)?.is_some_and(|(attempt, _)| attempt.id == child)
    {
        return Ok(false);
    }
    let Some(record) = comm_widen_in(memory.vault(), txn, child)? else {
        return Ok(false);
    };
    let Some(request) = record
        .requests
        .iter()
        .find(|request| request.needed == needed)
    else {
        return Ok(false);
    };
    Ok(request.state == CommWidenState::Pending
        && request
            .question
            .is_some_and(|question| question.turn == turn)
        && ask_spec(child, request, turn)? == *input)
}

/// The child, reach and request a comm widen ask group carries, when its
/// child's reservation names it; `None` for every other ask.
fn routed_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
) -> Result<Option<(AttemptId, CommWidenRequest)>> {
    let Some((child, needed, turn)) = intent_parts(&group.requested.intent_key) else {
        return Ok(None);
    };
    let Some(record) = comm_widen_in(vault, txn, child)? else {
        return Ok(None);
    };
    Ok(record
        .requests
        .into_iter()
        .find(|request| {
            request.needed == needed
                && request.ask == Some(id)
                && request
                    .question
                    .is_some_and(|question| question.turn == turn)
        })
        .map(|request| (child, request)))
}

/// The source the asked recipient's own word takes: an agent parent answers
/// as an executor, the owner as a person. An erased recipient's actor
/// matches no word, whatever its source.
const fn recipient_source(recipient: CommWidenRecipient) -> TaskAskSource {
    match recipient {
        CommWidenRecipient::Agent(_) => TaskAskSource::Executor,
        CommWidenRecipient::Owner(_) | CommWidenRecipient::Erased => TaskAskSource::Human,
    }
}

/// Refuses a word on a comm widen ask unless it is the asked recipient's own
/// approve or decline, on the node that admitted the ask (CALLS W2); any
/// other ask passes untouched. Runs in shared word admission, before the word
/// is recorded.
pub(super) fn guard_word(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    source: TaskAskSource,
    actor: EntityId,
    word: &TaskAskWord,
) -> Result<()> {
    if !is_comm_widen_ask_intent(&group.requested.intent_key) {
        return Ok(());
    }
    // A widen intent its reservation does not name back fails closed.
    let (_, request) = routed_in(vault, txn, id, group)?.ok_or_else(ask_record::invalid)?;
    if word.companion_for.is_some()
        || word.inform_for.is_some()
        || word.confirmation.is_some()
        || !word
            .option
            .as_ref()
            .is_some_and(|option| widen_choice(request.recipient, option.as_str()).is_some())
        || request.state != CommWidenState::Pending
        || request.recipient.actor() != Some(actor)
        || source != recipient_source(request.recipient)
        || !ask_record::owns_revision(vault, txn, id, group)?
    {
        return Err(ask_record::invalid());
    }
    if let CommWidenRecipient::Owner(owner) = request.recipient
        && !crate::memory::actor_is_vault_owner_in_txn(vault, txn, owner, EdgeActorClass::Human)
            .unwrap_or(false)
    {
        return Err(ask_record::invalid());
    }
    Ok(())
}

/// Settles a comm widen request from its ask's settlement, in the settling
/// commit (CALLS W2): the asked recipient's first approve widens the child,
/// its decline is final for the reach (CALLS W5). A round that closed with no
/// such word (its deadline, or a stale cut) approves nothing; it frees the
/// request for a fresh round. Every other ask is untouched.
pub(super) fn resolve_answer_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    group: &AskGroup,
    result: &TaskAskResult,
) -> Result<()> {
    let id = result.settlement.group_ref;
    let Some((child, request)) = routed_in(vault, txn, id, group)? else {
        return Ok(());
    };
    let recipient = request.recipient;
    let answer = (result.settlement.reason != TaskAskSettlementReason::Stale)
        .then(|| {
            result
                .evidence
                .iter()
                .filter(|entry| {
                    recipient.actor() == Some(entry.answer.actor_ref)
                        && entry.source == recipient_source(recipient)
                })
                .min_by_key(|entry| entry.order)
                .and_then(|entry| entry.word.option.as_ref())
                .and_then(|option| widen_choice(recipient, option.as_str()))
        })
        .flatten();
    let Some(mut record) = comm_widen_in(vault, txn, child)? else {
        return Ok(());
    };
    let moved = match answer {
        Some(choice) => record.settle(
            id,
            choice != ConsentConfirmOutcome::Deny,
            CommWidenDecision {
                by: recipient,
                at: result.settlement.at,
                ask: id,
                choice,
            },
        ),
        None => record.close_round(id),
    };
    if moved {
        put_comm_widen_in(vault, txn, child, &record)?;
    }
    Ok(())
}

/// What the reservation write found for one refused send.
enum Reserved {
    /// An approval covers the reach; only an ancestor's clamp refused it.
    Covered(EntityId),
    /// The request, as it now stands.
    Request(CommWidenRequest),
}

impl Memory<'_> {
    /// Raises the one widen signal for `child`, refused for want of `needed`
    /// (CALLS W1, W5, W6). One write re-proves the bound sender and reserves
    /// or reuses the request; a request with no admitted ask then gets its
    /// question witnessed (once) and its ask admitted, the ask bound to the
    /// request in the ask's own commit. A pending request is not asked again,
    /// a declined one never is. A failure after the reservation keeps it, and
    /// the next refused send resumes it.
    pub(crate) fn raise_comm_widen(
        &self,
        child: AttemptId,
        needed: CommReach,
    ) -> MemoryResult<CommWidenView> {
        let vault = self.vault();
        let now = vault.store.clock.now_recorded_at();
        let reserved = self.with_verified_actor_write_txn(|txn| {
            let (run, _) = super::message_dispatch_in_txn(self, txn)?
                .filter(|(attempt, _)| attempt.id == child)
                .ok_or_else(|| {
                    invalid_state(
                        "the refused run is no longer the bound sender",
                        "Send the message from the agent run the host bound.",
                    )
                })?;
            let mut record = comm_widen_in(vault, txn, child)?.unwrap_or_default();
            if record.covers(needed)
                && let Some(approval) = record.approved
            {
                return Ok(Reserved::Covered(approval.decision.ask));
            }
            let recipient = comm_widen_recipient_in_txn(vault, txn, &run)?;
            if record.request_mut(needed).is_none() {
                record.requests.push(CommWidenRequest {
                    needed,
                    recipient,
                    at: now,
                    question: None,
                    ask: None,
                    state: CommWidenState::Pending,
                    decided: None,
                });
            }
            let request = record
                .request_mut(needed)
                .ok_or_else(|| MemoryError::from(ask_record::invalid()))?;
            if request.state == CommWidenState::Pending && request.question.is_none() {
                request.question = Some(CommWidenQuestion {
                    conversation: vault.store.clock.entity_id()?,
                    turn: vault.store.clock.entity_id()?,
                    message: vault.store.clock.entity_id()?,
                    at: now,
                });
            }
            let request = request.clone();
            put_comm_widen_in(vault, txn, child, &record)?;
            Ok(Reserved::Request(request))
        })?;
        let request = match reserved {
            Reserved::Covered(ask) => {
                return Ok(CommWidenView {
                    needed,
                    ask: Some(ask),
                    outcome: CommWidenOutcome::Clamped,
                });
            }
            Reserved::Request(request) => request,
        };
        let settled_ask = request.decided.map(|decision| decision.ask);
        match (request.state, request.ask, request.question) {
            (CommWidenState::Declined, _, _) => Ok(CommWidenView {
                needed,
                ask: settled_ask,
                outcome: CommWidenOutcome::Declined,
            }),
            (CommWidenState::Approved, _, _) => Ok(CommWidenView {
                needed,
                ask: settled_ask,
                outcome: CommWidenOutcome::Clamped,
            }),
            (CommWidenState::Pending, Some(ask), _) => Ok(CommWidenView {
                needed,
                ask: Some(ask),
                outcome: CommWidenOutcome::Pending,
            }),
            (CommWidenState::Pending, None, Some(question)) => {
                let ask = self.ask_comm_widen(child, &request, question)?;
                Ok(CommWidenView {
                    needed,
                    ask: Some(ask),
                    outcome: CommWidenOutcome::Asked,
                })
            }
            (CommWidenState::Pending, None, None) => Err(ask_record::invalid().into()),
        }
    }

    /// Witnesses `question` unless it already landed, then admits its ask
    /// with the group bound to the request in the admission's commit.
    fn ask_comm_widen(
        &self,
        child: AttemptId,
        request: &CommWidenRequest,
        question: CommWidenQuestion,
    ) -> MemoryResult<EntityId> {
        let vault = self.vault();
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
                    author: if self.actor_class() == EdgeActorClass::Agent {
                        WitnessAuthor::Companion
                    } else {
                        WitnessAuthor::User
                    },
                    message_type: QUESTION_TYPE.to_owned(),
                    content: format!(
                        "This run asks to widen whom it may address to {}. Approve or decline; \
                         an approval lasts while this run does.",
                        request.needed.as_str()
                    ),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at: question.at,
                assertions: Default::default(),
            })?;
        }
        let spec = ask_spec(child, request, question.turn)?;
        let needed = request.needed;
        let receipt = self.tasks_ask_with_txn_effect(&spec, |txn, group| {
            bind_ask_in(vault, txn, child, needed, question.turn, group)
        })?;
        if receipt.idempotent_replay {
            self.with_verified_actor_write_txn(|txn| {
                bind_ask_in(
                    vault,
                    txn,
                    child,
                    needed,
                    question.turn,
                    receipt.handle.group_ref,
                )
            })?;
        }
        Ok(receipt.handle.group_ref)
    }
}

/// Binds the admitted ask `group` to `child`'s request for `needed`, once,
/// while that request still waits on the question `turn` carries.
fn bind_ask_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    child: AttemptId,
    needed: CommReach,
    turn: EntityId,
    group: EntityId,
) -> MemoryResult<()> {
    let mut record = comm_widen_in(vault, txn, child)?.unwrap_or_default();
    if let Some(stored) = record.request_mut(needed)
        && stored.ask.is_none()
        && stored
            .question
            .is_some_and(|question| question.turn == turn)
    {
        stored.ask = Some(group);
        put_comm_widen_in(vault, txn, child, &record)?;
    }
    Ok(())
}

/// The widening a consult TASK asks for (FIX 3901), read in `txn`: its
/// consult names an ask group whose intent a child's comm widen reservation
/// routes. `None` for any other consult, and for one whose group or
/// reservation does not read: that one renders as the plain consult it is.
pub(super) fn consult_widening_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    consult: Option<&super::ConsultPayload>,
) -> Option<crate::context_board::ConsultWidening> {
    let group_ref = consult?.correlation_ref;
    let group = ask_record::read_group(vault, txn, group_ref).ok()??;
    let (child, request) = routed_in(vault, txn, group_ref, &group).ok()??;
    let approved = comm_widen_in(vault, txn, child)
        .ok()
        .flatten()
        .and_then(|record| record.approved)
        .map(|approval| approval.reach);
    Some(widening(child, approved, &request))
}

/// What `child`'s `request` asks: from the reach an earlier approval gave
/// it, if any, to the reach it needs.
fn widening(
    child: AttemptId,
    approved: Option<CommReach>,
    request: &CommWidenRequest,
) -> crate::context_board::ConsultWidening {
    crate::context_board::ConsultWidening {
        child: attempt_hex(child),
        from: approved,
        to: request.needed,
    }
}

impl Vault {
    /// The comm widen asks waiting on their recipients (FIX 3901), one
    /// INBOX lens row each: the widening it asks and the recipient's own
    /// consult TASK, which the recipient answers on the consult's existing
    /// answer door. No channel identity carries the row. A record that does
    /// not read makes no row, as an ask it cannot route answers nothing.
    pub(crate) fn comm_widen_inbox_items(&self) -> Result<Vec<AgentInboxLensItem>> {
        let txn = self.store.env.read_txn()?;
        let mut items = Vec::new();
        for row in crate::attempt_queue::AttemptQueue::new(self).list_in_txn(&txn)? {
            let Some(record) = comm_widen_in(self, &txn, row.id).ok().flatten() else {
                continue;
            };
            let approved = record.approved.map(|approval| approval.reach);
            for request in &record.requests {
                let (CommWidenState::Pending, Some(ask), Some(question), Some(recipient)) = (
                    request.state,
                    request.ask,
                    request.question,
                    request.recipient.actor(),
                ) else {
                    continue;
                };
                let Some(member) = ask_record::read_group(self, &txn, ask)
                    .ok()
                    .flatten()
                    .and_then(|group| {
                        group.members.into_iter().find(|member| {
                            EntityId::from_hex(&member.actor).ok() == Some(recipient)
                        })
                    })
                else {
                    continue;
                };
                items.push(AgentInboxLensItem {
                    item_id: format!("comm_widen:{}", ask.to_hex()),
                    kind: AgentInboxItemKind::ApprovalRequired,
                    thread_ref: None,
                    identity_ref: None,
                    actor_ref: recipient,
                    facet_ref: None,
                    participants: vec![AgentInboxParticipant {
                        identity_ref: None,
                        actor_ref: recipient,
                    }],
                    impact: InboxImpact(crate::agent_dispatch::widen_doors::WIDEN_INBOX_IMPACT),
                    occurred_at: question.at,
                    receipt_ref: None,
                    payload_ref: Some(member.task),
                    concern: None,
                    diary_review: None,
                    sender: None,
                    widening: Some(widening(row.id, approved, request)),
                });
            }
        }
        Ok(items)
    }
}
