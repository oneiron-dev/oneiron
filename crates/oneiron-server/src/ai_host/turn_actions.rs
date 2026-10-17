//! The turn-action worker: runs each queued Continue and Retry
//! (`vault.conversations.turn.continue` / `.retry`) as the reply it asks
//! for, through chat's answer producer, admitted exactly as a chat turn is:
//! the agent's definition, the role's route, the requester's budget line,
//! and the requester's standing for the whole turn. Its model call runs
//! under `host.turn.generate` (ARCH-0080 §5), as a chat turn's does.
//!
//! The request is rebuilt from the ledger as the requester reads it. Continue
//! opens a continuation on the same MESSAGE: a model that keeps a trailing
//! assistant message open gets the saved text as its prefill, any other gets
//! it as history and then [`CONTINUE_INSTRUCTION`]; either way only the new
//! suffix is appended. Retry answers the user turn again in a new assistant
//! TURN. Replies are whole messages: no partial is published.
//!
//! It wakes on the vault's post-commit attempt signal and once at start. An
//! attempt claimed a second time was cut off when the process stopped under
//! it: it is failed and never run again, so its reply stays as saved until
//! someone asks again.
use std::sync::Arc;

use oneiron::agent_dispatch::{AgentDispatchTarget, AgentDispatcher};
use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt, FailAttempt,
};
use oneiron::conversation::{TURN_ACTION_ATTEMPT_KIND, TurnAction, TurnActionAttempt};
use oneiron::memory::{MessageWriteMode, WitnessAuthor};
use oneiron::{LlmCapability, LlmMessage, LlmMessageRole, Vault, WriteActor};
use tokio::sync::{broadcast, watch};

use super::{AiHandle, CHAT_ROLE};
use crate::api::ai::chat::{
    Answer, AnswerOpen, AnswerRefused, CONTINUE_INSTRUCTION, TurnCredential, after_turn,
    begin_answer, chat_request, keepalive_every, text_message, turn_generate_pre, witness_turn,
};
use crate::server::blocking;

const LEASE_OWNER: &str = "oneiron-server-turn-actions";
/// Recorded on an attempt whose reason does not fit the queue's bound.
const FAILED: &str = "the turn action failed";

/// Starts the worker on the current runtime when a seat serves chat;
/// otherwise queued actions stay queued, visibly, for a host that has one.
pub(super) fn spawn(vault: &Arc<Vault>, ai: &AiHandle) {
    if ai.chat_seat().is_none() {
        return;
    }
    let vault = Arc::downgrade(vault);
    let ai = ai.clone();
    let mut stopped = ai.turns.stop_signal();
    tokio::spawn(async move {
        let Some(mut signals) = vault
            .upgrade()
            .map(|vault| AttemptQueue::new(&vault).subscribe())
        else {
            return;
        };
        loop {
            while !stopping(&stopped) {
                let Some(vault) = vault.upgrade() else {
                    return;
                };
                let Some(attempt) = claim(&vault) else {
                    break;
                };
                let result = act(&vault, &ai, &attempt).await;
                settle(&vault, &attempt, result);
            }
            tokio::select! {
                biased;
                _ = stopped.wait_for(|stop| *stop) => return,
                signal = signals.recv() => {
                    if matches!(signal, Err(broadcast::error::RecvError::Closed)) {
                        return;
                    }
                }
            }
            // Drain the burst our own commits (and any concurrent ones) caused.
            while let Ok(()) | Err(broadcast::error::TryRecvError::Lagged(_)) = signals.try_recv() {
            }
        }
    });
}

/// Whether shutdown asked the worker to stop; the borrow ends here.
fn stopping(stopped: &watch::Receiver<bool>) -> bool {
    *stopped.borrow()
}

fn claim(vault: &Vault) -> Option<AttemptRecord> {
    let claimed = blocking(|| {
        AttemptQueue::new(vault).claim_kind(
            TURN_ACTION_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: LEASE_OWNER.to_owned(),
                now: vault.now_recorded_at(),
            },
        )
    });
    match claimed {
        Ok(ClaimOutcome::Claimed(attempt)) => Some(attempt),
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "turn action claim failed");
            None
        }
    }
}

/// Runs one claimed action to its reply's terminal. `Ok` once the reply is
/// saved, complete or not; the reason it did not run or was not saved
/// otherwise.
async fn act(vault: &Arc<Vault>, ai: &AiHandle, attempt: &AttemptRecord) -> Result<(), String> {
    if attempt.attempt_count > 1 {
        return Err("cut off when the process stopped; not run again".into());
    }
    let action = TurnActionAttempt::decode(attempt).map_err(|error| error.to_string())?;
    let (actor, class) = action.requester().map_err(|error| error.to_string())?;
    let settings = ai.chat_settings();
    let context = blocking(|| {
        vault
            .memory(actor, class)
            .turn_action_context(&action, settings.history_turns)
    })
    .map_err(|error| error.to_string())?;
    let seat = ai
        .chat_seat()
        .cloned()
        .ok_or("no [models] rung serves generative_reasoner")?;
    // The agent must still pass the dispatch predicate, as chat's does.
    let instructions = AgentDispatcher::new(vault)
        .dispatchable_definition(&AgentDispatchTarget::Custom(context.agent))
        .map_err(|error| error.to_string())?
        .instructions
        .filter(|text| !text.trim().is_empty());
    let mut messages: Vec<LlmMessage> = instructions
        .into_iter()
        .map(|text| text_message(LlmMessageRole::System, text))
        .collect();
    for line in context.history {
        let role = if line.author == WitnessAuthor::User {
            LlmMessageRole::User
        } else {
            LlmMessageRole::Assistant
        };
        messages.push(text_message(role, line.text));
    }
    messages.push(text_message(LlmMessageRole::User, context.user_text));
    let admit = |messages| {
        ai.admit_role(vault, CHAT_ROLE, chat_request(&seat, messages))
            .map_err(|refusal| refusal.to_string())
    };
    let mut admitted = admit(messages.clone())?;
    // An empty saved reply is an honest empty prefix: the reply is generated
    // afresh on the same MESSAGE.
    if action.action == TurnAction::Continue && !context.saved.is_empty() {
        let prefill = admitted
            .ladder
            .supports(&admitted.request.model, &LlmCapability::AssistantPrefill);
        messages.push(text_message(LlmMessageRole::Assistant, context.saved));
        if !prefill {
            messages.push(text_message(
                LlmMessageRole::User,
                CONTINUE_INSTRUCTION.to_owned(),
            ));
        }
        admitted = admit(messages)?;
    }
    let keepalive = keepalive_every(
        vault
            .message_stream_policy()
            .map_err(|error| error.to_string())?
            .idle_timeout_ms,
    );
    // `host.turn.generate`'s pre chain runs once the reply is admitted and
    // before its stream opens: a skip, or an ask, ends the turn with its
    // reason. Its post chain runs once the reply's producer ends.
    // A queued action carries no credential: its hooks read as its actor.
    // Its room is the conversation the action's context resolved.
    let generating = turn_generate_pre(
        vault,
        actor,
        None,
        None,
        &action.conversation.to_hex(),
        Some(action.conversation),
    )
    .map_err(|error| error.to_string())?
    .map_err(|stop| stop.to_string())?;
    let open = match action.action {
        TurnAction::Continue => AnswerOpen::Continue(action.message),
        TurnAction::Retry => AnswerOpen::Turn(witness_turn(
            &action.conversation.to_hex(),
            None,
            WitnessAuthor::Companion,
            String::new(),
            vault.now_recorded_at(),
        )),
    };
    let answering = begin_answer(
        ai,
        Answer {
            vault: Arc::clone(vault),
            agent: context.agent,
            session_key: None,
            open,
            mode: MessageWriteMode::Atomic,
            admitted,
            payer: WriteActor::new(actor, class),
            budget_units: settings.turn_budget_units,
            credential: TurnCredential::Action {
                action: Box::new(action),
                vault: Arc::clone(vault),
            },
            keepalive,
        },
    )
    .map_err(|refusal| match refusal {
        AnswerRefused::WaitedOut(reason)
        | AnswerRefused::Engine(reason)
        | AnswerRefused::NotAdmitted(reason) => reason,
    })?;
    let answering = after_turn(Arc::clone(vault), generating, answering);
    drop(answering.subscription);
    let outcome = answering
        .outcome
        .await
        .map_err(|_| "the producer stopped".to_owned())?;
    // A failure that saved the reply cut short still failed: the reply
    // stays incomplete, and nothing runs it again unasked.
    outcome.result?;
    if outcome.saved.is_none() {
        return Err("the reply was not recorded".into());
    }
    Ok(())
}

/// Completes or fails the attempt; either is terminal.
fn settle(vault: &Vault, attempt: &AttemptRecord, result: Result<(), String>) {
    let queue = AttemptQueue::new(vault);
    let now = vault.now_recorded_at();
    let fail = |reason: String| {
        queue.fail(FailAttempt {
            id: attempt.id,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: attempt.attempt_count,
            reason,
            now,
        })
    };
    let settled = match result {
        Ok(()) => queue
            .complete(CompleteAttempt {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                now,
            })
            .map(drop),
        // The reason is recorded on the attempt, not logged: it can quote
        // the vault.
        Err(reason) => fail(reason).or_else(|_| fail(FAILED.to_owned())).map(drop),
    };
    if let Err(error) = settled {
        tracing::warn!(kind = ?error.kind(), attempt = ?attempt.id, "turn action was not settled");
    }
}
