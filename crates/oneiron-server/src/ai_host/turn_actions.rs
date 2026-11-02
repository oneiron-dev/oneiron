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
//! TURN, which lands with its reply or not at all. Replies are whole
//! messages: no partial is published.
//!
//! On a host bound to its server, a slip-backed action also reads the
//! vault's memory through a fresh context board, as a live chat turn does
//! (FIX 6920): one request-only message right before the user turn the
//! reply answers. Reading it never fails the action. An answer that stood on
//! it keeps its context records as a live turn's does (FIX 7145), after the
//! answer is handed on.
//!
//! It wakes on the vault's post-commit attempt signal and once at start. An
//! attempt claimed a second time was cut off when the process stopped under
//! it: it is failed and never run again, so its reply stays as saved until
//! someone asks again.
//!
//! [`CONTINUE_INSTRUCTION`]: crate::api::ai::chat::CONTINUE_INSTRUCTION
use std::sync::{Arc, Weak};

use oneiron::agent_dispatch::{AgentDispatchTarget, AgentDispatcher};
use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt, FailAttempt,
    ManifestEntry,
};
use oneiron::claim::CallerLocality;
use oneiron::conversation::{TURN_ACTION_ATTEMPT_KIND, TurnActionAttempt, TurnActionAuthority};
use oneiron::memory::{Memory, MessageWriteMode, WitnessAuthor};
use oneiron::{EntityId, LlmMessage, LlmMessageRole, Vault, WriteActor};
use tokio::sync::{broadcast, watch};

use super::AiHandle;
use super::payer_funding::room_launch_funding;
use super::resident_craft::{craft_withdrawn, place_craft, snapshot_craft_scoped};
use crate::api::ai::chat::{
    Answer, AnswerRefused, ChatReuse, ReplyAssertionCollector, TurnCredential, after_turn,
    begin_answer, keepalive_every, live_fork_unavailable, reuse_chat_breakpoint, text_message,
    turn_generate_pre,
};
use crate::api::{action_board, freeze_chat_context, record_action_answer};
use crate::server::{SyncServer, blocking};

mod phases;
use phases::{ActionText, admit_action, answer_open};

const LEASE_OWNER: &str = "oneiron-server-turn-actions";
/// Recorded on an attempt whose reason does not fit the queue's bound.
const FAILED: &str = "the turn action failed";

/// Starts the worker on the current runtime when a seat serves chat;
/// otherwise queued actions stay queued, visibly, for a host that has one.
pub(super) fn spawn(vault: &Arc<Vault>, ai: &AiHandle) {
    run(vault, ai, None);
}

/// [`spawn`], for a host attached to `server`: each action also reads a
/// fresh context board through it (FIX 6920), held weakly.
pub(super) fn spawn_hosted(vault: &Arc<Vault>, ai: &AiHandle, server: Weak<SyncServer>) {
    run(vault, ai, Some(server));
}

/// The worker, reading each action's board through `server` when it has one.
fn run(vault: &Arc<Vault>, ai: &AiHandle, server: Option<Weak<SyncServer>>) {
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
                let result = act(&vault, &ai, server.as_ref(), &attempt).await;
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
/// otherwise. `server`, the host's own once bound, reads its fresh board.
async fn act(
    vault: &Arc<Vault>,
    ai: &AiHandle,
    server: Option<&Weak<SyncServer>>,
    attempt: &AttemptRecord,
) -> Result<(), String> {
    if attempt.attempt_count > 1 {
        return Err("cut off when the process stopped; not run again".into());
    }
    let action = TurnActionAttempt::decode(attempt).map_err(|error| error.to_string())?;
    let (actor, class) = action.requester().map_err(|error| error.to_string())?;
    let settings = ai.chat_settings();
    // The reply's newcomer barrier, marked before its history is read
    // (FIX 1389): a Retry's second read of it runs after this mark too.
    let mark = vault.container_output_mark();
    let context = blocking(|| {
        vault
            .memory(actor, class)
            .turn_action_context(&action, settings.history_turns)
    })
    .map_err(|error| error.to_string())?;
    // A reply in a room bills the payer whose consent on its agent's join
    // funds that room (FIX 805): one with no payer to bill is refused, typed,
    // before anything is written or any model is called. A reply in a thread
    // lands beside the turn it answers again, so the join filed for that
    // thread funds it first, then the room's (FIX 3572).
    let place = blocking(|| vault.turn_room_work(action.assistant_turn))
        .map_err(|error| error.to_string())?;
    let (room, branch) = place.map_or((action.conversation, None), |work| (work.room, work.branch));
    let funding = blocking(|| room_launch_funding(vault, room, branch, context.agent, actor))
        .map_err(|fault| fault.to_string())?;
    let seat = ai
        .chat_seat()
        .cloned()
        .ok_or("no [models] rung serves generative_reasoner")?;
    // FIX 4465 D: a self agent's kept prefix, read before its context is
    // spent below; the action takes it only once its own call is admitted.
    let reuse = blocking(|| reuse_chat_breakpoint(ai, vault, &action, &context));
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
    // OF-490: the answering agent is shown its own craft, read on one
    // snapshot, and its action's attempt names what it was shown. Only the
    // notes the requester's own read admits are shown (SCAN C009, FIX 6102),
    // read as the action's context is: where the requester asked from, under
    // the authority its action stands on, judged again now (FIX 9464). A
    // call that runs as it always did is stamped with today's craft before
    // it is shown, and shows none whose stamp fails. Beside a reused prefix,
    // which shows and stamps the craft it captured, today's call is stamped
    // only if it answers. One layout, the vault's or else the host's, places
    // it (FIX 6676).
    let layout = ai.prompt_layout();
    let lead = messages.len();
    let at = vault.now_recorded_at();
    let craft = blocking(|| {
        craft_reader(vault, &action)
            .and_then(|reader| snapshot_craft_scoped(vault, &reader, &context.agent, at, layout))
    });
    let (shown, mut today_craft) = if matches!(reuse, ChatReuse::Reused(_)) {
        craft.map(|craft| (craft.message, craft.entries)).unzip()
    } else {
        let mut shown = None;
        if let Some(craft) = craft
            && stamp_craft(vault, attempt, context.agent, &craft.entries)
        {
            shown = Some(craft.message);
        }
        (shown, None)
    };
    for line in context.history {
        let role = if line.author == WitnessAuthor::User {
            LlmMessageRole::User
        } else {
            LlmMessageRole::Assistant
        };
        messages.push(text_message(role, line.text));
    }
    // FIX 6920: the board the action reads, hydrated once, as its
    // requester's kept slip reads now. It rides as one request-only User
    // right before the user turn the reply answers, so a Continue's saved
    // reply and its suffix stay after it; the witness and the log never
    // hold it.
    let board = match server.and_then(Weak::upgrade) {
        Some(server) => {
            action_board(
                &server,
                ai,
                &seat,
                &action,
                context.agent,
                &context.user_text,
            )
            .await
        }
        None => None,
    };
    let answers = messages.len();
    messages.push(text_message(LlmMessageRole::User, context.user_text));
    // FIX 6676: the craft joins once the restored history and the user's
    // turn are in, where the session layout places it, and before any saved
    // reply or continuation ask below: that ask is never the latest real
    // user turn. A reused prefix is sent exactly as it was captured.
    if let Some(craft) = shown {
        place_craft(&mut messages, lead, craft, layout);
    }
    let text = ActionText {
        saved: context.saved,
        answers,
    };
    let (admitted, board_context) = admit_action(vault, ai, &seat, &action, text, messages, board)?;
    // FIX 7145: what the admitted board showed, frozen against the call it
    // rides in.
    let board_context =
        board_context.map(|capture| freeze_chat_context(capture, &admitted.request));
    // A missing, stale or refused breakpoint leaves the action as it always
    // ran; a kept one is sent first, with this call behind it. One whose
    // captured craft names a note erased, revised or no longer supported
    // since is never sent again (FIX 8985): the action runs as it always
    // did, on today's craft, stamped before it is sent.
    let (admitted, today, breakpoint) = match reuse {
        ChatReuse::Reused(reused) => {
            let captured = &reused.craft;
            match blocking(|| craft_withdrawn(vault, captured)) {
                None => {
                    let reused = *reused;
                    stamp_craft(vault, attempt, context.agent, &reused.craft);
                    (reused.live, Some(admitted), Some(reused.breakpoint))
                }
                Some(reason) => {
                    live_fork_unavailable(reason);
                    if let Some(entries) = today_craft.take() {
                        stamp_craft(vault, attempt, context.agent, &entries);
                    }
                    (admitted, None, None)
                }
            }
        }
        ChatReuse::Unavailable(reason) => {
            live_fork_unavailable(reason);
            (admitted, None, None)
        }
        ChatReuse::Today => (admitted, None, None),
    };
    let prefix_reused = breakpoint.is_some();
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
        None,
    )
    .map_err(|error| error.to_string())?
    .map_err(|stop| stop.to_string())?;
    let open = answer_open(vault, &action);
    let answering = begin_answer(
        ai,
        Answer {
            vault: Arc::clone(vault),
            agent: context.agent,
            session_key: None,
            activity: None,
            open,
            mode: MessageWriteMode::Atomic,
            admitted,
            payer: WriteActor::new(actor, class),
            funding,
            budget_units: settings.turn_budget_units,
            credential: TurnCredential::Action {
                action: Box::new(action),
                vault: Arc::clone(vault),
            },
            keepalive,
            mark,
            breakpoint,
            today,
            craft: None,
            // Continue and Retry gather evidence of their own, never the
            // earlier reply's (FIX 3416).
            assertions: ReplyAssertionCollector::default(),
        },
    )
    .map_err(|refusal| match refusal {
        AnswerRefused::WaitedOut(reason)
        | AnswerRefused::Engine(reason)
        | AnswerRefused::NotAdmitted(reason) => reason,
    })?;
    let answering = after_turn(Arc::clone(vault), generating, answering);
    // FIX 7145: the answer's context records, kept once it is handed on.
    let answering = match server.and_then(Weak::upgrade) {
        Some(server) => record_action_answer(
            server,
            board_context,
            context.agent,
            WriteActor::new(actor, class),
            prefix_reused,
            answering,
        ),
        None => answering,
    };
    drop(answering.subscription);
    let outcome = answering
        .outcome
        .await
        .map_err(|_| "the producer stopped".to_owned())?;
    // Today's call answered for the reused prefix: what it showed is named.
    if outcome.fell_back
        && let Some(entries) = &today_craft
    {
        stamp_craft(vault, attempt, context.agent, entries);
    }
    // A failure that saved the reply cut short still failed: the reply
    // stays incomplete, and nothing runs it again unasked.
    outcome.result?;
    if outcome.saved.is_none() {
        return Err("the reply was not recorded".into());
    }
    Ok(())
}

/// The reader a queued `action`'s craft is read through (FIX 9464), built
/// as its context's is: the requester's own handle, where it asked from,
/// under the slip its request was admitted on, verified again now. A native
/// action, and an attested owner's, stand on the actor binding alone and
/// read with no proof. `None`, logged without content, for an action that
/// no longer stands (its slip revoked, or taken by its requester's erase,
/// or its owner no longer the vault's) or whose slip does not verify now:
/// its call is shown no craft.
fn craft_reader<'v>(vault: &'v Vault, action: &TurnActionAttempt) -> Option<Memory<'v>> {
    let (actor, class) = action.requester().ok()?;
    if !action.requester_live(vault) {
        tracing::info!(
            "a turn action no longer stands for its requester; its call is shown no craft"
        );
        return None;
    }
    let reader = vault.memory(actor, class).at(if action.off_device {
        CallerLocality::OffDevice
    } else {
        CallerLocality::OnDevice
    });
    let TurnActionAuthority::Slip { binding } = &action.authority else {
        return Some(reader);
    };
    match vault.verify_invocation_slip(binding) {
        Ok(proof) => Some(reader.with_read_proof(&proof)),
        Err(error) => {
            tracing::info!(
                kind = ?error.kind(),
                "a turn action's slip did not verify for its craft; its call is shown no craft"
            );
            None
        }
    }
}

/// Stamps craft `agent`'s call on `attempt` was shown without a load on the
/// attempt's manifest (OF-490). A stamp that fails leaves the reply as it
/// runs, logged. Whether it stamped.
fn stamp_craft(
    vault: &Vault,
    attempt: &AttemptRecord,
    agent: EntityId,
    entries: &[ManifestEntry],
) -> bool {
    match blocking(|| vault.record_resident_craft_exposure(attempt, &agent, entries)) {
        Ok(_) => true,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), attempt = ?attempt.id, "a turn action's craft was not stamped on its attempt");
            false
        }
    }
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
