//! Chat answer opening and request construction.
//! Entry: begin_answer.
//! Answer types and their fields stay in the parent; moved functions keep equal-scope old-path exports.

use super::{
    AgentWakeSignals, AiHandle, Answer, AnswerOpen, AnswerOutcome, AnswerRefused, Answering, Arc,
    AssistantMessage, BTreeMap, BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose,
    EntityId, LlmEventBus, LlmMessage, LlmRequest, MessageStreamError, ModelTierRef, Mutex,
    Producer, ReplyCraft, ResponseFormat, Seat, SessionHint, StreamCancelReason, TierPrecedence,
    Vault, WakeTurnSubject, answer_memory, compaction, produce,
};

/// Opens the reply's stream, admits its run and starts the model call, then
/// drives it on a task of its own: a caller that goes away does not stop it.
pub(crate) fn begin_answer(ai: &AiHandle, answer: Answer) -> Result<Answering, AnswerRefused> {
    begin_sourced_answer(ai, answer, None)
}

/// [`begin_answer`] for a call fixed code assembled from `sources` (FIX
/// 6935): its run's permits and metered settlement carry them. `None` is
/// unknown.
pub(in crate::api::ai::chat) fn begin_sourced_answer(
    ai: &AiHandle,
    answer: Answer,
    sources: Option<Vec<EntityId>>,
) -> Result<Answering, AnswerRefused> {
    let Answer {
        vault,
        agent,
        session_key,
        activity,
        open,
        mode,
        admitted,
        payer,
        funding,
        budget_units,
        credential,
        keepalive,
        mark,
        breakpoint,
        today,
        craft,
        assertions,
    } = answer;
    // The exact request the reply's craft rides in, read before it is sent.
    let craft = craft.and_then(|entries| {
        let digest = admitted.request.canonical_hash_hex().ok()?;
        Some((entries, digest))
    });
    // Past the vault's message-stream row the stream waits its turn (rule 5),
    // so it waits off the runtime's workers.
    let begun = crate::server::blocking(|| {
        // The sitting keeps who answered it and who asked (FIX 2015), so its
        // distill can name them once presence is gone. A failed write never
        // stops the answer.
        if let Some(key) = session_key
            && let Err(error) = vault.bind_session_answer(key, agent)
        {
            tracing::warn!(kind = ?error.kind(), "the answer's sitting kept no speakers");
        }
        let memory = answer_memory(&vault, agent, session_key);
        match &open {
            AnswerOpen::Turn { turn, .. } => memory.begin_message_stream(turn, Some(mode)),
            AnswerOpen::Retry { turn, action } => {
                memory.begin_message_regeneration(turn, action, Some(mode))
            }
            AnswerOpen::Continue(message) => memory.begin_message_continuation(message, Some(mode)),
        }
    });
    let handle = match begun {
        Ok(handle) => handle,
        Err(MessageStreamError::WaitedOut(waited)) => {
            return Err(AnswerRefused::WaitedOut(waited.to_string()));
        }
        Err(error) => return Err(AnswerRefused::Engine(error.to_string())),
    };
    let container = answer_container(&vault, &open);
    let wakes = container.map(|_| vault.subscribe_task_updates());
    // FIX 4465 D: a self agent's breakpoint, right before the answer's
    // stream: its live fork is this answer's own admitted call.
    let pending = breakpoint.map(|breakpoint| {
        compaction::enter(
            ai,
            &vault,
            breakpoint,
            &admitted,
            handle.message_id(),
            compaction::TurnMeter {
                payer,
                funding: funding.clone(),
                budget_units,
            },
        )
    });

    // The turn is a run on the vault's budget policy for this actor, one line
    // per turn, billed to its funding. Each rung the call reaches is admitted
    // on its own permit and settles itself; the first is admitted here, so a
    // turn the line cannot hold is refused before any model is called.
    let started = vault
        .policy_budget_guard(
            format!("chat:{}", handle.message_id().to_hex()),
            budget_units,
            oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(budget_units),
            BudgetExhaustionPolicy::Suspend,
            payer,
        )
        .map_err(|error| error.to_string())
        .and_then(|meter| {
            let run = ai.model_runtime().funded_run(
                format!("chat:{}", handle.message_id().to_hex()),
                meter,
                funding,
            );
            compaction::open_stream(&run.sourced(sources), admitted, today, pending.as_ref())
                .map_err(|error| format!("chat budget: {error:?}"))
        });
    let stream = match started {
        Ok(stream) => stream,
        // A Retry its budget refused never started: its stream goes and no
        // TURN or MESSAGE is left (FIX 3152).
        Err(reason) => {
            let memory = answer_memory(&vault, agent, session_key);
            if matches!(open, AnswerOpen::Retry { .. }) {
                memory
                    .abandon_unstarted_retry(handle)
                    .map_err(|error| AnswerRefused::Engine(error.to_string()))?;
            } else {
                let _ = memory.cancel_stream(handle, StreamCancelReason::AgentAborted);
            }
            return Err(AnswerRefused::NotAdmitted(reason));
        }
    };

    let streamed = Arc::new(Mutex::new(String::new()));
    let saved = Arc::new(Mutex::new(None));
    let mut bus = LlmEventBus::new(Box::new(AssistantMessage {
        vault: Arc::clone(&vault),
        agent,
        session_key,
        handle,
        credential: credential.clone(),
        streamed: Arc::clone(&streamed),
        saved: Arc::clone(&saved),
    }));
    let subscription = bus.subscribe();
    let (finished, outcome) = tokio::sync::oneshot::channel();
    let ai = ai.clone();
    let landed = (Arc::clone(&vault), agent);
    let turn = ai.enter_turn();
    let producer = Producer {
        bus,
        stream,
        vault,
        agent,
        session_key,
        handle,
        credential,
        streamed: Arc::clone(&streamed),
        saved: Arc::clone(&saved),
        keepalive,
        turn,
        mark,
        container,
        wakes,
        assertions,
    };
    tokio::spawn(async move {
        let result = produce(producer).await;
        if let Some(sitting) = activity {
            ai.session_hint(sitting, SessionHint::Activity, None);
        }
        // The answer is the agent's turn, so its own cadence dial counts it.
        ai.turn_landed(
            &landed.0,
            WakeTurnSubject::Agent {
                id: landed.1,
                signals: AgentWakeSignals::default(),
            },
        );
        let saved = saved.lock().ok().and_then(|mut slot| slot.take());
        let fell_back = pending
            .as_ref()
            .is_some_and(|pending| !pending.answered_live());
        compaction::keep(&landed.0, pending, saved.as_ref());
        let text = streamed
            .lock()
            .map_or_else(|_| String::new(), |text| text.clone());
        if let (Some((entries, request_digest)), Some(receipt), Some(conversation)) =
            (craft, saved.as_ref(), container)
        {
            keep_reply_craft(
                &landed.0,
                ReplyCraft {
                    agent: landed.1,
                    session_key,
                    conversation,
                    message: receipt.message_id,
                    entries,
                    request_digest,
                    result_digest: oneiron::receipt::call_bytes_digest(text.as_bytes()),
                },
            );
        }
        let _ = finished.send(AnswerOutcome {
            result,
            saved,
            text,
            fell_back,
        });
    });
    Ok(Answering {
        handle,
        subscription,
        outcome,
    })
}

/// The conversation a reply is written into: a fresh turn's, as its caller
/// bound it before generation (FIX 8132), or the continued MESSAGE's.
/// `None` when it lies in none; a placement that cannot be read binds the
/// record itself, where its stream is written anyway, and is never refused.
pub(in crate::api::ai::chat) fn answer_container(
    vault: &Vault,
    open: &AnswerOpen,
) -> Option<EntityId> {
    let record = match open {
        // Its TURN is not written until the reply lands: the conversation
        // its user's turn was witnessed into is the one it answers in.
        AnswerOpen::Turn { conversation, .. } => return *conversation,
        // A Retry's TURN lands only with its reply (FIX 3152): the reply it
        // answers again sits in the same conversation.
        AnswerOpen::Retry { action, .. } => action.message,
        AnswerOpen::Continue(message) => *message,
    };
    vault
        .record_container(record)
        .inspect_err(
            |error| tracing::warn!(%error, "chat: the reply's conversation was not placed"),
        )
        .unwrap_or(Some(record))
}

/// Keeps the craft a saved reply was shown on the receipt spine, as its
/// answering agent. A receipt that is not kept leaves the reply as saved,
/// logged.
pub(in crate::api::ai::chat) fn keep_reply_craft(vault: &Vault, craft: ReplyCraft) {
    let kept = crate::server::blocking(|| {
        answer_memory(vault, craft.agent, craft.session_key).record_craft_reply(
            craft.conversation,
            craft.message,
            &craft.entries,
            craft.request_digest,
            craft.result_digest,
        )
    });
    if let Err(error) = kept {
        tracing::warn!(code = %error.code, "a chat reply's craft receipt was not kept");
    }
}

pub(crate) fn chat_request(seat: &Seat, messages: Vec<LlmMessage>) -> LlmRequest {
    let purpose = CallPurpose::AnswerGen;
    LlmRequest {
        model: seat.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef("answer".into())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: seat.locality,
            host_keyless: false,
        },
        messages,
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    }
}
