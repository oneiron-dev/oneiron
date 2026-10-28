//! Chat turn admission and setup.
//! Entry: start_turn.
//! Chat types and shared helpers stay in the parent; start_turn keeps its original chat-only scope.

use super::{
    Answer, AnswerOpen, AnswerRefused, Arc, ChatTurnRequest, CoreAuth, CoreScope, EntityId,
    HOST_TURN_GENERATE, HistoryRole, IntoResponse, Json, JsonRejection, LlmMessage, LlmMessageRole,
    MessageWriteMode, Refused, ReplyAssertionCollector, RoleRefusal, SessionHint, Started,
    StatusCode, StreamCadence, StreamSyncVisibility, SyncServer, TurnCredential, Value, VerbCall,
    WITNESS_ROW, WakeTurnSubject, WitnessAuthor, WriteActor, after_turn, assistant,
    begin_sourced_answer, compaction, credential_memory, hook_ask, hook_stopped, invocation,
    keepalive_every, mark_history_end, principal, recall, refused, resolve_entity_ref,
    room_launch_funding, segments, sitting, sources, text_message, turn_generate_pre,
    verb_hook_boundary, witness_through_row, witness_turn,
};

pub(in crate::api::ai::chat) fn start_turn(
    auth: &CoreAuth,
    server: &Arc<SyncServer>,
    peer: oneiron::authority::PeerMachine,
    locality: oneiron::claim::CallerLocality,
    headers: &axum::http::HeaderMap,
    payload: Result<Json<ChatTurnRequest>, JsonRejection>,
    read: recall::TurnRead,
) -> Result<Started, Refused> {
    let recall::TurnRead { mark, board } = read;
    // A turn reads the agent and the conversation, and writes both turns.
    for scope in [CoreScope::Read, CoreScope::Write] {
        auth.require(scope)
            .map_err(|error| Box::new(error.into_response()))?;
    }
    let Json(request) = payload.map_err(|rejection| {
        refused(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            rejection.body_text(),
        )
    })?;
    if request.text.trim().is_empty() {
        return Err(refused(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "text is empty",
        ));
    }
    let invocation = invocation(headers)?;
    let seat = server.ai.chat_seat().cloned().ok_or_else(|| {
        refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_model_configured",
            "no [models] rung serves generative_reasoner",
        )
    })?;
    let vault = Arc::clone(server.vault());
    // `mark`, the reply's newcomer barrier, was taken before the first read
    // the request is assembled from, its board's included (FIX 1389, 8133).
    let (actor, class) = principal(auth, &vault)?;
    let (agent, instructions) = assistant(auth, &vault, request.agent_ref.as_deref())?;
    let settings = server.ai.chat_settings();
    let engine = |error: &dyn std::fmt::Display| {
        refused(StatusCode::CONFLICT, "turn_refused", error.to_string())
    };
    let mut messages: Vec<LlmMessage> = instructions
        .into_iter()
        .map(|text| text_message(LlmMessageRole::System, text))
        .collect();
    // FIX 6935: the rows the call is read from, gathered as it is assembled.
    let mut sources = sources::TurnSources::of_agent(agent);
    // OF-490: the answering agent is shown its own craft, read on one
    // snapshot; the reply's receipt keeps the exact pack once the reply is
    // saved. A turn runs on no attempt. Only the notes the caller's own read
    // admits are shown (SCAN C009), read through the handle its self-chat
    // log reads through. It joins the request once the history and the
    // user's turn are in it (FIX 6676), under the one layout this turn reads.
    let layout = server.ai.prompt_layout();
    let lead = messages.len();
    let craft = crate::server::blocking(|| {
        let reader = match auth.principal_ref() {
            Some(_) => credential_memory(&vault, Some(auth), actor, class).at(locality),
            None => vault.memory(actor, class),
        };
        crate::ai_host::resident_craft::snapshot_craft_scoped(
            &vault,
            &reader,
            &agent,
            vault.now_recorded_at(),
            layout,
        )
    });
    if let Some(craft) = &craft {
        sources.craft(&craft.entries);
    }
    let system_end = messages.len();
    // FIX 4465 D: a self agent on its live fork reads its log from the
    // retained ledger, as the caller reads it where it sits; every other
    // turn takes the caller's lines as before.
    let self_chat = crate::server::blocking(|| {
        let reader = match auth.principal_ref() {
            Some(_) => credential_memory(&vault, Some(auth), actor, class).at(locality),
            None => vault.memory(actor, class),
        };
        compaction::self_chat(
            &server.ai,
            &vault,
            &reader,
            agent,
            &request.conversation_ref,
            settings.history_turns,
        )
    });
    match &self_chat {
        Some(chat) => {
            chat.push_log(&mut messages);
            sources.add(chat.sources().as_deref());
        }
        None => {
            let skip = request.history.len().saturating_sub(settings.history_turns);
            for earlier in request.history.into_iter().skip(skip) {
                // A caller's line names no row it was read from.
                sources.add(None);
                let role = match earlier.role {
                    HistoryRole::User => LlmMessageRole::User,
                    HistoryRole::Assistant => LlmMessageRole::Assistant,
                };
                messages.push(text_message(role, earlier.text));
            }
        }
    }
    let log_end = messages.len();
    messages.push(text_message(LlmMessageRole::User, request.text.clone()));
    // FIX 6676: the craft goes where the session layout places it, the
    // user's turn as typed staying the latest user message. The turn's
    // context is the outgoing request's alone: the witness below keeps the
    // user's own text, and the kept log never holds it.
    let (craft, turn_context) = match craft {
        Some(craft) => {
            let at = crate::ai_host::resident_craft::place_craft(
                &mut messages,
                lead,
                craft.message,
                layout,
            );
            (Some(craft.entries), at)
        }
        None => (None, None),
    };
    // Admitted through its role before anything is written: a vault route
    // this server cannot serve refuses here, with no call made.
    // FIX 6794: the board rides after the stable history, right before the
    // newest User (FIX 6676's layout); a role that does not admit it with
    // the board admits the turn without it, its omission's note in its
    // place (FIX 8136).
    // The board goes in at the latest user message's place: with no craft,
    // it opens the turn's context.
    let board_at = messages
        .iter()
        .rposition(|message| message.role == LlmMessageRole::User);
    // DESIGN-V2 R2: the messages and the board as assembled, for the call's
    // segment manifest.
    let assembled = messages.clone();
    let read_board = board.as_ref().ok().and_then(Option::as_ref);
    let board_view = read_board.map(|board| (board.block.clone(), board.sections.clone()));
    let board_rows = read_board.map(|board| board.rows.clone());
    let recall::AdmittedTurn {
        call: admitted,
        recalled,
        context,
        omitted,
        noted,
    } = recall::admit(&server.ai, &vault, &seat, auth, messages, board);
    let turn_context = turn_context.or(board_at.filter(|_| recalled || noted));
    // A board the call goes without is no row it read.
    if recalled {
        sources.add(board_rows.as_deref());
    }
    // The board's place holds the board, or the note of its omission, which
    // the call's segments name as one unnamed board section.
    let board_view = if recalled {
        board_view
    } else {
        omitted
            .filter(|_| noted)
            .map(|omission| (omission.note(), Vec::new()))
    };
    let mut admitted = admitted.map_err(|refusal| match refusal {
        RoleRefusal::NoSeat => refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_model_configured",
            refusal.to_string(),
        ),
        RoleRefusal::RouteNotServed { .. } => refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "model_route_not_served",
            refusal.to_string(),
        ),
        RoleRefusal::Refused(_) => refused(
            StatusCode::PAYMENT_REQUIRED,
            "turn_not_admitted",
            refusal.to_string(),
        ),
    })?;
    if self_chat.is_some() {
        // The history before the turn's context is the prefix the next turn
        // sends again, so its end is marked beside the request's own. Today's
        // layout keeps today's marks.
        let stable_prefix = layout == oneiron::prompt::PromptLayout::StableHistoryThenTurnContext;
        if let Some(history_end) = turn_context
            .filter(|_| stable_prefix)
            .and_then(|at| at.checked_sub(1))
        {
            mark_history_end(&mut admitted.request, history_end);
        }
        compaction::mark_prefix(&mut admitted.request);
    }
    // DESIGN-V2 R2: the call's typed segments, set once it is admitted and
    // only when they describe the admitted messages exactly.
    let session_reader = segments::Reader {
        vault: Arc::clone(&vault),
        auth: auth.clone(),
        actor,
        class,
        locality,
    };
    let turn_segments = segments::admitted(
        &session_reader,
        segments::Assembled {
            layout: segments::Layout {
                system_end,
                log_end,
            },
            self_chat: self_chat.as_ref(),
            messages: &assembled,
            board: board_view.as_ref(),
            agent,
            craft: craft.as_deref(),
        },
        &admitted.request.messages,
    );
    admitted.request.host_segments = turn_segments
        .as_ref()
        .map(|segments| Arc::clone(&segments.manifest));
    // FIX 6921: what the admitted board showed, frozen against the call it
    // rides in.
    let context = context
        .map(|capture| crate::api::context_board::freeze_chat_context(capture, &admitted.request));
    // `host.turn.generate` (ARCH-0080 §5): its pre chain runs once the turn
    // is admitted, so a refused admission leaves no hook's blocks or notes,
    // and before the user's turn is witnessed, so a skip or an ask ends the
    // turn before anything lands and a retry of it witnesses once.
    // The turn's hooks read under the caller's credential, where its
    // connection sits (ARCH-0080 §3). An owner-grade credential naming no
    // principal reads as the owner it writes as. The surface is bound to the
    // conversation this request starts its work in (OF-221), so a root TASK
    // it creates carries that origin to the agent that realizes it; a ref
    // that does not resolve binds none, and the witness refuses it.
    let origin = resolve_entity_ref(&vault, &request.conversation_ref).ok();
    // A turn in a room bills the payer whose consent on the answering
    // agent's join funds that room (FIX 805), resolved before anything is
    // written: a turn with no payer to bill is refused, typed.
    let funding = match origin {
        Some(room) => {
            crate::server::blocking(|| room_launch_funding(&vault, room, None, agent, actor))
                .map_err(|fault| {
                    refused(
                        StatusCode::PAYMENT_REQUIRED,
                        fault.reason(),
                        fault.to_string(),
                    )
                })?
        }
        None => None,
    };
    let hooked = || {
        let memory = match auth.principal_ref() {
            Some(_) => credential_memory(&vault, Some(auth), actor, class).at(locality),
            None => vault.memory(actor, class),
        };
        match origin {
            Some(conversation) => memory.with_origin_conversation(conversation),
            None => memory,
        }
    };
    let reader =
        VerbCall::reader_of(&hooked(), HOST_TURN_GENERATE).map_err(|error| engine(&error))?;
    // A turn in an anonymous off-record session its principal is verified
    // in keeps its hooks' records and pauses in that session only, as a row
    // does (FIX 5380): judged on the caller's own surface, never a header.
    // Its retry names the hook pause it resumes (FIX 5526).
    let resumes = hook_ask::named(headers, &hooked());
    let hooked_call = || match invocation {
        Some(id) => hook_ask::resuming(hooked().with_invocation(id), resumes),
        None => hooked(),
    };
    // Each session is judged on the call's own input (FIX 10344), as a row
    // door's is: a call that serves a room NOTE keeps its records there.
    let at = vault.now_recorded_at();
    let user_turn = witness_turn(
        &request.conversation_ref,
        None,
        WitnessAuthor::User,
        request.text.clone(),
        at,
    );
    let generate_session = verb_hook_boundary::hook_session_for_call(
        Some(&hooked_call()),
        HOST_TURN_GENERATE,
        &super::hooks::turn_generate_args(&request.conversation_ref),
        None,
    )
    .map_err(|error| engine(&error))?;
    let witness_args = serde_json::to_value(&user_turn).map_err(|error| engine(&error))?;
    let witness_session = verb_hook_boundary::hook_session_for_call(
        Some(&hooked_call()),
        WITNESS_ROW,
        &witness_args,
        None,
    )
    .map_err(|error| engine(&error))?;
    // Chat resolves no room before the user's turn is witnessed, so its
    // call names none.
    let generating = turn_generate_pre(
        &vault,
        actor,
        invocation,
        reader,
        &request.conversation_ref,
        None,
        generate_session.as_ref(),
    )
    .map_err(|error| engine(&error))?
    .map_err(|stop| hook_stopped(&stop))?;

    // The assistant message closes after the vault's idle timeout without
    // an append; read before anything is written.
    let keepalive = keepalive_every(
        vault
            .message_stream_policy()
            .map_err(|error| engine(&error))?
            .idle_timeout_ms,
    );
    let session_key = crate::api::ai::bound_session_key(server, actor, peer, locality)?;
    // A turn in an anonymous off-record session opens and bumps no durable
    // sitting; its witness and stream still bind the key (FIX 5564).
    let signals = sitting::signals_sitting(&vault, &hooked());
    // The rows its snapshot craft showed ride its breakpoint (FIX 9439).
    let breakpoint_craft = craft.clone().unwrap_or_default();
    // A turn that keeps no durable record keeps no craft receipt either.
    let craft = craft.filter(|_| !verb_hook_boundary::keeps_no_record(&hooked()));
    // Nor its context's records (FIX 6921): a session-only turn keeps none.
    let context = context.filter(|_| generate_session.is_none() && witness_session.is_none());
    if signals {
        server.ai.session_hint(session_key, SessionHint::AppOpen);
    }
    let mut written = None;
    let user = crate::server::blocking(|| {
        let memory = vault.memory(actor, class).with_session(session_key);
        let (memory, hooked) = match invocation {
            Some(id) => (memory.with_invocation(id), hooked().with_invocation(id)),
            None => (memory, hooked()),
        };
        witness_through_row(
            &vault,
            &memory,
            &hooked,
            &user_turn,
            witness_session.as_ref(),
            &mut written,
        )
    })
    .map_err(|error| engine(&error))?
    .map_err(|stop| hook_stopped(&stop))?;
    // FIX 7004: the MESSAGE row the user's words were witnessed into.
    sources.add(written.as_deref());
    // FIX 8132: the reply is bound, before generation, to the conversation
    // its own turn is written into, so its newcomer wakes and every
    // publication check read the conversation that receives its text: the
    // destination the assistant's turn below writes to, the request's ref,
    // resolved once above (`origin`), never the user's witnessed MESSAGE,
    // which a pre-hook may have moved. A destination in no conversation
    // answers standalone, as before; one whose placement was not read binds
    // the destination itself, where its stream is written anyway. Only a
    // ref that names nothing is refused, before any model is called: no
    // conversation would hold its reply.
    let destination = origin.ok_or_else(|| engine(&"the reply's conversation was not placed"))?;
    let conversation = crate::server::blocking(|| vault.record_container(destination))
        .unwrap_or(Some(destination));
    // The caller's view of the receipt, which a hook may have redacted.
    let user_turn = user
        .get("turn_short_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    server.ai.turn_landed(&vault, WakeTurnSubject::Vault);
    let turn = EntityId::now();
    let credential = TurnCredential::Request {
        auth: auth.clone(),
        vault: Arc::clone(&vault),
    };
    // A streamed turn publishes each saved delta to every device; a whole
    // one keeps its partials private.
    let mode = if request.stream {
        MessageWriteMode::Streamed {
            visibility: StreamSyncVisibility::AllDevices,
            cadence: StreamCadence::PerToken,
        }
    } else {
        MessageWriteMode::Atomic
    };
    let hooks_vault = Arc::clone(&vault);
    let answering = begin_sourced_answer(
        &server.ai,
        Answer {
            vault,
            agent,
            session_key: Some(session_key),
            activity: signals.then_some(session_key),
            open: AnswerOpen::Turn {
                turn: witness_turn(
                    &request.conversation_ref,
                    Some(turn),
                    WitnessAuthor::Companion,
                    String::new(),
                    at,
                ),
                conversation,
            },
            mode,
            admitted,
            payer: WriteActor::new(actor, class),
            funding,
            budget_units: settings.turn_budget_units,
            credential: credential.clone(),
            keepalive,
            mark,
            breakpoint: self_chat.map(|chat| {
                let reader = WriteActor::new(actor, class);
                chat.breakpoint(reader, locality, recalled, breakpoint_craft)
            }),
            today: None,
            craft,
            assertions: ReplyAssertionCollector::default(),
        },
        sources.rows(),
    )
    .map_err(|refusal| match refusal {
        AnswerRefused::WaitedOut(reason) => {
            refused(StatusCode::SERVICE_UNAVAILABLE, "turn_waited_out", reason)
        }
        AnswerRefused::Engine(reason) => refused(StatusCode::CONFLICT, "turn_refused", reason),
        AnswerRefused::NotAdmitted(reason) => {
            refused(StatusCode::PAYMENT_REQUIRED, "turn_not_admitted", reason)
        }
    })?;
    let answering = after_turn(hooks_vault, generating, answering);
    // FIX 6921: the answer's context records, kept once it is handed on.
    let answering = crate::api::context_board::record_chat_answer(
        Arc::clone(server),
        context,
        turn,
        agent,
        WriteActor::new(actor, class),
        session_key,
        answering,
    );
    // DESIGN-V2 R2: once the reply lands whole, the session coordinator
    // stages its canonical successor.
    let answering = segments::commit_on_answer(
        turn_segments,
        &session_reader,
        &credential,
        written.as_deref(),
        turn,
        answering,
    );
    Ok(Started {
        stream: request.stream,
        conversation_ref: request.conversation_ref,
        user_turn,
        turn,
        answering,
        credential,
        board_omitted: omitted,
    })
}
