//! Chat response delivery and producer driving.
//! Entry: streamed.
//! Started, Producer and credential helpers stay in the parent; moved functions keep chat-only scope.

use super::{
    Answering, Body, ChatLine, ChatReply, EntryWake, IntoResponse, InvocationClaim, Json, Lapse,
    LlmStreamEvent, NEWCOMER, Producer, REVOKED, Response, Started, StatusCode, StreamCancelReason,
    StreamExt, answer_memory, entry_wake, header, line, message_text, next_entry_wake, refusal,
    revoked_line,
};

/// The NDJSON answer: accepted, each delta, the terminal, then saved or the
/// error. A claimed invocation stays claimed until the producer ends, and
/// keeps the turn's whole reply for each duplicate (FIX 2004).
pub(in crate::api::ai::chat) fn streamed(
    started: Started,
    claim: Option<InvocationClaim>,
) -> Response {
    let started = kept_on_claim(started, claim);
    let Started {
        user_turn,
        answering,
        credential,
        board_omitted,
        ..
    } = started;
    let Answering {
        handle,
        subscription,
        outcome,
    } = answering;
    let accepted = ChatLine::Accepted {
        user_turn,
        message_id: handle.message_id().to_hex(),
        board_omitted,
    };
    let head = futures_util::stream::once(async move { line(&accepted) });
    let events = subscription.filter_map(|event| async move {
        match event {
            LlmStreamEvent::TextDelta { text, .. } => Some(line(&ChatLine::Delta { text })),
            LlmStreamEvent::Done {
                message,
                usage,
                finish_reason,
                ..
            } => Some(line(&ChatLine::Done {
                text: message_text(&message),
                usage,
                finish_reason,
            })),
            _ => None,
        }
    });
    let tail = futures_util::stream::once(async move {
        outcome.await.map_or_else(
            |_| {
                line(&ChatLine::Error {
                    code: "turn_failed",
                    message: "the producer stopped".into(),
                })
            },
            |outcome| {
                line(&match outcome.result {
                    Ok(()) => match outcome.saved {
                        Some(receipt) => ChatLine::Saved { receipt },
                        None => ChatLine::Error {
                            code: "not_saved",
                            message: "the terminal message was not recorded".into(),
                        },
                    },
                    Err(message) => ChatLine::Error {
                        code: "turn_failed",
                        message,
                    },
                })
            },
        )
    });
    // The response body is disclosure too: each line goes out only while the
    // credential is live; the first line after it lapses says so and ends it.
    let body = head
        .chain(events)
        .chain(tail)
        .scan(true, move |open, bytes| {
            let next = if !*open {
                None
            } else if credential.live() {
                Some(bytes)
            } else {
                *open = false;
                Some(revoked_line())
            };
            std::future::ready(next)
        })
        .map(Ok::<_, std::io::Error>);
    (
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        Body::from_stream(body),
    )
        .into_response()
}

/// The whole-message answer, once the reply is saved. A reply cut short is
/// answered as saved and incomplete; one that saved nothing is an error.
pub(in crate::api::ai::chat) async fn whole(started: Started) -> Response {
    let Started {
        conversation_ref,
        turn,
        answering,
        credential,
        board_omitted,
        ..
    } = started;
    let Answering {
        handle,
        subscription,
        outcome,
    } = answering;
    drop(subscription);
    let outcome = outcome.await;
    // The answer is disclosure too: none goes out once the credential lapsed.
    if !credential.live() {
        return refusal(
            StatusCode::FORBIDDEN,
            REVOKED,
            "the credential this turn was admitted under is no longer live",
        );
    }
    let Ok(outcome) = outcome else {
        return refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "turn_failed",
            "the producer stopped",
        );
    };
    let Some(receipt) = outcome.saved else {
        return match outcome.result {
            Ok(()) => refusal(
                StatusCode::INTERNAL_SERVER_ERROR,
                "not_saved",
                "the terminal message was not recorded",
            ),
            Err(message) => refusal(StatusCode::INTERNAL_SERVER_ERROR, "turn_failed", message),
        };
    };
    Json(ChatReply {
        conversation_ref,
        turn_id: turn.to_hex(),
        message_id: handle.message_id().to_hex(),
        text: outcome.text,
        incomplete: !receipt.complete(),
        finish_reason: receipt.finish_reason,
        board_omitted,
    })
    .into_response()
}

/// `started` with its reply kept on `claim` for each duplicate of the turn
/// (FIX 2004): once the producer ends, the claim saves the answer [`whole`]
/// would send ([`whole_reply`]), and the outcome goes on to the stream.
/// Unclaimed, `started` is as it was.
fn kept_on_claim(mut started: Started, claim: Option<InvocationClaim>) -> Started {
    let Some(claim) = claim else {
        return started;
    };
    let conversation_ref = started.conversation_ref.clone();
    let turn = started.turn;
    let message_id = started.answering.handle.message_id();
    let credential = started.credential.clone();
    let board_omitted = started.board_omitted;
    let ended = std::mem::replace(
        &mut started.answering.outcome,
        tokio::sync::oneshot::channel().1,
    );
    started.answering.outcome =
        crate::api::facade::finish_streamed_claim(claim, ended, move |outcome| {
            whole_reply(
                &conversation_ref,
                turn,
                message_id,
                &credential,
                board_omitted,
                outcome,
            )
        });
    started
}

/// The answer [`whole`] sends once a reply's producer ended with `outcome`
/// (`None` when it stopped with none): refused once the turn's credential
/// lapsed, an error when nothing was saved, and the saved message otherwise.
fn whole_reply(
    conversation_ref: &str,
    turn: super::EntityId,
    message_id: super::EntityId,
    credential: &super::TurnCredential,
    board_omitted: Option<super::recall::BoardOmission>,
    outcome: Option<&super::AnswerOutcome>,
) -> Response {
    if !credential.live() {
        return refusal(
            StatusCode::FORBIDDEN,
            REVOKED,
            "the credential this turn was admitted under is no longer live",
        );
    }
    let Some(outcome) = outcome else {
        return refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "turn_failed",
            "the producer stopped",
        );
    };
    let Some(receipt) = &outcome.saved else {
        return match &outcome.result {
            Ok(()) => refusal(
                StatusCode::INTERNAL_SERVER_ERROR,
                "not_saved",
                "the terminal message was not recorded",
            ),
            Err(message) => refusal(
                StatusCode::INTERNAL_SERVER_ERROR,
                "turn_failed",
                message.as_str(),
            ),
        };
    };
    Json(ChatReply {
        conversation_ref: conversation_ref.to_owned(),
        turn_id: turn.to_hex(),
        message_id: message_id.to_hex(),
        text: outcome.text.clone(),
        incomplete: !receipt.complete(),
        finish_reason: receipt.finish_reason.clone(),
        board_omitted,
    })
    .into_response()
}

/// Drives the model stream into the presence plane and the bus. The run
/// settles each rung: honest usage on a terminal (saved or not), the
/// reservation of a rung that went out and failed, or was stopped. A
/// credential that lapses mid-turn stops the call: nothing more reaches any
/// plane, and the message is cancelled, keeping every delta it saved.
pub(in crate::api::ai::chat) async fn produce(producer: Producer) -> Result<(), String> {
    let Producer {
        mut bus,
        mut stream,
        vault,
        agent,
        session_key,
        handle,
        credential,
        streamed,
        saved,
        keepalive,
        mut turn,
        mark,
        container,
        mut wakes,
        assertions,
    } = producer;
    let memory = answer_memory(&vault, agent, session_key);
    let cancel = |reason: StreamCancelReason| {
        if let Ok(receipt) = memory.cancel_stream(handle, reason)
            && let Ok(mut slot) = saved.lock()
        {
            *slot = Some(receipt);
        }
    };
    let fail = |reason: String| {
        cancel(StreamCancelReason::AgentAborted);
        Err(reason)
    };
    let revoked = || {
        let lapse = credential.lapse();
        cancel(lapse.cancel_reason());
        Err(lapse.reason().to_owned())
    };
    // The newcomer barrier: the reply was assembled for the audience before
    // the entry. Its MESSAGE keeps what it saved and is cancelled; the next
    // turn is assembled afresh.
    let newcomer = || {
        cancel(StreamCancelReason::Custom(NEWCOMER.into()));
        Err("an attendee entered the conversation".to_owned())
    };
    let mut keepalive = tokio::time::interval(keepalive);
    keepalive.reset();
    loop {
        let item = tokio::select! {
            item = stream.next() => item,
            () = turn.stopping() => return fail("the server is stopping".into()),
            woke = next_entry_wake(&mut wakes) => {
                if let Some(container) = container
                    && !matches!(
                        entry_wake(&vault, container, woke, &mut wakes),
                        EntryWake::Quiet
                    )
                {
                    return newcomer();
                }
                continue;
            }
            _ = keepalive.tick() => {
                if !credential.live() {
                    return revoked();
                }
                if let Err(error) = memory.append_to_stream(handle, "") {
                    return fail(format!("message stream closed while waiting: {error}"));
                }
                continue;
            }
        };
        let Some(item) = item else {
            break;
        };
        let event = match item {
            Ok(event) => event,
            Err(error) => return fail(format!("model stream failed: {error:?}")),
        };
        // The publish arm, before any delta or the terminal goes out: an
        // attendee entered the conversation since the reply was marked,
        // whatever its wake says.
        if container.is_some_and(|container| !vault.container_output_admits(mark, container)) {
            return newcomer();
        }
        if matches!(event, LlmStreamEvent::Done { .. }) {
            // The run settled the answer before it arrived: the provider
            // spent it whether or not the answer is saved. It asserts the
            // records this host gathered, never the ones it came with.
            if let Err(error) = bus.publish(assertions.stamp(event)) {
                if credential.live() {
                    cancel(StreamCancelReason::AgentAborted);
                } else {
                    let lapse = credential.lapse();
                    cancel(lapse.cancel_reason());
                    // An attested owner's lapse is his action's own reason
                    // (FIX 11090); a revoked credential's stays as it was.
                    if lapse != Lapse::Revoked {
                        return Err(lapse.reason().to_owned());
                    }
                }
                return Err(format!("terminal message was not saved: {error:?}"));
            }
            return Ok(());
        }
        if !credential.live() {
            return revoked();
        }
        if let LlmStreamEvent::TextDelta { text, .. } = &event {
            // The stream saves each delta in the vault before it is
            // published, so the append is a write: it runs off the workers.
            let appended = crate::server::blocking(|| memory.append_to_stream(handle, text));
            if let Err(error) = appended {
                return fail(format!("message stream refused a delta: {error}"));
            }
            if let Ok(mut so_far) = streamed.lock() {
                so_far.push_str(text);
            }
        }
        if let Err(error) = bus.publish(event) {
            return fail(format!("model event was not published: {error:?}"));
        }
    }
    fail("model stream ended without a terminal".into())
}
