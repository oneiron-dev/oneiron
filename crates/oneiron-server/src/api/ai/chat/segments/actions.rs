//! A reused turn action's fresh session metadata and post-save successor.
use oneiron::conversation::{TurnAction, TurnActionAttempt};
use oneiron::prompt::PromptLayout;

use super::*;
use crate::ai_host::AiHandle;
use crate::api::ai::chat::compaction::{self, ChatReused};

pub(crate) struct ActionSession {
    reader: Reader,
    segments: TurnSegments,
    /// The agent the reused call answers as.
    agent: EntityId,
}

impl ActionSession {
    /// Rebuilds the captured request's metadata, then describes Continue's
    /// request-only suffix. A source or layout that drifted stays cold;
    /// neither the request nor its kept breakpoint changes.
    pub(crate) fn of(
        ai: &AiHandle,
        vault: &Arc<Vault>,
        action: &TurnActionAttempt,
        reused: &ChatReused,
    ) -> Option<Self> {
        let continuing = action.action == TurnAction::Continue;
        let memory = crate::ai_host::action_reader(vault, action)?;
        let (chat, borrowed, captured) =
            reused.breakpoint.action_chat(ai, vault, &memory, action)?;
        let (actor, class) = action.requester().ok()?;
        let agent = reused.breakpoint.agent()?;
        let reader = Reader {
            vault: Arc::clone(vault),
            credential: TurnCredential::Action {
                action: Box::new(action.clone()),
                vault: Arc::clone(vault),
            },
            actor,
            class,
            locality: if action.off_device {
                CallerLocality::OffDevice
            } else {
                CallerLocality::OnDevice
            },
        };
        let request = &reused.live.request;
        let prompt = ai.prompt_layout();
        let craft = !reused.craft.is_empty();
        // A captured call may close with its opener right after the user's
        // turn (FIX 14676); the turn's own messages end before it.
        let user_text = captured
            .len()
            .checked_sub(2)
            .and_then(|at| captured.get(at))
            .map(compaction::message_text)
            .unwrap_or_default();
        let opened = compaction::captured_opener(&captured, &user_text);
        let captured = &captured[..captured.len() - usize::from(opened)];
        let system_end = captured
            .len()
            .checked_sub(chat.log().lines.len().checked_add(1 + usize::from(craft))?)?;
        let instructions = &captured[..system_end];
        if instructions
            .iter()
            .any(|message| message.role != LlmMessageRole::System)
        {
            return None;
        }
        let mut messages = instructions.to_vec();
        chat.push_log(&mut messages);
        let log_end = messages.len();
        messages.push(captured.last()?.clone());
        if craft {
            let early = prompt == PromptLayout::EarlySystem;
            let index = if early {
                system_end
            } else {
                captured.len().checked_sub(2)?
            };
            messages.insert(
                if early { system_end } else { log_end },
                captured.get(index)?.clone(),
            );
        }
        // The opener the reused call closes with: the captured one a
        // Continue keeps, or the one a Retry samples now, where the request
        // holds one right after the user's turn.
        let tail = request
            .messages
            .get(captured.len())
            .filter(|message| {
                message.role == LlmMessageRole::User
                    && oneiron::context_board::is_turn_opener_line(&compaction::message_text(
                        message,
                    ))
            })
            .map(|opener| BoardView {
                state: None,
                tail: Some(TurnTail {
                    text: compaction::message_text(opener),
                    sections: Vec::new(),
                    opener: true,
                }),
            });
        let ends = captured.len() + usize::from(tail.is_some());
        let segments = admitted_with_sources(
            &reader,
            Assembled {
                layout: Layout {
                    prompt,
                    system_end,
                    log_end,
                },
                self_chat: Some(&chat),
                messages: &messages,
                board: tail.as_ref(),
                agent,
                craft: craft.then_some(reused.craft.as_slice()),
            },
            &request.messages,
            &borrowed,
            (continuing && request.messages.len() != ends).then_some(action.message),
        )?;
        segments.manifest.anchor()?;
        Some(Self {
            reader,
            segments,
            agent,
        })
    }

    pub(crate) fn manifest(&self) -> Arc<SegmentManifest> {
        Arc::clone(&self.segments.manifest)
    }

    /// A Retry saves a new whole reply; a Continue appends to its existing
    /// MESSAGE. Only that generation's full persisted text can advance the
    /// captured request. A fallback publishes no successor for it. With
    /// `preparing`, the session then prepares beside the successor what the
    /// conversation's next turn, its requester's, puts right after the
    /// history (I1 = C, FIX 14677).
    pub(crate) fn commit_on_answer(
        self,
        answering: Answering,
        preparing: Option<Arc<crate::server::SyncServer>>,
    ) -> Answering {
        let Self {
            reader,
            segments,
            agent,
        } = self;
        let next = preparing.and_then(|server| {
            let TurnCredential::Action { action, .. } = &reader.credential else {
                return None;
            };
            Some(Arc::new(crate::api::ai::chat::next_turn::ChatNextTurn {
                server,
                reader: reader.clone(),
                agent,
                conversation: Some(action.conversation),
            }) as Arc<dyn NextTurnSource>)
        });
        let authority = segments
            .authority
            .as_ref()
            .map(|(read_key, sources)| ChatAuthority {
                reader: reader.clone(),
                credential: reader.credential.clone(),
                read_key: read_key.clone(),
                sources: sources.clone(),
                at: None,
                path: segments.path.clone(),
                revocation: segments.revocation,
            });
        let Answering {
            handle,
            subscription,
            outcome,
        } = answering;
        let expected_message = handle.recorded_message_id();
        let (finished, forwarded) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _retain = segments._turn;
            let Ok(ended) = outcome.await else {
                return;
            };
            let whole = !ended.fell_back
                && ended.result.is_ok()
                && ended.saved.as_ref().is_some_and(|saved| {
                    Some(saved.message_id) == expected_message
                        && saved.finality == StreamFinality::Final
                });
            let saved = ended.saved.clone().filter(|_| whole);
            let _ = finished.send(ended);
            if let (Some(saved), Some(authority)) = (saved, authority) {
                let message = saved.message_id;
                let text = crate::server::blocking(|| {
                    let TurnCredential::Action { action, .. } = &reader.credential else {
                        return None;
                    };
                    crate::ai_host::action_reader(&reader.vault, action)?
                        .message_stream_committed_text(&saved)
                        .ok()?
                        .value
                });
                let Some(text) = text else {
                    return;
                };
                let turn = crate::server::blocking(|| {
                    let turns = reader
                        .vault
                        .targets(&message, oneiron::EdgeKind::PartOf, None)
                        .ok()?;
                    let [turn] = turns.as_slice() else {
                        return None;
                    };
                    Some(*turn)
                });
                if let Some(head) = turn {
                    let commit = ReplyCommit {
                        head,
                        message,
                        text,
                    };
                    match next {
                        Some(next) => reply_committed_preparing(
                            &segments.manifest,
                            commit,
                            Arc::new(authority),
                            next,
                        ),
                        None => reply_committed(&segments.manifest, commit, Arc::new(authority)),
                    }
                }
            }
        });
        Answering {
            handle,
            subscription,
            outcome: forwarded,
        }
    }
}
