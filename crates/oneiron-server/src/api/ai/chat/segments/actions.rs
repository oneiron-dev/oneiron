//! A reused turn action's fresh session metadata and post-save successor.
use oneiron::conversation::{TurnAction, TurnActionAttempt};
use oneiron::prompt::PromptLayout;

use super::*;
use crate::ai_host::AiHandle;
use crate::api::ai::chat::compaction::ChatReused;

pub(crate) struct ActionSession {
    reader: Reader,
    segments: TurnSegments,
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
                board: None,
                agent: reused.breakpoint.agent()?,
                craft: craft.then_some(reused.craft.as_slice()),
            },
            &request.messages,
            &borrowed,
            (continuing && request.messages.len() != captured.len()).then_some(action.message),
        )?;
        segments.manifest.anchor()?;
        Some(Self { reader, segments })
    }

    pub(crate) fn manifest(&self) -> Arc<SegmentManifest> {
        Arc::clone(&self.segments.manifest)
    }

    /// A Retry saves a new whole reply; a Continue appends to its existing
    /// MESSAGE. Only that generation's full persisted text can advance the
    /// captured request. A fallback publishes no successor for it.
    pub(crate) fn commit_on_answer(self, answering: Answering) -> Answering {
        let Self { reader, segments } = self;
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
        let message = handle.message_id();
        let (finished, forwarded) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _retain = segments._turn;
            let Ok(ended) = outcome.await else {
                return;
            };
            let whole = !ended.fell_back
                && ended.result.is_ok()
                && ended.saved.as_ref().is_some_and(|saved| {
                    saved.message_id == message && saved.finality == StreamFinality::Final
                });
            let saved = ended.saved.clone().filter(|_| whole);
            let _ = finished.send(ended);
            if let (Some(saved), Some(authority)) = (saved, authority) {
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
                    reply_committed(
                        &segments.manifest,
                        ReplyCommit {
                            head,
                            message,
                            text,
                        },
                        Arc::new(authority),
                    );
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
