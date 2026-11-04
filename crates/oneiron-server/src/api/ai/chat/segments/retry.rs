//! A reused Retry's fresh session metadata and post-save successor.
use oneiron::conversation::{TurnAction, TurnActionAttempt};
use oneiron::prompt::PromptLayout;

use super::*;
use crate::ai_host::AiHandle;
use crate::api::ai::chat::compaction::ChatReused;

pub(crate) struct RetrySession {
    reader: Reader,
    segments: TurnSegments,
}

impl RetrySession {
    /// Rebuilds only the captured Retry's metadata. The request and its kept
    /// breakpoint are unchanged; a source or layout that drifted stays cold.
    pub(crate) fn of(
        ai: &AiHandle,
        vault: &Arc<Vault>,
        action: &TurnActionAttempt,
        reused: &ChatReused,
    ) -> Option<Self> {
        if action.action != TurnAction::Retry {
            return None;
        }
        let memory = crate::ai_host::action_reader(vault, action)?;
        let (chat, borrowed) = reused.breakpoint.retry_chat(ai, vault, &memory, action)?;
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
        let system_end = request
            .messages
            .len()
            .checked_sub(chat.log().lines.len().checked_add(1 + usize::from(craft))?)?;
        let instructions = &request.messages[..system_end];
        if instructions
            .iter()
            .any(|message| message.role != LlmMessageRole::System)
        {
            return None;
        }
        let mut messages = instructions.to_vec();
        chat.push_log(&mut messages);
        let log_end = messages.len();
        messages.push(request.messages.last()?.clone());
        if craft {
            let early = prompt == PromptLayout::EarlySystem;
            let index = if early {
                system_end
            } else {
                request.messages.len().checked_sub(2)?
            };
            messages.insert(
                if early { system_end } else { log_end },
                request.messages.get(index)?.clone(),
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
        )?;
        segments.manifest.anchor()?;
        Some(Self { reader, segments })
    }

    pub(crate) fn manifest(&self) -> Arc<SegmentManifest> {
        Arc::clone(&self.segments.manifest)
    }

    /// A Retry saves a new whole reply. A Continue's suffix and a fallback's
    /// answer never publish a successor for this captured request.
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
            let text = whole.then(|| ended.text.clone());
            let _ = finished.send(ended);
            if let (Some(text), Some(authority)) = (text, authority) {
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
