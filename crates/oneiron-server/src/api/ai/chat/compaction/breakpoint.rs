//! A self agent's answer breakpoint (FIX 4465 D): what the reply keeps
//! once it is saved, and the flight its turn enters. Both bind the rung
//! that answered the answer, once it ended (FIX 4933), from the recorded
//! terminal binding, never the rung its walk would have taken when it was
//! admitted.
use crate::models::AnsweringRung;

use super::*;

/// What the answer's breakpoint holds until the answer ends (FIX 4933):
/// the breakpoint, the answer's own admitted call for a turn that compacts
/// its log, its reply's MESSAGE and its meter; and whether its own captured
/// call answered it.
pub(in crate::api::ai::chat) struct PendingSeed {
    breakpoint: AnswerBreakpoint,
    admitted: Option<RoleCall>,
    message: EntityId,
    meter: TurnMeter,
    pub(super) live: Arc<AtomicBool>,
}

impl PendingSeed {
    /// Whether the call it was entered with answered: `false` once a reused
    /// prefix's captured rung gave way to today's call (OF-490 reads this
    /// for the craft the reply was shown).
    pub(in crate::api::ai::chat) fn answered_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }
}

/// The turn's meter, as the flight's own guard is opened on it.
pub(in crate::api::ai::chat) struct TurnMeter {
    pub(in crate::api::ai::chat) payer: WriteActor,
    pub(in crate::api::ai::chat) funding: Option<PayerPerson>,
    pub(in crate::api::ai::chat) budget_units: u64,
}

/// The answer's breakpoint, right before its stream: held until the answer
/// ends, when [`keep`] binds the rung that answered it (FIX 4933), never the
/// rung its walk would take now. A chat turn that compacts its log keeps a
/// copy of its own `admitted` call for its flight. `message` is the reply's
/// MESSAGE.
pub(in crate::api::ai::chat) fn enter(
    breakpoint: AnswerBreakpoint,
    admitted: &RoleCall,
    message: EntityId,
    meter: TurnMeter,
) -> PendingSeed {
    let admitted = matches!(breakpoint.log, Some(BreakpointLog::Compact(_))).then(|| RoleCall {
        request: admitted.request.clone(),
        ladder: Arc::clone(&admitted.ladder),
    });
    PendingSeed {
        breakpoint,
        admitted,
        message,
        meter,
        live: Arc::new(AtomicBool::new(true)),
    }
}

/// The seed a chat turn's reply keeps: its call exactly as `answering`, the
/// rung that answered it, sent it (FIX 4933), that rung by ref, the log's
/// sources, and the craft rows the host's snapshot read for it (FIX 9439).
/// None for a log whose turns were not all pinned or that a room's
/// projection read (FIX 5031: a reuse checks its seed on its own reader).
fn capture_seed(
    agent: EntityId,
    reader: WriteActor,
    log: &ChatLog,
    instructions_digest: Option<String>,
    craft: Vec<ManifestEntry>,
    answering: &AnsweringRung,
) -> Option<ChatBreakpoint> {
    if !log.pinned || log.room_projection {
        return None;
    }
    let AnsweringRung { rung, request } = answering;
    let digest = request.canonical_hash().ok()?;
    Some(ChatBreakpoint {
        agent,
        reader: reader.entity_ref(),
        reader_class: reader.actor_class() as u8,
        conversation: log.conversation,
        branch: log.branch,
        session: log.session,
        request: serde_json::to_string(&**request).ok()?,
        request_digest: hex(&digest),
        rung: ChatBreakpointRung {
            offer_digest: oneiron::code_run::live_fork_offer_digest(&rung.offer)?,
            provider: rung.provider.clone(),
            position: rung.position,
            wire_model: rung.wire_model.clone(),
        },
        instructions_digest,
        sources: log.sources.clone(),
        summaries: log.summaries.clone(),
        craft_entries: craft,
    })
}

/// Once the answer ends, its breakpoint binds `answering`, the rung that
/// answered it, if one did (FIX 4933). The saved reply keeps its seed when
/// its own captured call answered it: a chat turn's, captured from that
/// rung's call; a reuse's, its source's again. A breakpoint that is not
/// kept leaves the reply's actions to run as they always did. A chat turn
/// past its threshold then queues its flight off the answer's path, on that
/// rung; with none that answered, a forced fork binds none and `auto`
/// writes on the cheap writer.
pub(in crate::api::ai::chat) fn keep(
    ai: &AiHandle,
    vault: &Arc<Vault>,
    pending: Option<PendingSeed>,
    saved: Option<&MessageStreamReceipt>,
    answering: Option<AnsweringRung>,
) {
    let Some(PendingSeed {
        breakpoint,
        admitted,
        message,
        meter,
        live,
    }) = pending
    else {
        return;
    };
    let AnswerBreakpoint {
        mode,
        log,
        locality,
        reader,
        instructions_digest,
        source,
        recalled,
        craft,
    } = breakpoint;
    let seed = match source {
        Some(source) => Some(source),
        None if recalled => None,
        None => log.as_ref().and_then(|log| {
            capture_seed(
                mode.agent(),
                reader,
                log.log(),
                instructions_digest,
                craft,
                answering.as_ref()?,
            )
        }),
    };
    if let (Some(seed), Some(receipt)) = (seed, saved)
        && live.load(Ordering::Acquire)
    {
        let kept = crate::server::blocking(|| {
            keep_chat_breakpoint(vault, receipt.message_id, receipt.generation, seed)
        });
        if let Err(error) = kept {
            tracing::warn!(kind = ?error.kind(), "a chat reply's breakpoint was not kept");
        }
    }
    if let (Some(BreakpointLog::Compact(log)), Some(admitted)) = (log, admitted) {
        let call = ChatBreakpointCall {
            vault: Arc::clone(vault),
            mode,
            log,
            locality,
            payer: meter.payer,
            funding: meter.funding,
            budget_units: meter.budget_units,
            message,
        };
        match crate::server::blocking(|| ai.enter_chat_breakpoint(call, &admitted, answering)) {
            Ok(()) | Err(ConversationCompactionUnavailable::Quiet) => {}
            Err(why) => tracing::info!(
                reason = why.as_str(),
                "a chat turn's own compaction is unavailable; its log stays raw"
            ),
        }
    }
}
