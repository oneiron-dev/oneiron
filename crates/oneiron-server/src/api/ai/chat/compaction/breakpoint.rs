//! A self agent's answer breakpoint (FIX 4465 D): what the reply keeps
//! once it is saved, and the flight its turn enters. Moved whole from
//! `compaction.rs` (FIX 4933); the bodies are as they were.
use super::*;

/// What the reply keeps once it is saved, and whether its own captured
/// call answered it.
pub(in crate::api::ai::chat) struct PendingSeed {
    seed: Option<ChatBreakpoint>,
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

/// The answer's breakpoint, right before its stream: the seed its reply
/// keeps (a chat turn's, captured from its own admitted call; a reuse's,
/// its source's again), and, for a chat turn past its threshold, its flight
/// queued off the answer's path. `message` is the reply's MESSAGE.
pub(in crate::api::ai::chat) fn enter(
    ai: &AiHandle,
    vault: &Arc<Vault>,
    breakpoint: AnswerBreakpoint,
    admitted: &RoleCall,
    message: EntityId,
    meter: TurnMeter,
) -> PendingSeed {
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
                admitted,
            )
        }),
    };
    if let Some(BreakpointLog::Compact(log)) = log {
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
        match crate::server::blocking(|| ai.enter_chat_breakpoint(call, admitted)) {
            Ok(()) | Err(ConversationCompactionUnavailable::Quiet) => {}
            Err(why) => tracing::info!(
                reason = why.as_str(),
                "a chat turn's own compaction is unavailable; its log stays raw"
            ),
        }
    }
    PendingSeed {
        seed,
        live: Arc::new(AtomicBool::new(true)),
    }
}

/// The seed a chat turn's reply keeps: its request exactly as the rung its
/// walk takes now sends it, the rung by ref, the log's sources, and the
/// craft rows the host's snapshot read for it (FIX 9439). None for a log
/// whose turns were not all pinned, or a call no rung takes now.
fn capture_seed(
    agent: EntityId,
    reader: WriteActor,
    log: &ChatLog,
    instructions_digest: Option<String>,
    craft: Vec<ManifestEntry>,
    admitted: &RoleCall,
) -> Option<ChatBreakpoint> {
    if !log.pinned {
        return None;
    }
    let (rung, request) = admitted.ladder.live_rung(&admitted.request)?;
    let digest = request.canonical_hash().ok()?;
    Some(ChatBreakpoint {
        agent,
        reader: reader.entity_ref(),
        reader_class: reader.actor_class() as u8,
        conversation: log.conversation,
        branch: log.branch,
        session: log.session,
        request: serde_json::to_string(&request).ok()?,
        request_digest: hex(&digest),
        rung: ChatBreakpointRung {
            offer_digest: oneiron::code_run::live_fork_offer_digest(&rung.offer)?,
            provider: rung.provider,
            position: rung.position,
            wire_model: rung.wire_model,
        },
        instructions_digest,
        sources: log.sources.clone(),
        summaries: log.summaries.clone(),
        craft_entries: craft,
    })
}

/// Keeps the saved reply's breakpoint, when its own captured call answered
/// it. A breakpoint that is not kept leaves the reply's actions to run as
/// they always did.
pub(in crate::api::ai::chat) fn keep(
    vault: &Vault,
    pending: Option<PendingSeed>,
    saved: Option<&MessageStreamReceipt>,
) {
    let (
        Some(PendingSeed {
            seed: Some(seed),
            live,
        }),
        Some(receipt),
    ) = (pending, saved)
    else {
        return;
    };
    if !live.load(Ordering::Acquire) {
        return;
    }
    let kept = crate::server::blocking(|| {
        keep_chat_breakpoint(vault, receipt.message_id, receipt.generation, seed)
    });
    if let Err(error) = kept {
        tracing::warn!(kind = ?error.kind(), "a chat reply's breakpoint was not kept");
    }
}
