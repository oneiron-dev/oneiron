//! A self agent's reply seed, its durable lifecycle and the flight its turn
//! enters (FIX 4465 D). The seed and the flight bind the rung that answered
//! the answer, once it ended (FIX 4933), from the recorded terminal binding,
//! never the rung its walk would have taken when it was admitted. A reused
//! prefix's seed is its source's, known before its call: it is kept for the
//! reply's stream generation, by its handle, right before that call is sent
//! (FIX 5028), so a reply a crash cuts before its terminal is recovered on
//! the same generation and its Continue finds the seed there. A reused
//! prefix whose captured rung gives way to today's call drops that seed
//! first, durably, and sends no fallback while it still stands, so no
//! restart reads a prefix that did not answer. A fresh turn's seed needs the
//! rung that answered, so it is kept once the answer ends, on its own
//! generation's receipt; a reply cut before then keeps none. Either way the
//! older generations of the reply's MESSAGE that no read addresses go (FIX
//! 5033). A reply that never starts, or saves no receipt, keeps none. A
//! native session stream
//! (#5514) names no MESSAGE before its terminal: its seed is kept then, on
//! the receipt that terminal retains.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures_util::StreamExt;
use oneiron::attempt_queue::ManifestEntry;
use oneiron::compaction::{ChatLog, ConversationCompactionUnavailable};
use oneiron::conversation::{
    ChatBreakpoint, ChatBreakpointRung, ChatBreakpointUserTurn, forget_chat_breakpoint,
    forget_superseded_chat_breakpoints, keep_chat_breakpoint,
};
use oneiron::llm::run_admission::RunAdmission;
use oneiron::memory::{MessageStreamHandle, MessageStreamReceipt};
use oneiron::{
    EntityId, LlmError, LlmResult, LlmStream, LlmStreamEvent, RetryableLlmError, Vault, WriteActor,
};

use super::{AnswerBreakpoint, BreakpointLog, TurnMeter, hex};
use crate::ai_host::{AiHandle, ChatBreakpointCall};
use crate::api::ai::chat::AnswerStream;
use crate::api::ai::chat::model_call::Recorder;
use crate::models::{AnsweringRung, RoleCall};

/// What the answer's breakpoint holds until the answer ends (FIX 4933):
/// the breakpoint, the answer's own admitted call for a turn that compacts
/// its log, its reply's MESSAGE, its meter and the rows that call was read
/// from; and the reply's seed slot, which a reuse's seed is kept in before
/// its call (FIX 5028).
pub(in crate::api::ai::chat) struct PendingSeed {
    breakpoint: AnswerBreakpoint,
    admitted: Option<RoleCall>,
    message: EntityId,
    meter: TurnMeter,
    sources: Option<Vec<EntityId>>,
    slot: Arc<SeedSlot>,
}

/// One reply generation's seed, as its stream's legs share it.
struct SeedSlot {
    vault: Arc<Vault>,
    /// The reply's recorded stream: its MESSAGE and generation key the
    /// seed. `None` for a native session stream, which names neither
    /// before its terminal.
    handle: Option<MessageStreamHandle>,
    /// A reused prefix's seed, its source's again, known before its call
    /// (FIX 5028). `None` for a fresh turn, whose seed waits for the rung
    /// that answered (FIX 4933).
    early: Option<ChatBreakpoint>,
    /// `false` once a reused prefix's captured rung gave way to today's
    /// call.
    live: AtomicBool,
    /// Whether the early seed's row is kept now.
    kept: AtomicBool,
}

impl PendingSeed {
    /// The pending breakpoint of the reply `handle` writes; nothing is kept
    /// yet.
    pub(super) fn new(
        vault: &Arc<Vault>,
        handle: &AnswerStream,
        breakpoint: AnswerBreakpoint,
        admitted: Option<RoleCall>,
        meter: TurnMeter,
        sources: Option<Vec<EntityId>>,
    ) -> Self {
        let recorded = match handle {
            AnswerStream::Recorded(handle) => Some(*handle),
            AnswerStream::Session { .. } => None,
        };
        let early = breakpoint.source.clone();
        Self {
            breakpoint,
            admitted,
            message: handle.correlation_id(),
            meter,
            sources,
            slot: Arc::new(SeedSlot {
                vault: Arc::clone(vault),
                handle: recorded,
                early,
                live: AtomicBool::new(true),
                kept: AtomicBool::new(false),
            }),
        }
    }

    /// Whether the call it was entered with answered: `false` once a reused
    /// prefix's captured rung gave way to today's call (OF-490 reads this
    /// for the craft the reply was shown).
    pub(in crate::api::ai::chat) fn answered_live(&self) -> bool {
        self.slot.live.load(Ordering::Acquire)
    }

    /// Drops the seed of a reply whose stream was refused before its call
    /// went out (FIX 5028): it never answered, so it keeps none.
    pub(in crate::api::ai::chat) fn withdraw(&self) {
        self.slot.withdraw();
    }
}

impl SeedSlot {
    /// Keeps a reuse's seed for the reply's generation before its call is
    /// sent (FIX 5028). A keep that fails leaves the reply as before: its
    /// terminal keeps the seed, and a crash before then keeps none. A native
    /// session stream's seed waits for its terminal; a fresh turn's for the
    /// rung that answered (FIX 4933).
    fn keep_before_dispatch(&self) {
        let (Some(seed), Some(handle)) = (&self.early, self.handle) else {
            return;
        };
        let kept = crate::server::blocking(|| {
            keep_chat_breakpoint(
                &self.vault,
                handle.message_id(),
                handle.generation(),
                seed.clone(),
            )
        });
        match kept {
            Ok(()) => self.kept.store(true, Ordering::Release),
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "a chat reply's breakpoint was not kept before its call"
            ),
        }
    }

    /// Drops the kept seed durably; whether none is kept now.
    fn withdraw(&self) -> bool {
        let (Some(seed), Some(handle)) = (
            self.early
                .as_ref()
                .filter(|_| self.kept.load(Ordering::Acquire)),
            self.handle,
        ) else {
            return true;
        };
        let dropped = crate::server::blocking(|| {
            forget_chat_breakpoint(
                &self.vault,
                seed.conversation,
                handle.message_id(),
                handle.generation(),
            )
        });
        match dropped {
            Ok(()) => {
                self.kept.store(false, Ordering::Release);
                true
            }
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "a chat reply's breakpoint was not dropped");
                false
            }
        }
    }

    /// Forgets the older generations of the reply's MESSAGE that no read
    /// addresses once its terminal confirms its early seed (FIX 5033). A
    /// forget that fails leaves them for the MESSAGE's next keep.
    fn forget_superseded(&self) {
        let (Some(seed), Some(handle)) = (&self.early, self.handle) else {
            return;
        };
        let forgotten = crate::server::blocking(|| {
            forget_superseded_chat_breakpoints(&self.vault, seed.conversation, handle.message_id())
        });
        if let Err(error) = forgotten {
            tracing::warn!(
                kind = ?error.kind(),
                "a chat reply's superseded breakpoints were not forgotten"
            );
        }
    }
}

/// The captured rung gave way: its seed goes, durably, before today's call
/// is sent (FIX 5028). `false` when the seed could not be dropped: no
/// fallback is sent while it stands.
fn give_way(slot: Option<&SeedSlot>) -> bool {
    let Some(slot) = slot else {
        return true;
    };
    if !slot.withdraw() {
        return false;
    }
    slot.live.store(false, Ordering::Release);
    true
}

/// The seed a chat turn's reply keeps: its call exactly as `answering`, the
/// rung that answered it, sent it (FIX 4933), that rung by ref, the log's
/// sources, the craft rows the host's snapshot read for it (FIX 9439), and
/// `user_turn`, the user turn the request answers, by the rows the admission
/// that put its words in witnessed (FIX 5033). The keep stores no seed that
/// binds none. None for a log whose turns were not all pinned. A log read
/// through a room's held projection keeps its seed too: a reuse checks it
/// through that same lane (FIX 5031).
pub(super) fn capture_seed(
    agent: EntityId,
    reader: WriteActor,
    log: &ChatLog,
    instructions_digest: Option<String>,
    craft: Vec<ManifestEntry>,
    user_turn: Option<ChatBreakpointUserTurn>,
    answering: &AnsweringRung,
) -> Option<ChatBreakpoint> {
    if !log.pinned {
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
        user_turn,
        craft_entries: craft,
    })
}

/// The answer's stream. With no `today` it is the admitted call's own, as
/// it always was. A reused prefix sends first on its captured rung: when
/// that rung fails before it speaks, the call is sent as the action would
/// always have sent it, on `today`'s route. The seed is kept right before
/// the admitted call is sent (FIX 5028).
pub(in crate::api::ai::chat) fn open_stream(
    run: &RunAdmission,
    today_run: &RunAdmission,
    admitted: RoleCall,
    today: Option<RoleCall>,
    pending: Option<&PendingSeed>,
    recorder: &Recorder,
) -> LlmResult<LlmStream<'static>> {
    let slot = pending.map(|pending| Arc::clone(&pending.slot));
    let Some(today) = today else {
        if let Some(slot) = &slot {
            slot.keep_before_dispatch();
        }
        return recorder.stream(run, admitted);
    };
    if let Err(reason) = live_attempt_headroom(run) {
        // Nothing was kept yet: today's call goes alone.
        if let Some(slot) = &slot {
            slot.live.store(false, Ordering::Release);
        }
        live_fork_unavailable(reason);
        return recorder.stream(today_run, today);
    }
    if let Some(slot) = &slot {
        slot.keep_before_dispatch();
    }
    match recorder.stream(run, admitted) {
        Ok(stream) => Ok(first_or_today(
            stream,
            today_run.clone(),
            today,
            slot,
            recorder.clone(),
        )),
        Err(error) if device_stopped(&error) => Err(error),
        Err(error) => {
            if !give_way(slot.as_deref()) {
                return Err(error);
            }
            recorder.stream(today_run, today)
        }
    }
}

/// Whether `error` is the device's admission stopping: terminal, never a
/// fallback's trigger.
fn device_stopped(error: &LlmError) -> bool {
    matches!(
        error,
        LlmError::Retryable(RetryableLlmError::DeviceAdmissionStopped)
    )
}

/// `live_attempt_headroom`: whether the reply's budget line, as its run
/// reads now, covers the kept rung's reservation and today's first one
/// beside it, each the line's own per-call reservation the ladder admits a
/// rung with. A line that cannot cover both skips the live attempt: today's
/// call goes alone, as it always did, and the live fork is unavailable.
fn live_attempt_headroom(run: &RunAdmission) -> Result<(), &'static str> {
    let reserve = run.declaration().budget().reserve_units;
    if run.read().remaining_units >= reserve.saturating_mul(2) {
        Ok(())
    } else {
        Err("budget_headroom")
    }
}

/// Reports a turn action's live fork unavailable, typed by `reason`: the
/// action runs as it always did.
pub(crate) fn live_fork_unavailable(reason: &'static str) {
    tracing::info!(
        reason,
        "a turn action's live fork is unavailable; the action runs as it always did"
    );
}

/// One leg of a reused prefix's stream.
enum Leg {
    First(Box<FirstLeg>),
    Rest(LlmStream<'static>),
    Done,
}

/// The captured rung's stream before it spoke, and the call behind it.
struct FirstLeg {
    live: LlmStream<'static>,
    run: RunAdmission,
    today: RoleCall,
    slot: Option<Arc<SeedSlot>>,
    recorder: Recorder,
}

/// `live`, unless its first event is a failure: then `today`'s stream, once
/// the captured call's seed is dropped.
fn first_or_today(
    live: LlmStream<'static>,
    run: RunAdmission,
    today: RoleCall,
    slot: Option<Arc<SeedSlot>>,
    recorder: Recorder,
) -> LlmStream<'static> {
    let first = Leg::First(Box::new(FirstLeg {
        live,
        run,
        today,
        slot,
        recorder,
    }));
    LlmStream::new(futures_util::stream::unfold(first, |leg| async move {
        match leg {
            Leg::First(first) => {
                let FirstLeg {
                    mut live,
                    run,
                    today,
                    slot,
                    recorder,
                } = *first;
                match live.next().await {
                    Some(Ok(event)) => Some((Ok::<LlmStreamEvent, _>(event), Leg::Rest(live))),
                    Some(Err(error)) if device_stopped(&error) => Some((Err(error), Leg::Done)),
                    failed => {
                        drop(live);
                        if !give_way(slot.as_deref()) {
                            return failed.map(|item| (item, Leg::Done));
                        }
                        match recorder.stream(&run, today) {
                            Ok(mut stream) => {
                                stream.next().await.map(|item| (item, Leg::Rest(stream)))
                            }
                            Err(error) => Some((Err(error), Leg::Done)),
                        }
                    }
                }
            }
            Leg::Rest(mut stream) => stream.next().await.map(|item| (item, Leg::Rest(stream))),
            Leg::Done => None,
        }
    }))
}

/// Once the answer ends, its breakpoint binds `answering`, the rung that
/// answered it, if one did (FIX 4933). The saved reply keeps its seed when
/// its own captured call answered it and `saved` is its own generation's
/// receipt (FIX 5028): a reuse's, its source's again, kept before its call
/// was sent, stands confirmed (or stays gone where an erase took it with its
/// conversation's words since; one whose early keep failed is kept now); a
/// chat turn's is captured now from the call the answering rung sent. A
/// reply its call did not answer, or that saved no receipt, keeps none, and
/// a reuse's early seed is withdrawn. A keep forgets the generations the
/// seed superseded (FIX 5033). A breakpoint that is not kept leaves
/// the reply's actions to run as they always did. A turn past its threshold,
/// or a reuse that compacts its own action log (FIX 5027), then queues its
/// flight off the answer's path, on that rung; with none that answered, a
/// forced fork binds none and `auto` writes on the cheap writer.
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
        sources,
        slot,
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
        user_turn,
    } = breakpoint;
    let own = saved.filter(|receipt| {
        slot.handle.is_none_or(|handle| {
            receipt.message_id == handle.message_id() && receipt.generation == handle.generation()
        })
    });
    match own.filter(|_| slot.live.load(Ordering::Acquire)) {
        None => {
            slot.withdraw();
        }
        Some(receipt) if !slot.kept.load(Ordering::Acquire) => {
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
                        user_turn,
                        answering.as_ref()?,
                    )
                }),
            };
            if let Some(seed) = seed {
                let kept = crate::server::blocking(|| {
                    keep_chat_breakpoint(vault, receipt.message_id, receipt.generation, seed)
                });
                if let Err(error) = kept {
                    tracing::warn!(kind = ?error.kind(), "a chat reply's breakpoint was not kept");
                }
            }
        }
        // A reuse's seed kept before its call stands confirmed; the
        // generations it superseded go (FIX 5033).
        Some(_) => slot.forget_superseded(),
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
            sources,
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
