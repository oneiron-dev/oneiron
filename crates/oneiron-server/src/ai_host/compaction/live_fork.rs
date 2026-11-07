//! The agent's own compaction from its live context (FIX 4465 C). At the
//! breakpoint that seals a flight, the run's latest completed call is read
//! as the rung that answered it sent it (FIX 4933), and each call of the
//! flight forks it on that rung: the prefix unchanged with its end marked
//! as a cache boundary, then the house compaction's instruction, the
//! agent's home and the span's input after it. The span's input sends each
//! step the prefix already holds as a reference to it, never its text again
//! (FIX 4931); the gate still judges the full sealed window. A call is
//! admitted on the live role as exactly that rung's model, sent on that
//! rung alone with a permit of its own on the run's compaction meter, and
//! files, lands and is checked as any other self-written pass. Under a row
//! on `auto` (FIX 6029) the fork is bound only while the live prefix is
//! still warm on its rung, and its flight's first call goes out only while
//! it still is; otherwise the cheap writer writes as the agent.

mod input;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Instant;

use oneiron::EntityId;
use oneiron::code_run::{
    CacheBoundary, CompactionHome, LiveCompactionFork, LiveForkRung, compaction_home_budget,
    mark_cache_boundary,
};
use oneiron::compaction::{
    CompactionCheck, CompactionHomeRef, CompactionRefusal, CompactionRequest,
    SelfCompactionUnavailable, compaction_home_worn_rows,
};
use oneiron::llm::{
    CallEnvelope, ContentPart, LlmMessage, LlmMessageRole, LlmRequest, SelfCompactionDefault,
};

use super::self_writer::SelfWriterFrame;
use super::serve::{Dispatch, Served, admission_refused, request_input_tokens};
use super::{CompactionMeter, LiveAdmission, ServedCompactionBackend, output_tokens};
use crate::ai_host::CHAT_ROLE;
use crate::models::{AnsweringRung, ModelCallBinding, RoleCall};

/// How a breakpoint binds the live fork: forced, under a row that selects
/// it, each failure typed; or, under a row on `auto` (FIX 6029), only while
/// the live prefix is still warm on its rung, sized to no more than
/// `cold_room`, what the cheap writer standing by takes, so its window
/// still fits that writer if the prefix goes cold before the first call.
pub(super) enum LiveBind {
    Forced,
    WhileWarm { cold_room: Option<u64> },
}

/// `bind_live_compaction_fork`: the run's `live` request at a breakpoint,
/// admitted on the live role exactly as its host admits it, for `writer`
/// under `row`, as `how` says. The fork binds the rung that answered the
/// run's latest completed call, and that call as the rung sent it is its
/// prefix (FIX 4933): never the rung the walk would take now, and never a
/// wait for a call not sent yet. The room and, under `auto`, the warmth are
/// read for that rung and that prefix now, before the flight is sealed: the
/// room against that rung's raw configured context, with the prefix, which
/// holds the rung's prompt, counted once (FIX 4932), and `frame`, the one
/// its calls render, counted too (FIX 4575).
/// The answering rung witnesses no source of the prefix, so its sources
/// stay unknown (FIX 9463). A forced fork that a route refuses, a run with
/// no completed call, or a rung its live route no longer takes now binds
/// none and says why: no rung is guessed and nothing falls through to the
/// cheap route. A prefix that leaves the live model no room for the window
/// is refused, never cut. Under `auto` every such failure, and a cold
/// prefix, binds none and says nothing: `None`, so the cheap writer writes
/// the flight as the agent.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one fact the breakpoint binds the fork under"
)]
pub(super) fn bind_live_compaction_fork(
    route: &ServedCompactionBackend,
    frame: &SelfWriterFrame,
    admission: &dyn LiveAdmission,
    writer: EntityId,
    row: &SelfCompactionDefault,
    live: &LlmRequest,
    summary_token_budget: u64,
    how: LiveBind,
) -> Option<Result<LiveCompactionFork, SelfCompactionUnavailable>> {
    let forced = matches!(how, LiveBind::Forced);
    let unbound = |why: SelfCompactionUnavailable| forced.then_some(Err(why));
    let Ok(call) = admission.admit_live(live.clone()) else {
        return unbound(SelfCompactionUnavailable::LiveRungUnbound);
    };
    let Some(AnsweringRung { rung, request }) = admission.answering_rung(live).filter(|answered| {
        call.ladder
            .takes_answering_rung(&answered.rung, &call.request)
    }) else {
        return unbound(SelfCompactionUnavailable::LiveRungUnbound);
    };
    // The row bounds where the fork may be served: an egress limit, never a
    // test of where the agent runs.
    if rung.offer.locality > row.locality {
        return unbound(SelfCompactionUnavailable::RouteWiderThanPolicy);
    }
    let Some(mut room) = route.live_compaction_room(&rung, &request, frame, summary_token_budget)
    else {
        return unbound(SelfCompactionUnavailable::ModelNotServed);
    };
    if let LiveBind::WhileWarm { cold_room } = how {
        // Warmth is the provider's cache on this rung, never where the
        // agent runs.
        if !call.ladder.live_prefix_warm(&rung, &request) {
            return None;
        }
        room = cold_room.map_or(room, |cold| room.min(cold));
    }
    if room == 0 {
        return unbound(SelfCompactionUnavailable::LivePrefixTooLong);
    }
    Some(Ok(LiveCompactionFork::capture(
        Arc::unwrap_or_clone(request),
        rung,
        writer,
        room,
    )))
}

impl ServedCompactionBackend {
    /// `live_compaction_room`: what `rung`'s raw configured context leaves
    /// the compaction's own input once the immutable prefix (its rung's
    /// prompt already first), the instruction and its `frame`, and the
    /// reply's reserve are each counted once (FIX 4465 C, FIX 4932, FIX
    /// 4575). The home takes only what the sealed window leaves after that.
    /// `None` when no context is configured for the rung.
    fn live_compaction_room(
        &self,
        rung: &LiveForkRung,
        prefix: &LlmRequest,
        frame: &SelfWriterFrame,
        summary_token_budget: u64,
    ) -> Option<u64> {
        let context = self.live_rung_context(rung)?;
        Some(
            context
                .saturating_sub(request_input_tokens(prefix))
                .saturating_sub(output_tokens(summary_token_budget))
                .saturating_sub(self.prompt_tokens)
                .saturating_sub(frame.tokens()),
        )
    }

    /// `live_rung_context` (FIX 4932): the raw configured context of the
    /// provider `rung` names, when one of its configured rungs serves the
    /// model `rung`'s offer binds. Never an allowance that already took a
    /// rung's prompt out, and never another route's minimum for that model.
    fn live_rung_context(&self, rung: &LiveForkRung) -> Option<u64> {
        self.rung_contexts
            .get(&rung.provider)?
            .get(&rung.offer.model)
            .copied()
    }

    /// The fork's request: the live request unchanged, its end marked as a
    /// cache boundary beside any it carried, then one user message holding
    /// the house compaction's instruction and the span's input, in which a
    /// step the prefix holds byte for byte is a reference to where it sits
    /// there and every other step keeps its text (FIX 4931). It takes
    /// the house call's purpose, class and tier, and keeps the live
    /// request's route, effort, scope and reply format, so the prefix's wire
    /// is the live call's. Its tools are sent, never run.
    fn fork_request(
        &self,
        fork: &LiveCompactionFork,
        request: &CompactionRequest,
        retry: Option<CompactionCheck>,
    ) -> Result<LlmRequest, CompactionRefusal> {
        let house = self.llm_request(request, retry);
        let mut call = fork.request().clone();
        if let Some(end) = CacheBoundary::prefix_end(&call) {
            mark_cache_boundary(&mut call, end)
                .map_err(|_| SelfCompactionUnavailable::LiveForkStale.refusal())?;
        }
        call.envelope = CallEnvelope {
            purpose: house.envelope.purpose,
            class: house.envelope.class,
            tier: house.envelope.tier,
            ..call.envelope
        };
        let mut suffix: Vec<ContentPart> = house
            .messages
            .into_iter()
            .flat_map(|message| message.content)
            .collect();
        // The span's input, last, names each step the prefix already holds
        // by where it sits there, never by its text again (FIX 4931).
        if let Some(ContentPart::Text { text }) = suffix.last_mut() {
            *text = input::live_fork_span_input(fork.request(), request, retry);
        }
        call.messages.push(LlmMessage {
            role: LlmMessageRole::User,
            content: suffix,
        });
        Ok(call)
    }

    /// One call of a live flight (FIX 4465 C): the fork's request, admitted
    /// on the live role as exactly its rung's model under that role's clamp,
    /// sent on the captured rung alone, waiting on its own offer but never
    /// falling back to another, held to that rung's raw configured context,
    /// the one its room was read against (FIX 4932), then dressed in
    /// `frame` (FIX 4575) and the agent's home in what that context leaves,
    /// both in the current suffix, never in the prefix. A rung the live
    /// route no longer admits at the captured offer is stale, and nothing is
    /// sent; a rung with no configured context is not served. `while_warm`
    /// is the first call of a flight under a row on `auto` (FIX 6029): it
    /// goes out only while the captured prefix is still warm, and `None`
    /// says it went cold first, or could not be admitted or bound, before
    /// anything was sent, so the cheap writer writes the flight instead.
    pub(super) fn serve_live_fork(
        &self,
        fork: &LiveCompactionFork,
        frame: &SelfWriterFrame,
        home: &CompactionHome,
        request: &CompactionRequest,
        retry: Option<CompactionCheck>,
        while_warm: bool,
    ) -> Result<Option<Served<Vec<CompactionHomeRef>>>, CompactionRefusal> {
        let started = Instant::now();
        let unsent = |refusal: CompactionRefusal| {
            if while_warm { Ok(None) } else { Err(refusal) }
        };
        let llm = match self.fork_request(fork, request, retry) {
            Ok(llm) => llm,
            Err(refusal) => return unsent(refusal),
        };
        let role = match &self.meter {
            CompactionMeter::Profiled { generation, .. } => generation.live_role(),
            _ => CHAT_ROLE,
        };
        let admitted = match self.models.admit_seat_bound(&self.vault, role, llm) {
            Ok(admitted) => admitted,
            Err(refusal) => return unsent(admission_refused(refusal)),
        };
        let Some(ladder) = admitted.ladder.live_fork_ladder(fork.rung()) else {
            return unsent(SelfCompactionUnavailable::LiveForkStale.refusal());
        };
        // The rung just found again at its offer is the one whose context
        // holds the call (FIX 4932).
        let Some(context) = self.live_rung_context(fork.rung()) else {
            return unsent(SelfCompactionUnavailable::ModelNotServed.refusal());
        };
        let call = RoleCall {
            request: admitted.request,
            ladder: Arc::new(ladder),
        };
        self.send(
            started,
            call,
            Dispatch::Live {
                fork,
                context,
                while_warm,
            },
            // The live prefix's complete input set is not witnessed yet;
            // only the home can contribute rows to this call (FIX 6999).
            None,
            request.summary_token_budget,
            |call, room| {
                let home = home.render(compaction_home_budget(
                    room.context,
                    room.input,
                    room.output,
                    frame.tokens(),
                ));
                // The home goes after the prefix, before the span's input, never
                // into the prefix.
                if let Some(suffix) = call.messages.last_mut() {
                    let at = suffix.content.len().saturating_sub(1);
                    suffix.content.insert(
                        at,
                        ContentPart::Text {
                            text: format!("{}\n\n{}", frame.text(), home.text),
                        },
                    );
                }
                let home_rows = compaction_home_worn_rows(&home.refs).collect();
                Ok((home.refs, Some(home_rows)))
            },
        )
    }
}

/// The slot one run's answering rungs fill (FIX 4933): the run's latest
/// call that answered, as its rung sent it. The run's own compaction writer
/// holds it, so it lives as long as the run's seat. A call that fails, or a
/// stream that drops, leaves what it holds.
#[derive(Default)]
pub(in crate::ai_host) struct AnsweringRungSlot(Mutex<Option<AnsweringRung>>);

/// A host's answering rung slots, by run (FIX 4933): each beside the
/// compaction writer that holds it, and gone with it. Only a run whose
/// writer holds a slot keeps its calls' rungs.
#[derive(Default)]
pub(in crate::ai_host) struct AnsweringRungSlots {
    runs: Mutex<HashMap<EntityId, Weak<AnsweringRungSlot>>>,
}

impl AnsweringRungSlots {
    /// `run`'s slot, for its writer to hold: the one held already, else a
    /// fresh one.
    pub(in crate::ai_host) fn hold(&self, run: EntityId) -> Arc<AnsweringRungSlot> {
        let mut runs = self.held();
        if let Some(slot) = runs.get(&run).and_then(Weak::upgrade) {
            return slot;
        }
        let slot = Arc::new(AnsweringRungSlot::default());
        runs.insert(run, Arc::downgrade(&slot));
        slot
    }

    /// `run`'s latest call that answered, as its rung sent it.
    pub(in crate::ai_host) fn latest(&self, run: EntityId) -> Option<AnsweringRung> {
        let slot = self.held().get(&run).and_then(Weak::upgrade)?;
        slot.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// One of `run`'s calls answered, on `binding`'s rung: a held slot keeps
    /// it in place of the call before it. Only a call that answered comes
    /// here, so a failed rung never replaces one that answered.
    pub(in crate::ai_host) fn answered(&self, run: EntityId, binding: &ModelCallBinding) {
        let Some(slot) = self.held().get(&run).and_then(Weak::upgrade) else {
            return;
        };
        if let Some(answering) = &binding.answering {
            *slot.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(answering.clone());
        }
    }

    /// The slots whose writers still hold them: each let go goes here.
    fn held(&self) -> MutexGuard<'_, HashMap<EntityId, Weak<AnsweringRungSlot>>> {
        let mut runs = self.runs.lock().unwrap_or_else(PoisonError::into_inner);
        runs.retain(|_, slot| slot.strong_count() > 0);
        runs
    }
}
