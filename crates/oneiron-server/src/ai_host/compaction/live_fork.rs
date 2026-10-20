//! The agent's own compaction from its live context (FIX 4465 C). At the
//! breakpoint that seals a flight, the run's live request is read as the
//! host's admitted rung sends it, and each call of the flight forks it on
//! that rung: the prefix unchanged with its end marked as a cache boundary,
//! then the house compaction's instruction, the agent's home and the span's
//! input after it. A call is admitted on the live role as exactly that
//! rung's model, sent on that rung alone with a permit of its own on the
//! run's compaction meter, and files, lands and is checked as any other
//! self-written pass. Under a row on `auto` (FIX 6029) the fork is bound
//! only while the live prefix is still warm on its rung, and its flight's
//! first call goes out only while it still is; otherwise the cheap writer
//! writes as the agent.

use std::sync::Arc;
use std::time::Instant;

use oneiron::EntityId;
use oneiron::code_run::{
    CacheBoundary, CompactionHome, LiveCompactionFork, compaction_home_budget, mark_cache_boundary,
};
use oneiron::compaction::{
    CompactionCheck, CompactionHomeRef, CompactionRefusal, CompactionRequest,
    SelfCompactionUnavailable,
};
use oneiron::llm::{
    CallEnvelope, ContentPart, LlmMessage, LlmMessageRole, LlmRequest, SelfCompactionDefault,
};

use super::self_writer::SELF_WRITER_FRAME;
use super::serve::{Dispatch, Served, admission_refused, request_input_tokens};
use super::{LiveAdmission, ServedCompactionBackend, output_tokens};
use crate::ai_host::CHAT_ROLE;
use crate::models::RoleCall;

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
/// admitted on the live role exactly as its host admits it, bound to the
/// rung its walk would send it to now, for `writer` under `row`, as `how`
/// says. A forced fork that a route refuses, or a ladder with no rung to
/// take it now, binds none and says why: no rung is guessed and nothing
/// falls through to the cheap route. A prefix that leaves the live model no
/// room for the window is refused, never cut. Under `auto` every such
/// failure, and a cold prefix, binds none and says nothing: `None`, so the
/// cheap writer writes the flight as the agent.
pub(super) fn bind_live_compaction_fork(
    route: &ServedCompactionBackend,
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
    let Some((rung, request)) = call.ladder.live_rung(&call.request) else {
        return unbound(SelfCompactionUnavailable::LiveRungUnbound);
    };
    // The row bounds where the fork may be served: an egress limit, never a
    // test of where the agent runs.
    if rung.offer.locality > row.locality {
        return unbound(SelfCompactionUnavailable::RouteWiderThanPolicy);
    }
    let Some(mut room) = route.live_compaction_room(&request, summary_token_budget) else {
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
    Some(Ok(LiveCompactionFork::capture(request, rung, writer, room)))
}

impl ServedCompactionBackend {
    /// `live_compaction_room`: what the live model's context leaves the
    /// compaction's own input once the immutable prefix, the instruction and
    /// its frame, and the reply's reserve are counted (FIX 4465 C). The home
    /// takes only what the sealed window leaves after that. `None` when no
    /// context is known for the model.
    fn live_compaction_room(&self, prefix: &LlmRequest, summary_token_budget: u64) -> Option<u64> {
        let context = *self.allowances.get(&prefix.model)?;
        let frame = oneiron::count_context_pack_tokens(SELF_WRITER_FRAME) as u64;
        Some(
            context
                .saturating_sub(request_input_tokens(prefix))
                .saturating_sub(output_tokens(summary_token_budget))
                .saturating_sub(self.prompt_tokens)
                .saturating_sub(frame),
        )
    }

    /// The fork's request: the live request unchanged, its end marked as a
    /// cache boundary beside any it carried, then one user message holding
    /// the house compaction's instruction and the span's input. It takes
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
        call.messages.push(LlmMessage {
            role: LlmMessageRole::User,
            content: house
                .messages
                .into_iter()
                .flat_map(|message| message.content)
                .collect(),
        });
        Ok(call)
    }

    /// One call of a live flight (FIX 4465 C): the fork's request, admitted
    /// on the live role as exactly its rung's model under that role's clamp,
    /// sent on the captured rung alone, waiting on its own offer but never
    /// falling back to another, then dressed in the agent's home in what the
    /// live model's context leaves. A rung the live route no longer admits
    /// at the captured offer is stale, and nothing is sent. `while_warm`
    /// is the first call of a flight under a row on `auto` (FIX 6029): it
    /// goes out only while the captured prefix is still warm, and `None`
    /// says it went cold first, or could not be admitted or bound, before
    /// anything was sent, so the cheap writer writes the flight instead.
    pub(super) fn serve_live_fork(
        &self,
        fork: &LiveCompactionFork,
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
        let admitted = match self.models.admit_seat_bound(&self.vault, CHAT_ROLE, llm) {
            Ok(admitted) => admitted,
            Err(refusal) => return unsent(admission_refused(refusal)),
        };
        let Some(ladder) = admitted.ladder.live_fork_ladder(fork.rung()) else {
            return unsent(SelfCompactionUnavailable::LiveForkStale.refusal());
        };
        let call = RoleCall {
            request: admitted.request,
            ladder: Arc::new(ladder),
        };
        let dispatch = if while_warm {
            Dispatch::WhileWarm(fork)
        } else {
            Dispatch::Exact
        };
        self.send(
            started,
            call,
            dispatch,
            request.summary_token_budget,
            |call, room| {
                let frame = oneiron::count_context_pack_tokens(SELF_WRITER_FRAME) as u64;
                let home = home.render(compaction_home_budget(
                    room.context,
                    room.input,
                    room.output,
                    frame,
                ));
                // The home goes after the prefix, before the span's input, never
                // into the prefix.
                if let Some(suffix) = call.messages.last_mut() {
                    let at = suffix.content.len().saturating_sub(1);
                    suffix.content.insert(
                        at,
                        ContentPart::Text {
                            text: format!("{SELF_WRITER_FRAME}\n\n{}", home.text),
                        },
                    );
                }
                Ok(home.refs)
            },
        )
    }
}
