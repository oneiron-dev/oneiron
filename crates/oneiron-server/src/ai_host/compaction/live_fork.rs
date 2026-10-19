//! The agent's own compaction from its live context (FIX 4465 C). At the
//! breakpoint that seals a flight, the run's live request is read as the
//! host's admitted rung sends it, and each call of the flight forks it on
//! that rung: the prefix unchanged with its end marked as a cache boundary,
//! then the house compaction's instruction, the agent's home and the span's
//! input after it. A call is admitted on the live role as exactly that
//! rung's model, sent on that rung alone with a permit of its own on the
//! run's compaction meter, and files, lands and is checked as any other
//! self-written pass.

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
use super::serve::{Served, admission_refused, request_input_tokens};
use super::{LiveAdmission, ServedCompactionBackend, output_tokens};
use crate::ai_host::CHAT_ROLE;
use crate::models::RoleCall;

/// `bind_live_compaction_fork`: the run's `live` request at a breakpoint,
/// admitted on the live role exactly as its host admits it, bound to the
/// rung its walk would send it to now, for `writer` under `row`. A route
/// that refuses it, or a ladder with no rung to take it now, binds none: no
/// rung is guessed and nothing falls through to the cheap route. A prefix
/// that leaves the live model no room for the window is refused, never cut.
pub(super) fn bind_live_compaction_fork(
    route: &ServedCompactionBackend,
    admission: &dyn LiveAdmission,
    writer: EntityId,
    row: &SelfCompactionDefault,
    live: &LlmRequest,
    summary_token_budget: u64,
) -> Result<LiveCompactionFork, SelfCompactionUnavailable> {
    let call = admission
        .admit_live(live.clone())
        .map_err(|_| SelfCompactionUnavailable::LiveRungUnbound)?;
    let (rung, request) = call
        .ladder
        .live_rung(&call.request)
        .ok_or(SelfCompactionUnavailable::LiveRungUnbound)?;
    // The row bounds where the fork may be served: an egress limit, never a
    // test of where the agent runs.
    if rung.offer.locality > row.locality {
        return Err(SelfCompactionUnavailable::RouteWiderThanPolicy);
    }
    let room = route
        .live_compaction_room(&request, summary_token_budget)
        .ok_or(SelfCompactionUnavailable::ModelNotServed)?;
    if room == 0 {
        return Err(SelfCompactionUnavailable::LivePrefixTooLong);
    }
    Ok(LiveCompactionFork::capture(
        request, rung, writer, row.source, room,
    ))
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
    /// at the captured offer is stale, and nothing is sent.
    pub(super) fn serve_live_fork(
        &self,
        fork: &LiveCompactionFork,
        home: &CompactionHome,
        request: &CompactionRequest,
        retry: Option<CompactionCheck>,
    ) -> Result<Served<Vec<CompactionHomeRef>>, CompactionRefusal> {
        let started = Instant::now();
        let llm = self.fork_request(fork, request, retry)?;
        let admitted = self
            .models
            .admit_seat_bound(&self.vault, CHAT_ROLE, llm)
            .map_err(admission_refused)?;
        let ladder = admitted
            .ladder
            .live_fork_ladder(fork.rung())
            .ok_or_else(|| SelfCompactionUnavailable::LiveForkStale.refusal())?;
        let call = RoleCall {
            request: admitted.request,
            ladder: Arc::new(ladder),
        };
        self.send(
            started,
            call,
            true,
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
