//! One verb-hook run (ARCH-0080 §3): its body run under the hook's grant,
//! the verdict, the engine's own checks on its outcome, and what the run
//! leaves its chain to commit.

use std::time::Instant;

use serde_json::Value;

use crate::runtime_hooks::outcome::HookOutcome;
use crate::runtime_hooks::runner::{Verdict, bounded, judge};
use crate::runtime_hooks::store::{
    HookDependency, HookIntent, HookIntentState, HookReadPin, HookRunState, RunKey,
};
use crate::runtime_hooks::{
    HookBodyUsage, HookBudgetOverrun, HookPreparation, HookRunContext, apply, grant, read,
};
use crate::skill_hub::pack_catalog::PackHookBinding;
use crate::{EntityId, Error, Result};

use super::super::VerbArgsCheck;
use super::projection::{HookView, merge_withheld};
use super::{Chain, run_key, session};

/// One run, as its receipt tells it, and what its saved copy keeps.
pub(super) struct RunRecord<'c> {
    pub(super) id: EntityId,
    pub(super) binding: &'c PackHookBinding,
    pub(super) key: RunKey,
    /// The outcome kind, or `refused` or `failed`.
    pub(super) token: String,
    pub(super) reason: Option<String>,
    pub(super) note: Option<String>,
    /// What a blocking hook's failure did: `ask`, `skipped`, `hidden` or
    /// `recorded`.
    pub(super) fail_safe: Option<&'static str>,
    /// The canonical work its room could not do for its outcome.
    pub(super) unavailable: Option<&'static str>,
    pub(super) duration_ms: u64,
    /// The run ended past its `budget_ms`: measured beside its outcome,
    /// never a failure and never its hook's fail-safe (FIX 8842).
    pub(super) budget_overrun: Option<HookBudgetOverrun>,
    pub(super) rows_read: usize,
    /// What the body used; a count its runtime did not measure stays
    /// unavailable (FIX 9332).
    pub(super) usage: HookBodyUsage,
    /// The exact input the body saw, as its grant showed it (FIX 10084).
    pub(super) input: String,
    /// The rows whose content that input showed.
    pub(super) dependencies: Vec<EntityId>,
    /// That input also showed content whose rows no host names.
    pub(super) unattributed: bool,
    /// The digest of the grant the input was built under.
    pub(super) grant: String,
    /// How the body was prepared before it ran (FIX 9208).
    pub(super) preparation: Option<HookPreparation>,
    pub(super) reads: Vec<HookReadPin>,
    /// The outcome the body returned, before the engine's own checks.
    pub(super) outcome_json: Option<String>,
}

impl RunRecord<'_> {
    /// Every source row the saved input and callback reads depend on.
    pub(super) fn hook_dependencies(&self) -> Vec<HookDependency> {
        self.dependencies
            .iter()
            .chain(
                self.reads
                    .iter()
                    .flat_map(|pin| pin.rows.iter().map(|row| &row.id)),
            )
            .map(|id| HookDependency {
                id: *id,
                revision: None,
                body_hash: None,
            })
            .collect()
    }
}

impl<'c> Chain<'c> {
    /// One body run, judged. Its input is built for this hook alone, under
    /// what both its caller and its current grant may read (FIX 10084). A
    /// Rewrite over args it saw withheld keeps the caller's originals there
    /// before the engine checks it. Blocks, notes and queued outcomes join
    /// the chain here; the flow outcomes go back to the chain.
    pub(super) fn run(
        &mut self,
        id: EntityId,
        binding: &'c PackHookBinding,
        args: &Value,
        result: Option<&Value>,
        check: Option<VerbArgsCheck<'_>>,
    ) -> Result<Option<HookOutcome>> {
        let key = run_key(self.call.invocation, id, self.phase);
        // The caller's lane, narrowed to the hook's grant: its reader's lane
        // when that is someone else, and its predicates and worlds. A caller
        // whose door carried its key reads under it; a host's own call reads
        // as its actor. In a room both read the room's view. Its input and
        // its reads are both built under that one view.
        let grant = session::hook_read(
            self.storage,
            "grant",
            grant::effective_grant(self.vault, id, binding),
        )?;
        let view = self.view()?;
        let (lane, cap) = self.lanes(&grant, view.as_ref());
        let seen = HookView {
            lane: lane.as_ref(),
            cap: cap.as_ref().map(Option::as_ref),
            grant: &grant,
        };
        let input = self.input(id, binding, args, result, &seen)?;
        let args_withheld = self.args_withheld(&seen);
        let mut pins = Vec::new();
        let started = Instant::now();
        let mut context = HookRunContext::new(binding.selector.budget_ms);
        let ran = match self.runtime {
            Err(reason) => Err(Error::InvalidConfig(reason.to_owned())),
            Ok(runtime) => match self.vault.verb_hook_state.body(self.vault, binding) {
                Err(reason) => Err(Error::InvalidConfig(reason)),
                Ok(body) => {
                    let mut answer = |request: &str| match (&lane, &cap) {
                        (Some(lane), None) => {
                            read::answer_within(lane, None, &grant, request, &mut pins)
                        }
                        (Some(lane), Some(Some(cap))) => {
                            read::answer_within(lane, Some(cap), &grant, request, &mut pins)
                        }
                        _ => Err("this call has no read lane".to_owned()),
                    };
                    // What a runtime's body uses is unavailable until the
                    // runtime reports it (FIX 9332).
                    context.body_starts();
                    runtime.run_hook(&body, &input.json, &mut context, &mut answer)
                }
            },
        };
        // The body's worker has joined, a failed run's too: its accounting
        // ends here. Time judges nothing (FIX 8842).
        let overrun = context.finish();
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut verdict = judge(binding, ran, overrun, &context);
        if args_withheld && let Some(HookOutcome::Rewrite { args: next }) = &mut verdict.outcome {
            *next = merge_withheld(args, std::mem::take(next));
        }
        if let Some(reason) = verdict
            .outcome
            .as_ref()
            .and_then(|outcome| self.admit(outcome, check).err())
        {
            verdict = Verdict {
                state: HookRunState::Refused,
                outcome: None,
                token: "refused".to_owned(),
                reason: Some(reason),
                ..verdict
            };
        }
        let rows_read = pins.iter().map(|pin| pin.rows.len()).sum::<usize>();
        let mut run = RunRecord {
            id,
            binding,
            key,
            token: verdict.token.clone(),
            reason: verdict.reason.clone(),
            note: None,
            fail_safe: None,
            unavailable: None,
            duration_ms,
            budget_overrun: verdict.budget_overrun,
            rows_read,
            usage: verdict.usage,
            input: input.json,
            dependencies: input.dependencies,
            unattributed: input.unattributed,
            grant: grant.digest(),
            preparation: verdict.preparation.clone(),
            reads: pins,
            outcome_json: verdict.outcome_json.clone(),
        };
        // A room does no canonical work: an outcome that needs it is this
        // hook's own, and the call goes on as after a Continue (CALLS-3).
        if let Some(work) = self.room_cannot(verdict.outcome.as_ref()) {
            run.unavailable(work);
            self.runs.push(run);
            return Ok(Some(HookOutcome::Continue));
        }
        match &verdict.outcome {
            Some(HookOutcome::AddBlock { block }) => self.block(id, binding, &key, block)?,
            Some(HookOutcome::Annotate { note }) => run.note = Some(bounded(note)),
            Some(outcome) if outcome.is_queued() => {
                let proposal = match outcome {
                    HookOutcome::Propose { .. } => Some(apply::proposal_id(&key)?),
                    _ => None,
                };
                let intent = HookIntent {
                    dependencies: run.hook_dependencies(),
                    binding: id,
                    author: binding.author_id(),
                    outcome_json: verdict.outcome_json.clone().unwrap_or_default(),
                    lineage: self.lineage(id, &key),
                    state: HookIntentState::Pending,
                    landed: None,
                    reason: None,
                    created_at: self.vault.store.clock.now_recorded_at(),
                    settled_at: None,
                };
                self.intents.push((key, intent, proposal));
            }
            _ => {}
        }
        self.runs.push(run);
        Ok(verdict.outcome)
    }
}
