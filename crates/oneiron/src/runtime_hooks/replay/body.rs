//! One replayed body run (ARCH-0080 §6 Replay): on a run's memo, on a
//! verb run's saved copy, or live on an entry no run pinned.

use crate::claim::ScopedRead;
use crate::runtime_hooks::body::{HookBudgetOverrun, HookRunContext};
use crate::runtime_hooks::filter;
use crate::runtime_hooks::read;
use crate::runtime_hooks::runner::{ask_verdict, input_json, judge};
use crate::runtime_hooks::source::FactEntry;
use crate::runtime_hooks::store::HookRunRecord;
use crate::runtime_hooks::verb::HookVerbRunRecord;
use crate::{Error, Result};

use super::{HookReplayResult, PinnedReads, PinnedVerdicts, Replay, input_too_large, ran};

impl Replay<'_> {
    /// A run pinned this entry: its input as it was, each read only when it
    /// answers what it answered then, and each verdict as the run heard it.
    pub(super) fn from_memo(
        &self,
        lane: &ScopedRead<'_>,
        memo: &HookRunRecord,
    ) -> HookReplayResult {
        let Some(input) = memo.input_json.as_deref() else {
            return input_too_large();
        };
        if !memo.verdicts_complete {
            return HookReplayResult::MissingHistory {
                reason: "the run's verdicts were too large to pin".to_owned(),
            };
        }
        let mut reads = PinnedReads::new(&memo.reads);
        let mut verdicts = PinnedVerdicts::new(&memo.verdicts);
        let mut context = HookRunContext::new(self.binding.selector.budget_ms);
        let result = match &self.body {
            Ok(body) => self.runtime.run_fact_hook(
                body,
                input,
                &mut context,
                &mut |request: &str| reads.answer(lane, self.grant, request),
                &mut |request: &str| {
                    let (reply, evidence) = verdicts.answer(request);
                    self.heard(evidence);
                    reply
                },
            ),
            Err(reason) => Err(Error::InvalidConfig(reason.clone())),
        };
        let overrun = self.overrun(&context);
        self.served(&memo.reads);
        self.served(&reads.scratch);
        if let Some(reason) = reads.missing.or(verdicts.missing) {
            return HookReplayResult::MissingHistory { reason };
        }
        ran(
            judge(self.binding, result, overrun),
            Some(memo.outcome.as_str()),
            memo.outcome_json.as_deref(),
            true,
            false,
        )
    }

    /// A verb run saved this case: its input as it was, a post-hook's view
    /// of the result in it, and each read only when it answers what it
    /// answered then. A verb hook calls no model.
    pub(super) fn verb_run(
        &self,
        lane: &ScopedRead<'_>,
        saved: &HookVerbRunRecord,
    ) -> HookReplayResult {
        let Some(input) = saved.input_json.as_deref() else {
            return input_too_large();
        };
        let mut reads = PinnedReads::new(&saved.reads);
        let mut context = HookRunContext::new(self.binding.selector.budget_ms);
        let result = match &self.body {
            Ok(body) => self
                .runtime
                .run_hook(body, input, &mut context, &mut |request: &str| {
                    reads.answer(lane, self.grant, request)
                }),
            Err(reason) => Err(Error::InvalidConfig(reason.clone())),
        };
        let overrun = self.overrun(&context);
        self.served(&saved.reads);
        self.served(&reads.scratch);
        if let Some(reason) = reads.missing {
            return HookReplayResult::MissingHistory { reason };
        }
        ran(
            judge(self.binding, result, overrun),
            Some(saved.outcome.as_str()),
            saved.outcome_json.as_deref(),
            true,
            false,
        )
    }

    /// No run pinned this entry. The live entity stands in only while its
    /// body is the one the entry wrote; a generative hook's verdicts ask the
    /// live ladder, as the runner would.
    pub(super) fn live(
        &self,
        lane: &ScopedRead<'_>,
        entry: &FactEntry,
    ) -> Result<Option<HookReplayResult>> {
        let Some(seen) = read::fact_row(lane, self.grant, entry.entity)? else {
            return Ok(None);
        };
        let actor = filter::actor_class(self.vault, entry.actor)?;
        if !filter::fact_matches(
            self.vault,
            &self.binding.selector,
            entry.kind,
            entry.entity,
            seen.claim.as_ref(),
            actor,
        )? {
            return Ok(None);
        }
        if entry.body_hash != Some(seen.body_hash) {
            return Ok(Some(HookReplayResult::MissingHistory {
                reason: "the entity changed after this entry and no run pinned its input"
                    .to_owned(),
            }));
        }
        self.rows.borrow_mut().push(entry.actor);
        let now = self
            .vault
            .store
            .clock
            .now_recorded_at()
            .saturating_mul(1_000);
        let input = input_json(
            self.binding_id,
            self.binding,
            entry,
            actor,
            &seen.claim_json,
            now,
        )?;
        let mut context = HookRunContext::new(self.binding.selector.budget_ms);
        let deadline = context.deadline();
        let mut pins = Vec::new();
        let result = match &self.body {
            Ok(body) => {
                let mut answer = |request: &str| read::answer(lane, self.grant, request, &mut pins);
                let mut verdict = |request: &str| {
                    let (reply, evidence) =
                        ask_verdict(self.binding, self.grant, self.verdict, request, deadline);
                    self.heard(evidence.as_deref());
                    reply
                };
                self.runtime
                    .run_fact_hook(body, &input, &mut context, &mut answer, &mut verdict)
            }
            Err(reason) => Err(Error::InvalidConfig(reason.clone())),
        };
        let overrun = self.overrun(&context);
        self.served(&pins);
        Ok(Some(ran(
            judge(self.binding, result, overrun),
            None,
            None,
            false,
            true,
        )))
    }

    /// A replayed body's overrun, read once it has ended, on the fresh
    /// clock its replay ran on (FIX 8842): a runtime observation only. The
    /// run it replays keeps the timing it saved, and the replay answer
    /// carries none.
    fn overrun(&self, context: &HookRunContext) -> Option<HookBudgetOverrun> {
        let overrun = context.finish();
        if let Some(overrun) = &overrun {
            tracing::info!(
                binding = %self.binding_id.to_hex(),
                budget_ms = overrun.budget_ms,
                elapsed_ms = overrun.elapsed_ms,
                overrun_ms = overrun.overrun_ms,
                callback_ms = overrun.callback_ms,
                read_overruns = overrun.read_overruns,
                verdict_overruns = overrun.verdict_overruns,
                "a replayed hook body ran past its budget"
            );
        }
        overrun
    }
}
