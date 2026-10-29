//! One replayed body run (ARCH-0080 §6 Replay): on a run's memo, on a
//! verb run's saved copy, or live on an entry no run pinned.

use crate::claim::{PointRead, ScopedRead};
use crate::runtime_hooks::body::{HookBudgetOverrun, HookRunContext};
use crate::runtime_hooks::filter;
use crate::runtime_hooks::read::{self, grant_view::shows_row};
use crate::runtime_hooks::runner::{ask_verdict, input_json, judge, verdict_context};
use crate::runtime_hooks::source::FactEntry;
use crate::runtime_hooks::store::{self, HookRunRecord};
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
            Ok(body) => {
                // Unavailable until the runtime reports it (FIX 9332).
                context.body_starts();
                self.runtime.run_fact_hook(
                    body,
                    input,
                    &mut context,
                    &mut |request: &str| reads.answer(lane, self.grant, request),
                    &mut |request: &str| {
                        let (reply, evidence) = verdicts.answer(request);
                        self.heard(evidence);
                        reply
                    },
                )
            }
            Err(reason) => Err(Error::InvalidConfig(reason.clone())),
        };
        let overrun = self.overrun(&context);
        self.served(&memo.reads);
        self.served(&reads.scratch);
        if let Some(reason) = reads.missing.or(verdicts.missing) {
            return HookReplayResult::MissingHistory { reason };
        }
        ran(
            judge(self.binding, result, overrun, &context),
            Some(memo.outcome.as_str()),
            memo.outcome_json.as_deref(),
            true,
            false,
        )
    }

    /// A verb run saved this case: its input as it was, a post-hook's view
    /// of the result in it, and each read only when it answers what it
    /// answered then. A verb hook calls no model. The saved input runs again
    /// only while the hook's current grant still shows every row whose
    /// content it holds (FIX 10084); else its history is named gone, never
    /// run on content the hook may no longer read.
    pub(super) fn verb_run(
        &self,
        lane: &ScopedRead<'_>,
        saved: &HookVerbRunRecord,
    ) -> HookReplayResult {
        let Some(input) = saved.input_json.as_deref() else {
            return input_too_large();
        };
        if !saved
            .dependencies
            .iter()
            .all(|id| self.still_shown(lane, *id))
        {
            return HookReplayResult::MissingHistory {
                reason: "a row the saved input held is not shown to this hook now".to_owned(),
            };
        }
        if saved.unattributed && saved.grant != self.grant.digest() {
            return HookReplayResult::MissingHistory {
                reason: "the saved input holds content its hook's grant has changed for since"
                    .to_owned(),
            };
        }
        let mut reads = PinnedReads::new(&saved.reads);
        let mut context = HookRunContext::new(self.binding.selector.budget_ms);
        let result = match &self.body {
            Ok(body) => {
                context.body_starts();
                self.runtime
                    .run_hook(body, input, &mut context, &mut |request: &str| {
                        reads.answer(lane, self.grant, request)
                    })
            }
            Err(reason) => Err(Error::InvalidConfig(reason.clone())),
        };
        let overrun = self.overrun(&context);
        self.served(&saved.reads);
        self.served(&reads.scratch);
        if let Some(reason) = reads.missing {
            return HookReplayResult::MissingHistory { reason };
        }
        ran(
            judge(self.binding, result, overrun, &context),
            Some(saved.outcome.as_str()),
            saved.outcome_json.as_deref(),
            true,
            false,
        )
    }

    /// No run pinned this entry. The source's exact live or retained revision
    /// supplies the body the entry wrote; a generative hook's verdicts ask
    /// the live ladder, as the runner would.
    pub(super) fn live(
        &self,
        lane: &ScopedRead<'_>,
        entry: &FactEntry,
    ) -> Result<Option<HookReplayResult>> {
        let Some(seen) = read::fact_row(lane, self.grant, entry)? else {
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
        // A live replay is an execution of its own: its verdicts ask under
        // the entry's run key, and nothing keeps what they settled.
        let key = store::run_key(self.binding_id, self.binding, entry)?;
        let mut context = HookRunContext::new(self.binding.selector.budget_ms);
        let deadline = context.deadline();
        let mut pins = Vec::new();
        let mut asked = 0_u32;
        let result = match &self.body {
            Ok(body) => {
                let mut answer = |request: &str| read::answer(lane, self.grant, request, &mut pins);
                let mut verdict = |request: &str| {
                    let trusted = verdict_context(
                        self.binding_id,
                        self.binding,
                        self.grant,
                        &key,
                        asked,
                        deadline,
                    );
                    asked = asked.saturating_add(1);
                    let answer = ask_verdict(self.binding, self.verdict, &trusted, request);
                    self.heard(answer.evidence.as_deref());
                    answer.reply
                };
                context.body_starts();
                self.runtime
                    .run_fact_hook(body, &input, &mut context, &mut answer, &mut verdict)
            }
            Err(reason) => Err(Error::InvalidConfig(reason.clone())),
        };
        let overrun = self.overrun(&context);
        self.served(&pins);
        Ok(Some(ran(
            judge(self.binding, result, overrun, &context),
            None,
            None,
            false,
            true,
        )))
    }

    /// Whether the hook's current grant still shows the row `id` through
    /// `lane`; a read that fails shows nothing.
    fn still_shown(&self, lane: &ScopedRead<'_>, id: crate::EntityId) -> bool {
        lane.read(&[PointRead::id(id)], None)
            .ok()
            .and_then(|read| read.value.into_iter().next().flatten())
            .is_some_and(|row| shows_row(self.grant, &row).unwrap_or(false))
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
