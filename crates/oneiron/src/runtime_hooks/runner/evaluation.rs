//! One evaluation, kept intact until its memo and completion tail commit.

use std::time::Instant;

use crate::claim::ScopedRead;
use crate::runtime_hooks::body::{HookBodyRuntime, HookRunContext, HookVerdict};
use crate::runtime_hooks::store::{HookReadPin, HookRunRecord};
use crate::{Error, Result, Vault};

use super::body::{Verdict, VerdictPins, ask_verdict, judge, record, verdict_context};
use super::{Run, read};

pub(super) struct PreparedRun {
    input: String,
    reads: Vec<HookReadPin>,
    verdicts: VerdictPins,
    pub(super) verdict: Verdict,
    duration_ms: u64,
    now: u64,
    runtime_identity: Option<String>,
}

impl PreparedRun {
    pub(super) fn memo(&self, vault: &Vault, run: &Run<'_>) -> Result<HookRunRecord> {
        record(
            vault,
            run,
            &self.input,
            self.reads.clone(),
            self.verdicts.clone(),
            &self.verdict,
            self.duration_ms,
            self.now,
            self.runtime_identity.clone(),
        )
    }
}

pub(super) fn evaluate(
    runtime: &dyn HookBodyRuntime,
    host: Option<&dyn HookVerdict>,
    run: &Run<'_>,
    lane: &ScopedRead<'_>,
    body: std::result::Result<String, String>,
    input: String,
    now: u64,
    catch_runtime_panic: bool,
) -> PreparedRun {
    let started = Instant::now();
    let mut context = HookRunContext::new(run.binding.selector.budget_ms);
    let deadline = context.deadline();
    let mut pins = Vec::new();
    let mut verdicts = VerdictPins::new();
    let result = match body {
        Ok(body) => {
            let mut answer = |request: &str| read::answer(lane, run.grant, request, &mut pins);
            let mut verdict = |request: &str| {
                let trusted = verdict_context(
                    run.binding_id,
                    run.binding,
                    run.grant,
                    &run.key,
                    verdicts.heard(),
                    deadline,
                );
                let answer = ask_verdict(run.binding, host, &trusted, request);
                let reply = answer.reply.clone();
                verdicts.push(request, answer);
                reply
            };
            context.body_starts();
            let mut call =
                || runtime.run_fact_hook(&body, &input, &mut context, &mut answer, &mut verdict);
            if catch_runtime_panic {
                // A panicked owned runtime is failed, never entered again by
                // the next pass. Keep the context and pins it had reported.
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(call)).unwrap_or_else(|_| {
                    Err(Error::InvariantViolation("fact hook runtime panicked"))
                })
            } else {
                call()
            }
        }
        Err(reason) => Err(Error::InvalidConfig(reason)),
    };
    let overrun = context.finish();
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let verdict = judge(run.binding, result, overrun, &context);
    PreparedRun {
        input,
        reads: pins,
        verdicts,
        verdict,
        duration_ms,
        now,
        runtime_identity: runtime.runtime_identity(),
    }
}
