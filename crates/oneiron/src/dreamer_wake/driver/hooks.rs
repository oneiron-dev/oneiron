//! `host.wake` (ARCH-0080 §5) around one wake pass. The pre chain runs before
//! the pass does any work, so a hook may skip the wake with a reason (quiet
//! hours, say) or add material for it; the post chain reads what the pass
//! did, and may note it. A pass its wake budget stopped is that line's
//! `host.budget.hit`, under the Suspend the Dreamer's budget defaults to.

use serde_json::{Value, json};

use super::*;
use crate::runtime_hooks::{
    BudgetHit, HOST_BUDGET_HIT, InvocationId, VerbCall, VerbDomain, VerbHookPre,
};
use crate::skill_hub::pack_catalog::HookActorClass;

/// The host verb a wake pass runs under.
const HOST_WAKE: &str = "host.wake";
/// Queued attempts the args name, oldest first.
const QUEUE_HEAD: usize = 8;

/// A pass past its pre chain, as its post chain picks it up.
pub(super) struct WakeHooks {
    pre: Option<VerbHookPre>,
    /// The invocation of the pass's budget hit, if its budget stops it.
    hit: InvocationId,
}

impl DreamerWakeDriver<'_> {
    /// Runs `host.wake`'s pre chain for `input`. `Err(report)` when a hook
    /// skipped the wake or asked first: the pass does nothing, and the
    /// report says so; the hook's receipt keeps why.
    pub(super) fn pre_wake_hooks(
        &self,
        input: &RunWakePass,
    ) -> Result<std::result::Result<WakeHooks, WakePassReport>> {
        let kind = input.scope.attempt_kind();
        let queued: Vec<Value> = AttemptQueue::new(self.vault)
            .list()?
            .into_iter()
            .filter(|attempt| attempt.kind == kind && !attempt.state.is_terminal())
            .map(|attempt| {
                json!({
                    "attempt": bytes_to_hex_lower(attempt.id.as_bytes()),
                    "state": format!("{:?}", attempt.state),
                    "scheduled_at": attempt.scheduled_at,
                })
            })
            .collect();
        let args = json!({
            "kind": trigger_word(input.trigger),
            "scope": input.scope.as_str(),
            "queue_head": {
                "queued": queued.len(),
                "head": &queued[..queued.len().min(QUEUE_HEAD)],
            },
        });
        let pass = |verb: &str| {
            InvocationId::of_run_step(
                &[self.budget_id.as_bytes(), verb.as_bytes()].concat(),
                input.now,
            )
        };
        let hit = pass(HOST_BUDGET_HIT);
        let call = VerbCall {
            verb: HOST_WAKE.to_owned(),
            invocation: pass(HOST_WAKE),
            actor: crate::dreamer_runner::authority::dreamer_actor_id()?,
            // A write a host verb causes stamps the System class.
            class: HookActorClass::System,
            scope: None,
            board_epoch: None,
            domain: VerbDomain::Write,
        };
        let check = |rewritten: &Value| {
            if *rewritten == args {
                Ok(())
            } else {
                Err("a host verb's args are the host's".to_owned())
            }
        };
        Ok(
            match self.vault.pre_verb_hooks(call, args.clone(), &check)? {
                Ok(pre) => Ok(WakeHooks {
                    pre: Some(pre),
                    hit,
                }),
                Err(stop) => {
                    tracing::info!(%stop, "host.wake pre-hooks skipped a wake pass");
                    Err(WakePassReport {
                        admitted: 0,
                        completed: 0,
                        failed: 0,
                        deferred: 0,
                        parked: 0,
                        landed: 0,
                        sources_truncated: 0,
                        stop: WakePassStop::HookSkipped,
                    })
                }
            },
        )
    }

    /// Runs `host.wake`'s post chain over what the pass did, after the
    /// budget hit's chains when its wake budget stopped it. The pass stands
    /// whatever a post-hook says.
    pub(super) fn post_wake_hooks(&self, hooks: WakeHooks, report: &WakePassReport) {
        if report.stop == WakePassStop::BudgetExhausted {
            self.wake_budget_hit(hooks.hit);
        }
        let Some(pre) = hooks.pre else {
            return;
        };
        let result = json!({
            "admitted": report.admitted,
            "completed": report.completed,
            "failed": report.failed,
            "deferred": report.deferred,
            "parked": report.parked,
            "landed": report.landed,
            "sources_truncated": report.sources_truncated,
            "stop": format!("{:?}", report.stop),
        });
        if let Err(error) = self.vault.post_verb_hooks(pre, result) {
            tracing::warn!(?error, "host.wake post-hooks failed on a finished pass");
        }
    }
}

impl DreamerWakeDriver<'_> {
    /// `host.budget.hit` for this pass's wake budget: its line, its policy,
    /// and its accounting as the hit left it.
    fn wake_budget_hit(&self, invocation: InvocationId) {
        let (policy, accounting) = match &self.guard {
            Some(guard) => {
                let read = guard.read();
                (
                    read.on_budget_exhausted,
                    serde_json::to_value(&read).unwrap_or(Value::Null),
                )
            }
            None => (
                crate::BudgetExhaustionPolicy::Suspend,
                match self.store.budget(&self.budget_id) {
                    Ok(Some(record)) => json!({
                        "total_units": record.total_units,
                        "remaining_units": record.remaining_units,
                        "reserved_units": record.reserved_units,
                        "updated_at": record.updated_at,
                    }),
                    Ok(None) => Value::Null,
                    Err(error) => {
                        tracing::warn!(?error, "a spent wake budget could not be read");
                        Value::Null
                    }
                },
            ),
        };
        let actor = match crate::dreamer_runner::authority::dreamer_actor_id() {
            Ok(actor) => actor,
            Err(error) => {
                tracing::warn!(?error, "host.budget.hit has no Dreamer actor");
                return;
            }
        };
        self.vault.budget_hit_hooks(BudgetHit {
            seat: &self.budget_id,
            policy,
            accounting,
            actor,
            invocation,
        });
    }
}

/// The wake kind a hook reads.
const fn trigger_word(trigger: WakeTrigger) -> &'static str {
    match trigger {
        WakeTrigger::Compaction => "compaction",
        WakeTrigger::SessionEnd => "session_end",
        WakeTrigger::Event => "event",
        WakeTrigger::Timer => "timer",
    }
}
