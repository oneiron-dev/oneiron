//! A verb hook's golden inputs, run (ARCH-0080 §9): a hub pack's test runs
//! the body on each call its pack declares for it, as the gate runs it, and
//! lands nothing: no receipt, saved run, block or queued outcome. A verb hook
//! its vault never ran has no saved run to replay; these are what test it.

use serde_json::{Value, json};

use crate::claim::ClaimReadStatus;
use crate::runtime_hooks::outcome::HookOutcome;
use crate::runtime_hooks::runner::{bounded, judge};
use crate::runtime_hooks::{
    HookBodyRuntime, HookReplayCompare, HookReplayResult, HookRunContext, filter, grant,
    host_doors, read,
};
use crate::skill_hub::pack_catalog::{HookGoldenInput, HookPhase, PackHookBinding};
use crate::{EntityId, Error, Result, Vault};

use super::{InvocationId, served};

/// One golden input's run, as a replay entry tells it, beside the outcome
/// the engine accepted, if any.
pub(crate) struct VerbGoldenRun {
    pub(crate) result: HookReplayResult,
    pub(crate) outcome: Option<HookOutcome>,
}

impl Vault {
    /// `row`'s body over `golden`, the inputs its pack declares, each run as
    /// the gate runs it on a call its selector takes: the input in the
    /// gate's shape, as the reader the replay reads as, in the hook's own
    /// scope, with an empty receipt tail; each read live under the grant
    /// [`Self::hooks_replay_binding`] reads with; the outcome judged against
    /// the binding and put to the gate's own checks, all but the verb's args
    /// check, which only its dispatcher holds. `None` for a call the
    /// selector does not take, as the gate runs no body on it. Beside the
    /// runs, the body's source and every row a read served.
    ///
    /// # Errors
    ///
    /// A fact hook, which takes no call; storage errors as they occur. A
    /// body's own failure is a run's, never one.
    pub(crate) fn verb_hook_golden_runs(
        &self,
        runtime: &dyn HookBodyRuntime,
        binding_id: EntityId,
        row: &PackHookBinding,
        golden: &[HookGoldenInput],
    ) -> Result<(Vec<Option<VerbGoldenRun>>, Vec<EntityId>)> {
        let selector = &row.selector;
        let phase = match selector.phase {
            HookPhase::Pre => "pre",
            HookPhase::Post => "post",
            HookPhase::Fact => {
                return Err(Error::InvalidConfig(
                    "a fact hook takes no golden call".to_owned(),
                ));
            }
        };
        let grant = grant::effective_grant(self, binding_id, row)?;
        let memory = self.memory(grant.reader, filter::edge_class(grant.reader_class));
        let lane = memory
            .read_lane(ClaimReadStatus::Recorded)
            .map_err(|error| Error::InvalidConfig(format!("{}: {}", error.code, error.message)))?;
        let body = self
            .pack_hook_body(row)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                String::from_utf8(bytes).map_err(|_| "hook body is not UTF-8".to_owned())
            });
        let now = self.store.clock.now_recorded_at().saturating_mul(1_000);
        let mut rows = vec![row.source];
        let mut runs = Vec::with_capacity(golden.len());
        for (index, call) in golden.iter().enumerate() {
            let class = call.caller_class(selector);
            let result = call.result.as_ref().unwrap_or(&Value::Null);
            let takes = selector
                .verbs
                .iter()
                .any(|glob| filter::glob_match(glob, &call.verb))
                && (selector.actors.is_empty() || selector.actors.contains(&class))
                && (selector.phase == HookPhase::Pre || served::admits(&selector.served, result));
            if !takes {
                runs.push(None);
                continue;
            }
            let mut input = json!({
                "hook": {
                    "binding": binding_id.to_hex(),
                    "code": row.code.to_hex(),
                    "pack": row.pack,
                    "name": row.hook,
                    "version": row.hook_version,
                    "body_hash": row.body_hash,
                    "blocking": selector.blocking,
                },
                "verb": call.verb,
                "phase": phase,
                "invocation": golden_invocation(binding_id, index).to_hex(),
                "actor": grant.reader.to_hex(),
                "class": filter::class_token(class),
                "scope": selector.scope,
                "args": call.args,
                "board_epoch": Value::Null,
                "receipt_tail": [],
                "now": now,
            });
            if selector.phase == HookPhase::Post {
                input["result"] = result.clone();
                if let Some(served) = served::rows(result, &selector.served) {
                    input["served"] = serde_json::to_value(served)
                        .map_err(|_| Error::InvariantViolation("hook input encode"))?;
                }
            }
            let input = serde_json::to_string(&input)
                .map_err(|_| Error::InvariantViolation("hook input encode"))?;
            let mut pins = Vec::new();
            let mut context = HookRunContext::new(selector.budget_ms);
            let ran = match &body {
                Ok(body) => {
                    context.body_starts();
                    runtime.run_hook(body, &input, &mut context, &mut |request: &str| {
                        read::answer(&lane, &grant, request, &mut pins)
                    })
                }
                Err(reason) => Err(Error::InvalidConfig(reason.clone())),
            };
            let overrun = context.finish();
            let verdict = judge(row, ran, overrun, &context);
            let refusal = verdict
                .outcome
                .as_ref()
                .and_then(|outcome| gate_check(&call.verb, &call.args, outcome).err());
            let (outcome, token, reason) = match refusal {
                Some(reason) => (None, "refused".to_owned(), Some(bounded(&reason))),
                None => (verdict.outcome, verdict.token, verdict.reason),
            };
            rows.extend(
                pins.iter()
                    .flat_map(|pin| pin.rows.iter().map(|read_row| read_row.id)),
            );
            runs.push(Some(VerbGoldenRun {
                result: HookReplayResult::Ran {
                    outcome_json: verdict.outcome_json,
                    outcome: token,
                    reason,
                    recorded: None,
                    recorded_outcome_json: None,
                    compare: HookReplayCompare::Incomplete,
                    from_memo: false,
                    reads_live: true,
                },
                outcome,
            }));
        }
        rows.sort_unstable();
        rows.dedup();
        Ok((runs, rows))
    }
}

/// The invocation a golden input's call names: one per binding and input,
/// the same on every run of the test.
fn golden_invocation(binding_id: EntityId, index: usize) -> InvocationId {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron.hook-golden-invocation.v1");
    hasher.update(binding_id.as_bytes());
    hasher.update(&u64::try_from(index).unwrap_or(u64::MAX).to_le_bytes());
    let mut id = [0; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    InvocationId(id)
}

/// The gate's own checks on an outcome its binding accepted, as a call's
/// chain puts them, all but the verb's args check; the reason refuses it.
fn gate_check(verb: &str, args: &Value, outcome: &HookOutcome) -> std::result::Result<(), String> {
    match outcome {
        HookOutcome::Rewrite { args: next } => host_doors::check_rewrite(verb, args, next)
            .map_err(|reason| format!("the rewritten args are refused: {reason}")),
        HookOutcome::Skip { .. } if verb == "host.compact" => {
            Err("a host.compact pre-hook may not skip".to_owned())
        }
        HookOutcome::Redact { paths } if paths.is_empty() => {
            Err("a redact names one or more paths".to_owned())
        }
        HookOutcome::Annotate { note } if note.trim().is_empty() => {
            Err("an annotation is empty".to_owned())
        }
        _ => Ok(()),
    }
}
