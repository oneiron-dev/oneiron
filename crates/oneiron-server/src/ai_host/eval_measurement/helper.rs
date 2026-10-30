//! The helper gate's measurement and verdict (FIX 10677, 12069, 12093):
//! each callable helper awaiting its gate asks for the paired measurement of
//! its exact content against its parent's, on the seat whose code mode calls
//! helpers, with both arms answered by that seat's served model at its
//! registry revision. The same request again keeps its row, so a measured
//! helper is not measured twice. A row that settled Partial is not yet
//! measured for the gate: the same request queues one new measurement
//! beside it, and that one takes its place once it settles (FIX 12175).
//! With no judge, no served seat or no live cohort, nothing is asked.
//!
//! Once that row is Final, the same pass asks the gate: the helper and its
//! parent each run, in the code sandbox, the frozen calls of both that
//! callers other than the helper's author made, and an accepted verdict
//! admits the helper.

use std::sync::Arc;

use oneiron::engine_executor::JsCodeModeRuntime;
use oneiron::error::ArtifactError;
use oneiron::llm::manifest::ModelRole;
use oneiron::skill::SkillRecord;
use oneiron::skill::helper::{
    CallableCase, CallableHarness, HarnessScore, HelperPairedVerdict, admit_callable_helper,
    callable_case_passes, callable_gate_verdict, callable_helper_cases,
    callable_helper_measurement_requests, gate_callable_helper,
};
use oneiron::skill_hub::HubFile;
use oneiron::skill_optimize::offer_pilot::model_offer_pin;
use oneiron::skill_optimize::{HeldOutReplayNotes, MeasurementState, model_role_seat};
use oneiron::{EntityId, Error, Vault};

use crate::server::SyncServer;

/// The role a helper's legs answer as: agents call helpers from the code
/// mode the generative reasoner serves (CALL).
const HELPER_ROLE: ModelRole = ModelRole::GenerativeReasoner;

/// Asks for each awaiting helper's measurement against its parent, and asks
/// the gate of each whose measurement is Final.
/// # Errors
/// Storage errors.
pub(in crate::ai_host) fn request_helper_measurements(
    server: &SyncServer,
    vault: &Vault,
    now: u64,
) -> oneiron::Result<()> {
    let Some(judge) = crate::replay_judge::registered() else {
        return Ok(());
    };
    let runtime = server.ai.model_runtime();
    let Some(seat) = runtime.seat(HELPER_ROLE) else {
        return Ok(());
    };
    let Ok(route) = runtime.route_role(vault, HELPER_ROLE, seat) else {
        return Ok(());
    };
    let Some((pin, _)) = vault
        .model_registry_rows()?
        .iter()
        .find(|row| row.catalog.model.as_str() == route.model.as_str())
        .and_then(model_offer_pin)
    else {
        return Ok(());
    };
    let requests = callable_helper_measurement_requests(
        vault,
        &model_role_seat(HELPER_ROLE),
        (&pin.model, &pin.revision),
        judge.judge_revision(),
    )?;
    let runtimes = CaseRuntimes::default();
    for (helper, request) in requests {
        let digest = match vault.request_eval_measurement(&request, now) {
            Ok(digest) => digest,
            // A pair the measurement door refuses is measured by nothing.
            Err(Error::InvalidConfig(reason)) => {
                tracing::debug!(
                    helper = %helper.to_hex(),
                    %reason,
                    "the helper's pair has no eval measurement"
                );
                continue;
            }
            Err(error) => return Err(error),
        };
        // A Partial row reads as no row: its pair is measured again, and its
        // results stay as they are until the new measurement replaces them.
        if let Err(error) = vault.remeasure_partial_eval_measurement(&digest, now) {
            tracing::warn!(
                helper = %helper.to_hex(),
                kind = ?error.kind(),
                "the helper's Partial measurement was not asked again"
            );
            continue;
        }
        // A gate that does not run through stores no verdict, and the
        // helper stays a Candidate; the next pass asks again.
        match gate_measured_helper(server.vault(), &helper, &digest, &runtimes, now) {
            Ok(()) => {}
            Err(Error::Artifact(ArtifactError::InvalidSkillBody(reason))) => {
                tracing::debug!(
                    helper = %helper.to_hex(),
                    reason,
                    "the callable helper gate refused"
                );
            }
            // By kind only: an engine error can quote the vault.
            Err(error) => {
                tracing::warn!(
                    helper = %helper.to_hex(),
                    kind = ?error.kind(),
                    "the callable helper gate stored no verdict"
                );
            }
        }
    }
    Ok(())
}

/// Asks the gate of `helper` once its paired measurement `digest` is Final,
/// on its own and its parent's frozen calls, and admits it on an accepted
/// verdict. With no Final row or no case, the gate is not asked this pass.
/// A helper whose standing verdict already reads this measurement as worse
/// is not run again: nothing it is scored on can change that.
fn gate_measured_helper(
    vault: &Arc<Vault>,
    helper: &EntityId,
    digest: &[u8; 32],
    runtimes: &CaseRuntimes,
    now: u64,
) -> oneiron::Result<()> {
    let Some(row) = vault.eval_measurement(digest)? else {
        return Ok(());
    };
    if row.state != MeasurementState::Final {
        return Ok(());
    }
    if callable_gate_verdict(vault, helper)?.is_some_and(|verdict| {
        verdict.measurement == row.digest && verdict.paired == HelperPairedVerdict::Worse
    }) {
        return Ok(());
    }
    let cases = callable_helper_cases(vault, helper)?;
    if cases.is_empty() {
        return Ok(());
    }
    let harness = SandboxHarness {
        vault,
        helper: *helper,
        runtimes,
        frozen_unix_ms: now.saturating_mul(1000),
    };
    let verdict = gate_callable_helper(vault, helper, &cases, &harness, digest, now)?;
    tracing::debug!(
        helper = %helper.to_hex(),
        accepted = verdict.accepted,
        "the callable helper gate"
    );
    if verdict.accepted {
        admit_callable_helper(vault, helper, now)?;
    }
    Ok(())
}

/// The helper gate's runner: each case of each arm runs on a fresh runtime
/// in the code sandbox, as a call of that exact source runs, at the pass's
/// clock. A case passes when its answer equals the frozen one.
struct SandboxHarness<'a> {
    vault: &'a Arc<Vault>,
    helper: EntityId,
    runtimes: &'a CaseRuntimes,
    frozen_unix_ms: u64,
}

impl SandboxHarness<'_> {
    fn pass_rate(
        &self,
        skill: &EntityId,
        source: (&SkillRecord, &[HubFile]),
        cases: &[&CallableCase],
    ) -> oneiron::Result<f64> {
        if cases.is_empty() {
            return Ok(0.0);
        }
        let mut passed = 0_u32;
        for case in cases {
            let mut runtime = self.runtimes.fresh()?;
            let passes = callable_case_passes(
                self.vault,
                skill,
                source,
                case,
                runtime.as_mut(),
                self.frozen_unix_ms,
            )?;
            passed += u32::from(passes);
        }
        Ok(f64::from(passed) / cases.len() as f64)
    }
}

impl CallableHarness for SandboxHarness<'_> {
    fn score(
        &self,
        candidate: &SkillRecord,
        candidate_files: &[HubFile],
        incumbent: Option<(&SkillRecord, &[HubFile])>,
        cases: &[&CallableCase],
    ) -> oneiron::Result<HarnessScore> {
        let baseline = match (incumbent, candidate.forked_from) {
            (Some(incumbent), Some(parent)) => self.pass_rate(&parent, incumbent, cases)?,
            // No helper at all answers no case.
            _ => 0.0,
        };
        Ok(HarnessScore {
            baseline,
            candidate: self.pass_rate(&self.helper, (candidate, candidate_files), cases)?,
        })
    }
}

/// Each case's runtime: a fresh one of the checked-in QuickJS component, the
/// one code mode runs, compiled once per pass on its first case.
#[derive(Default)]
struct CaseRuntimes {
    #[cfg(feature = "code-sandbox-wasmtime")]
    component: std::cell::OnceCell<Option<oneiron::code_sandbox::quickjs::QuickJsRuntimeFactory>>,
}

impl CaseRuntimes {
    #[cfg(feature = "code-sandbox-wasmtime")]
    fn fresh(&self) -> oneiron::Result<Box<dyn JsCodeModeRuntime>> {
        let factory = self
            .component
            .get_or_init(|| match crate::mcp::checked_in_quickjs_runtime() {
                Ok(factory) => Some(factory),
                Err(error) => {
                    tracing::error!(%error, "the checked-in QuickJS component did not load");
                    None
                }
            })
            .as_ref()
            .ok_or_else(|| {
                Error::InvalidConfig("the checked-in QuickJS component did not load".to_owned())
            })?;
        let runtime: Box<dyn JsCodeModeRuntime> = Box::new(factory.runtime()?);
        Ok(runtime)
    }

    /// A server built without the code sandbox runs no case.
    #[cfg(not(feature = "code-sandbox-wasmtime"))]
    fn fresh(&self) -> oneiron::Result<Box<dyn JsCodeModeRuntime>> {
        Err(Error::InvalidConfig(
            "this server has no code sandbox".to_owned(),
        ))
    }
}
