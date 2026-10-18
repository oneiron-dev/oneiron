//! The Coach's eval authoring (ARCH-0053 "Eval authoring", OF-578): each
//! night it keeps each seat's test set from the vault's own history. Fixed
//! code reads the inventory, metadata only, and skips the night when there
//! is nothing to decide. Otherwise the Coach's model, running the
//! eval-authoring skill it loads on its attempt, answers with one plan:
//! purposes for new source groups, cases to keep, cohorts to cut and
//! cohorts to retire. The engine checks the plan against the inventory and
//! applies it through the eval-set doors. No skill, no model, or no plan
//! that parses changes nothing.
use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::skill_optimize::{
    EvalAuthoringPlan, eval_authoring_inventory, eval_authoring_skill_id,
};
use oneiron::{EntityId, Error, LlmMessageRole};

use super::code_fix::{HostModels, message};
use crate::server::SyncServer;

/// The call purpose the eval-authoring model call is metered under.
const EVAL_AUTHORING_CALL_PURPOSE: &str = "coach_eval_authoring";
/// What one job's call may spend.
const BUDGET_UNITS: u64 = 1 << 20;
/// The skill's file the Coach runs; the inventory goes as data.
const SKILL_FILE: &str = "SKILL.md";

/// Runs one eval-authoring pass.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    let inventory = eval_authoring_inventory(vault, now)?;
    // No new candidate, label, cut or exposure: no model call.
    if !inventory.has_work() {
        return Ok(());
    }
    let runtime = server.ai.model_runtime();
    let models = HostModels::open(
        server,
        format!(
            "coach-eval-authoring:{}",
            EntityId::from_bytes(*admitted.status.attempt.id.as_bytes())?.to_hex()
        ),
        EVAL_AUTHORING_CALL_PURPOSE,
        BUDGET_UNITS,
    )?;
    let Some(executor) = runtime
        .seat(models.coach())
        .map(|seat| seat.model.as_str().to_owned())
    else {
        return Ok(());
    };
    // The skill's body is the Coach's instruction. The load stamps its
    // revision and the Coach's model on the attempt, and each cut and
    // retirement names them.
    let attempt = &admitted.status.attempt;
    let loaded = match vault.load_attempt_skill_pack(
        attempt.id,
        &eval_authoring_skill_id()?,
        attempt.lease_owner.as_deref().unwrap_or_default(),
        attempt.attempt_count,
        &executor,
        now,
    ) {
        Ok(loaded) => loaded,
        // A retired, unapproved or deleted skill authors nothing.
        Err(Error::EntityNotFound | Error::InvalidClaimBody(_)) => return Ok(()),
        Err(error) => return Err(error),
    };
    let Some(instruction) = loaded
        .source_files
        .as_ref()
        .and_then(|files| files.iter().find(|file| file.path == SKILL_FILE))
        .and_then(|file| std::str::from_utf8(&file.content).ok())
        .map(str::to_owned)
    else {
        return Ok(());
    };
    let skill = (loaded.entity, loaded.record.version);
    let data = serde_json::to_string(&inventory)
        .map_err(|_| Error::InvalidConfig("the eval inventory could not be encoded".into()))?;
    let Some(text) = models.generate(
        models.coach(),
        vec![
            message(LlmMessageRole::System, instruction),
            message(LlmMessageRole::User, data),
        ],
    )?
    else {
        // No seat took the call: the next night asks again.
        return Ok(());
    };
    let Some(plan) = parse_plan(&text) else {
        tracing::debug!("the Coach's eval-authoring answer held no plan");
        return Ok(());
    };
    match vault.run_coach_eval_authoring(admitted, plan, &inventory, skill, now) {
        Ok(report) => {
            tracing::debug!(
                cases = report.cases_recorded,
                cuts = report.cohorts_cut.len(),
                retired = report.cohorts_retired.len(),
                skipped = report.skipped.len(),
                "the Coach kept the eval sets"
            );
            Ok(())
        }
        // A plan the engine refuses changes nothing; the next night asks again.
        Err(Error::Artifact(_)) => {
            tracing::debug!("the Coach's eval-authoring plan was refused");
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// The one JSON object in the answer; `None` when there is none or it is
/// not a plan.
fn parse_plan(text: &str) -> Option<EvalAuthoringPlan> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    serde_json::from_str(text.get(start..=end)?).ok()
}
