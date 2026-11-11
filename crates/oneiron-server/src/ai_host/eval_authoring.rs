//! The Coach's eval authoring (ARCH-0053 "Eval authoring", OF-578): each
//! night it keeps each seat's test set from the vault's own history. Fixed
//! code reads the inventory, metadata only, and skips the night when there
//! is nothing to decide. Otherwise the Coach's model, running the
//! eval-authoring skill it loads on its attempt, answers with one plan:
//! purposes for new source groups, cases to keep, cohorts to cut and
//! cohorts to retire. The engine checks the plan against the inventory and
//! applies it through the eval-set doors. No skill, no model, or no plan
//! that parses changes nothing.
use oneiron::attempt_queue::ReadSetProducer;
use oneiron::dreamer_runner::{AdmitDreamerAttempt, DreamerAdmittedAttempt, DreamerRunnerStore};
use oneiron::memory::{MEMORY_CODE_INTERNAL, Memory, MemoryError, MemoryResult};
use oneiron::skill_optimize::{
    EVAL_AUTHORING_EXECUTE_VERB, EvalAuthoringAdmission, EvalAuthoringExecuteAnswer,
    EvalAuthoringExecuteRequest, EvalAuthoringInventory, EvalAuthoringOutcome, EvalAuthoringPlan,
    admit_eval_authoring_execution, eval_authoring_inventory_sourced, eval_authoring_skill_id,
    union_source_rows,
};
use oneiron::{EntityId, Error, LlmMessageRole};

use super::coach_heal::{LEASE_OWNER, settle};
use super::coach_host::{
    BUDGET_ID as COACH_HOST_BUDGET_ID, BUDGET_UNITS as COACH_HOST_BUDGET_UNITS,
};
use super::code_fix::{HostModels, message};
use crate::server::SyncServer;

/// The call purpose the eval-authoring model call is metered under.
const EVAL_AUTHORING_CALL_PURPOSE: &str = "coach_eval_authoring";
/// What one job's call may spend.
const BUDGET_UNITS: u64 = 1 << 20;
/// The skill's file the Coach runs; the inventory goes as data.
const SKILL_FILE: &str = "SKILL.md";
/// The pass's key in its attempt's read set (FIX 7019, 7073).
const EVAL_AUTHORING: ReadSetProducer = ReadSetProducer::COACH_EVAL_AUTHORING;

/// How a pass's model step ended: with a plan to apply, or before one.
enum PassEnd {
    /// The inventory held nothing new to decide: no model call.
    NoWork,
    /// No Coach seat, no loadable approved skill or no seat took the call.
    Unavailable {
        skill: Option<(EntityId, String)>,
        digest: String,
    },
    /// The answer held no plan.
    NoPlan {
        skill: (EntityId, String),
        digest: String,
    },
    /// The Coach's plan for `inventory`, made running `skill`.
    Plan {
        plan: EvalAuthoringPlan,
        inventory: Box<EvalAuthoringInventory>,
        skill: (EntityId, String),
    },
}

impl PassEnd {
    fn unavailable(skill: Option<(EntityId, String)>, digest: String) -> Self {
        Self::Unavailable { skill, digest }
    }
}

/// Runs one eval-authoring pass.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let PassEnd::Plan {
        plan,
        inventory,
        skill,
    } = pass(server, admitted, now)?
    else {
        return Ok(());
    };
    match server
        .vault()
        .run_coach_eval_authoring(admitted, plan, &inventory, skill, now)
    {
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

/// `vault.evals.authoring.execute` on this host: admits `memory`'s caller
/// and the request's own Coach attempt in one writer, runs the pass on it as
/// the nightly worker would, keeps the pass's record and settles the
/// attempt on the Coach queue's lease and budget line. The effects are the
/// Coach's; the record names the caller.
pub(crate) fn execute(
    server: &SyncServer,
    memory: &Memory<'_>,
    input: EvalAuthoringExecuteRequest,
) -> MemoryResult<EvalAuthoringExecuteAnswer> {
    let vault = server.vault();
    let store = DreamerRunnerStore::new(vault);
    let now = vault.now_recorded_at();
    let admitted = match admit_eval_authoring_execution(
        memory,
        input,
        AdmitDreamerAttempt {
            lease_owner: LEASE_OWNER.to_owned(),
            now,
            budget_id: COACH_HOST_BUDGET_ID.to_owned(),
            budget_total_units: COACH_HOST_BUDGET_UNITS,
            reserve_units: 1,
            started_milestone: None,
        },
    )? {
        EvalAuthoringAdmission::Admitted { attempt, .. } => attempt,
        EvalAuthoringAdmission::Waiting { attempt } => {
            return Ok(EvalAuthoringExecuteAnswer::Waiting { attempt });
        }
    };
    let ended = pass(server, &admitted, now).and_then(|end| match end {
        PassEnd::Plan {
            plan,
            inventory,
            skill,
        } => vault.apply_requested_eval_authoring(&admitted, plan, &inventory, skill, now),
        PassEnd::NoWork => vault.end_requested_eval_authoring(
            &admitted,
            EvalAuthoringOutcome::NoWork,
            None,
            None,
            now,
        ),
        PassEnd::Unavailable { skill, digest } => vault.end_requested_eval_authoring(
            &admitted,
            EvalAuthoringOutcome::Unavailable,
            skill,
            Some(digest),
            now,
        ),
        PassEnd::NoPlan { skill, digest } => vault.end_requested_eval_authoring(
            &admitted,
            EvalAuthoringOutcome::NoPlan,
            Some(skill),
            Some(digest),
            now,
        ),
    });
    match ended {
        Ok(execution) => {
            settle(vault, &store, &admitted, Ok(()), COACH_HOST_BUDGET_ID)?;
            Ok(EvalAuthoringExecuteAnswer::Ran {
                execution: Box::new(execution),
            })
        }
        Err(error) => {
            // The record ends Failed before the attempt fails with the
            // error's kind; a record that already ended keeps its end.
            if let Err(record) = vault.end_requested_eval_authoring(
                &admitted,
                EvalAuthoringOutcome::Failed,
                None,
                None,
                vault.now_recorded_at(),
            ) {
                tracing::warn!(%record, "a requested eval-authoring pass could not record its failure");
            }
            let kind = error.kind();
            settle(vault, &store, &admitted, Err(error), COACH_HOST_BUDGET_ID)?;
            Err(MemoryError::new(
                MEMORY_CODE_INTERNAL,
                format!("{EVAL_AUTHORING_EXECUTE_VERB} failed on this host: {kind:?}"),
                &["Read vault.evals.authoring.result for the attempt's state."],
            ))
        }
    }
}

/// One pass up to its plan: the inventory, the Coach's seat, the skill it
/// loads on `admitted` and the model's answer.
fn pass(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<PassEnd> {
    let vault = server.vault();
    let (inventory, inventory_rows) = eval_authoring_inventory_sourced(vault, now)?;
    // No new candidate, label, cut or exposure: no model call.
    if !inventory.has_work() {
        return Ok(PassEnd::NoWork);
    }
    let digest = inventory.inventory_digest.clone();
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
        return Ok(PassEnd::unavailable(None, digest));
    };
    // The skill's body is the Coach's instruction. The load stamps its
    // revision and the Coach's model on the attempt, and each cut and
    // retirement names them.
    let attempt = &admitted.status.attempt;
    // The pass and the pack load door that reads the authoring skill are
    // the producers its attempt's read set waits on: declared before the
    // load reads anything, the set reads complete only once both reported,
    // and stays unknown if either never does (FIX 7019, 7073).
    let mut read_set_lost = false;
    if let Err(error) = vault
        .declare_attempt_read_producers(attempt.id, &[EVAL_AUTHORING, ReadSetProducer::SKILL_PACK])
    {
        read_set_lost = true;
        tracing::warn!(
            attempt = ?attempt.id,
            %error,
            "the eval authoring could not declare its read set; its pack receipt keeps it unknown"
        );
    }
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
        Err(Error::EntityNotFound | Error::InvalidClaimBody(_)) => {
            return Ok(PassEnd::unavailable(None, digest));
        }
        Err(error) => return Err(error),
    };
    let skill = (loaded.entity, loaded.record.version.clone());
    let Some(instruction) = loaded
        .source_files
        .as_ref()
        .and_then(|files| files.iter().find(|file| file.path == SKILL_FILE))
        .and_then(|file| std::str::from_utf8(&file.content).ok())
        .map(str::to_owned)
    else {
        return Ok(PassEnd::unavailable(Some(skill), digest));
    };
    let data = serde_json::to_string(&inventory)
        .map_err(|_| Error::InvalidConfig("the eval inventory could not be encoded".into()))?;
    // The call reads the inventory's rows and the skill it loaded (FIX 6997).
    let rows = union_source_rows([inventory_rows, Some(vec![skill.0])]);
    // The pass reads what its call carries: the same rows are its read set
    // (FIX 7019). Capture only (FIX 7021): a storage error recording them
    // never ends the pass, and a set no complete read backs records
    // nothing, so the attempt reads as unknown either way.
    if !read_set_lost
        && let Some(report) = rows.clone()
        && let Err(error) = vault.record_attempt_sources(attempt.id, EVAL_AUTHORING, Some(report))
    {
        tracing::warn!(
            attempt = ?attempt.id,
            %error,
            "the eval authoring could not record its read set; its pack receipt keeps it unknown"
        );
        let _ = vault.record_attempt_sources(attempt.id, EVAL_AUTHORING, None);
    }
    let Some(text) = models.generate_sourced(
        models.coach(),
        vec![
            message(LlmMessageRole::System, instruction),
            message(LlmMessageRole::User, data),
        ],
        rows,
    )?
    else {
        // No seat took the call: the next night asks again.
        return Ok(PassEnd::unavailable(Some(skill), digest));
    };
    let Some(plan) = parse_plan(&text) else {
        tracing::debug!("the Coach's eval-authoring answer held no plan");
        return Ok(PassEnd::NoPlan { skill, digest });
    };
    Ok(PassEnd::Plan {
        plan,
        inventory: Box::new(inventory),
        skill,
    })
}

/// The one JSON object in the answer; `None` when there is none or it is
/// not a plan.
fn parse_plan(text: &str) -> Option<EvalAuthoringPlan> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    serde_json::from_str(text.get(start..=end)?).ok()
}
