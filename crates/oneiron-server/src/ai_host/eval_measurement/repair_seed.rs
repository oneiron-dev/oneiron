//! The Coach's repair-seed measuring job (census L1-20 PR D). Each Pending
//! seed's old and candidate arms answer the released task under their pinned
//! skills, and the gate grades both answers in fixed code against the app's
//! observed outcome. One clock and one budget per job. A job that cannot run
//! yet (no such seed, one no longer Pending, an arm this host does not serve
//! exactly) leaves the seed Pending and spends nothing: no other model
//! stands in. A seed whose task moved settles at once with no leg run. A
//! skill arm answers under the exact skill content it pins, loaded on the
//! job's own attempt through the pinned-pack load (FIX 10677). The host
//! names only the seed key and never sees the expected answer.

use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::skill_optimize::{
    EvalRepairLegAnswer, EvalRepairSeedLegs, EvalRepairSeedRelease, EvalRepairToolCall,
    seat_model_role,
};
use oneiron::{BudgetExhaustionPolicy, Vault};

use crate::server::SyncServer;

use super::legs::{self, Generated, Opened};
use super::{MEASUREMENT_BUDGET_UNITS, MEASUREMENT_CLOCK};

/// One leg's answer, stored sourced on the capture's rows and read as the
/// gate grades it: the text for a text world, the tool calls for a tool
/// world.
fn stored_answer(
    vault: &Vault,
    release: &EvalRepairSeedRelease,
    text: &str,
    tool_calls: &[EvalRepairToolCall],
) -> oneiron::Result<EvalRepairLegAnswer> {
    if release.tools.is_empty() {
        let _output = oneiron::compaction::output::store_output_sourced(
            vault,
            text.as_bytes(),
            Some(release.source_rows.clone()),
        )?;
        Ok(EvalRepairLegAnswer::Response(text.to_owned()))
    } else {
        let bytes = serde_json::to_vec(tool_calls).map_err(|_| {
            oneiron::Error::InvariantViolation("a repair seed's tool calls did not encode")
        })?;
        let _output = oneiron::compaction::output::store_output_sourced(
            vault,
            &bytes,
            Some(release.source_rows.clone()),
        )?;
        Ok(EvalRepairLegAnswer::ToolCalls(tool_calls.to_vec()))
    }
}

/// Runs one leased `coach.eval_repair_seed` attempt.
pub(in crate::ai_host) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    let key = vault.coach_eval_repair_seed_target(admitted)?;
    let Some(release) = vault.eval_repair_seed_release(&key)? else {
        return Ok(());
    };
    let hex = oneiron_hex::encode(&key);
    let seed_legs = EvalRepairSeedLegs {
        old_receipt: format!("eval_repair_seed:{hex}:old"),
        candidate_receipt: format!("eval_repair_seed:{hex}:candidate"),
    };
    // The capture's task no longer compiles to the seed's: settle at once
    // with no leg run, as the release says.
    if release.moved {
        vault.settle_eval_repair_seed_release(
            &key,
            &EvalRepairLegAnswer::Response(String::new()),
            &EvalRepairLegAnswer::Response(String::new()),
            &seed_legs,
            vault.now_recorded_at(),
        )?;
        return Ok(());
    }
    if seat_model_role(&release.seat).is_none() {
        return Ok(());
    }
    let arms = match legs::open_pins(
        server,
        vault,
        &release.seat,
        &release.old,
        &release.candidate,
        &admitted.status.attempt,
        now,
    )? {
        Opened::Ready(arms) => arms,
        Opened::Unserved | Opened::Refused(_) => return Ok(()),
    };
    let run_id = format!("coach-eval-repair-seed:{hex}");
    let authority = vault.coach_authority()?;
    let principal = authority.entity_ref();
    let guard = vault.policy_budget_guard(
        run_id.clone(),
        MEASUREMENT_BUDGET_UNITS,
        oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS,
        BudgetExhaustionPolicy::Suspend,
        authority,
    )?;
    let run = server.ai.model_runtime().undeclared_run(run_id, guard);
    let clock = RetrievalDeadline::after(MEASUREMENT_CLOCK);
    let prompt = release.input.to_string();
    // The old leg first, then the candidate: a leg with no answer settles
    // nothing and spends no second call.
    let old = match arms.generate(
        server,
        vault,
        &run,
        &arms.incumbent,
        &prompt,
        &clock,
        principal,
        &release.tools,
    ) {
        Generated::Answer {
            text, tool_calls, ..
        } => stored_answer(vault, &release, &text, &tool_calls)?,
        Generated::Unavailable(_) => return Ok(()),
    };
    let candidate = match arms.generate(
        server,
        vault,
        &run,
        &arms.candidate,
        &prompt,
        &clock,
        principal,
        &release.tools,
    ) {
        Generated::Answer {
            text, tool_calls, ..
        } => stored_answer(vault, &release, &text, &tool_calls)?,
        Generated::Unavailable(_) => return Ok(()),
    };
    let settled = vault.settle_eval_repair_seed_release(
        &key,
        &old,
        &candidate,
        &seed_legs,
        vault.now_recorded_at(),
    )?;
    match settled {
        Some(seed) => tracing::debug!(state = ?seed.state, "the Coach's eval repair seed"),
        None => tracing::debug!("the Coach's eval repair seed is withheld"),
    }
    Ok(())
}
