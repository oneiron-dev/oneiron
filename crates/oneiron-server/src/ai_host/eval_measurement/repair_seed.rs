//! The Coach's repair-seed measuring job (census L1-20 PR D). Each Pending
//! seed's old and candidate arms answer the released task under their pinned
//! skills, and the gate grades both answers in fixed code against the app's
//! observed outcome. One clock and one budget per job. A job that cannot run
//! yet (no such seed, one no longer Pending, an arm this host does not serve
//! exactly) leaves the seed Pending and spends nothing: no other model
//! stands in. A seed whose task moved settles at once with no leg run. A
//! skill arm answers under the exact skill content it pins, loaded on the
//! job's own attempt through the pinned-pack load (FIX 10677). The host
//! names only the seed key and never sees the expected answer. Each leg's
//! receipt names the seed, the leg and the stored answer the gate graded
//! (its content handle).

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

/// One leg's answer as the gate grades it ([`legs::repair_answer`]),
/// stored sourced on the capture's rows, and the leg's receipt:
/// `eval_repair_seed:<key>:<leg>:<stored answer's handle>`.
fn stored_answer(
    vault: &Vault,
    release: &EvalRepairSeedRelease,
    leg: &str,
    text: &str,
    tool_calls: Option<Vec<EvalRepairToolCall>>,
) -> oneiron::Result<(EvalRepairLegAnswer, String)> {
    let answer = legs::repair_answer(&release.tools, text, tool_calls);
    let output = oneiron::compaction::output::store_output_sourced(
        vault,
        &legs::repair_answer_bytes(&answer)?,
        Some(release.source_rows.clone()),
    )?;
    let receipt = format!(
        "eval_repair_seed:{}:{leg}:{}",
        oneiron_hex::encode(&release.key),
        output.handle()
    );
    Ok((answer, receipt))
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
    // The capture's task no longer compiles to the seed's: settle at once
    // with no leg run, as the release says. The gate refuses it TaskMoved
    // before any grade, so no receipt names an answer.
    if release.moved {
        vault.settle_eval_repair_seed_release(
            &key,
            &EvalRepairLegAnswer::Response(String::new()),
            &EvalRepairLegAnswer::Response(String::new()),
            &EvalRepairSeedLegs {
                old_receipt: format!("eval_repair_seed:{hex}:old"),
                candidate_receipt: format!("eval_repair_seed:{hex}:candidate"),
            },
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
    let (old, old_receipt) = match arms.generate(
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
        } => stored_answer(vault, &release, "old", &text, tool_calls)?,
        Generated::Unavailable(_) => return Ok(()),
    };
    let (candidate, candidate_receipt) = match arms.generate(
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
        } => stored_answer(vault, &release, "candidate", &text, tool_calls)?,
        Generated::Unavailable(_) => return Ok(()),
    };
    let settled = vault.settle_eval_repair_seed_release(
        &key,
        &old,
        &candidate,
        &EvalRepairSeedLegs {
            old_receipt,
            candidate_receipt,
        },
        vault.now_recorded_at(),
    )?;
    match settled {
        Some(state) => tracing::debug!(?state, "the Coach's eval repair seed"),
        None => tracing::debug!("the Coach's eval repair seed is withheld"),
    }
    Ok(())
}
