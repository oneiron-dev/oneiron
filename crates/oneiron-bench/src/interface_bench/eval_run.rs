//! Smoke, probe, and full execution plus resume validation.

use super::cli_and_pinned_config::PinnedAttestation;
use super::config_types::{
    ArmContext, ArmId, BenchTask, CAMPAIGN_ID, FixtureVault, MemoProbeReport,
    PER_TASK_TOKEN_CEILING, RunSettings, SMOKE_TOKEN_CEILING, SmokeReport, SmokeRunRow,
    TOOL_CALL_CAP, TaskBundle, TaskClass,
};
use super::reports_and_fixture_helpers::{
    aggregate_rows, full_run_report, token_burn_extrapolation, unix_now,
};
use super::taskgen::{build_task_bundle, read_json, write_json_atomic, write_taskgen_outputs};
use super::wire_and_scoring::{
    call_openrouter, chat_message, eval_memo_key, judge_browse_answer, judge_cache_key,
    openrouter_request_body, pinned_transmit_attestation, request_hash, request_nonce, score_task,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
/// The identity this run expects the memoized row to carry.
///
/// Every field is compared against the row before it is reused, so they
/// travel together: a row that matches five of six is not a partial match,
/// it is a refusal.
pub(super) struct ExpectedRowIdentity<'a> {
    pub(super) arm: ArmId,
    pub(super) rep_index: u32,
    pub(super) memo_key: &'a str,
    pub(super) request_hash: &'a str,
    pub(super) request_nonce: &'a str,
    pub(super) pinned: Option<&'a PinnedAttestation>,
}

pub(super) fn validate_loaded_row(
    row: &SmokeRunRow,
    task: &BenchTask,
    expected: &ExpectedRowIdentity<'_>,
) -> Result<(), String> {
    let &ExpectedRowIdentity {
        arm,
        rep_index,
        memo_key,
        request_hash,
        request_nonce,
        pinned,
    } = expected;
    // Pinned identity is the FIRST check (ONE-1344): a row whose attestation is
    // not exactly this run's — an unpinned row read by a pinned run, a pinned
    // row read by an unpinned run, or a row pinned to another revision or pin
    // file — is never reused, it is a hard refusal.
    if row.pinned.as_ref() != pinned {
        return Err(format!(
            "pinned identity mismatch for task={} arm={} rep={} key={memo_key}: \
             row={:?}, run={:?}",
            task.task_id,
            arm.as_str(),
            rep_index,
            row.pinned,
            pinned,
        ));
    }
    if row.task_id != task.task_id
        || row.class != task.class
        || row.arm != arm
        || row.rep_index != rep_index
        || row.memo_key != memo_key
        || row.request_hash != request_hash
        || row.request_nonce != request_nonce
    {
        return Err(format!(
            "memo row mismatch for task={} arm={} rep={} key={memo_key}",
            task.task_id,
            arm.as_str(),
            rep_index
        ));
    }
    enforce_row_budget(row)
}

fn enforce_row_budget(row: &SmokeRunRow) -> Result<(), String> {
    let charged = row_charge(row);
    if charged > u64::from(PER_TASK_TOKEN_CEILING) {
        return Err(format!(
            "row task={} arm={} rep={} used {} tokens, above per-task ceiling {PER_TASK_TOKEN_CEILING}",
            row.task_id,
            row.arm.as_str(),
            row.rep_index,
            charged
        ));
    }
    Ok(())
}

fn enforce_budget(rows: &[SmokeRunRow], run_ceiling: u32) -> Result<(), String> {
    for row in rows {
        enforce_row_budget(row)?;
    }
    let tokens_total = rows.iter().map(row_charge).sum::<u64>();
    if tokens_total > u64::from(run_ceiling) {
        return Err(format!(
            "run used {tokens_total} tokens, above run ceiling {run_ceiling}"
        ));
    }
    Ok(())
}

pub(super) fn run_smoke(out_dir: &Path, settings: &RunSettings) -> Result<PathBuf, String> {
    let mut settings = settings.clone();
    settings.campaign_budget = oneiron::BudgetGuard::new(
        CAMPAIGN_ID,
        u64::from(SMOKE_TOKEN_CEILING),
        oneiron::BudgetExhaustionPolicy::Suspend,
    );
    settings.accounted_rows = Default::default();
    let settings = &settings;
    let api_key = openrouter_api_key();
    write_taskgen_outputs(out_dir, settings)?;
    let bundle = build_task_bundle();
    let rows = run_eval_rows(
        &api_key,
        out_dir,
        "smoke_rows",
        &bundle,
        &bundle.smoke_tasks,
        &ArmId::ALL,
        &[0],
        settings,
    )?;
    enforce_budget(&rows, SMOKE_TOKEN_CEILING)?;

    let report = SmokeReport {
        campaign: CAMPAIGN_ID.to_owned(),
        model: settings.model.clone(),
        provider: settings.provider_lock(),
        run_id: format!("interface-bench-1-smoke-{}", unix_now()),
        task_count: bundle.smoke_tasks.len(),
        aggregates: aggregate_rows(&rows),
        full_run_token_burn_extrapolation: token_burn_extrapolation(&rows, settings.full_reps),
        runs: rows,
    };
    let report_path = out_dir.join("smoke_report.json");
    write_json_atomic(&report_path, &report)?;
    Ok(report_path)
}

pub(super) fn run_memo_probe(out_dir: &Path, settings: &RunSettings) -> Result<PathBuf, String> {
    let api_key = openrouter_api_key();
    write_taskgen_outputs(out_dir, settings)?;
    let bundle = build_task_bundle();
    let task = bundle
        .full_tasks
        .iter()
        .find(|task| task.class == TaskClass::RetrievalQa)
        .ok_or_else(|| "no retrieval-QA task available for memo probe".to_owned())?;
    let rows = run_eval_rows(
        &api_key,
        out_dir,
        "full_rows",
        &bundle,
        std::slice::from_ref(task),
        &[ArmId::Sdk],
        &[0, 1],
        settings,
    )?;
    let memo_keys_distinct = rows[0].memo_key != rows[1].memo_key;
    let request_hashes_distinct = rows[0].request_hash != rows[1].request_hash;
    let generation_ids_distinct = match (&rows[0].generation_id, &rows[1].generation_id) {
        (Some(left), Some(right)) => left != right,
        _ => false,
    };
    let passed = memo_keys_distinct && request_hashes_distinct && generation_ids_distinct;
    let report = MemoProbeReport {
        campaign: CAMPAIGN_ID.to_owned(),
        model: settings.model.clone(),
        provider: settings.provider_lock(),
        task_id: task.task_id.clone(),
        arm: ArmId::Sdk,
        reps: rows,
        memo_keys_distinct,
        request_hashes_distinct,
        generation_ids_distinct,
        passed,
    };
    let report_path = out_dir.join("memo_probe_report.json");
    write_json_atomic(&report_path, &report)?;
    if !passed && report.reps.iter().all(|row| row.status == "completed") {
        return Err(format!(
            "memo probe failed; report written to {}",
            report_path.display()
        ));
    }
    Ok(report_path)
}

pub(super) fn run_full(out_dir: &Path, settings: &RunSettings) -> Result<PathBuf, String> {
    run_memo_probe(out_dir, settings)?;
    let api_key = openrouter_api_key();
    write_taskgen_outputs(out_dir, settings)?;
    let bundle = build_task_bundle();
    let reps = (0..settings.full_reps).collect::<Vec<_>>();
    let rows = run_eval_rows(
        &api_key,
        out_dir,
        "full_rows",
        &bundle,
        &bundle.full_tasks,
        &ArmId::ALL,
        &reps,
        settings,
    )?;
    let expected_runs = settings.full_run_count();
    if rows.len() != expected_runs {
        return Err(format!(
            "full campaign produced {} rows, expected {expected_runs}",
            rows.len()
        ));
    }
    enforce_budget(&rows, settings.full_token_ceiling())?;
    let report = full_run_report(&bundle, rows, settings);
    let report_path = out_dir.join("full_report.json");
    write_json_atomic(&report_path, &report)?;
    Ok(report_path)
}

fn openrouter_api_key() -> String {
    std::env::var("OPENROUTER_API_KEY").unwrap_or_default()
}

fn row_charge(row: &SmokeRunRow) -> u64 {
    row.answer_cost
        .iter()
        .chain(&row.judge_overhead)
        .map(|c| c.charged_tokens)
        .sum()
}

fn account_existing(row: &SmokeRunRow, settings: &RunSettings) -> Result<(), String> {
    let mut accounted = settings
        .accounted_rows
        .lock()
        .map_err(|_| "campaign row accounting lock")?;
    if !accounted.contains(&row.memo_key) {
        let charge = row_charge(row);
        if charge > 0 {
            let lease = settings
                .campaign_budget
                .admit_reserve(1)
                .map_err(|_| "campaign resume admission failed")?
                .lease;
            settings
                .campaign_budget
                .settle_usage(&lease, charge)
                .map_err(|_| "campaign resume settlement failed")?;
        }
        accounted.insert(row.memo_key.clone());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_eval_rows(
    api_key: &str,
    out_dir: &Path,
    row_dir_name: &str,
    bundle: &TaskBundle,
    tasks: &[BenchTask],
    arms: &[ArmId],
    reps: &[u32],
    settings: &RunSettings,
) -> Result<Vec<SmokeRunRow>, String> {
    let row_dir = out_dir.join(row_dir_name);
    fs::create_dir_all(&row_dir).map_err(|error| format!("create row dir: {error}"))?;
    // Restore every retained paid row before any new admission, including rows
    // outside the selected task slice. Repeated probe/full passes do not double charge.
    for entry in fs::read_dir(&row_dir).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            account_existing(&read_json::<SmokeRunRow>(&path)?, settings)?;
        }
    }
    let mut rows = Vec::with_capacity(tasks.len() * arms.len() * reps.len());
    for task in tasks {
        for arm in arms {
            for rep_index in reps {
                let row = run_or_load_eval_row(
                    api_key,
                    &row_dir,
                    task,
                    *arm,
                    *rep_index,
                    &bundle.fixture,
                    settings,
                )?;
                rows.push(row);
            }
        }
    }
    Ok(rows)
}

pub(super) fn run_or_load_eval_row(
    api_key: &str,
    row_dir: &Path,
    task: &BenchTask,
    arm: ArmId,
    rep_index: u32,
    fixture: &FixtureVault,
    settings: &RunSettings,
) -> Result<SmokeRunRow, String> {
    let (context, unavailable_reason) = match arm_context(arm, task, fixture) {
        Ok(context) => (Some(context), None),
        Err(reason) => (None, Some(reason)),
    };
    if context
        .as_ref()
        .is_some_and(|context| context.tool_calls > TOOL_CALL_CAP)
    {
        return Err(format!(
            "task={} arm={} rep={} would use {} tool calls, above cap {TOOL_CALL_CAP}",
            task.task_id,
            arm.as_str(),
            rep_index,
            context.as_ref().map_or(0, |c| c.tool_calls)
        ));
    }
    let messages = context.as_ref().map_or_else(Vec::new, |context| {
        vec![
            chat_message("system", shared_system_prompt(arm)),
            chat_message("user", eval_user_prompt(task, context)),
        ]
    });
    let request_nonce = request_nonce(task, arm, rep_index);
    let mut request = openrouter_request_body(&messages, 900, &request_nonce, settings);
    if let Some(reason) = &unavailable_reason {
        request["interface_unavailable_reason"] = serde_json::json!(reason);
    }
    // Resolved from the body that will actually be transmitted: an uncovered
    // wire id refuses here, before any row is read, written, or reused.
    let pinned = pinned_transmit_attestation(settings, &request)?;
    let request_hash = request_hash(&request, pinned.as_ref());
    let judge_cache_key = judge_cache_key(task);
    let memo_key = eval_memo_key(
        task,
        arm,
        rep_index,
        &request_nonce,
        &request_hash,
        judge_cache_key.as_deref(),
    );
    let row_path = row_dir.join(format!("{memo_key}.json"));
    if row_path.exists() {
        let row = read_json::<SmokeRunRow>(&row_path)?;
        validate_loaded_row(
            &row,
            task,
            &ExpectedRowIdentity {
                arm,
                rep_index,
                memo_key: &memo_key,
                request_hash: &request_hash,
                request_nonce: &request_nonce,
                pinned: pinned.as_ref(),
            },
        )?;
        account_existing(&row, settings)?;
        return Ok(row);
    }

    let started = Instant::now();
    let mut row = SmokeRunRow {
        task_id: task.task_id.clone(),
        class: task.class,
        arm,
        rep_index,
        memo_key,
        request_hash,
        request_nonce,
        pinned,
        generation_id: None,
        judge_generation_id: None,
        judge_relationship: None,
        status: "unavailable".into(),
        reason: unavailable_reason,
        accuracy: None,
        tokens_total: None,
        answer_cost: None,
        judge_overhead: None,
        rate_limit_wait_s: 0.0,
        tool_calls: context.as_ref().map_or(0, |c| c.tool_calls),
        wall_clock_s: 0.0,
        answer: String::new(),
        score_detail: serde_json::Value::Null,
    };
    if context.is_some() {
        let result = (|| -> Result<(), String> {
            let response = call_openrouter(api_key, &messages, 900, &row.request_nonce, settings)?;
            row.wall_clock_s = started.elapsed().as_secs_f64();
            row.tokens_total = response.accounting.provider_tokens;
            row.rate_limit_wait_s += response.accounting.rate_limit_wait_s;
            row.generation_id = response.generation_id.clone();
            row.answer_cost = Some(response.accounting.clone());
            row.answer = response.content;
            if let Some(cause) = response.accounting.failure_cause {
                return Err(cause);
            }
            let (base_accuracy, base_detail) = score_task(task, &row.answer);
            let (accuracy, detail, judge) = if task.class == TaskClass::BrowseThenAnswer {
                judge_browse_answer(
                    api_key,
                    task,
                    fixture,
                    &row.answer,
                    base_accuracy,
                    base_detail,
                    rep_index,
                    settings,
                )?
            } else {
                (base_accuracy, base_detail, None)
            };
            if let Some(judge) = judge {
                row.judge_generation_id = judge.generation_id;
                // The current binding sends answer and judge to the identical resolved pin.
                row.judge_relationship = Some("self_judged".into());
                row.rate_limit_wait_s += judge.accounting.rate_limit_wait_s;
                let failure = judge.accounting.failure_cause.clone();
                row.judge_overhead = Some(judge.accounting);
                if let Some(cause) = failure {
                    return Err(format!("judge_{cause}"));
                }
            }
            row.accuracy = Some(accuracy);
            row.score_detail = detail;
            Ok(())
        })();
        match result {
            Ok(()) => {
                row.status = "completed".into();
                row.reason = None;
            }
            Err(cause) => {
                row.status = "failed".into();
                row.reason = Some(cause);
            }
        }
    }
    // The ledger already charged new calls. Mark the stored row so a later
    // probe/full pass in this process restores it at most once.
    settings
        .accounted_rows
        .lock()
        .map_err(|_| "campaign row accounting lock")?
        .insert(row.memo_key.clone());
    write_json_atomic(&row_path, &row)?;
    Ok(row)
}

pub(super) fn shared_system_prompt(arm: ArmId) -> String {
    let affordance = match arm {
        ArmId::Sdk => {
            "You have typed tools: search(query, k), traverse(claim_id, relation), and get(claim_id). Prefer search for topics, traverse for connected facts, and get for provenance."
        }
        ArmId::Fs => {
            "You have a bash shell over the vault filesystem: claims live under /claims/, entities under /entities/, sources under /sources/; grep -r is index-accelerated; ls -t sorts by time. Navigate and cite claim paths."
        }
        ArmId::Hybrid => {
            "You have the filesystem shell plus ranked retrieval as paths: cat '/q/<your query>' returns a ranked listing of claim paths. Use query paths when browsing is slower than asking."
        }
    };
    format!(
        "You are answering questions against a personal-memory vault. Answer ONLY from what you retrieve; if the vault does not contain it, say so. Cite claim ids or paths. You have a budget of {TOOL_CALL_CAP} tool calls.\n\n{affordance}"
    )
}

pub(super) fn eval_user_prompt(task: &BenchTask, context: &ArmContext) -> String {
    format!(
        "{}\n\nInterface transcript ({} tool calls):\n{}\n\nReturn a concise final answer with citations.",
        task.prompt, context.tool_calls, context.transcript
    )
}

pub(super) fn arm_context(
    arm: ArmId,
    _task: &BenchTask,
    _fixture: &FixtureVault,
) -> Result<ArmContext, String> {
    Err(format!(
        "{}: real interface execution over a shared seeded vault is not implemented; gold-selected evidence and synthetic transcripts are disabled",
        arm.as_str()
    ))
}
