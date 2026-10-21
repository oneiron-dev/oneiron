//! Row aggregation and report tables.

use super::config_types::{
    ArmAggregate, ArmId, ArmVerdictClaim, BROWSE_JUDGE_PROMPT_VERSION, BudgetSummary, CAMPAIGN_ID,
    ClassArmSummary, FULL_TASK_COUNT, FalsificationVerdict, FixtureClaim, FixtureVault,
    FullRunReport, PER_TASK_TOKEN_CEILING, PERSON_COUNT, ParetoPoint, RunSettings, SCORER_VERSION,
    STANCES, SmokeRunRow, TOPIC_COUNT, TaskBundle, TaskClass, TokenBurnExtrapolation,
};
use std::time::{SystemTime, UNIX_EPOCH};
fn usage_reason(tokens: Option<u32>) -> Option<String> {
    tokens
        .is_none()
        .then(|| "provider_usage_unknown_or_no_interface_execution".into())
}
fn sum_tokens(rows: impl Iterator<Item = &SmokeRunRow>) -> Option<u32> {
    let rows = rows
        .filter(|row| row.status != "unavailable")
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return None;
    }
    rows.iter()
        .try_fold(0_u32, |total, row| total.checked_add(row.tokens_total?))
}
fn mean(values: impl Iterator<Item = f64>) -> Option<f64> {
    let values = values.collect::<Vec<_>>();
    (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
}

pub(super) fn aggregate_rows(rows: &[SmokeRunRow]) -> Vec<ArmAggregate> {
    ArmId::ALL
        .into_iter()
        .map(|arm| {
            let arm_rows = rows.iter().filter(|row| row.arm == arm).collect::<Vec<_>>();
            let measured = arm_rows
                .iter()
                .copied()
                .filter(|r| r.status != "unavailable")
                .collect::<Vec<_>>();
            let tokens_total = sum_tokens(arm_rows.iter().copied());
            ArmAggregate {
                arm,
                status: if measured.is_empty() {
                    "unavailable"
                } else if measured.iter().all(|r| r.status == "completed") {
                    "completed"
                } else {
                    "incomplete"
                }
                .into(),
                usage_reason: usage_reason(tokens_total),
                runs: measured.len(),
                mean_accuracy: mean(measured.iter().filter_map(|r| r.accuracy)),
                tokens_total,
                mean_tool_calls: mean(measured.iter().map(|r| f64::from(r.tool_calls)))
                    .unwrap_or(0.0),
                mean_wall_clock_s: mean(measured.iter().map(|r| r.wall_clock_s)).unwrap_or(0.0),
                accuracy_per_class: TaskClass::ALL
                    .into_iter()
                    .map(|class| {
                        (
                            class.as_str().to_owned(),
                            mean(
                                measured
                                    .iter()
                                    .filter(|r| r.class == class)
                                    .filter_map(|r| r.accuracy),
                            ),
                        )
                    })
                    .collect(),
            }
        })
        .collect()
}

pub(super) fn full_run_report(
    bundle: &TaskBundle,
    rows: Vec<SmokeRunRow>,
    settings: &RunSettings,
) -> FullRunReport {
    let aggregates = aggregate_rows(&rows);
    let class_arm_table = class_arm_table(&rows, settings.full_reps);
    let pareto_frontier = pareto_frontier(&aggregates);
    let arm_verdict_claims = arm_verdict_claims(&aggregates, &pareto_frontier);
    let falsification_verdict = falsification_verdict(&rows);
    let falsification_unavailable_reason = falsification_verdict
        .is_none()
        .then(|| "requires completed SDK and filesystem rows with known arm usage".into());
    let budget = budget_summary(&rows, settings.full_token_ceiling());
    FullRunReport {
        campaign: CAMPAIGN_ID.into(),
        model: settings.model.clone(),
        provider: settings.provider_lock(),
        run_id: format!("interface-bench-1-full-{}", unix_now()),
        task_count: bundle.full_tasks.len(),
        reps_per_task_arm: settings.full_reps,
        expected_runs: settings.full_run_count(),
        completed_runs: rows.iter().filter(|r| r.status == "completed").count(),
        scorer_version: SCORER_VERSION.into(),
        browse_judge_prompt_version: BROWSE_JUDGE_PROMPT_VERSION.into(),
        runs: rows,
        aggregates,
        class_arm_table,
        pareto_frontier,
        arm_verdict_claims,
        falsification_verdict,
        falsification_unavailable_reason,
        budget,
    }
}

pub(super) fn class_arm_table(rows: &[SmokeRunRow], reps: u32) -> Vec<ClassArmSummary> {
    let mut table = Vec::new();
    for class in TaskClass::ALL {
        for arm in ArmId::ALL {
            let selected = rows
                .iter()
                .filter(|r| r.class == class && r.arm == arm && r.status == "completed")
                .collect::<Vec<_>>();
            let Some(accuracy_mean) = mean(selected.iter().filter_map(|r| r.accuracy)) else {
                continue;
            };
            let accuracy_by_rep = (0..reps)
                .filter_map(|rep| {
                    mean(
                        selected
                            .iter()
                            .filter(|r| r.rep_index == rep)
                            .filter_map(|r| r.accuracy),
                    )
                })
                .collect::<Vec<_>>();
            let tokens = selected
                .iter()
                .map(|r| r.tokens_total)
                .collect::<Option<Vec<_>>>();
            let tokens_mean = tokens
                .as_ref()
                .and_then(|tokens| mean(tokens.iter().map(|n| f64::from(*n))));
            let tokens_range = tokens.as_ref().and_then(|tokens| {
                tokens
                    .iter()
                    .max()
                    .zip(tokens.iter().min())
                    .map(|(max, min)| max - min)
            });
            table.push(ClassArmSummary {
                class: class.as_str().into(),
                arm,
                runs: selected.len(),
                reps,
                accuracy_mean,
                accuracy_range: numeric_range(&accuracy_by_rep),
                tokens_mean,
                tokens_range,
                usage_reason: tokens_mean
                    .is_none()
                    .then(|| "provider_usage_unknown".into()),
                tool_calls_mean: mean(selected.iter().map(|r| f64::from(r.tool_calls)))
                    .unwrap_or(0.0),
                wall_clock_mean_s: mean(selected.iter().map(|r| r.wall_clock_s)).unwrap_or(0.0),
            });
        }
    }
    table
}
fn numeric_range(values: &[f64]) -> f64 {
    values
        .iter()
        .copied()
        .reduce(f64::max)
        .zip(values.iter().copied().reduce(f64::min))
        .map_or(0.0, |(max, min)| max - min)
}
fn pareto_frontier(aggregates: &[ArmAggregate]) -> Vec<ParetoPoint> {
    aggregates
        .iter()
        .filter_map(|candidate| {
            if candidate.status != "completed" {
                return None;
            }
            let (accuracy, tokens) = (candidate.mean_accuracy?, candidate.tokens_total?);
            let dominated = aggregates.iter().any(|other| {
                other.status == "completed"
                    && other.arm != candidate.arm
                    && other
                        .mean_accuracy
                        .zip(other.tokens_total)
                        .is_some_and(|(a, t)| {
                            a >= accuracy && t <= tokens && (a > accuracy || t < tokens)
                        })
            });
            Some(ParetoPoint {
                arm: candidate.arm,
                mean_accuracy: Some(accuracy),
                tokens_total: Some(tokens),
                dominated,
            })
        })
        .collect()
}
fn arm_verdict_claims(aggregates: &[ArmAggregate], points: &[ParetoPoint]) -> Vec<ArmVerdictClaim> {
    points.iter().filter_map(|point| {
        let aggregate = aggregates.iter().find(|a| a.arm == point.arm)?;
        let (accuracy, tokens) = (point.mean_accuracy?, point.tokens_total?);
        Some(ArmVerdictClaim {
            band: "Proposed".into(), arm: point.arm,
            claim_id: format!("{CAMPAIGN_ID}-{}-verdict", point.arm.as_str()),
            claim: format!("{} achieved mean accuracy {accuracy:.4} with {tokens} measured interface tokens; judge overhead excluded.", point.arm.as_str()),
            mean_accuracy: Some(accuracy), tokens_total: Some(tokens), pareto_dominated: point.dominated,
            evidence: vec![format!("runs={}", aggregate.runs)],
        })
    }).collect()
}
fn falsification_verdict(rows: &[SmokeRunRow]) -> Option<FalsificationVerdict> {
    let class = TaskClass::RetrievalQa;
    let selected = |arm| {
        rows.iter()
            .filter(|r| r.class == class && r.arm == arm)
            .collect::<Vec<_>>()
    };
    let (fs, sdk) = (selected(ArmId::Fs), selected(ArmId::Sdk));
    if fs.is_empty() || sdk.is_empty() || fs.iter().chain(&sdk).any(|r| r.status != "completed") {
        return None;
    }
    let arm_fs_accuracy = mean(fs.iter().filter_map(|r| r.accuracy))?;
    let arm_sdk_accuracy = mean(sdk.iter().filter_map(|r| r.accuracy))?;
    let arm_fs_tokens = sum_tokens(fs.into_iter())?;
    let arm_sdk_tokens = sum_tokens(sdk.into_iter())?;
    if arm_sdk_tokens == 0 {
        return None;
    }
    let token_ratio = f64::from(arm_fs_tokens) / f64::from(arm_sdk_tokens);
    let matches_accuracy = arm_fs_accuracy >= arm_sdk_accuracy;
    let within_token_bound = token_ratio <= 1.5;
    Some(FalsificationVerdict {
        band: "Proposed".into(),
        class: class.as_str().into(),
        arm_fs_accuracy,
        arm_sdk_accuracy,
        arm_fs_tokens,
        arm_sdk_tokens,
        token_ratio,
        matches_accuracy,
        within_token_bound,
        falsifies_sdk_necessity_premise: matches_accuracy && within_token_bound,
    })
}
fn budget_summary(rows: &[SmokeRunRow], run_token_ceiling: u32) -> BudgetSummary {
    let tokens_total = sum_tokens(rows.iter());
    let judge_overhead_tokens = rows
        .iter()
        .filter_map(|r| r.judge_overhead.as_ref())
        .try_fold(0_u32, |total, c| total.checked_add(c.provider_tokens?));
    BudgetSummary {
        per_task_token_ceiling: PER_TASK_TOKEN_CEILING,
        run_token_ceiling,
        tokens_total,
        usage_reason: if tokens_total.is_none() || judge_overhead_tokens.is_none() {
            Some("provider_usage_unknown_or_no_interface_execution; reservation charges are not measured usage".into())
        } else {
            None
        },
        max_row_tokens: rows
            .iter()
            .filter(|r| r.status != "unavailable")
            .map(|r| r.tokens_total)
            .collect::<Option<Vec<_>>>()
            .and_then(|v| v.into_iter().max()),
        charged_tokens: rows
            .iter()
            .filter_map(|r| r.answer_cost.as_ref())
            .map(|c| c.charged_tokens)
            .sum(),
        judge_overhead_tokens,
        judge_reservation_charges: rows
            .iter()
            .filter_map(|r| r.judge_overhead.as_ref())
            .map(|c| c.charged_tokens)
            .sum(),
    }
}
pub(super) fn token_burn_extrapolation(
    rows: &[SmokeRunRow],
    full_reps: u32,
) -> TokenBurnExtrapolation {
    let smoke_tokens = sum_tokens(rows.iter());
    let observed_runs = rows.iter().filter(|r| r.status != "unavailable").count();
    let full_run_equivalent_runs = FULL_TASK_COUNT * ArmId::ALL.len() * full_reps as usize;
    let extrapolated_full_tokens = smoke_tokens
        .filter(|_| observed_runs > 0)
        .and_then(|tokens| {
            u32::try_from(
                u64::from(tokens) * full_run_equivalent_runs as u64 / observed_runs as u64,
            )
            .ok()
        });
    TokenBurnExtrapolation {
        usage_reason: usage_reason(smoke_tokens),
        smoke_tokens,
        full_run_equivalent_runs,
        observed_runs,
        extrapolated_full_tokens,
    }
}

pub(super) fn fixture_claim(
    fixture: &FixtureVault,
    person_index: usize,
    topic_index: usize,
) -> &FixtureClaim {
    &fixture.claims[person_index * TOPIC_COUNT + topic_index]
}

pub(super) fn claim_id_for(person_index: usize, topic_index: usize) -> String {
    format!("claim-{:04}", person_index * TOPIC_COUNT + topic_index)
}

pub(super) fn topic_id(index: usize) -> String {
    format!("topic-{index:03}")
}

pub(super) fn topic_name(index: usize) -> String {
    format!("topic-{index:03}-interface-memory")
}

pub(super) fn person_id(index: usize) -> String {
    format!("person-{index:02}")
}

pub(super) fn person_name(index: usize) -> String {
    format!("Person {index:02}")
}

pub(super) fn object_id(index: usize) -> String {
    format!("artifact-{index:02}")
}

pub(super) fn object_name(index: usize) -> String {
    format!("artifact notebook {index:02}")
}

pub(super) fn organization_id(index: usize) -> String {
    format!("org-{:02}", index % 10)
}

pub(super) fn organization_name(index: usize) -> String {
    format!("Organization {:02}", index % 10)
}

pub(super) fn source_ref(person_index: usize, topic_index: usize) -> String {
    format!("source-{:02}", (person_index * 3 + topic_index) % 17)
}

pub(super) fn learned_at(person_index: usize, topic_index: usize) -> u64 {
    1_767_225_600 + ((topic_index * PERSON_COUNT + person_index) as u64 * 3_600)
}

pub(super) fn stance_for(person_index: usize, topic_index: usize) -> String {
    STANCES[(person_index * 17 + topic_index * 31) % STANCES.len()].to_owned()
}

pub(super) fn superseded_by_for(person_index: usize, topic_index: usize) -> Option<String> {
    (topic_index.is_multiple_of(25) && topic_index + 1 < TOPIC_COUNT)
        .then(|| claim_id_for(person_index, topic_index + 1))
}

pub(super) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
