//! Row aggregation and report tables.

use super::config_types::{
    ArmAggregate, ArmId, ArmVerdictClaim, BROWSE_JUDGE_PROMPT_VERSION, BudgetSummary, CAMPAIGN_ID,
    ClassArmSummary, FULL_TASK_COUNT, FalsificationVerdict, FixtureClaim, FixtureVault,
    FullRunReport, PER_TASK_TOKEN_CEILING, PERSON_COUNT, ParetoPoint, RunSettings, SCORER_VERSION,
    STANCES, SmokeRunRow, TOPIC_COUNT, TaskBundle, TaskClass, TokenBurnExtrapolation,
};
use std::time::{SystemTime, UNIX_EPOCH};
pub(super) fn aggregate_rows(rows: &[SmokeRunRow]) -> Vec<ArmAggregate> {
    ArmId::ALL
        .into_iter()
        .map(|arm| {
            let arm_rows = rows.iter().filter(|row| row.arm == arm).collect::<Vec<_>>();
            let runs = arm_rows.len();
            let tokens_total = arm_rows.iter().map(|row| row.tokens_total).sum::<u32>();
            let mean_accuracy = mean(arm_rows.iter().map(|row| row.accuracy));
            let mean_tool_calls = mean(arm_rows.iter().map(|row| f64::from(row.tool_calls)));
            let mean_wall_clock_s = mean(arm_rows.iter().map(|row| row.wall_clock_s));
            let accuracy_per_class = TaskClass::ALL
                .into_iter()
                .map(|class| {
                    let class_accuracy = mean(
                        arm_rows
                            .iter()
                            .filter(|row| row.class == class)
                            .map(|row| row.accuracy),
                    );
                    (class.as_str().to_owned(), class_accuracy)
                })
                .collect();
            ArmAggregate {
                arm,
                runs,
                mean_accuracy,
                tokens_total,
                mean_tool_calls,
                mean_wall_clock_s,
                accuracy_per_class,
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
    let budget = budget_summary(&rows, settings.full_token_ceiling());
    FullRunReport {
        campaign: CAMPAIGN_ID.to_owned(),
        model: settings.model.clone(),
        provider: settings.provider_lock(),
        run_id: format!("interface-bench-1-full-{}", unix_now()),
        task_count: bundle.full_tasks.len(),
        reps_per_task_arm: settings.full_reps,
        expected_runs: settings.full_run_count(),
        completed_runs: rows.len(),
        scorer_version: SCORER_VERSION.to_owned(),
        browse_judge_prompt_version: BROWSE_JUDGE_PROMPT_VERSION.to_owned(),
        runs: rows,
        aggregates,
        class_arm_table,
        pareto_frontier,
        arm_verdict_claims,
        falsification_verdict,
        budget,
    }
}

pub(super) fn class_arm_table(rows: &[SmokeRunRow], reps: u32) -> Vec<ClassArmSummary> {
    let mut table = Vec::new();
    for class in TaskClass::ALL {
        for arm in ArmId::ALL {
            let class_arm_rows = rows
                .iter()
                .filter(|row| row.class == class && row.arm == arm)
                .collect::<Vec<_>>();
            let accuracy_by_rep = rep_values(&class_arm_rows, reps, |rep_rows| {
                mean(rep_rows.iter().map(|row| row.accuracy))
            });
            let tokens_by_row = class_arm_rows
                .iter()
                .map(|row| f64::from(row.tokens_total))
                .collect::<Vec<_>>();
            table.push(ClassArmSummary {
                class: class.as_str().to_owned(),
                arm,
                runs: class_arm_rows.len(),
                reps,
                accuracy_mean: mean(accuracy_by_rep.iter().copied()),
                accuracy_range: numeric_range(&accuracy_by_rep),
                tokens_mean: mean(tokens_by_row.iter().copied()),
                tokens_range: numeric_range(&tokens_by_row).round() as u32,
                tool_calls_mean: mean(class_arm_rows.iter().map(|row| f64::from(row.tool_calls))),
                wall_clock_mean_s: mean(class_arm_rows.iter().map(|row| row.wall_clock_s)),
            });
        }
    }
    table
}

fn rep_values(
    rows: &[&SmokeRunRow],
    reps: u32,
    value_for_rep: impl Fn(&[&SmokeRunRow]) -> f64,
) -> Vec<f64> {
    (0..reps)
        .map(|rep_index| {
            let rep_rows = rows
                .iter()
                .copied()
                .filter(|row| row.rep_index == rep_index)
                .collect::<Vec<_>>();
            value_for_rep(&rep_rows)
        })
        .collect()
}

fn numeric_range(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    max - min
}

fn pareto_frontier(aggregates: &[ArmAggregate]) -> Vec<ParetoPoint> {
    aggregates
        .iter()
        .map(|candidate| {
            let dominated = aggregates.iter().any(|other| {
                other.arm != candidate.arm
                    && other.mean_accuracy >= candidate.mean_accuracy
                    && other.tokens_total <= candidate.tokens_total
                    && (other.mean_accuracy > candidate.mean_accuracy
                        || other.tokens_total < candidate.tokens_total)
            });
            ParetoPoint {
                arm: candidate.arm,
                mean_accuracy: candidate.mean_accuracy,
                tokens_total: candidate.tokens_total,
                dominated,
            }
        })
        .collect()
}

fn arm_verdict_claims(
    aggregates: &[ArmAggregate],
    pareto_points: &[ParetoPoint],
) -> Vec<ArmVerdictClaim> {
    ArmId::ALL
        .into_iter()
        .filter_map(|arm| {
            let aggregate = aggregates.iter().find(|aggregate| aggregate.arm == arm)?;
            let pareto_dominated = pareto_points
                .iter()
                .find(|point| point.arm == arm)
                .is_some_and(|point| point.dominated);
            let claim_id = format!("{}-{}-verdict", CAMPAIGN_ID, arm.as_str());
            let claim = format!(
                "{} achieved mean accuracy {:.4} with {} total tokens and is {} on the accuracy/token Pareto frontier.",
                arm.as_str(),
                aggregate.mean_accuracy,
                aggregate.tokens_total,
                if pareto_dominated { "dominated" } else { "not dominated" }
            );
            let mut evidence = Vec::with_capacity(2 + aggregate.accuracy_per_class.len());
            evidence.push(format!("runs={}", aggregate.runs));
            evidence.push(format!(
                "meanToolCalls={:.4}",
                aggregate.mean_tool_calls
            ));
            for (class, accuracy) in &aggregate.accuracy_per_class {
                evidence.push(format!("{class}.accuracy={accuracy:.4}"));
            }
            Some(ArmVerdictClaim {
                band: "Proposed".to_owned(),
                arm,
                claim_id,
                claim,
                mean_accuracy: aggregate.mean_accuracy,
                tokens_total: aggregate.tokens_total,
                pareto_dominated,
                evidence,
            })
        })
        .collect()
}

fn falsification_verdict(rows: &[SmokeRunRow]) -> FalsificationVerdict {
    let class = TaskClass::RetrievalQa;
    let fs_rows = rows
        .iter()
        .filter(|row| row.class == class && row.arm == ArmId::Fs)
        .collect::<Vec<_>>();
    let sdk_rows = rows
        .iter()
        .filter(|row| row.class == class && row.arm == ArmId::Sdk)
        .collect::<Vec<_>>();
    let arm_fs_accuracy = mean(fs_rows.iter().map(|row| row.accuracy));
    let arm_sdk_accuracy = mean(sdk_rows.iter().map(|row| row.accuracy));
    let arm_fs_tokens = fs_rows.iter().map(|row| row.tokens_total).sum::<u32>();
    let arm_sdk_tokens = sdk_rows.iter().map(|row| row.tokens_total).sum::<u32>();
    let token_ratio = if arm_sdk_tokens == 0 {
        f64::INFINITY
    } else {
        f64::from(arm_fs_tokens) / f64::from(arm_sdk_tokens)
    };
    let matches_accuracy = arm_fs_accuracy >= arm_sdk_accuracy;
    let within_token_bound = token_ratio <= 1.5;
    FalsificationVerdict {
        band: "Proposed".to_owned(),
        class: class.as_str().to_owned(),
        arm_fs_accuracy,
        arm_sdk_accuracy,
        arm_fs_tokens,
        arm_sdk_tokens,
        token_ratio,
        matches_accuracy,
        within_token_bound,
        falsifies_sdk_necessity_premise: matches_accuracy && within_token_bound,
    }
}

fn budget_summary(rows: &[SmokeRunRow], run_token_ceiling: u32) -> BudgetSummary {
    BudgetSummary {
        per_task_token_ceiling: PER_TASK_TOKEN_CEILING,
        run_token_ceiling,
        tokens_total: rows.iter().map(|row| row.tokens_total).sum(),
        max_row_tokens: rows.iter().map(|row| row.tokens_total).max().unwrap_or(0),
    }
}

fn mean(values: impl Iterator<Item = f64>) -> f64 {
    let mut count = 0_u32;
    let mut sum = 0.0;
    for value in values {
        count += 1;
        sum += value;
    }
    if count == 0 {
        0.0
    } else {
        sum / f64::from(count)
    }
}

pub(super) fn token_burn_extrapolation(
    rows: &[SmokeRunRow],
    full_reps: u32,
) -> TokenBurnExtrapolation {
    let smoke_tokens = rows.iter().map(|row| row.tokens_total).sum::<u32>();
    let observed_runs = rows.len();
    let full_run_equivalent_runs = FULL_TASK_COUNT * ArmId::ALL.len() * full_reps as usize;
    let extrapolated_full_tokens = if observed_runs == 0 {
        0
    } else {
        let projected =
            (u64::from(smoke_tokens) * full_run_equivalent_runs as u64) / observed_runs as u64;
        u32::try_from(projected).unwrap_or(u32::MAX)
    };
    TokenBurnExtrapolation {
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
