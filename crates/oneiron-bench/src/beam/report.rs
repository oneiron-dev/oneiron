//! Report assembly and serialization.

use super::arms::{
    ActiveSerializedContextPackSection, BudgetedContextPack, SerializedContextPackIds,
    SerializedContextPackSection,
};
use super::model::{CompetitorConfig, FixtureCase, FixtureClass};
use super::report_model::{
    AbilityKind, AbilityScoreReport, ArmOutcome, ArmReport, ContextEntityReport, ContextPackReport,
    CostBreakdownReport, CostComponentInput, CostComponentReport, EmptyContextReport,
    NotReadyState, PackItemTokenReport, PackSectionTokenReport, PackStatsReport,
    TokenAccountingSource,
};
use super::util::{accounting_reasons, empty_reason_label, pack_format_label, signal_label};
use super::{BEAM_CONTEXT_PACK_FORMAT, COST_USD_SCALE, MAX_NORMALIZABLE_COST_USD};
use oneiron::ContextPack;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;

pub(super) fn context_pack_report(
    pack: &BudgetedContextPack,
    case: &FixtureCase,
) -> ContextPackReport {
    let results = context_entity_reports_for_ids(&pack.raw.results, &pack.serialized_ids.results);
    let neighbors =
        context_entity_reports_for_ids(&pack.raw.neighbors, &pack.serialized_ids.neighbors);
    let budgeted_text_by_entity_id =
        budgeted_text_by_entity_id(&pack.raw, &pack.serialized_ids.text_by_id);
    let result_count = results.len();
    let neighbor_count = neighbors.len();
    let stats = &pack.serialized_stats;
    let items_truncated = stats.items_truncated.count;
    let items_dropped = stats.items_dropped.count;
    let items_truncated_reasons =
        accounting_reasons(items_truncated, stats.items_truncated.reason.as_str());
    let items_dropped_reasons =
        accounting_reasons(items_dropped, stats.items_dropped.reason.as_str());

    ContextPackReport {
        token_budget: case.token_budget,
        limit: case.limit,
        serialized_format: pack_format_label(BEAM_CONTEXT_PACK_FORMAT).to_owned(),
        serialized_bytes: pack.serialized.len(),
        serialized_tokens: pack.serialized_tokens,
        tokenizer_id: stats.tokens.tokenizer_id.clone(),
        query_cost: query_cost_report(case, pack),
        result_count,
        neighbor_count,
        results,
        neighbors,
        stats: PackStatsReport {
            candidates_considered: stats.candidates_considered,
            signals_used: stats
                .signals_used
                .iter()
                .copied()
                .map(signal_label)
                .map(str::to_owned)
                .collect(),
            query_time_us: stats.query_time_us,
            entities_hydrated: result_count,
            neighbors_hydrated: neighbor_count,
            cosine_ghosts_dampened: stats.cosine_ghosts_dampened,
            claims_suppressed: stats.claims_suppressed,
            tokenizer_id: stats.tokens.tokenizer_id.clone(),
            total_tokens: stats.tokens.total_tokens,
            section_tokens: stats
                .tokens
                .sections
                .iter()
                .map(|section| PackSectionTokenReport {
                    section: section.section.clone(),
                    tokens: section.tokens,
                })
                .collect(),
            item_tokens: stats
                .tokens
                .items
                .iter()
                .map(|item| PackItemTokenReport {
                    section: item.section.clone(),
                    id: item.id.clone(),
                    entity_type: item.entity_type,
                    tokens: item.tokens,
                })
                .collect(),
            items_truncated,
            items_truncated_reasons,
            items_dropped,
            items_dropped_reasons,
        },
        empty: pack.raw.empty.as_ref().map(|empty| EmptyContextReport {
            reason: empty_reason_label(empty.reason).to_owned(),
            total_in_scope: empty.total_in_scope,
            hint: empty.hint.clone(),
        }),
        temporal_result_ids: pack.temporal_result_ids.clone(),
        budgeted_text_by_entity_id,
    }
}
pub(super) fn cost_breakdown(case: &FixtureCase, arm: &ArmReport) -> CostBreakdownReport {
    let query = match &arm.outcome {
        ArmOutcome::Completed { context_pack } => context_pack.query_cost.clone(),
        ArmOutcome::NotReady { .. } | ArmOutcome::RetrievalSweep { .. } => not_applicable_cost(),
    };
    let offline = cost_component_from_input(&case.offline_amortized_cost);
    let judge = if matches!(arm.outcome, ArmOutcome::RetrievalSweep { .. }) {
        not_applicable_cost()
    } else {
        fixed_scorer_judge_cost()
    };
    let total_cost_usd = normalized_cost_usd(query.cost_usd + offline.cost_usd + judge.cost_usd);

    CostBreakdownReport {
        query,
        offline,
        judge,
        total_cost_usd,
    }
}
pub(super) fn query_cost_report(
    case: &FixtureCase,
    pack: &BudgetedContextPack,
) -> CostComponentReport {
    CostComponentReport {
        token_source: TokenAccountingSource::TokenizerCount,
        tokenizer_id: Some(pack.serialized_stats.tokens.tokenizer_id.clone()),
        input_tokens: oneiron::count_context_pack_tokens(&case.query) as u64,
        output_tokens: pack.serialized_tokens,
        target_tokens: case.token_budget as u64,
        elapsed_us: pack.serialized_elapsed_us,
        cost_usd: 0.0,
    }
}
pub(super) fn fixed_scorer_judge_cost() -> CostComponentReport {
    CostComponentReport {
        token_source: TokenAccountingSource::FixtureDeclaredZero,
        tokenizer_id: None,
        input_tokens: 0,
        output_tokens: 0,
        target_tokens: 0,
        elapsed_us: 0,
        cost_usd: 0.0,
    }
}
pub(super) fn cost_component_from_input(input: &CostComponentInput) -> CostComponentReport {
    CostComponentReport {
        token_source: input.token_source,
        tokenizer_id: None,
        input_tokens: input.input_tokens,
        output_tokens: input.output_tokens,
        target_tokens: input.target_tokens,
        elapsed_us: input.elapsed_us,
        cost_usd: normalized_cost_usd(input.cost_usd),
    }
}
pub(super) fn not_applicable_cost() -> CostComponentReport {
    CostComponentReport {
        token_source: TokenAccountingSource::NotApplicable,
        tokenizer_id: None,
        input_tokens: 0,
        output_tokens: 0,
        target_tokens: 0,
        elapsed_us: 0,
        cost_usd: 0.0,
    }
}
pub(super) fn validate_cost_component(
    owner: &str,
    input: &CostComponentInput,
) -> Result<(), String> {
    if input.token_source == TokenAccountingSource::CharCountEstimate {
        return Err(format!(
            "{owner} must not use char_count_estimate token accounting"
        ));
    }
    if !input.cost_usd.is_finite() || input.cost_usd < 0.0 {
        return Err(format!("{owner}.costUsd must be non-negative and finite"));
    }
    if input.cost_usd > MAX_NORMALIZABLE_COST_USD {
        return Err(format!("{owner}.costUsd is too large to normalize safely"));
    }
    if matches!(
        input.token_source,
        TokenAccountingSource::FixtureDeclaredZero | TokenAccountingSource::NotApplicable
    ) && !cost_component_metrics_are_zero(input)
    {
        return Err(format!(
            "{owner} with {:?} token accounting must declare zero tokens, elapsed time, and cost",
            input.token_source
        ));
    }
    Ok(())
}
pub(super) fn cost_component_metrics_are_zero(input: &CostComponentInput) -> bool {
    input.input_tokens == 0
        && input.output_tokens == 0
        && input.target_tokens == 0
        && input.elapsed_us == 0
        && input.cost_usd == 0.0
}
pub(super) fn normalized_cost_usd(cost: f64) -> f64 {
    if cost > MAX_NORMALIZABLE_COST_USD {
        cost
    } else {
        (cost * COST_USD_SCALE).round() / COST_USD_SCALE
    }
}
pub(super) fn completed_ability_scores(
    case: &FixtureCase,
    context_pack: &ContextPackReport,
) -> Vec<AbilityScoreReport> {
    if case.fixture_class.expects_abstention() {
        return abstention_ability_scores(case, context_pack);
    }

    let coverage = if case.expected_min_results == 0 {
        1.0
    } else {
        (context_pack.result_count as f32 / case.expected_min_results as f32).min(1.0)
    };
    let budget_passed =
        context_pack.stats.items_dropped == 0 && context_pack.stats.items_truncated == 0;
    let budget_score = if budget_passed { 1.0 } else { 0.0 };
    let budget_detail = budget_discipline_detail(case, context_pack);

    vec![
        AbilityScoreReport {
            ability: AbilityKind::RetrievalCoverage,
            score: Some(coverage),
            passed: Some(coverage >= 1.0),
            detail: format!(
                "{} serialized results for expected minimum {}",
                context_pack.result_count, case.expected_min_results
            ),
        },
        AbilityScoreReport {
            ability: AbilityKind::BudgetDiscipline,
            score: Some(budget_score),
            passed: Some(budget_passed),
            detail: budget_detail,
        },
        AbilityScoreReport {
            ability: AbilityKind::Readiness,
            score: Some(1.0),
            passed: Some(true),
            detail: "arm completed".to_owned(),
        },
    ]
}
pub(super) fn abstention_ability_scores(
    case: &FixtureCase,
    context_pack: &ContextPackReport,
) -> Vec<AbilityScoreReport> {
    let (gate_passed, gate_detail) = abstention_gate_status(case, context_pack);

    vec![
        AbilityScoreReport {
            ability: AbilityKind::AbstentionGate,
            score: None,
            passed: Some(gate_passed),
            detail: format!("{}: {gate_detail}", case.fixture_class.gate_label()),
        },
        AbilityScoreReport {
            ability: AbilityKind::NoRegressionGate,
            score: None,
            passed: Some(true),
            detail: "numeric score suppressed before publication".to_owned(),
        },
        AbilityScoreReport {
            ability: AbilityKind::Readiness,
            score: None,
            passed: Some(true),
            detail: "arm completed and abstained by fixture safety gate".to_owned(),
        },
    ]
}
pub(super) fn abstention_gate_status(
    case: &FixtureCase,
    context_pack: &ContextPackReport,
) -> (bool, String) {
    match case.fixture_class {
        FixtureClass::EvidenceSupported => (
            false,
            "evidence_supported cases must use scored BEAM abilities".to_owned(),
        ),
        FixtureClass::EmptyMemory => {
            let Some(empty) = context_pack.empty.as_ref() else {
                return (
                    false,
                    format!(
                        "empty vault had {} serialized results but no empty report",
                        context_pack.result_count
                    ),
                );
            };
            let passed = context_pack.result_count == 0
                && empty.total_in_scope == 0
                && empty.reason == "no_data";
            (
                passed,
                format!(
                    "empty vault had {} serialized results, {} in-scope records, and empty reason={}",
                    context_pack.result_count, empty.total_in_scope, empty.reason
                ),
            )
        }
        FixtureClass::LowConfidence => {
            let (empty_reason, total_in_scope) =
                context_pack.empty.as_ref().map_or(("none", 0), |empty| {
                    (empty.reason.as_str(), empty.total_in_scope)
                });
            let passed = context_pack.result_count == 0
                && empty_reason == "below_threshold"
                && total_in_scope > 0;
            (
                passed,
                format!(
                    "low-confidence query produced {} serialized results with {total_in_scope} in-scope records and empty reason={empty_reason}",
                    context_pack.result_count,
                ),
            )
        }
        FixtureClass::AdversarialContradiction => {
            let surfaced = context_pack_result_ids(context_pack);
            let required_ids = case
                .opposing_evidence
                .as_ref()
                .map(|evidence| evidence.record_ids.as_slice())
                .unwrap_or_default();
            let matched = required_ids
                .iter()
                .filter(|id| surfaced.contains(id.as_str()))
                .count();
            let passed = !required_ids.is_empty() && matched == required_ids.len();
            (
                passed,
                format!(
                    "contradictory fixture evidence surfaced {matched}/{} required opposing records",
                    required_ids.len()
                ),
            )
        }
        FixtureClass::TemporalStaleness => {
            let surfaced = context_pack_result_ids(context_pack);
            let used_temporal_signal = context_pack
                .stats
                .signals_used
                .iter()
                .any(|signal| signal == "temporal");
            let matched = case
                .temporal_evidence_ids
                .iter()
                .filter(|id| {
                    surfaced.contains(id.as_str())
                        && context_pack.temporal_result_ids.contains(id.as_str())
                })
                .count();
            let passed = !case.temporal_evidence_ids.is_empty()
                && used_temporal_signal
                && matched == case.temporal_evidence_ids.len();
            (
                passed,
                format!(
                    "staleness fixture surfaced {matched}/{} required temporal records with temporal signal={used_temporal_signal}",
                    case.temporal_evidence_ids.len()
                ),
            )
        }
    }
}
pub(super) fn context_pack_result_ids(context_pack: &ContextPackReport) -> BTreeSet<&str> {
    context_pack
        .results
        .iter()
        .map(|entity| entity.id.as_str())
        .collect()
}
pub(super) fn budget_discipline_detail(
    case: &FixtureCase,
    context_pack: &ContextPackReport,
) -> String {
    format!(
        "{} serialized items dropped [{}], {} truncated [{}] under {} token budget ({} bytes emitted)",
        context_pack.stats.items_dropped,
        accounting_reason_detail(&context_pack.stats.items_dropped_reasons),
        context_pack.stats.items_truncated,
        accounting_reason_detail(&context_pack.stats.items_truncated_reasons),
        case.token_budget,
        context_pack.serialized_bytes
    )
}
pub(super) fn accounting_reason_detail(reasons: &[String]) -> String {
    if reasons.is_empty() {
        "none".to_owned()
    } else {
        reasons.join(", ")
    }
}
pub(super) fn not_ready_ability_scores(
    competitor: &CompetitorConfig,
    not_ready: &NotReadyState,
) -> Vec<AbilityScoreReport> {
    [
        AbilityKind::RetrievalCoverage,
        AbilityKind::BudgetDiscipline,
        AbilityKind::Readiness,
    ]
    .into_iter()
    .map(|ability| AbilityScoreReport {
        ability,
        score: None,
        passed: None,
        detail: format!(
            "{} could not be scored for {}: {}",
            competitor.competitor_id,
            ability.as_str(),
            not_ready.reason
        ),
    })
    .collect()
}
pub(super) fn mean_score(abilities: &[AbilityScoreReport]) -> Option<f32> {
    let (total, count) = abilities
        .iter()
        .filter_map(|ability| ability.score)
        .fold((0.0_f32, 0_usize), |(total, count), score| {
            (total + score, count + 1)
        });
    if count == 0 {
        None
    } else {
        Some(total / count as f32)
    }
}
pub(super) fn context_entity_reports_for_ids(
    entities: &[oneiron::ContextEntity],
    serialized_ids: &HashSet<String>,
) -> Vec<ContextEntityReport> {
    entities
        .iter()
        .filter(|entity| serialized_ids.contains(&serialized_context_entity_id(entity)))
        .map(context_entity_report)
        .collect()
}
pub(super) fn context_entity_report(entity: &oneiron::ContextEntity) -> ContextEntityReport {
    ContextEntityReport {
        id: entity.id.to_hex(),
        short_id: entity.short_id.clone(),
        entity_type: entity.entity_type,
        score: entity.score,
    }
}
pub(super) fn serialized_context_pack_ids(serialized: &str) -> SerializedContextPackIds {
    let mut ids = SerializedContextPackIds::default();
    let mut active_section: Option<ActiveSerializedContextPackSection> = None;

    for line in serialized.lines() {
        let trimmed_start = line.trim_start();
        let trimmed = trimmed_start.trim_end();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - trimmed_start.len();

        if indent == 0 {
            active_section = match trimmed {
                "results:" => Some(ActiveSerializedContextPackSection {
                    section: SerializedContextPackSection::Results,
                    section_indent: indent,
                    group_indent: None,
                    row_indent: None,
                    row_id: None,
                }),
                "neighbors:" => Some(ActiveSerializedContextPackSection {
                    section: SerializedContextPackSection::Neighbors,
                    section_indent: indent,
                    group_indent: None,
                    row_indent: None,
                    row_id: None,
                }),
                _ => None,
            };
            continue;
        }

        let Some(section) = active_section.as_mut() else {
            continue;
        };
        if indent <= section.section_indent {
            active_section = None;
            continue;
        }
        if section
            .group_indent
            .is_some_and(|group_indent| indent <= group_indent)
        {
            section.group_indent = None;
            section.row_indent = None;
            section.row_id = None;
        }

        if indent == section.section_indent + 2
            && trimmed.ends_with(':')
            && !trimmed.starts_with("- ")
        {
            section.group_indent = Some(indent);
            section.row_indent = None;
            section.row_id = None;
            continue;
        }

        let expected_row_indent = section
            .group_indent
            .map_or(section.section_indent + 2, |group_indent| group_indent + 2);

        if indent == expected_row_indent
            && let Some(raw_id) = trimmed.strip_prefix("- id: ")
        {
            let id = generated_yaml_scalar(raw_id);
            match section.section {
                SerializedContextPackSection::Results => {
                    ids.results.insert(id.clone());
                }
                SerializedContextPackSection::Neighbors => {
                    ids.neighbors.insert(id.clone());
                }
            }
            section.row_indent = Some(indent);
            section.row_id = Some(id);
            continue;
        }

        if let (Some(row_indent), Some(row_id)) = (section.row_indent, section.row_id.as_ref())
            && indent > row_indent
            && let Some(raw_text) = trimmed.strip_prefix("txt: ")
        {
            ids.text_by_id
                .insert(row_id.clone(), generated_yaml_scalar(raw_text));
        }
    }

    ids
}
pub(super) fn budgeted_text_by_entity_id(
    pack: &ContextPack,
    text_by_serialized_id: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    pack.results
        .iter()
        .chain(pack.neighbors.iter())
        .filter_map(|entity| {
            let serialized_id = serialized_context_entity_id(entity);
            text_by_serialized_id
                .get(&serialized_id)
                .map(|text| (entity.id.to_hex(), text.clone()))
        })
        .collect()
}
pub(super) fn generated_yaml_scalar(raw: &str) -> String {
    let trimmed = raw.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|quoted| quoted.strip_suffix('"'))
        .unwrap_or(trimmed)
        .replace("\\\"", "\"")
        .replace("\\\\", "\\")
}
pub(super) fn serialized_context_entity_id(entity: &oneiron::ContextEntity) -> String {
    let short_id = if entity.short_id.is_empty() {
        entity.id.to_hex()
    } else {
        entity.short_id.clone()
    };
    format!("{}:{:02x}", short_id, entity.content_hash)
}
