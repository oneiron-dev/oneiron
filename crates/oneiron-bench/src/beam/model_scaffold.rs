//! Shared measured answerer scaffold. Gold is only visible after answering.
use super::{
    BeamError, BeamResult,
    judge::AnswerPromptPin,
    llm_host::{HostConfig, ModelPin, ModelSession},
    llm_judge::{JudgeConfig, JudgeItem, score_item},
    load::resolve_manifest_paths,
    model::ArmKind,
    model_usage::sum_costs,
    nuggets::{NuggetJudgment, WedgeBucket},
    report_model::{CostComponentReport, ScoreReport, TokenAccountingSource},
    runner::parse_manifest_json,
    scorer::FixedBeamScorer,
};
use oneiron::policy_model::SecretScanMode;
use oneiron::{CallPurpose, ModelId, Vault};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::Instant,
};
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AnswererArm {
    pub arm: ArmKind,
    pub model: ModelPin,
    pub cheap_chat: bool,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Effort {
    pub name: String,
    pub token_budget: usize,
    pub retrieval_steps: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ModelRunPlan {
    pub retrieval_manifest: PathBuf,
    pub temporal_now: u64,
    pub host: HostConfig,
    pub judge: JudgeConfig,
    pub answer_prompt: String,
    pub routing_prompt: AnswerPromptPin,
    pub answerers: Vec<AnswererArm>,
    pub efforts: Vec<Effort>,
    pub amortized_question_count: usize,
    pub chroma: Option<super::chroma::ChromaConfig>,
    /// Run-card result folders: `<resultsRoot>/<commit>/<set>/<tier>/<split>/`.
    #[serde(default)]
    pub results_root: Option<PathBuf>,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(super) struct AccuracyCostPoint {
    pub arm: ArmKind,
    pub effort: String,
    pub answerer: ModelId,
    pub answerer_params_sha256: String,
    pub accuracy: f64,
    pub latency_us: u64,
    pub cost_usd: f64,
}
#[derive(Debug, Serialize)]
pub(super) struct ModelRow {
    pub ablation: Option<String>,
    pub question_id: String,
    pub arm: ArmKind,
    pub effort: String,
    pub answerer: ModelId,
    pub answer: String,
    pub scoring: ScoreReport,
    pub query_cost: CostComponentReport,
    pub judge_overhead: CostComponentReport,
    /// The reader refused this question's temporal phrase; the answerer got no pack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reader_refusal: Option<String>,
}
#[derive(Debug, Serialize)]
pub(super) struct AblationUnavailable {
    question_id: String,
    effort: String,
    ablation: &'static str,
    reason: &'static str,
}
mod offline;
use offline::{OfflineStages, elapsed_cost, offline_provider_cost, offline_totals};

#[derive(Debug, Serialize)]
pub(super) struct MeasuredReport {
    /// Retrieval-manifest cards, separate from the measured answerer/judge pins.
    pub retrieval_cards: BTreeMap<String, super::model::CompetitorCardConfig>,
    pub scorer: super::report_model::ScorerReport,
    pub execution_contract: &'static str,
    pub answerers: Vec<AnswererArm>,
    pub prices: super::model_usage::PriceTable,
    pub calls: Vec<super::llm_host::ModelCallReceipt>,
    pub citations: super::citations::CitationCorpus,
    pub ablation_rows: Vec<ModelRow>,
    pub ablation_unavailable: Vec<AblationUnavailable>,
    pub temporal_now: u64,
    pub access_factor_observations: Vec<super::ablations::FactorObservation>,
    pub rows: Vec<ModelRow>,
    pub frontier: Vec<AccuracyCostPoint>,
    pub points: Vec<AccuracyCostPoint>,
    pub chat_cost_accuracy_points: Vec<AccuracyCostPoint>,
    pub agency_lift: BTreeMap<String, f64>,
    pub offline_stages: OfflineStages,
    pub offline_stages_amortized: OfflineStages,
    pub offline_total: CostComponentReport,
    pub offline_amortized: CostComponentReport,
    pub amortized_question_count: usize,
    pub offline_cost_usd_per_question: f64,
    pub query_cost_usd_total: f64,
    pub total_cost_usd: f64,
    pub judge_overhead_usd: f64,
    pub ablation_query_cost_usd: f64,
    pub ablation_judge_cost_usd: f64,
    pub answer_prompt: String,
    pub routing_prompt: AnswerPromptPin,
    pub judge: JudgeConfig,
    pub chroma_card_id: Option<String>,
    pub exactness: super::exactness::ExactnessReport,
    pub card: Option<super::card::RunCard>,
    /// Results rows (`oneiron-bench.results-row.v1`): answered approaches x
    /// effort budgets x groups x metrics; the chat arm is the rot row.
    pub results: Vec<super::sweep::ResultsRow>,
}
impl ModelRunPlan {
    pub(super) fn validate(&self) -> BeamResult<()> {
        self.judge.validate(&self.answer_prompt)?;
        if self.routing_prompt.content.trim().is_empty()
            || !self
                .routing_prompt
                .matches_exact_text(&self.routing_prompt.content)
        {
            return Err(refusal("exact routing prompt content and hash required"));
        }
        if self.efforts.is_empty() || self.amortized_question_count == 0 || self.temporal_now == 0 {
            return Err(refusal("efforts and fixed dataset denominator required"));
        }
        let mut names = BTreeSet::new();
        for effort in &self.efforts {
            if !names.insert(&effort.name)
                || effort.name.trim().is_empty()
                || effort.token_budget == 0
                || effort.retrieval_steps == 0
                || effort.retrieval_steps > 32
            {
                return Err(refusal("invalid or duplicate effort"));
            }
        }
        let find = |kind| {
            self.answerers
                .iter()
                .filter(|a| a.arm == kind)
                .collect::<Vec<_>>()
        };
        for kind in [
            ArmKind::Deterministic,
            ArmKind::Agentic,
            ArmKind::BackboneSolo,
            ArmKind::Chat,
        ] {
            if find(kind).len() != 1 {
                return Err(refusal(
                    "each memory run requires deterministic, agentic, backbone_solo and separate chat pins",
                ));
            }
        }
        if self.answerers.len() != 4 + usize::from(self.chroma.is_some())
            || find(ArmKind::VanillaRag).len() != usize::from(self.chroma.is_some())
        {
            return Err(refusal(
                "Chroma arm and its independent endpoint must be configured together",
            ));
        }
        let det = find(ArmKind::Deterministic)[0];
        for kind in [ArmKind::Agentic, ArmKind::BackboneSolo]
            .into_iter()
            .chain(self.chroma.as_ref().map(|_| ArmKind::VanillaRag))
        {
            let other = find(kind)[0];
            if serde_json::to_value(&det.model)? != serde_json::to_value(&other.model)? {
                return Err(refusal(
                    "retrieval arms and backbone-solo must share identical answerer pins and parameters",
                ));
            }
        }
        for row in &self.answerers {
            if row.model.model_id == self.judge.model.model_id {
                return Err(refusal(
                    "self-judged answerer rows cannot enter a measured comparison",
                ));
            }
            if row.cheap_chat != (row.arm == ArmKind::Chat) {
                return Err(refusal("only chat is a separate cheap-model cost point"));
            }
        }
        Ok(())
    }
}
pub(super) fn agency_lift(det: &AccuracyCostPoint, agent: &AccuracyCostPoint) -> BeamResult<f64> {
    if det.arm != ArmKind::Deterministic
        || agent.arm != ArmKind::Agentic
        || det.answerer != agent.answerer
        || det.effort != agent.effort
        || det.answerer_params_sha256 != agent.answerer_params_sha256
    {
        return Err(refusal(
            "agency lift only accepts matching deterministic and agentic rows; never chat",
        ));
    }
    Ok(agent.accuracy - det.accuracy)
}
pub(super) fn pareto(points: &[AccuracyCostPoint]) -> Vec<AccuracyCostPoint> {
    points
        .iter()
        .filter(|p| {
            !points.iter().any(|q| {
                q.accuracy >= p.accuracy
                    && q.cost_usd <= p.cost_usd
                    && (q.accuracy > p.accuracy || q.cost_usd < p.cost_usd)
            })
        })
        .cloned()
        .collect()
}

pub(super) fn run(path: &Path) -> BeamResult<MeasuredReport> {
    run_with(path, &super::sweep::SweepOptions::default())
}
/// `beam measure <plan> [--budget ...] [--results <path>]`: a sweep replaces
/// the plan's efforts with one effort per budget, keeping its retrieval steps.
pub(super) fn run_with(
    path: &Path,
    sweep: &super::sweep::SweepOptions,
) -> BeamResult<MeasuredReport> {
    let mut plan: ModelRunPlan = serde_json::from_slice(&std::fs::read(path)?)?;
    if !sweep.budgets.is_empty() {
        let steps = plan
            .efforts
            .first()
            .map_or(1, |effort| effort.retrieval_steps);
        plan.efforts = sweep
            .budgets
            .iter()
            .map(|budget| Effort {
                name: budget.label(),
                token_budget: budget.tokens().unwrap_or(super::sweep::FULL_BUDGET_TOKENS),
                retrieval_steps: steps,
            })
            .collect();
    }
    plan.validate()?;
    if plan.retrieval_manifest.is_relative() {
        plan.retrieval_manifest = path
            .parent()
            .unwrap_or(Path::new("."))
            .join(&plan.retrieval_manifest);
    }
    if let Some(root) = &mut plan.results_root
        && root.is_relative()
    {
        *root = path.parent().unwrap_or(Path::new(".")).join(&root);
    }
    let models: Vec<_> = plan
        .answerers
        .iter()
        .map(|a| a.model.clone())
        .chain(std::iter::once(plan.judge.model.clone()))
        .collect();
    // Move host configuration only after the full fairness gate has passed.
    let prices = plan.host.prices.clone();
    let host = std::mem::replace(
        &mut plan.host,
        HostConfig {
            endpoint: String::new(),
            api_key_env: None,
            token_budget: 0,
            prices,
        },
    );
    let session = ModelSession::connect(host, &models)?;
    let report = run_with_session_secrets(&plan, &session, sweep.secrets)?;
    if let Some(results) = &sweep.results_path {
        super::sweep::write_rows(results, &report.results)?;
    }
    Ok(report)
}
fn answer(
    session: &ModelSession,
    pin: &ModelPin,
    prompt: &str,
    question: &str,
    context: &str,
) -> BeamResult<(String, CostComponentReport)> {
    // This shape has no arm label, gold, ability, or judge feedback field.
    let input = serde_json::to_string(&serde_json::json!({"question":question,"context":context}))?;
    session.invoke(pin, CallPurpose::AnswerGen, prompt, &input)
}
#[cfg(test)]
pub(super) fn run_with_session(
    plan: &ModelRunPlan,
    session: &ModelSession,
) -> BeamResult<MeasuredReport> {
    run_with_session_secrets(plan, session, None)
}
/// [`run_with_session`] with the `secrets` switch each base vault gets
/// before ingest (None: the vault's own setting).
fn run_with_session_secrets(
    plan: &ModelRunPlan,
    session: &ModelSession,
    secrets: Option<SecretScanMode>,
) -> BeamResult<MeasuredReport> {
    plan.validate()?;
    let mut manifest = parse_manifest_json(&std::fs::read_to_string(&plan.retrieval_manifest)?)?;
    resolve_manifest_paths(&mut manifest, &plan.retrieval_manifest);
    manifest.outputs = None;
    let super::model::DatasetSource::Jsonl {
        path,
        arm_id,
        limit,
        expected_min_results,
        ..
    } = &manifest.dataset
    else {
        return Err(refusal("measured answering requires run.jsonl corpus"));
    };
    // Check the complete selected dataset before any answerer or judge call.
    for entry in super::load::read_run_jsonl_records(path)? {
        if manifest.case_ids.contains(&entry.record.question_id)
            && arm_id
                .as_ref()
                .is_none_or(|arm| arm == &entry.record.arm.id)
        {
            plan.judge.validate_dataset(&entry.record.dataset.id)?;
        }
    }
    if let Some(chroma) = &plan.chroma
        && !manifest
            .competitors
            .iter()
            .any(|row| row.arm == ArmKind::VanillaRag && row.competitor_id == chroma.card_id)
    {
        return Err(refusal(
            "Chroma card id must name the manifest vanilla-RAG competitor",
        ));
    }
    if manifest.case_ids.len() != plan.amortized_question_count {
        return Err(refusal(
            "offline denominator must equal the fixed dataset question count",
        ));
    }
    let chroma_comparable = plan.chroma.as_ref().is_some_and(|chroma| {
        manifest.competitors.iter().any(|row| {
            row.arm == ArmKind::VanillaRag
                && row.competitor_id == chroma.card_id
                && row.card.as_ref().is_some_and(|card| {
                    matches!(
                        card.axes.disposition(),
                        super::comparability::CitationDisposition::Cite
                            | super::comparability::CitationDisposition::CiteWithCaveat
                    )
                })
        })
    });
    let mut ablation_rows = Vec::new();
    let mut groups_by_question: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut secrets_by_question: BTreeMap<String, SecretScanMode> = BTreeMap::new();
    let mut ablation_unavailable = Vec::new();
    let mut access_factor_observations = Vec::new();
    let mut rows = Vec::new();
    let mut offline_ingest = elapsed_cost(0);
    offline_ingest.token_source = TokenAccountingSource::TokenizerCount;
    offline_ingest.tokenizer_id = Some(oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.into());
    let mut offline_index = elapsed_cost(0);
    let mut offline_receipts = Vec::new();
    // One base vault per corpus, one fork per question: a shared corpus is
    // ingested (and its offline cost counted) once, never once per question.
    let selected = super::load::select_run_jsonl_records(&manifest, path, arm_id.as_deref())?;
    let summaries = super::card::RecordSummary::of(&selected);
    let mut exactness = super::exactness::ExactnessReport::default();
    for (corpus_identity, mut group) in super::runner::group_by_corpus(selected) {
        super::load::resolve_corpus_refs(path, &mut group)?;
        let group_ids: BTreeSet<String> = group
            .iter()
            .map(|entry| entry.record.question_id.clone())
            .collect();
        let group_case_ids: Vec<String> = manifest
            .case_ids
            .iter()
            .filter(|id| group_ids.contains(*id))
            .cloned()
            .collect();
        let receipt_start = session.receipts().len();
        let shape = super::load::contract_vault_shape(&manifest, path, &group)?;
        let (base, (loaded, group_exactness)) =
            super::fork::BaseVault::build(corpus_identity, shape.config(), secrets, |vault| {
                let loaded = super::load::load_jsonl_group(
                    vault,
                    &shape,
                    &group_case_ids,
                    path,
                    group,
                    *limit,
                    *expected_min_results,
                )?;
                let report =
                    super::exactness::verify_loaded_corpus(vault, &loaded)?.into_result()?;
                Ok((loaded, report))
            })?;
        exactness.merge(group_exactness);
        offline_ingest.elapsed_us = offline_ingest.elapsed_us.saturating_add(
            loaded
                .offline
                .elapsed_us
                .saturating_sub(loaded.offline_index_build_us),
        );
        offline_index.elapsed_us = offline_index
            .elapsed_us
            .saturating_add(loaded.offline_index_build_us);
        offline_ingest.input_tokens += loaded.offline.input_tokens;
        // Only calls made while loading this corpus belong to offline work.
        // Query and judge calls below are deliberately excluded.
        offline_receipts.extend(session.receipts().into_iter().skip(receipt_start));
        for (id, record) in &loaded.contract_records {
            groups_by_question.insert(id.clone(), super::sweep::groups_for(record));
        }
        for id in &group_case_ids {
            let fork = base.fork(id)?;
            secrets_by_question.insert(id.clone(), fork.secrets);
            let vault = &fork.vault;
            let record = loaded
                .contract_records
                .get(id)
                .ok_or_else(|| refusal("measured answering requires run.jsonl corpus"))?;
            plan.judge.validate_dataset(&record.dataset.id)?;
            let case = loaded
                .cases
                .iter()
                .find(|case| &case.case_id == id)
                .ok_or_else(|| refusal("missing case"))?;
            if plan
                .chroma
                .as_ref()
                .is_some_and(|config| config.retrieval_k != case.limit)
            {
                return Err(refusal("Chroma and deterministic retrieval_k must match"));
            }
            let chroma_started = Instant::now();
            let chroma = plan
                .chroma
                .as_ref()
                .map(|config| super::chroma::ChromaArm::ingest(config, record.corpus_items()))
                .transpose()?;
            if chroma.is_some() {
                offline_index.elapsed_us += chroma_started
                    .elapsed()
                    .as_micros()
                    .min(u128::from(u64::MAX)) as u64;
            }
            let (factor_overrides, observations) =
                super::ablations::access_factors(vault, plan.temporal_now)?;
            access_factor_observations.extend(observations);
            for effort in &plan.efforts {
                for arm in &plan.answerers {
                    let legs: &[Option<&str>] = if arm.arm == ArmKind::Deterministic {
                        &[
                            None,
                            Some("ablation-1:context-budget-off"),
                            Some("ablation-2:access-factor-neutral"),
                        ]
                    } else {
                        &[None]
                    };
                    for &leg in legs {
                        if leg == Some("ablation-2:access-factor-neutral")
                            && factor_overrides.is_empty()
                        {
                            ablation_unavailable.push(AblationUnavailable {
                                question_id: id.clone(),
                                effort: effort.name.clone(),
                                ablation: "ablation-2:access-factor-neutral",
                                reason: "no_claim_rows",
                            });
                            continue;
                        }
                        let mut request_case = case.clone();
                        request_case.token_budget = if leg == Some("ablation-1:context-budget-off")
                        {
                            record
                                .corpus_items()
                                .iter()
                                .map(|row| oneiron::count_context_pack_tokens(&row.text))
                                .sum::<usize>()
                                .saturating_add(8192)
                                .max(effort.token_budget)
                        } else {
                            effort.token_budget
                        };
                        let started = Instant::now();
                        let mut costs = Vec::new();
                        let mut reader_refusal: Option<String> = None;
                        let context = match arm.arm {
                            ArmKind::Deterministic => {
                                let pack = if leg == Some("ablation-2:access-factor-neutral") {
                                    super::arms::run_budgeted_context_pack(
                                        || {
                                            super::arms::configured_context_pack_builder(
                                                vault,
                                                &request_case,
                                            )
                                            .with_temporal_now(
                                                request_case
                                                    .question_time
                                                    .unwrap_or(plan.temporal_now),
                                            )
                                            .with_access_factor_overrides(&factor_overrides)
                                        },
                                        vault,
                                        &request_case,
                                    )
                                } else {
                                    measured_pack(vault, &request_case, plan.temporal_now)
                                };
                                match pack {
                                    Ok(pack) => String::from_utf8(pack.serialized)
                                        .map_err(|_| refusal("invalid pack text"))?,
                                    Err(error) => {
                                        reader_refusal = Some(temporal_refusal_reason(error)?);
                                        String::new()
                                    }
                                }
                            }
                            ArmKind::Agentic => {
                                // The routed query replaces the question, so
                                // the question's embedding no longer applies.
                                request_case.query_vector = None;
                                let mut context = String::new();
                                // Routing calls share one system prompt, so one
                                // provider cache: each new pack edits the cached
                                // prompt and is charged as re-prefill.
                                let mut routing_cache = super::reprefill::PrefixCache::default();
                                for _ in 0..effort.retrieval_steps {
                                    let input = serde_json::json!({"question":case.query,"evidence":context})
                                        .to_string();
                                    let (query, mut cost) = session.invoke(
                                        &arm.model,
                                        CallPurpose::ToolRouting,
                                        &plan.routing_prompt.content,
                                        &input,
                                    )?;
                                    cost.reprefill_tokens = routing_cache
                                        .call(format!("{}\n{input}", plan.routing_prompt.content));
                                    costs.push(cost);
                                    request_case.query = query;
                                    context = match measured_pack(
                                        vault,
                                        &request_case,
                                        plan.temporal_now,
                                    ) {
                                        Ok(pack) => String::from_utf8(pack.serialized)
                                            .map_err(|_| refusal("invalid pack text"))?,
                                        Err(error) => {
                                            reader_refusal = Some(temporal_refusal_reason(error)?);
                                            String::new()
                                        }
                                    };
                                }
                                context
                            }
                            ArmKind::VanillaRag => chroma
                                .as_ref()
                                .ok_or_else(|| refusal("Chroma not configured"))?
                                .retrieve(
                                    loaded
                                        .query_vector_by_case_id
                                        .get(id)
                                        .ok_or_else(|| refusal("Chroma query vector missing"))?,
                                )?,
                            ArmKind::BackboneSolo => String::new(),
                            ArmKind::Chat => {
                                chat_history(record.corpus_items(), path, effort.token_budget)?
                            }
                            _ => return Err(refusal("arm not supported by shared model scaffold")),
                        };
                        let context = bounded_context(&context, request_case.token_budget);
                        let (answer_text, cost) = answer(
                            session,
                            &arm.model,
                            &plan.answer_prompt,
                            &case.query,
                            &context,
                        )?;
                        costs.push(cost);
                        let mut query_cost = sum_costs(&costs)?;
                        query_cost.elapsed_us =
                            started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
                        // Gold is first opened here, after the answer is immutable.
                        let gold = record
                            .gold
                            .as_ref()
                            .ok_or_else(|| refusal("model scoring requires gold"))?;
                        let labels = gold
                            .labels
                            .as_ref()
                            .ok_or_else(|| refusal("gold ability and wedge bucket required"))?;
                        let ability = labels["ability"]
                            .as_str()
                            .ok_or_else(|| refusal("missing ability"))?
                            .to_owned();
                        let wedge_bucket: WedgeBucket =
                            serde_json::from_value(labels["wedge_bucket"].clone())?;
                        let (best_verdict, judge_costs) = judge_aliases(
                            session,
                            plan,
                            &case.query,
                            &answer_text,
                            &gold.answers,
                            &ability,
                            wedge_bucket,
                        )?;
                        let row = ModelRow {
                            ablation: leg.map(str::to_owned),
                            question_id: id.clone(),
                            arm: arm.arm,
                            effort: effort.name.clone(),
                            answerer: arm.model.model_id.clone(),
                            answer: answer_text,
                            // These are alternative answers under one question label,
                            // not independent factual nuggets. Bill every alias vote.
                            scoring: {
                                let (replicate_value, fixed_value) =
                                    best_verdict.ok_or_else(|| refusal("gold aliases required"))?;
                                FixedBeamScorer.score_nuggets(&[NuggetJudgment {
                                    ability,
                                    wedge_bucket,
                                    question_id: Some(id.clone()),
                                    replicate_value,
                                    fixed_value,
                                }])?
                            },
                            query_cost,
                            judge_overhead: sum_costs(&judge_costs)?,
                            reader_refusal,
                        };
                        if leg.is_some() {
                            ablation_rows.push(row);
                        } else {
                            rows.push(row);
                        }
                    }
                }
            }
        }
    }
    // Any unexpected model call during ingestion must not disappear from the cost row.
    if offline_receipts.iter().any(|r| {
        !matches!(
            r.purpose,
            CallPurpose::Extraction | CallPurpose::Consolidation
        )
    }) {
        return Err(refusal("unexpected offline provider call purpose"));
    }
    let stages = OfflineStages {
        ingest: offline_ingest,
        extraction: offline_provider_cost(&offline_receipts, CallPurpose::Extraction, session)?,
        dreamer_consolidation: offline_provider_cost(
            &offline_receipts,
            CallPurpose::Consolidation,
            session,
        )?,
        index_build: offline_index,
    };
    let (offline, offline_amortized, stages_amortized) =
        offline_totals(&stages, plan.amortized_question_count)?;
    let mut points = Vec::new();
    for effort in &plan.efforts {
        for arm in &plan.answerers {
            let selected: Vec<_> = rows
                .iter()
                .filter(|r| r.arm == arm.arm && r.effort == effort.name)
                .collect();
            let n = selected.len() as f64;
            points.push(AccuracyCostPoint {
                arm: arm.arm,
                effort: effort.name.clone(),
                answerer: arm.model.model_id.clone(),
                answerer_params_sha256: model_params_hash(&arm.model)?,
                accuracy: selected
                    .iter()
                    .map(|r| {
                        r.scoring
                            .beam
                            .as_ref()
                            .expect("FixedBeamScorer produces BEAM columns")
                            .aggregate
                            .replicate
                    })
                    .sum::<f64>()
                    / n,
                latency_us: selected
                    .iter()
                    .map(|r| r.query_cost.elapsed_us)
                    .sum::<u64>()
                    / selected.len() as u64,
                cost_usd: selected.iter().map(|r| r.query_cost.cost_usd).sum::<f64>() / n,
            });
        }
    }
    let mut lift = BTreeMap::new();
    for effort in &plan.efforts {
        let det = points
            .iter()
            .find(|p| p.effort == effort.name && p.arm == ArmKind::Deterministic)
            .expect("validated plan includes a deterministic arm for every effort");
        let agent = points
            .iter()
            .find(|p| p.effort == effort.name && p.arm == ArmKind::Agentic)
            .expect("validated plan includes an agentic arm for every effort");
        lift.insert(effort.name.clone(), agency_lift(det, agent)?);
    }
    let query_total = rows.iter().map(|r| r.query_cost.cost_usd).sum();
    let judge_total = rows.iter().map(|r| r.judge_overhead.cost_usd).sum();
    let ablation_query_cost_usd = ablation_rows
        .iter()
        .map(|r| r.query_cost.cost_usd)
        .sum::<f64>();
    let ablation_judge_cost_usd = ablation_rows
        .iter()
        .map(|r| r.judge_overhead.cost_usd)
        .sum::<f64>();
    let scorer = super::report_model::ScorerReport {
        judge_instruction_sha256: Some(plan.judge.instruction.sha256.clone()),
        ..super::scorer::BeamScorer::metadata(&FixedBeamScorer)
    };
    let mut card = measured_card(MeasuredCardInputs {
        plan,
        manifest: &manifest,
        run_jsonl: path,
        summaries: &summaries,
        scorer: &scorer,
        exactness: &exactness,
        rows: &rows,
        offline_amortized: &offline_amortized,
    })?;
    card.pins.secrets = super::sweep::secrets_pins(secrets_by_question.values().copied());
    let results = measured_results(
        plan,
        session,
        &rows,
        &groups_by_question,
        &secrets_by_question,
        &card,
        &manifest.run_id,
    );
    let report = MeasuredReport {
        results,
        exactness,
        card: Some(card),
        retrieval_cards: manifest
            .competitors
            .iter()
            .map(|row| {
                (
                    row.competitor_id.clone(),
                    row.card.clone().expect("validated competitor card"),
                )
            })
            .collect(),
        scorer,
        execution_contract: "response_format=text; tools=none; provider_options=none",
        ablation_rows,
        ablation_unavailable,
        temporal_now: plan.temporal_now,
        access_factor_observations,
        citations: super::citations::corpus()?,
        answerers: plan.answerers.clone(),
        prices: session.prices.clone(),
        calls: session.receipts(),
        frontier: pareto(
            &points
                .iter()
                .filter(|p| {
                    p.arm != ArmKind::Chat && (p.arm != ArmKind::VanillaRag || chroma_comparable)
                })
                .cloned()
                .collect::<Vec<_>>(),
        ),
        chat_cost_accuracy_points: points
            .iter()
            .filter(|p| p.arm == ArmKind::Chat)
            .cloned()
            .collect(),
        points,
        rows,
        chroma_card_id: plan.chroma.as_ref().map(|c| c.card_id.clone()),
        agency_lift: lift,
        offline_stages: stages,
        offline_stages_amortized: stages_amortized,
        offline_total: offline.clone(),
        offline_amortized,
        amortized_question_count: plan.amortized_question_count,
        offline_cost_usd_per_question: offline.cost_usd / plan.amortized_question_count as f64,
        query_cost_usd_total: query_total,
        total_cost_usd: offline.cost_usd + query_total,
        ablation_query_cost_usd,
        ablation_judge_cost_usd,
        judge_overhead_usd: judge_total,
        answer_prompt: plan.answer_prompt.clone(),
        routing_prompt: plan.routing_prompt.clone(),
        judge: plan.judge.clone(),
    };
    if let Some(card) = &report.card
        && let Some(dir) = &card.result_dir
    {
        super::card::write_result_folder(
            dir,
            card,
            &report,
            &report.exactness,
            None,
            &report.results,
        )?;
    }
    Ok(report)
}
struct MeasuredCardInputs<'a> {
    plan: &'a ModelRunPlan,
    manifest: &'a super::model::RunManifest,
    run_jsonl: &'a Path,
    summaries: &'a [super::card::RecordSummary],
    scorer: &'a super::report_model::ScorerReport,
    exactness: &'a super::exactness::ExactnessReport,
    rows: &'a [ModelRow],
    offline_amortized: &'a CostComponentReport,
}
/// The measured run's card: the live judge pin and every answerer pin.
fn measured_card(inputs: MeasuredCardInputs<'_>) -> BeamResult<super::card::RunCard> {
    let MeasuredCardInputs {
        plan,
        manifest,
        run_jsonl,
        summaries,
        scorer,
        exactness,
        rows,
        offline_amortized,
    } = inputs;
    let mut card = super::card::build_card(super::card::CardInputs {
        manifest,
        run_jsonl,
        records: summaries,
        scorer,
        exactness,
        judges: vec![super::card::CardJudge {
            role: "answer-judge".to_owned(),
            judge_pin: plan.judge.model.model_id.as_str().to_owned(),
            vote_count: plan.judge.card.vote_count,
            prompt_sha256: Some(plan.judge.instruction.sha256.clone()),
        }],
        answerers: plan
            .answerers
            .iter()
            .map(|arm| super::card::CardAnswerer {
                arm: arm.arm.as_str().to_owned(),
                model_pin: arm.model.model_id.as_str().to_owned(),
                prompt_sha256: super::load::sha256_hex(plan.answer_prompt.as_bytes()),
            })
            .collect(),
        cost: measured_arm_costs(rows, offline_amortized),
        budgets: plan
            .efforts
            .iter()
            .map(|effort| effort.name.clone())
            .collect(),
        references: if plan.answerers.iter().any(|arm| arm.arm == ArmKind::Chat) {
            vec![super::sweep::CONTEXT_ROT]
        } else {
            Vec::new()
        },
    })?;
    if let Some(root) = &plan.results_root {
        card.result_dir = Some(super::card::result_dir(root, &card));
    }
    Ok(card)
}
/// Results rows for the measured run. A budget is the effort's token budget
/// (`full` reads as no budget); the chat arm is the full-context reader, the
/// rot row. Costs are provider usage priced by the plan's price table.
fn measured_results(
    plan: &ModelRunPlan,
    session: &ModelSession,
    rows: &[ModelRow],
    groups_by_question: &BTreeMap<String, Vec<String>>,
    secrets_by_question: &BTreeMap<String, SecretScanMode>,
    card: &super::card::RunCard,
    run_id: &str,
) -> Vec<super::sweep::ResultsRow> {
    use super::sweep::{Observation, PriceStamp};
    let beam_columns = plan.judge.benchmark == super::llm_judge::JudgeBenchmark::Beam;
    let observations: Vec<Observation> = rows
        .iter()
        .map(|row| {
            let effort = plan.efforts.iter().find(|effort| effort.name == row.effort);
            let budget = effort
                .filter(|effort| effort.name != "full")
                .map(|effort| effort.token_budget);
            let price = session
                .prices
                .models
                .get(&row.answerer)
                .map(|prices| PriceStamp {
                    as_of: session.prices.revision.clone(),
                    source: session.prices.source.clone(),
                    model: row.answerer.as_str().to_owned(),
                    input_per_million: prices.input_per_million,
                    output_per_million: prices.output_per_million,
                });
            let approach = match row.arm {
                ArmKind::Deterministic => "oneiron-deterministic",
                ArmKind::Agentic => "oneiron-agentic",
                ArmKind::VanillaRag => "vanilla-rag",
                ArmKind::Chat => super::sweep::FULL_CONTEXT_APPROACH,
                ArmKind::BackboneSolo => "backbone-solo",
                ArmKind::PprVadSweep => "ppr-vad-sweep",
            };
            Observation {
                approach: approach.to_owned(),
                approach_kind: "answered",
                reader_model: Some(row.answerer.as_str().to_owned()),
                budget,
                budget_label: row.effort.clone(),
                rot: row.arm == ArmKind::Chat,
                groups: groups_by_question
                    .get(&row.question_id)
                    .cloned()
                    .unwrap_or_else(|| vec!["all".to_owned()]),
                metrics: super::sweep::judged_metrics(&row.scoring, beam_columns),
                refused: row.reader_refusal.is_some(),
                prompt_tokens: row.query_cost.input_tokens as f64,
                reprefill_tokens: row.query_cost.reprefill_tokens as f64,
                output_tokens: row.query_cost.output_tokens as f64,
                judge_tokens: (row.judge_overhead.input_tokens + row.judge_overhead.output_tokens)
                    as f64,
                usd: Some(row.query_cost.cost_usd),
                price,
                latency_ms: Some(row.query_cost.elapsed_us as f64 / 1000.0),
                secrets: secrets_by_question.get(&row.question_id).copied(),
            }
        })
        .collect();
    super::sweep::aggregate(
        &super::sweep::RowContext {
            producer: "oneiron-bench beam measure".to_owned(),
            run_id: run_id.to_owned(),
            commit: card.identity.commit.clone(),
            set: card.identity.set.clone(),
            set_revision: card.identity.dataset_revision.clone(),
            tier: card.identity.tier.clone(),
            split: card.identity.split.label.clone(),
        },
        &observations,
    )
}
/// The best (replicate, fixed) verdict over aliases, and every judge call's cost.
type AliasVerdicts = (Option<(f64, f64)>, Vec<CostComponentReport>);
/// Judges one answer against every gold alias. Returns the best verdict per
/// pass, (replicate, fixed), and every call's cost: each alias is billed.
fn judge_aliases(
    session: &ModelSession,
    plan: &ModelRunPlan,
    question: &str,
    answer_text: &str,
    aliases: &[String],
    ability: &str,
    wedge_bucket: WedgeBucket,
) -> BeamResult<AliasVerdicts> {
    let mut best_verdict: Option<(f64, f64)> = None;
    let mut judge_costs = Vec::new();
    for gold_answer in aliases {
        let judged = score_item(
            session,
            &plan.judge,
            &plan.answer_prompt,
            &JudgeItem {
                question: question.to_owned(),
                candidate_answer: answer_text.to_owned(),
                gold_answer: gold_answer.clone(),
                ability: ability.to_owned(),
                wedge_bucket,
            },
        )?;
        let replicate = judged.replicate_verdict.unwrap_or(judged.verdict);
        best_verdict = Some(best_verdict.map_or(
            (replicate, judged.verdict),
            |(best_replicate, best_fixed)| {
                (
                    best_replicate.max(replicate),
                    best_fixed.max(judged.verdict),
                )
            },
        ));
        judge_costs.push(judged.judge_cost);
    }
    Ok((best_verdict, judge_costs))
}
/// Per arm and effort: the measured cost columns of the card.
fn measured_arm_costs(
    rows: &[ModelRow],
    offline_amortized: &CostComponentReport,
) -> Vec<super::card::CardArmCost> {
    let mut groups: BTreeMap<String, Vec<&ModelRow>> = BTreeMap::new();
    for row in rows {
        groups
            .entry(format!("{}/{}", row.arm.as_str(), row.effort))
            .or_default()
            .push(row);
    }
    groups
        .into_iter()
        .map(|(arm, rows)| {
            let elapsed: Vec<u64> = rows.iter().map(|r| r.query_cost.elapsed_us).collect();
            super::card::CardArmCost {
                arm,
                questions: rows.len(),
                refused: rows.iter().filter(|r| r.reader_refusal.is_some()).count(),
                pack_tokens: None,
                query_input_tokens: rows.iter().map(|r| r.query_cost.input_tokens).sum(),
                query_output_tokens: rows.iter().map(|r| r.query_cost.output_tokens).sum(),
                reprefill_tokens: rows.iter().map(|r| r.query_cost.reprefill_tokens).sum(),
                judge_input_tokens: rows.iter().map(|r| r.judge_overhead.input_tokens).sum(),
                offline_input_tokens_amortized: offline_amortized.input_tokens * rows.len() as u64,
                elapsed_us_p50: super::card::percentile(&elapsed, 50),
                elapsed_us_p95: super::card::percentile(&elapsed, 95),
                cost_usd: rows
                    .iter()
                    .map(|r| r.query_cost.cost_usd + r.judge_overhead.cost_usd)
                    .sum(),
            }
        })
        .collect()
}
fn chat_history(
    corpus: &[super::report_model::ContractCorpusRecord],
    path: &Path,
    budget: usize,
) -> BeamResult<String> {
    let mut ordered = corpus
        .iter()
        .map(|item| {
            // load_dataset already validates timestamps with their source line.
            super::corpus_clock::occurred_at(item, path, 0).map(|at| (at, item))
        })
        .collect::<BeamResult<Vec<_>>>()?;
    ordered.sort_by_key(|(at, _)| *at);
    let mut history = String::new();
    for (_, item) in ordered.into_iter().rev() {
        let text = format!("{}\n{history}", item.text);
        if oneiron::count_context_pack_tokens(&text) > budget {
            break;
        }
        history = text;
    }
    Ok(history)
}

fn bounded_context(text: &str, budget: usize) -> String {
    if oneiron::count_context_pack_tokens(text) <= budget {
        return text.to_owned();
    }
    let boundaries: Vec<usize> = text
        .char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(text.len()))
        .collect();
    let (mut lo, mut hi) = (0, boundaries.len() - 1);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if oneiron::count_context_pack_tokens(&text[..boundaries[mid]]) <= budget {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    text[..boundaries[lo]].to_owned()
}
/// The reason of a temporal-reader refusal; every other error passes through.
fn temporal_refusal_reason(error: BeamError) -> BeamResult<String> {
    match super::arms::temporal_reader_refusal(ArmKind::Deterministic, error)?.outcome {
        super::report_model::ArmOutcome::NotReady { not_ready } => Ok(not_ready.reason),
        _ => Err(refusal("temporal refusal produced no reason")),
    }
}
fn refusal(reason: &str) -> BeamError {
    BeamError::Comparability {
        reason: reason.into(),
    }
}
#[cfg(test)]
mod tests;

fn model_params_hash(pin: &ModelPin) -> BeamResult<String> {
    use sha2::{Digest, Sha256};
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(pin)?)))
}

fn measured_pack(
    vault: &Vault,
    case: &super::model::FixtureCase,
    now: u64,
) -> BeamResult<super::arms::BudgetedContextPack> {
    super::arms::run_budgeted_context_pack(
        || {
            // A contract v2 question_time is the reader's "now" and wins.
            super::arms::configured_context_pack_builder(vault, case)
                .with_temporal_now(case.question_time.unwrap_or(now))
        },
        vault,
        case,
    )
}
