//! Shared measured answerer scaffold. Gold is only visible after answering.
use super::{
    BeamError, BeamResult,
    llm_host::{HostConfig, ModelPin, ModelSession},
    llm_judge::{JudgeConfig, JudgeItem, score_item},
    load::{load_dataset, resolve_manifest_paths},
    model::ArmKind,
    model_usage::sum_costs,
    nuggets::{NuggetJudgment, WedgeBucket},
    report_model::{CostComponentReport, ScoreReport, TokenAccountingSource},
    runner::parse_manifest_json,
    scorer::FixedBeamScorer,
    util::beam_vault_config,
};
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
    pub answerers: Vec<AnswererArm>,
    pub efforts: Vec<Effort>,
    pub amortized_question_count: usize,
    pub chroma: Option<super::chroma::ChromaConfig>,
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
}
#[derive(Debug, Serialize)]
pub(super) struct AblationUnavailable {
    question_id: String,
    effort: String,
    ablation: &'static str,
    reason: &'static str,
}
#[derive(Debug, Serialize)]
pub(super) struct MeasuredReport {
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
    pub offline_total: CostComponentReport,
    pub amortized_question_count: usize,
    pub offline_cost_usd_per_question: f64,
    pub query_cost_usd_total: f64,
    pub total_cost_usd: f64,
    pub judge_overhead_usd: f64,
    pub ablation_query_cost_usd: f64,
    pub ablation_judge_cost_usd: f64,
    pub answer_prompt: String,
    pub judge: JudgeConfig,
    pub chroma_card_id: Option<String>,
}
impl ModelRunPlan {
    pub(super) fn validate(&self) -> BeamResult<()> {
        self.judge.validate(&self.answer_prompt)?;
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
    let mut plan: ModelRunPlan = serde_json::from_slice(&std::fs::read(path)?)?;
    plan.validate()?;
    if plan.retrieval_manifest.is_relative() {
        plan.retrieval_manifest = path
            .parent()
            .unwrap_or(Path::new("."))
            .join(&plan.retrieval_manifest);
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
    run_with_session(&plan, &session)
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
pub(super) fn run_with_session(
    plan: &ModelRunPlan,
    session: &ModelSession,
) -> BeamResult<MeasuredReport> {
    plan.validate()?;
    let mut manifest = parse_manifest_json(&std::fs::read_to_string(&plan.retrieval_manifest)?)?;
    resolve_manifest_paths(&mut manifest, &plan.retrieval_manifest);
    manifest.outputs = None;
    if manifest.case_ids.len() != plan.amortized_question_count {
        return Err(refusal(
            "offline denominator must equal the fixed dataset question count",
        ));
    }
    let mut ablation_rows = Vec::new();
    let mut ablation_unavailable = Vec::new();
    let mut access_factor_observations = Vec::new();
    let mut rows = Vec::new();
    let mut offline_tokens = 0_u64;
    let mut offline_us = 0_u64;
    for id in &manifest.case_ids {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), beam_vault_config())?;
        let mut one = manifest.clone();
        one.case_ids = vec![id.clone()];
        let started = Instant::now();
        let loaded = load_dataset(&vault, &one, None)?;
        offline_us += started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        let record = loaded
            .contract_records
            .get(id)
            .ok_or_else(|| refusal("measured answering requires run.jsonl corpus"))?;
        offline_tokens += record
            .corpus
            .iter()
            .map(|c| oneiron::count_context_pack_tokens(&c.text) as u64)
            .sum::<u64>();
        let case = loaded
            .cases
            .first()
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
            .map(|config| super::chroma::ChromaArm::ingest(config, &record.corpus))
            .transpose()?;
        if chroma.is_some() {
            offline_us += chroma_started
                .elapsed()
                .as_micros()
                .min(u128::from(u64::MAX)) as u64;
        }
        let (factor_overrides, observations) =
            super::ablations::access_factors(&vault, plan.temporal_now)?;
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
                    request_case.token_budget = if leg == Some("ablation-1:context-budget-off") {
                        record
                            .corpus
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
                    let context = match arm.arm {
                        ArmKind::Deterministic => {
                            let pack = if leg == Some("ablation-2:access-factor-neutral") {
                                super::arms::run_budgeted_context_pack(
                                    || {
                                        super::arms::configured_context_pack_builder(
                                            &vault,
                                            &request_case,
                                        )
                                        .with_temporal_now(plan.temporal_now)
                                        .with_access_factor_overrides(&factor_overrides)
                                    },
                                    &vault,
                                    &request_case,
                                )?
                            } else {
                                measured_pack(&vault, &request_case, plan.temporal_now)?
                            };
                            String::from_utf8(pack.serialized)
                                .map_err(|_| refusal("invalid pack text"))?
                        }
                        ArmKind::Agentic => {
                            let mut context = String::new();
                            for _ in 0..effort.retrieval_steps {
                                let (query,cost)=session.invoke(&arm.model,CallPurpose::ToolRouting,"Return one search query for the unanswered question. Do not answer it.",&serde_json::json!({"question":case.query,"evidence":context}).to_string())?;
                                costs.push(cost);
                                request_case.query = query;
                                context = String::from_utf8(
                                    measured_pack(&vault, &request_case, plan.temporal_now)?
                                        .serialized,
                                )
                                .map_err(|_| refusal("invalid pack text"))?;
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
                            let mut history = String::new();
                            for item in record.corpus.iter().rev() {
                                let text = format!("{}\n{history}", item.text);
                                if oneiron::count_context_pack_tokens(&text) > effort.token_budget {
                                    break;
                                }
                                history = text;
                            }
                            history
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
                    let mut judgments = Vec::new();
                    let mut judge_costs = Vec::new();
                    for gold_answer in &gold.answers {
                        let judged = score_item(
                            session,
                            &plan.judge,
                            &plan.answer_prompt,
                            &JudgeItem {
                                question: case.query.clone(),
                                candidate_answer: answer_text.clone(),
                                gold_answer: gold_answer.clone(),
                                ability: ability.clone(),
                                wedge_bucket,
                            },
                        )?;
                        judgments.push(NuggetJudgment {
                            ability: ability.clone(),
                            wedge_bucket,
                            value: judged.verdict,
                        });
                        judge_costs.push(judged.judge_cost);
                    }
                    let row = ModelRow {
                        ablation: leg.map(str::to_owned),
                        question_id: id.clone(),
                        arm: arm.arm,
                        effort: effort.name.clone(),
                        answerer: arm.model.model_id.clone(),
                        answer: answer_text,
                        scoring: FixedBeamScorer.score_nuggets(&judgments)?,
                        query_cost,
                        judge_overhead: sum_costs(&judge_costs)?,
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
                    .map(|r| r.scoring.beam.as_ref().unwrap().aggregate.official_int_cast)
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
            .unwrap();
        let agent = points
            .iter()
            .find(|p| p.effort == effort.name && p.arm == ArmKind::Agentic)
            .unwrap();
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
    let offline = CostComponentReport {
        token_source: TokenAccountingSource::TokenizerCount,
        tokenizer_id: Some(oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.into()),
        input_tokens: offline_tokens,
        output_tokens: 0,
        target_tokens: 0,
        elapsed_us: offline_us,
        cost_usd: 0.0,
    };
    Ok(MeasuredReport {
        scorer: super::scorer::BeamScorer::metadata(&FixedBeamScorer),
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
                .filter(|p| p.arm != ArmKind::Chat)
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
        offline_total: offline,
        amortized_question_count: plan.amortized_question_count,
        offline_cost_usd_per_question: 0.0,
        query_cost_usd_total: query_total,
        total_cost_usd: query_total
            + ablation_query_cost_usd
            + judge_total
            + ablation_judge_cost_usd,
        ablation_query_cost_usd,
        ablation_judge_cost_usd,
        judge_overhead_usd: judge_total,
        answer_prompt: plan.answer_prompt.clone(),
        judge: plan.judge.clone(),
    })
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
        || super::arms::configured_context_pack_builder(vault, case).with_temporal_now(now),
        vault,
        case,
    )
}
