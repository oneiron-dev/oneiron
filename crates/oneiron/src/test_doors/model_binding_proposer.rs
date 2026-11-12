//! Fixture for the `model_binding_proposer_grant` server test: one completed
//! held-out trial offer for a role, plus a read-only proposal scan.
//!
//! The trial (units, question, answers, labels, catalog, manifest, run,
//! receipt) is built through the engine's own public owner writers, so the
//! red branch (main plus this file) exercises the same owner path the fix
//! shares. It never writes a proposal. The scan reuses the proposals table's
//! declared keyspace read-only, so cases that expect no proposal can prove
//! it; no public trial-indexed list verb exists, and none is invented here.

use std::collections::BTreeMap;

use serde_json::json;

use crate::claim::{CallerLocality, base_world_id, default_project_id};
use crate::error::{Error, Result};
use crate::llm::catalog_doors::{
    ModelBindingProposal, ModelCatalogRefresh, ModelTrialComplete, ModelTrialNominate,
    ModelTrialRef,
};
use crate::llm::decision::questions::{
    GraphAnswerer, GraphPrediction, GraphQuestionInput, GraphUnitContext, OutcomeBinding,
    OutcomeSource, QuestionActivation, QuestionAudience, QuestionCriteria, QuestionDefinitionInput,
    QuestionMedia, RefreshPolicy, create_question, outcome_labels, project_bound_outcomes,
    refresh_due_questions_with, schedule_backfill,
};
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionDial, DecisionQuestion,
    DecisionQuestionInput, DecisionReceipt, DecisionRung, ProviderPin, TypedDecision,
};
use crate::llm::manifest::{
    MODEL_ROLES, ModelBinding, ModelManifest, ModelRole, ModelSlot, TeacherProbeApproval,
};
use crate::llm::model_trials::{
    HeldOutSelection, ModelTrialAction, ModelTrialPolicy, ModelTrialRequest, PairedQualityInterval,
    TrialAssessment, TrialReading, TrialSetPin,
};
use crate::llm::registry::{
    CatalogSeed, DescriptionContribution, ModelBackendPin, ModelDescription, ModelRegistryRow,
    ModelWireFormat, PricedModelBackend, ScoreObservation, ScoreSnapshot,
};
use crate::llm::{
    LlmCapability, LlmCatalogCost, LlmCatalogEntry, LlmInputUsage, LlmOutputUsage, LlmUsage,
    ModelId, ModelIdError, ModelLocality, ModelTierRef,
};
use crate::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, MemoryError, ScopedClaimInput,
    StructuralPutInput,
};
use crate::side_table::{self, Named, SideTable};
use crate::{EdgeActorClass, EntityId, Vault, WriteActor};

/// The role the fixture trial runs for, as the propose verb spells it.
pub const PROPOSE_ROLE: &str = "generative_reasoner";

const REVISION: &str = "bp-catalog-1";
const SCORE_SOURCE: &str = "bp-scores";
const BENCHMARK: &str = "bp-bench";
const SET_ID: &str = "bp-set";
const OUTCOME_PREDICATE: &str = "profile.binding_proposer.outcome";
const TIER: &str = "configured";
const INCUMBENT_MODEL: &str = "test/bp-incumbent@r1";
const CANDIDATE_MODEL: &str = "test/bp-candidate@r1";
const CASES: usize = 2;

/// What the server test needs to drive the propose verb and read it back.
pub struct TrialFixture {
    /// The vault owner the fixture was built under.
    pub owner: EntityId,
    /// The standing question the trial held out from.
    pub question: EntityId,
    /// The completed trial, receipted as an offer.
    pub trial: EntityId,
    /// The manifest incumbent for the role (the trial's incumbent arm).
    pub incumbent: String,
    /// The trial's candidate arm (the proposed binding's model).
    pub candidate: String,
    /// The manifest tier every role binds.
    pub tier: String,
}

/// The proposals table, the same declaration `catalog_doors` writes;
/// scan-only here.
const PROPOSALS: SideTable<EntityId, ModelBindingProposal, Named> =
    SideTable::new(&side_table::LLM_BINDING_PROPOSAL);

fn memory_failed(error: MemoryError) -> Error {
    Error::InvalidConfig(error.message)
}

fn model_id_failed(error: ModelIdError) -> Error {
    Error::InvalidConfig(format!("fixture model id: {error:?}"))
}

fn json_failed(error: serde_json::Error) -> Error {
    Error::InvalidConfig(error.to_string())
}

fn usage(input_tokens: u64, output_tokens: u64) -> LlmUsage {
    LlmUsage {
        input: LlmInputUsage {
            total: input_tokens,
            cache_read: 0,
            cache_write: 0,
        },
        output: LlmOutputUsage {
            total: output_tokens,
            text: output_tokens,
            reasoning: 0,
        },
        raw_provider: serde_json::Value::Null,
        call_metadata: None,
    }
}

fn registry_row(
    owner: EntityId,
    model: &ModelId,
    backend: &str,
    price: &str,
) -> Result<ModelRegistryRow> {
    let priced = PricedModelBackend {
        pin: ModelBackendPin {
            model: model.clone(),
            backend: backend.to_owned(),
            serving_revision: "r1".to_owned(),
            quantization: None,
            context_window_tokens: 8192,
        },
        price: LlmCatalogCost {
            input_per_million: price.to_owned(),
            output_per_million: price.to_owned(),
            cache_read_per_million: None,
            cache_write_per_million: None,
            currency: Some("USD".to_owned()),
        },
    };
    let description = ModelDescription {
        owner_line: Some(DescriptionContribution {
            text: "Binding-proposer trial fixture model.".to_owned(),
            source: owner.to_hex(),
        }),
        vault_measurements: None,
        public_benchmarks: None,
        vendor_copy: None,
    };
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "description".to_owned(),
        serde_json::to_value(&description).map_err(json_failed)?,
    );
    metadata.insert(
        "backends".to_owned(),
        serde_json::to_value(vec![&priced]).map_err(json_failed)?,
    );
    Ok(ModelRegistryRow {
        version: 1,
        wire: ModelWireFormat::OpenaiCompat,
        catalog: LlmCatalogEntry {
            model: model.clone(),
            display_name: model.as_str().to_owned(),
            locality: ModelLocality::OwnServer,
            context_window_tokens: 8192,
            max_output_tokens: None,
            cost: Some(priced.price.clone()),
            capabilities: vec![LlmCapability::JsonResponse],
            metadata,
        },
        scores: BTreeMap::new(),
        fetched_at: BTreeMap::new(),
        tokens_per_o200k: None,
        stale_since: None,
        source_rows: None,
    })
}

fn manifest(incumbent: &ModelId) -> Result<ModelManifest> {
    let mut roles = BTreeMap::new();
    for role in MODEL_ROLES {
        let model = if role == ModelRole::GenerativeReasoner {
            incumbent.clone()
        } else {
            ModelId::new(format!("test/bp-{role:?}@r1")).map_err(model_id_failed)?
        };
        roles.insert(
            role,
            ModelBinding {
                model,
                slot: if role == ModelRole::ExtractionEncoder {
                    ModelSlot::Oneironer
                } else {
                    ModelSlot::Llm
                },
                tier: ModelTierRef(TIER.to_owned()),
                route_models: BTreeMap::new(),
                disposition: None,
                reads_audio: false,
            },
        );
    }
    Ok(ModelManifest {
        version: 2,
        roles,
        routes: BTreeMap::from([
            (ModelSlot::Llm, ModelLocality::OwnServer),
            (ModelSlot::Embedder, ModelLocality::OwnServer),
            (ModelSlot::Oneironer, ModelLocality::OnDevice),
        ]),
        verdict: None,
        seat_policy: None,
    })
}

struct UnitFixtureAnswerer;

impl GraphAnswerer for UnitFixtureAnswerer {
    fn answer(
        &mut self,
        _question: &DecisionQuestion,
        _context: &GraphUnitContext,
    ) -> Result<Option<GraphPrediction>> {
        Ok(Some(GraphPrediction {
            answer: DecisionAnswer::Noul(true),
            probability: 0.9,
            provider: ProviderPin {
                rung: DecisionRung::Big,
                model: "bp-backfill".to_owned(),
                version: "r1".to_owned(),
            },
            cost_per_thousand: 0.0,
            paired: None,
            rule: None,
        }))
    }
}

/// Builds one completed held-out trial offer for [`PROPOSE_ROLE`] under the
/// vault's embedded owner: two fixture units, a standing yes/no question over
/// them, one scheduled graph answer each, the later outcome facts bound as labels,
/// a catalog revision pinning the incumbent and candidate arms, the manifest
/// with the incumbent binding, and the trial nominated, approved, run with
/// scripted readings and completed to an offer. Never writes a proposal.
///
/// The owner proof is the embedded owner's own authentication over the
/// owner the host root bound, never the test host issuer, so this works on
/// a server test's secret-issuer vault.
pub fn ensure_completed_trial_offer(vault: &Vault) -> Result<TrialFixture> {
    let owner = vault.ensure_embedded_owner_actor().map_err(memory_failed)?;
    let proof = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let now = vault.now_recorded_at();
    let mut units = Vec::new();
    for index in 0..CASES {
        let id = EntityId::now();
        vault
            .memory(owner, EdgeActorClass::Human)
            .with_owner_authorship(&proof)
            .put_structural(&StructuralPutInput {
                id: Some(id.to_hex()),
                kind: "PERSON".to_owned(),
                body: json!({"name": format!("Binding proposer fixture unit {index}")}),
                text_fields: None,
                edges: None,
                occurred_at: now,
                learned_at: None,
            })
            .map_err(memory_failed)?;
        units.push(id);
    }
    let record = create_question(
        vault,
        actor,
        QuestionDefinitionInput {
            question: DecisionQuestionInput {
                text: "Is this unit a binding-proposer fixture unit?".to_owned(),
                class: DecisionClass::Judgment,
                contract: AnswerContract::Noul,
                accept_type: true,
            },
            adapter: "graph".to_owned(),
            units: units.clone(),
            recipe: "unit_only".to_owned(),
            profile: "default".to_owned(),
            dial: DecisionDial {
                first: DecisionRung::Big,
                ceiling: DecisionRung::Big,
                band: DecisionBand {
                    low: 0.35,
                    high: 0.65,
                },
            },
            activation: QuestionActivation::Standing,
            refresh: RefreshPolicy {
                on_arrival: false,
                every_seconds: None,
            },
            delivery: "now".to_owned(),
            learning: true,
            binding: Some(OutcomeBinding {
                source: OutcomeSource::Claim {
                    predicate: OUTCOME_PREDICATE.to_owned(),
                },
                horizon: 31_536_000,
                mapping: BTreeMap::from([("yes".to_owned(), true), ("no".to_owned(), false)]),
                noise_weight: 1.0,
                linked_by: None,
            }),
            criteria: QuestionCriteria {
                yes_if_all: vec!["The unit is a binding-proposer fixture unit.".to_owned()],
                no_if_any: Vec::new(),
                not_a_reason_to_say_no: Vec::new(),
            },
            audience: QuestionAudience::Asker,
            posture: None,
            media: QuestionMedia::default(),
            deadline_ms: None,
            artifacts: Vec::new(),
        },
        now,
    )?;
    let question = record.definition.question.id;
    // The question needs only each unit's own body, not its neighbourhood.
    // Scheduled graph backfill records both body pins and the refresh frontier
    // that the public trial doors revalidate; bare host backfill records neither
    // that receipt nor that frontier format.
    schedule_backfill(
        vault,
        owner,
        question,
        1,
        now,
        units
            .iter()
            .map(|unit| GraphQuestionInput {
                unit: *unit,
                evidence: Vec::new(),
            })
            .collect(),
    )?;
    let batch = refresh_due_questions_with(vault, now, |_, _| Ok(UnitFixtureAnswerer))?;
    if let Some(failure) = batch.failures.into_iter().next() {
        return Err(failure.error);
    }
    if batch.answers.len() != CASES {
        return Err(Error::InvalidConfig(format!(
            "fixture stored {} answers, expected {CASES}",
            batch.answers.len()
        )));
    }
    let mut held_out = Vec::new();
    for (index, unit) in units.iter().enumerate() {
        let answer = batch
            .answers
            .iter()
            .find(|answer| answer.unit == *unit && answer.decision.receipt.question == question)
            .ok_or_else(|| Error::InvalidConfig("fixture unit has no graph answer".to_owned()))?;
        let fact = EntityId::now();
        vault
            .memory(owner, EdgeActorClass::Human)
            .with_owner_authorship(&proof)
            .claim_upsert_scoped(&ScopedClaimInput {
                id: Some(fact.to_hex()),
                predicate: OUTCOME_PREDICATE.to_owned(),
                subject_ref: unit.to_hex(),
                value: json!("yes"),
                confidence: 1.0,
                source: "user_stated".to_owned(),
                scope: ClaimScope {
                    world_id: base_world_id().to_hex(),
                    scope_facet_id: vault.default_facet()?.to_hex(),
                    scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                    scope_project_id: default_project_id().to_hex(),
                },
                sensitivity: None,
                evidence_turn_refs: Vec::new(),
                valid_from: None,
                valid_to: None,
                occurred_at: Some(answer.answered_at),
                learned_at: Some(answer.answered_at),
                salience: None,
            })
            .map_err(memory_failed)?;
        held_out.push(HeldOutSelection {
            answer: answer.claim,
            fact,
            source_family: format!("bp-family-{index}"),
        });
    }
    // Commits already project arrivals as each fact lands, so this returns
    // only newly projected labels (often none); the stored labels are the
    // assertion, not its count.
    project_bound_outcomes(vault, owner, question)?;
    let labels = outcome_labels(vault, owner, question, CallerLocality::OnDevice)?;
    if labels.len() != CASES {
        return Err(Error::InvalidConfig(format!(
            "fixture stored {} labels, expected {CASES}",
            labels.len()
        )));
    }
    let incumbent = ModelId::new(INCUMBENT_MODEL).map_err(model_id_failed)?;
    let candidate = ModelId::new(CANDIDATE_MODEL).map_err(model_id_failed)?;
    let revision = vault.refresh_model_catalog_as_owner(
        &proof,
        ModelCatalogRefresh {
            revision: REVISION.to_owned(),
            expected_revision: None,
            catalog: CatalogSeed {
                version: 1,
                rows: vec![
                    registry_row(owner, &incumbent, "bp-incumbent", "10")?,
                    registry_row(owner, &candidate, "bp-candidate", "1")?,
                ],
            },
            scores: vec![ScoreSnapshot {
                source: SCORE_SOURCE.to_owned(),
                fetched_at: now,
                observations: vec![
                    ScoreObservation {
                        model: incumbent.clone(),
                        benchmark: BENCHMARK.to_owned(),
                        score: 0.8,
                    },
                    ScoreObservation {
                        model: candidate.clone(),
                        benchmark: BENCHMARK.to_owned(),
                        score: 0.9,
                    },
                ],
                source_rows: None,
            }],
        },
    )?;
    let manifest = manifest(&incumbent)?;
    let policy = vault.teacher_probe_policy(None)?;
    let approval = TeacherProbeApproval::for_scored_checkpoint(&manifest, &policy, 1_000_000)?;
    vault.set_model_manifest_with_teacher_approval(&manifest, &approval)?;
    let locality = CallerLocality::OnDevice;
    let set = TrialSetPin {
        id: SET_ID.to_owned(),
        version: 1,
        rubric_version: "bp-rubric-1".to_owned(),
    };
    let nominated = vault.nominate_model_trial_as_owner(
        &proof,
        ModelTrialNominate {
            catalog_revision: revision.revision.clone(),
            request: ModelTrialRequest {
                principal: owner,
                question,
                question_version: 1,
                goal: EntityId::now(),
                incumbent: ModelBackendPin {
                    model: incumbent.clone(),
                    backend: "bp-incumbent".to_owned(),
                    serving_revision: "r1".to_owned(),
                    quantization: None,
                    context_window_tokens: 8192,
                },
                candidate: ModelBackendPin {
                    model: candidate.clone(),
                    backend: "bp-candidate".to_owned(),
                    serving_revision: "r1".to_owned(),
                    quantization: None,
                    context_window_tokens: 8192,
                },
                source: SCORE_SOURCE.to_owned(),
                benchmark: BENCHMARK.to_owned(),
                set: set.clone(),
                held_out,
                incumbent_usage_bound: usage(100, 10),
                candidate_usage_bound: usage(100, 10),
                future_units: 1000,
                policy: ModelTrialPolicy {
                    exploration_remaining: 1_000_000.0,
                    vault_cost_cap: None,
                    project_cost_cap: None,
                    auto_approve: false,
                    candidate_needs_download: false,
                },
            },
        },
        locality,
    )?;
    let trial = nominated.id;
    vault.approve_model_trial_as_owner(&proof, ModelTrialRef { question, trial }, locality)?;
    let run = vault.run_model_trial_as_owner(
        &proof,
        ModelTrialRef { question, trial },
        locality,
        |record, backend, _context| {
            let probability = if backend.pin.model == incumbent {
                0.6
            } else {
                0.9
            };
            Ok(TrialReading {
                backend: backend.pin.clone(),
                decision: Some(TypedDecision {
                    answer: DecisionAnswer::Noul(true),
                    probability: Some(probability),
                    evidence: Vec::new(),
                    in_band: true,
                    receipt: DecisionReceipt {
                        question: record.definition.question.id,
                        question_version: record.definition.question.version,
                        principal: record.principal,
                        providers: vec![ProviderPin {
                            rung: DecisionRung::Big,
                            model: backend.pin.model.as_str().to_owned(),
                            version: backend.pin.model.revision().to_owned(),
                        }],
                        band: DecisionBand {
                            low: 0.35,
                            high: 0.65,
                        },
                        band_version: 0,
                        evidence_versions: Vec::new(),
                        cost_per_thousand: None,
                        paired: Vec::new(),
                        person: Vec::new(),
                        time: None,
                        images: Vec::new(),
                        think_row: None,
                        person_row: None,
                        rule: None,
                        asked: None,
                        state_cut: None,
                    },
                    human_ask: None,
                }),
                usage: usage(50, 5),
            })
        },
    )?;
    let measurements_hash = run
        .evidence
        .as_ref()
        .map(|evidence| evidence.measurements_hash)
        .ok_or_else(|| Error::InvalidConfig("fixture trial run recorded no evidence".to_owned()))?;
    let completed = vault.complete_model_trial_as_owner(
        &proof,
        ModelTrialComplete {
            question,
            trial,
            assessment: TrialAssessment {
                set,
                measurements_hash,
                paired_gain: Some(PairedQualityInterval {
                    low: 0.1,
                    high: 0.2,
                }),
                retest_noise: 0.05,
                stricter_margin: None,
                required_families: CASES,
                rare_slices_sufficient: true,
                versions_match: true,
                canary_diverged: false,
            },
        },
        locality,
    )?;
    if !completed
        .receipt
        .as_ref()
        .is_some_and(|receipt| receipt.action == ModelTrialAction::Offer)
    {
        return Err(Error::InvalidConfig(
            "fixture trial did not settle as an offer".to_owned(),
        ));
    }
    Ok(TrialFixture {
        owner,
        question,
        trial,
        incumbent: incumbent.as_str().to_owned(),
        candidate: candidate.as_str().to_owned(),
        tier: TIER.to_owned(),
    })
}

/// The ids of every proposal kept for `trial`, in id order. Read-only: the
/// cases that expect no proposal prove it through this scan, since no public
/// verb lists proposals by trial.
pub fn proposal_ids_for_trial(vault: &Vault, trial: EntityId) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let mut ids: Vec<EntityId> = PROPOSALS
        .scan(&vault.store, &txn)?
        .into_iter()
        .filter(|(_, saved)| saved.trial.id == trial)
        .map(|(id, _)| id)
        .collect();
    ids.sort();
    Ok(ids)
}
