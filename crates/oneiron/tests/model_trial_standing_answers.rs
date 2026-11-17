//! MODEL-TRIAL-REFUSES-STANDING-ANSWERS: an owner's model trial takes the
//! held-out answers the standing writer saved. A host's own backfill
//! (`backfill_standing_answer`) keeps the engine's pins of the sources the
//! answer rests on, and the trial checks the answer's frontier in the form
//! the standing writer saved it, so a trial nominated over such answers is
//! admitted: over two units each answered alone, and over a unit answered
//! with a NOTE as its evidence, whose stored row is not the body its reader
//! is served. The stale-source check stays: once that NOTE is edited after
//! the answer, the nomination is refused as a source change.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::claim::{CallerLocality, base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::catalog_doors::{ModelCatalogRefresh, ModelTrialNominate, ModelTrialView};
use oneiron::llm::decision::questions::{
    AnswerRecord, OutcomeBinding, OutcomeSource, QuestionActivation, QuestionDefinitionInput,
    RefreshPolicy, StandingAnswer, backfill_standing_answer, create_question, outcome_labels,
    project_bound_outcomes, standing_source_frontier,
};
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionDial,
    DecisionQuestionInput, DecisionRung, ProviderPin,
};
use oneiron::llm::model_trials::{
    HeldOutSelection, ModelTrialPolicy, ModelTrialRequest, TrialSetPin,
};
use oneiron::llm::registry::{
    CatalogSeed, DescriptionContribution, ModelBackendPin, ModelDescription, ModelRegistryRow,
    ModelWireFormat, PricedModelBackend, ScoreObservation, ScoreSnapshot,
};
use oneiron::llm::{
    LlmCapability, LlmCatalogCost, LlmCatalogEntry, LlmInputUsage, LlmOutputUsage, LlmUsage,
    ModelId, ModelLocality,
};
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput, StructuralPutInput,
};
use oneiron::note::NoteEdit;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Error, Result, Vault, VaultConfig, WriteActor};
use serde_json::json;

const OUTCOME_PREDICATE: &str = "profile.standing_trial.outcome";
const REVISION: &str = "standing-trial-catalog-1";
const SCORE_SOURCE: &str = "standing-trial-scores";
const BENCHMARK: &str = "standing-trial-bench";
const INCUMBENT_MODEL: &str = "test/standing-trial-incumbent@r1";
const CANDIDATE_MODEL: &str = "test/standing-trial-candidate@r1";
const NOTE_TEXT: &str = "the unit's history";

/// A device vault with its embedded owner authenticated.
struct OwnerVault {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    proof: AuthenticatedOwner,
    actor: WriteActor,
    now: u64,
}

fn owner_vault() -> OwnerVault {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let now = vault.now_recorded_at();
    OwnerVault {
        vault,
        _dir: dir,
        owner,
        proof,
        actor: WriteActor::new(owner, EdgeActorClass::Human),
        now,
    }
}

/// A PERSON the owner writes.
fn person(fixture: &OwnerVault, name: &str) -> EntityId {
    let id = EntityId::now();
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_owner_authorship(&fixture.proof)
        .put_structural(&StructuralPutInput {
            id: Some(id.to_hex()),
            kind: "PERSON".to_owned(),
            body: json!({ "name": name }),
            text_fields: None,
            edges: None,
            occurred_at: Some(fixture.now),
            learned_at: None,
        })
        .expect("precondition: the owner writes the unit");
    id
}

/// A NOTE the owner writes, holding [`NOTE_TEXT`].
fn note(fixture: &OwnerVault) -> EntityId {
    fixture
        .vault
        .create_note("opinion/take", NOTE_TEXT, fixture.actor)
        .expect("precondition: the owner writes the note")
}

/// The owner's standing yes/no question over `units`, learning from the
/// outcome facts [`label`] writes.
fn question(fixture: &OwnerVault, units: &[EntityId]) -> EntityId {
    create_question(
        &fixture.vault,
        fixture.actor,
        QuestionDefinitionInput {
            question: DecisionQuestionInput {
                text: "Does this unit reach a positive outcome?".into(),
                class: DecisionClass::Judgment,
                contract: AnswerContract::Noul,
                accept_type: false,
            },
            adapter: "graph".into(),
            units: units.to_vec(),
            recipe: "unit_only".into(),
            profile: "default".into(),
            dial: DecisionDial {
                first: DecisionRung::Local,
                ceiling: DecisionRung::Local,
                band: DecisionBand::default(),
            },
            activation: QuestionActivation::Standing,
            refresh: RefreshPolicy {
                on_arrival: false,
                every_seconds: None,
            },
            delivery: "now".into(),
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
            criteria: Default::default(),
            audience: Default::default(),
            posture: None,
            media: Default::default(),
            deadline_ms: None,
            artifacts: Vec::new(),
        },
        fixture.now,
    )
    .expect("precondition: the owner saves the question")
    .definition
    .question
    .id
}

/// A host's own answer to `question` for `unit` resting on `evidence`: the
/// source frontier it read, then the bare backfill at that frontier.
fn backfill(
    fixture: &OwnerVault,
    question: EntityId,
    unit: EntityId,
    evidence: &[EntityId],
) -> AnswerRecord {
    let source_frontier = standing_source_frontier(
        &fixture.vault,
        fixture.owner,
        question,
        1,
        fixture.actor,
        unit,
        evidence,
    )
    .expect("precondition: the host reads the source frontier");
    backfill_standing_answer(
        &fixture.vault,
        fixture.owner,
        question,
        1,
        fixture.actor,
        StandingAnswer {
            unit,
            answer: DecisionAnswer::Noul(true),
            probability: Some(0.9),
            evidence: evidence.to_vec(),
            providers: vec![ProviderPin {
                rung: DecisionRung::Local,
                model: "standing-trial-host".to_owned(),
                version: "r1".to_owned(),
            }],
            paired: Vec::new(),
            rule: None,
            source_frontier,
        },
        fixture.now,
    )
    .expect("precondition: the host's backfill is kept")
}

/// One outcome fact per answer, bound as its label; the held-out selections
/// naming them.
fn label(
    fixture: &OwnerVault,
    question: EntityId,
    answers: &[AnswerRecord],
) -> Vec<HeldOutSelection> {
    let facet = fixture
        .vault
        .default_facet()
        .expect("owner default facet")
        .to_hex();
    let mut held_out = Vec::new();
    for (index, answer) in answers.iter().enumerate() {
        let fact = EntityId::now();
        fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .with_owner_authorship(&fixture.proof)
            .claim_upsert_scoped(&ScopedClaimInput {
                id: Some(fact.to_hex()),
                predicate: OUTCOME_PREDICATE.to_owned(),
                subject_ref: answer.unit.to_hex(),
                value: json!("yes"),
                confidence: 1.0,
                source: "user_stated".to_owned(),
                scope: ClaimScope {
                    world_id: base_world_id().to_hex(),
                    scope_facet_id: facet.clone(),
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
            .expect("precondition: the owner's outcome fact commits");
        held_out.push(HeldOutSelection {
            answer: answer.claim,
            fact,
            source_family: format!("standing-trial-family-{index}"),
        });
    }
    project_bound_outcomes(&fixture.vault, fixture.owner, question)
        .expect("precondition: the outcomes project");
    let labels = outcome_labels(
        &fixture.vault,
        fixture.owner,
        question,
        CallerLocality::OnDevice,
    )
    .expect("precondition: the labels read");
    assert_eq!(
        labels.len(),
        answers.len(),
        "precondition: one label per answer; seen {labels:?}"
    );
    held_out
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

fn backend_pin(model: &ModelId, backend: &str) -> ModelBackendPin {
    ModelBackendPin {
        model: model.clone(),
        backend: backend.to_owned(),
        serving_revision: "r1".to_owned(),
        quantization: None,
        context_window_tokens: 8192,
    }
}

fn registry_row(owner: EntityId, model: &ModelId, backend: &str, price: &str) -> ModelRegistryRow {
    let priced = PricedModelBackend {
        pin: backend_pin(model, backend),
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
            text: "Standing-answer trial fixture model.".to_owned(),
            source: owner.to_hex(),
        }),
        vault_measurements: None,
        public_benchmarks: None,
        vendor_copy: None,
    };
    let metadata = BTreeMap::from([
        (
            "description".to_owned(),
            serde_json::to_value(&description).expect("description json"),
        ),
        (
            "backends".to_owned(),
            serde_json::to_value(vec![&priced]).expect("backends json"),
        ),
    ]);
    ModelRegistryRow {
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
        answer_tokens_per_o200k: None,
        stale_since: None,
        source_rows: None,
    }
}

/// The owner nominates a trial of the candidate against the incumbent over
/// `held_out`, after a catalog revision that scores both.
fn nominate(
    fixture: &OwnerVault,
    question: EntityId,
    held_out: Vec<HeldOutSelection>,
) -> Result<ModelTrialView> {
    let incumbent = ModelId::new(INCUMBENT_MODEL).expect("incumbent model id");
    let candidate = ModelId::new(CANDIDATE_MODEL).expect("candidate model id");
    let revision = fixture
        .vault
        .refresh_model_catalog_as_owner(
            &fixture.proof,
            ModelCatalogRefresh {
                revision: REVISION.to_owned(),
                expected_revision: None,
                catalog: CatalogSeed {
                    version: 1,
                    rows: vec![
                        registry_row(fixture.owner, &incumbent, "standing-incumbent", "10"),
                        registry_row(fixture.owner, &candidate, "standing-candidate", "1"),
                    ],
                },
                scores: vec![ScoreSnapshot {
                    source: SCORE_SOURCE.to_owned(),
                    fetched_at: fixture.now,
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
        )
        .expect("precondition: the owner refreshes the catalog");
    fixture.vault.nominate_model_trial_as_owner(
        &fixture.proof,
        ModelTrialNominate {
            catalog_revision: revision.revision,
            request: ModelTrialRequest {
                principal: fixture.owner,
                question,
                question_version: 1,
                goal: EntityId::now(),
                incumbent: backend_pin(&incumbent, "standing-incumbent"),
                candidate: backend_pin(&candidate, "standing-candidate"),
                source: SCORE_SOURCE.to_owned(),
                benchmark: BENCHMARK.to_owned(),
                set: TrialSetPin {
                    id: "standing-trial-set".to_owned(),
                    version: 1,
                    rubric_version: "standing-trial-rubric-1".to_owned(),
                },
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
        CallerLocality::OnDevice,
    )
}

/// The ids an answer's receipt pins, in order.
fn pinned(answer: &AnswerRecord) -> Vec<EntityId> {
    answer
        .decision
        .receipt
        .evidence_versions
        .iter()
        .map(|pin| pin.id)
        .collect()
}

#[test]
fn trial_admits_answers_a_host_backfilled() {
    let fixture = owner_vault();
    let units = [
        person(&fixture, "Standing trial unit 0"),
        person(&fixture, "Standing trial unit 1"),
    ];
    let question = question(&fixture, &units);
    let answers: Vec<AnswerRecord> = units
        .iter()
        .map(|unit| backfill(&fixture, question, *unit, &[]))
        .collect();
    let held_out = label(&fixture, question, &answers);
    let trial = nominate(&fixture, question, held_out)
        .expect("a trial over answers a host backfilled is admitted");
    assert_eq!(trial.request.held_out.len(), 2);
    for answer in &answers {
        assert_eq!(
            pinned(answer),
            vec![answer.unit],
            "a host's backfill keeps the engine's pin of its unit"
        );
    }
}

#[test]
fn trial_admits_a_backfilled_answer_resting_on_a_note() {
    let fixture = owner_vault();
    let unit = person(&fixture, "Standing trial unit with a note");
    let evidence = note(&fixture);
    let question = question(&fixture, &[unit]);
    let answer = backfill(&fixture, question, unit, &[evidence]);
    let held_out = label(&fixture, question, std::slice::from_ref(&answer));
    let trial = nominate(&fixture, question, held_out)
        .expect("a trial over a backfilled answer resting on a NOTE is admitted");
    assert_eq!(trial.request.held_out.len(), 1);
    assert_eq!(
        pinned(&answer),
        vec![unit, evidence],
        "the unit first, then its evidence"
    );
}

#[test]
fn trial_refuses_a_backfilled_answer_once_its_note_moved() {
    let fixture = owner_vault();
    let unit = person(&fixture, "Standing trial unit with an edited note");
    let evidence = note(&fixture);
    let question = question(&fixture, &[unit]);
    let answer = backfill(&fixture, question, unit, &[evidence]);
    let held_out = label(&fixture, question, std::slice::from_ref(&answer));
    let document = fixture
        .vault
        .note_document(evidence)
        .expect("precondition: the note's document reads");
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_owner_authorship(&fixture.proof)
        .apply_note_ops(
            evidence,
            &document.frontier,
            &[NoteEdit {
                start: 0,
                delete: NOTE_TEXT.len(),
                insert: "a later history".to_owned(),
            }],
        )
        .expect("precondition: the owner edits the note after the answer");
    let refused = nominate(&fixture, question, held_out);
    assert!(
        matches!(refused, Err(Error::ConcurrentWrite(_))),
        "a source edited after the answer is refused as a source change; got {refused:?}"
    );
}
