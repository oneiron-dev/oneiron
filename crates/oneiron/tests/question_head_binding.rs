//! FIX 3864: an unmeasured question head binds only on the owner's reason.
//! The upstream trainer is a local fake; custody and every run write are real.
//! Evaluated binding needs a won trial against the current answerer.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::decision::questions::{
    QuestionActivation, QuestionAudience, QuestionCriteria, QuestionDefinitionInput, QuestionMedia,
    RefreshPolicy, create_question,
};
use oneiron::llm::decision::{
    AnswerContract, DecisionBand, DecisionClass, DecisionDial, DecisionQuestionInput, DecisionRung,
    ProviderPin,
};
use oneiron::llm::run_admission::{
    BudgetLine, KeyCustody, LeaseUnit, MemoryReceipts, OfferRoute, PaidConnector, Payer,
    RunAdmission, RunDeclaration,
};
use oneiron::llm::{ModelId, ModelLocality};
use oneiron::skill_optimize::{
    CutDecision, DerivationKind, EvalCaseDraft, EvalCohortSetup, EvalLabel, EvalLabelKind,
    EvalSeat, FamilyPurpose, eval_authoring_inventory, setup_eval_cohorts,
};
use oneiron::store::GateDecisionId;
use oneiron::training_pack::{
    CalibrationResult, CandleParityCheck, CheckpointFileKind, CheckpointFileUpload,
    CheckpointUpload, ComputeChoice, DetectorCorpusRef, HeldOutResult, ProbeCase, ProbeMeasurement,
    QUESTION_LABEL_SCHEMA, QUESTION_RENDERER, QuestionExportCheck, QuestionTarget,
    QuestionTrialCase, SourcePin, SplitPolicy, SplitSide, SwapChoice, TrainOutput, TrainRequest,
    TrainingConnector, TrainingDeclarationPin, TrainingEvalInput, TrainingFuture,
    TrainingPackDraft, TrainingPlan, TrainingRun, TrainingRunCaller, TrainingState, TrainingTarget,
};
use oneiron::{EdgeActorClass, EntityId, Result, Vault, VaultConfig, WriteActor};
use serde_json::{Value, json};

fn source_pin() -> SourcePin {
    SourcePin {
        repository: "fixture/question-head".to_owned(),
        revision: "1111111111111111111111111111111111111111".to_owned(),
    }
}

fn json_hash(value: &Value) -> [u8; 32] {
    let bytes = oneiron::llm::canonical_json_bytes(value).expect("canonical fixture JSON");
    *blake3::hash(&bytes).as_bytes()
}

fn checkpoint_upload(model: ModelId) -> CheckpointUpload {
    // Binding checks byte custody, not model loading. No trainer or loader runs.
    let bytes = b"question-head checkpoint custody fixture".to_vec();
    CheckpointUpload {
        model,
        files: vec![CheckpointFileUpload {
            name: "model.safetensors".to_owned(),
            kind: CheckpointFileKind::Weights,
            source: source_pin(),
            blake3: *blake3::hash(&bytes).as_bytes(),
            bytes,
        }],
    }
}

/// Supplies only upstream output; the engine checks and retains it normally.
struct FixtureTrainer;

impl TrainingConnector for FixtureTrainer {
    fn train<'a>(
        &'a self,
        request: TrainRequest,
        _admission: &'a RunAdmission,
    ) -> TrainingFuture<'a> {
        Box::pin(async move {
            let model = request.plan.target.output_model().clone();
            let training_checkpoint = checkpoint_upload(model.clone());
            let exported_checkpoint = checkpoint_upload(model);
            Ok(TrainOutput {
                run: request.run,
                spec_blake3: request.spec_blake3,
                probe_training_blake3: training_checkpoint.content_hash()?,
                probe_export_blake3: exported_checkpoint.content_hash()?,
                training_checkpoint,
                exported_checkpoint,
                probes: request
                    .plan
                    .probes
                    .iter()
                    .map(|probe| ProbeMeasurement {
                        probe_id: probe.id.clone(),
                        input_blake3: json_hash(&probe.input),
                        tokens_blake3: None,
                        training_argmax: 1,
                        export_argmax: 1,
                        max_logit_difference: 0.0,
                    })
                    .collect(),
                settings: request.plan.settings,
                harness: request.plan.harness,
                receipt: json!({"fixture": "question-head", "returned": true}),
                service_units: 1,
                question_check: Some(QuestionExportCheck {
                    finite: true,
                    tokens_match: true,
                    passed: true,
                }),
                candle_parity: Some(CandleParityCheck {
                    tokens_match: true,
                    token_mismatches: Vec::new(),
                    logits_match: Some(true),
                }),
            })
        })
    }
}

fn prepare_question_run(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    held_out_families: usize,
) -> Result<(TrainingRun, PaidConnector)> {
    let seat = EvalSeat::Decision;
    let training_yes = EntityId::now().to_hex();
    let training_no = EntityId::now().to_hex();
    let held_out: Vec<String> = (0..held_out_families)
        .map(|_| EntityId::now().to_hex())
        .collect();
    vault.assign_eval_family(
        &seat,
        &BTreeSet::from([training_yes.clone(), training_no.clone()]),
        FamilyPurpose::Development,
        1,
    )?;
    for receipt in &held_out {
        vault.assign_eval_family(
            &seat,
            &BTreeSet::from([receipt.clone()]),
            FamilyPurpose::SealedConfirmation,
            1,
        )?;
        let case = vault.record_eval_case(
            &EvalCaseDraft {
                seat: seat.clone(),
                kind: DerivationKind::Receipt,
                receipts: vec![receipt.clone()],
                parents: Vec::new(),
                stratum: None,
                draw_probability: None,
                source_at: 2,
            },
            2,
        )?;
        vault.label_eval_case(
            &case.id,
            EvalLabel {
                kind: EvalLabelKind::AdjudicatedAudit,
                value: "yes".to_owned(),
                reference: "fixture/adjudication".to_owned(),
                weight: 1.0,
                at: 3,
                source_rows: None,
            },
        )?;
    }
    let inventory = eval_authoring_inventory(vault, 5)?;
    let setup = setup_eval_cohorts(
        vault,
        owner,
        EvalCohortSetup {
            inventory_at: 5,
            inventory_digest: inventory.inventory_digest,
            families: Vec::new(),
            cases: Vec::new(),
            cuts: vec![CutDecision {
                seat: seat.clone(),
                from: 0,
                until: 4,
                rubric_revision: "fixture/rubric-v1".to_owned(),
                reference: false,
            }],
        },
        5,
    )?;
    assert_eq!(setup.cohorts_cut.len(), 1, "{setup:?}");

    let definition = json!({"question": "Does this target ask for help?"});
    let question = QuestionTarget {
        question_id: "fixture.help-request".to_owned(),
        question_version: 1,
        definition_blake3: json_hash(&definition),
        definition,
        family: "fixture.help".to_owned(),
        corpus_revision: "fixture/corpus-v1".to_owned(),
        feature_schema: "fixture/target-v1".to_owned(),
        label_schema: QUESTION_LABEL_SCHEMA.to_owned(),
        renderer: QUESTION_RENDERER.to_owned(),
        output_model: ModelId::new("local/question-head@v1").expect("output model"),
    };
    let mut rows = Vec::new();
    let source_rows = [
        (
            training_yes,
            "yes",
            "Please help with the report".to_owned(),
        ),
        (training_no, "no", "The report is finished".to_owned()),
    ]
    .into_iter()
    .chain(held_out.into_iter().enumerate().map(|(index, receipt)| {
        (
            receipt,
            "yes",
            format!("Can someone explain chart {index}?"),
        )
    }));
    for (receipt, answer, text) in source_rows {
        let row = json!({
            "row": receipt,
            "source": receipt,
            "question_id": question.question_id,
            "question_version": question.question_version,
            "corpus_revision": question.corpus_revision,
            "feature_schema": question.feature_schema,
            "label_schema": question.label_schema,
            "consent": {"basis": "owner", "receipt": "fixture/consent-v1"},
            "label": {"answer": answer, "unit": "target", "adjudication": "fixture/audit-v1"},
            "input": {"target": text, "context": []}
        });
        rows.extend(serde_json::to_vec(&row).expect("fixture row JSON"));
        rows.push(b'\n');
    }
    let corpus = DetectorCorpusRef {
        rows: vault.keep_training_verifier_log(owner, "detector-rows.jsonl", &rows)?,
    };
    let starting_checkpoint = vault.keep_training_checkpoint(
        owner,
        &checkpoint_upload(ModelId::new("local/question-base@v1").expect("base model")),
    )?;
    let unit = LeaseUnit::new("fixture-units").expect("cost unit");
    let connector = PaidConnector {
        connector: "fixture-trainer".to_owned(),
        route: OfferRoute::new("fixture-trainer", "device").expect("local route"),
        locality: ModelLocality::OnDevice,
        payer: Payer::Local,
        credential_binding: None,
        catalog_revision: None,
        custody: KeyCustody::Keyless,
        unit_cost: 1,
        cost_unit: unit,
        rates: Vec::new(),
    };
    let draft = TrainingPackDraft {
        plan: TrainingPlan {
            target: TrainingTarget::Question { question },
            seat,
            starting_checkpoint,
            purpose: "exercise owner question-head binding".to_owned(),
            settings: json!({"fixture": true}),
            harness: source_pin(),
            probes: vec![ProbeCase {
                id: "fixture/probe".to_owned(),
                input: json!({"target": "Please explain the result", "context": []}),
            }],
            export_logit_tolerance: 0.001,
        },
        split: SplitPolicy {
            held_out_cohort: setup.cohorts_cut[0],
        },
        compute: ComputeChoice::OwnerMachines,
        quantity: 1,
        consented_sources: Vec::new(),
    };
    let run = vault.prepare_question_training_pack(owner, &draft, &corpus, &connector)?;
    assert_eq!(run.state, TrainingState::Prepared);
    assert_eq!(run.corpus.exact_hash_overlaps, 0);
    Ok((run, connector))
}

/// A question run its owner authorized, with the connector and admission
/// the host dispatches it under.
fn authorized_question_run(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    held_out_families: usize,
) -> Result<(EntityId, PaidConnector, RunAdmission)> {
    let (prepared, connector) = prepare_question_run(vault, owner, held_out_families)?;
    let run = prepared.id;
    let admission = question_admission(&prepared, &connector);
    let authorized = vault.authorize_training_pack(
        owner,
        &run,
        &prepared.spec_blake3,
        TrainingDeclarationPin::of(&admission.declaration())?,
        6,
    )?;
    assert_eq!(authorized.state, TrainingState::Authorized);
    Ok((run, connector, admission))
}

/// A fresh admission of `run` on its connector's one-unit quote, as the
/// host builds it from the run's pinned quote.
fn question_admission(run: &TrainingRun, connector: &PaidConnector) -> RunAdmission {
    let declaration = RunDeclaration::declared(BudgetLine {
        limit_units: 1,
        reserve_units: 1,
        unit: connector.cost_unit.clone(),
    })
    .with_connector(connector.connector.clone());
    RunAdmission::new(
        run.admission_ref(),
        declaration,
        None,
        Arc::new(MemoryReceipts::default()),
    )
}

async fn scored_question_run(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    held_out_families: usize,
) -> Result<TrainingRun> {
    let (run, connector, admission) = authorized_question_run(vault, owner, held_out_families)?;
    let returned = vault
        .execute_authorized_training_pack(&run, &admission, &connector, &FixtureTrainer)
        .await?;
    assert_eq!(returned.state, TrainingState::Returned);
    assert!(returned.dispatch.as_ref().expect("dispatch").dispatched);
    assert!(returned.result.as_ref().expect("result").checks.passed());
    let input = vault.open_training_held_out(&run)?;
    let log =
        vault.keep_training_verifier_log_for_run(&run, "evaluation.json", b"{\"passed\":true}")?;
    let scored = vault.record_training_evaluation(
        &run,
        &HeldOutResult {
            exposure: input.exposure.id,
            checkpoint_blake3: input.checkpoint.content_hash()?,
            held_out_blake3: *blake3::hash(&input.held_out_jsonl).as_bytes(),
            harness: input.harness,
            cases: returned
                .corpus
                .rows
                .iter()
                .filter(|row| row.side == SplitSide::HeldOut)
                .count() as u64,
            metrics: BTreeMap::from([("agreement".to_owned(), 1.0)]),
            calibration: Some(CalibrationResult {
                temperature: 1.0,
                brier_score: 0.0,
                calibration_error: 0.0,
            }),
            verifier_logs: vec![log],
            passed: true,
        },
    )?;
    assert_eq!(scored.state, TrainingState::Scored);
    assert!(
        scored.can_bind_question_head(),
        "only the paired trial is missing"
    );

    Ok(scored)
}

/// The refusal text of a call that must fail.
fn refusal<T>(outcome: Result<T>) -> String {
    outcome.err().expect("the call is refused").to_string()
}

/// This crate's tokio has `macros` only under the `sync` feature, so the test
/// drives its steps on a runtime of its own.
#[test]
fn question_head_binds_on_an_owner_reason_and_never_on_an_unmeasured_trial() -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime")
        .block_on(binds_on_an_owner_reason())
}

async fn binds_on_an_owner_reason() -> Result<()> {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault.authenticate_owner(actor, "principal:owner", true, GateDecisionId::now())?;
    let run = scored_question_run(&vault, &owner, 1).await?.id;

    // The approval path keys by id and version without looking up a typed question.
    let question = EntityId::now();
    let question_version = 1;
    let refused = refusal(vault.approve_training_question_head(
        &owner,
        &run,
        question,
        question_version,
        SwapChoice::Evaluated,
        &[],
    ));
    assert!(refused.contains("no won paired trial"), "{refused}");
    assert_eq!(
        vault.training_run(&run)?.expect("run").state,
        TrainingState::Scored
    );
    assert!(vault.training_run_question_head(&run)?.is_none());
    assert!(
        vault
            .training_question_head(question, question_version)?
            .is_none()
    );
    assert!(vault.training_question_trial(&run)?.is_none());

    let refused = refusal(vault.approve_training_question_head(
        &owner,
        &run,
        question,
        question_version,
        SwapChoice::ExplicitOverride {
            reason: "   ".to_owned(),
        },
        &[],
    ));
    assert!(refused.contains("records the owner's reason"), "{refused}");
    assert_eq!(
        vault.training_run(&run)?.expect("run").state,
        TrainingState::Scored
    );
    assert!(vault.training_run_question_head(&run)?.is_none());
    assert!(
        vault
            .training_question_head(question, question_version)?
            .is_none()
    );
    assert!(vault.training_question_trial(&run)?.is_none());

    let choice = SwapChoice::ExplicitOverride {
        reason: "owner tried the head".to_owned(),
    };
    let binding = vault.approve_training_question_head(
        &owner,
        &run,
        question,
        question_version,
        choice.clone(),
        &[],
    )?;
    assert_eq!(binding.run, run);
    assert_eq!(binding.question, question);
    assert_eq!(binding.question_version, question_version);
    assert!(binding.trial.is_none());
    assert!(binding.previous_run.is_none());
    assert_eq!(binding.choice, choice);
    assert!(binding.temperature.is_finite() && binding.temperature > 0.0);
    assert_eq!(
        vault.training_run(&run)?.expect("run").state,
        TrainingState::Bound
    );
    assert_eq!(
        vault
            .training_question_head(question, question_version)?
            .as_ref(),
        Some(&binding)
    );
    assert_eq!(
        vault.training_run_question_head(&run)?.as_ref(),
        Some(&binding)
    );

    let repeated = vault.approve_training_question_head(
        &owner,
        &run,
        question,
        question_version,
        choice,
        &[],
    )?;
    assert_eq!(repeated.id, binding.id);
    assert_eq!(repeated, binding);
    assert_eq!(
        vault.unbind_training_question_head(&owner, question, question_version)?,
        Some(binding)
    );
    assert_eq!(
        vault.training_run(&run)?.expect("run").state,
        TrainingState::Scored
    );
    assert!(
        vault
            .training_question_head(question, question_version)?
            .is_none()
    );
    assert!(vault.training_run_question_head(&run)?.is_none());
    assert!(
        vault
            .unbind_training_question_head(&owner, question, question_version)?
            .is_none()
    );
    Ok(())
}

#[test]
fn question_head_binds_evaluated_only_on_a_won_trial_against_the_current_answerer() -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime")
        .block_on(binds_on_a_won_trial())
}

async fn binds_on_a_won_trial() -> Result<()> {
    // The estimator needs ten families and nonzero family-delta variance.
    const HELD_OUT_FAMILIES: usize = 12;

    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault.authenticate_owner(actor, "principal:owner", true, GateDecisionId::now())?;
    let scored = scored_question_run(&vault, &owner, HELD_OUT_FAMILIES).await?;
    let run = scored.id;
    let record = create_question(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Human),
        QuestionDefinitionInput {
            question: DecisionQuestionInput {
                text: "Does this target ask for help?".to_owned(),
                class: DecisionClass::Judgment,
                contract: AnswerContract::Noul,
                accept_type: false,
            },
            adapter: "graph".to_owned(),
            units: Vec::new(),
            recipe: "unit".to_owned(),
            profile: "local".to_owned(),
            dial: DecisionDial {
                first: DecisionRung::Rule,
                ceiling: DecisionRung::Big,
                band: DecisionBand::default(),
            },
            activation: QuestionActivation::Standing,
            refresh: RefreshPolicy {
                on_arrival: false,
                every_seconds: None,
            },
            delivery: "none".to_owned(),
            learning: false,
            binding: None,
            criteria: QuestionCriteria::default(),
            audience: QuestionAudience::Asker,
            posture: None,
            media: QuestionMedia::default(),
            deadline_ms: None,
            artifacts: Vec::new(),
        },
        7,
    )?;
    assert_eq!(record.definition.question.version, 1);
    let question = record.definition.question.id;
    let question_version = 1;
    let pin_a = ProviderPin {
        rung: DecisionRung::Big,
        model: "fixture/answerer-a".to_owned(),
        version: "v1".to_owned(),
    };
    let pin_b = ProviderPin {
        rung: DecisionRung::Big,
        model: "fixture/answerer-b".to_owned(),
        version: "v1".to_owned(),
    };
    assert_ne!(pin_a, pin_b);

    let before = vault.eval_cohort_exposure(&scored.corpus.cohort.id)?;
    let input = vault.open_question_head_trial(
        &owner,
        &run,
        question,
        question_version,
        vec![pin_a.clone()],
    )?;
    assert_eq!(
        vault
            .eval_cohort_exposure(&scored.corpus.cohort.id)?
            .candidates,
        before.candidates + 1
    );
    assert_eq!(
        input.held_out_jsonl,
        vault.read_training_artifact(&scored.corpus.held_out)?
    );
    let rows: Vec<Value> = input
        .held_out_jsonl
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("held-out row JSON"))
        .collect();
    assert_eq!(rows.len(), HELD_OUT_FAMILIES);
    let expected_rows: BTreeSet<&str> = scored
        .corpus
        .rows
        .iter()
        .filter(|row| row.side == SplitSide::HeldOut)
        .map(|row| row.receipt.as_str())
        .collect();
    assert_eq!(
        rows.iter()
            .map(|row| row["row"].as_str().expect("row id"))
            .collect::<BTreeSet<_>>(),
        expected_rows
    );
    let opened = vault.training_question_trial(&run)?.expect("open trial");
    assert_eq!(opened.question, question);
    assert_eq!(opened.question_version, question_version);
    assert_eq!(opened.exposure, input.exposure);
    assert_eq!(opened.incumbent_head, None);
    assert_eq!(opened.answerer, vec![pin_a.clone()]);
    assert!(opened.measured.is_none());
    assert!(!opened.wins());

    let refused = refusal(vault.approve_training_question_head(
        &owner,
        &run,
        question,
        question_version,
        SwapChoice::Evaluated,
        std::slice::from_ref(&pin_a),
    ));
    assert!(refused.contains("no won paired trial"), "{refused}");
    assert_eq!(
        vault.training_run(&run)?.expect("run").state,
        TrainingState::Scored
    );
    assert!(
        vault
            .training_question_head(question, question_version)?
            .is_none()
    );
    assert!(vault.training_run_question_head(&run)?.is_none());

    let cases: Vec<QuestionTrialCase> = rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let row_id = row["row"].as_str().expect("row id");
            let family = EntityId::from_hex(row["source_family"].as_str().expect("source family"))
                .expect("source family id");
            let split = scored
                .corpus
                .rows
                .iter()
                .find(|split| split.receipt == row_id)
                .expect("held-out split row");
            assert_eq!(split.side, SplitSide::HeldOut);
            assert_eq!(family, split.family);
            let label = match row["label"]["answer"].as_str().expect("answer label") {
                "yes" => true,
                "no" => false,
                answer => panic!("unexpected label: {answer}"),
            };
            let incumbent = if label {
                0.5 + index as f64 * 0.01
            } else {
                0.5 - index as f64 * 0.01
            };
            QuestionTrialCase {
                row: row_id.to_owned(),
                family,
                label,
                head: Some(if label { 0.9 } else { 0.1 }),
                head_ms: 1.0,
                incumbent: Some(incumbent),
                retest: Some(incumbent),
                incumbent_ms: 10.0,
                incumbent_pin: Some(pin_a.clone()),
                incumbent_cost_per_thousand: Some(2.0),
            }
        })
        .collect();
    assert_eq!(
        cases
            .iter()
            .map(|case| case.family)
            .collect::<BTreeSet<_>>()
            .len(),
        HELD_OUT_FAMILIES
    );
    let trial = vault.record_question_head_trial(&run, &input.exposure.id, &cases)?;
    assert!(trial.wins(), "{trial:?}");
    let measured = trial.measured.as_ref().expect("measured trial");
    assert_eq!(measured.cases, HELD_OUT_FAMILIES as u64);
    assert_eq!(measured.families, HELD_OUT_FAMILIES as u64);
    assert_eq!(measured.unknown_cases, 0);
    assert!(measured.gap.is_none());
    assert!(measured.quality_low.expect("quality interval") > 0.0);
    assert_eq!(measured.noise, Some(0.0));
    assert_eq!(measured.head_cost_per_thousand, 0.0);
    assert_eq!(measured.incumbent_cost_per_thousand, Some(2.0));
    assert_eq!(vault.training_question_trial(&run)?, Some(trial.clone()));

    let refused = refusal(vault.approve_training_question_head(
        &owner,
        &run,
        question,
        question_version,
        SwapChoice::Evaluated,
        std::slice::from_ref(&pin_b),
    ));
    assert!(refused.contains("no won paired trial"), "{refused}");
    assert_eq!(
        vault.training_run(&run)?.expect("run").state,
        TrainingState::Scored
    );
    assert!(
        vault
            .training_question_head(question, question_version)?
            .is_none()
    );
    assert!(vault.training_run_question_head(&run)?.is_none());

    let binding = vault.approve_training_question_head(
        &owner,
        &run,
        question,
        question_version,
        SwapChoice::Evaluated,
        std::slice::from_ref(&pin_a),
    )?;
    assert_eq!(binding.trial, Some(trial.clone()));
    assert_eq!(binding.run, run);
    assert_eq!(binding.question, question);
    assert_eq!(binding.question_version, question_version);
    assert_eq!(binding.choice, SwapChoice::Evaluated);
    assert_eq!(
        vault.training_run(&run)?.expect("run").state,
        TrainingState::Bound
    );
    assert_eq!(
        vault.training_question_head(question, question_version)?,
        Some(binding.clone())
    );
    assert_eq!(
        vault.training_run_question_head(&run)?,
        Some(binding.clone())
    );

    assert_eq!(
        vault.unbind_training_question_head(&owner, question, question_version)?,
        Some(binding)
    );
    assert_eq!(
        vault.training_run(&run)?.expect("run").state,
        TrainingState::Scored
    );
    let reopened = vault.open_question_head_trial(
        &owner,
        &run,
        question,
        question_version,
        vec![pin_a.clone()],
    )?;
    assert_ne!(reopened.exposure.id, input.exposure.id);
    assert_eq!(reopened.held_out_jsonl, input.held_out_jsonl);
    let replacement = vault
        .training_question_trial(&run)?
        .expect("replacement trial");
    assert_eq!(replacement.exposure, reopened.exposure);
    assert_eq!(replacement.incumbent_head, None);
    assert!(replacement.measured.is_none());
    let unpriced_cases: Vec<QuestionTrialCase> = cases
        .into_iter()
        .map(|mut case| {
            case.incumbent_cost_per_thousand = None;
            case
        })
        .collect();
    let losing = vault.record_question_head_trial(&run, &reopened.exposure.id, &unpriced_cases)?;
    let measured = losing.measured.as_ref().expect("measured unpriced trial");
    assert!(measured.quality_low.expect("quality interval") > 0.0);
    assert_eq!(measured.unknown_cases, 0);
    assert_eq!(measured.incumbent_cost_per_thousand, None);
    assert!(!losing.wins(), "{losing:?}");
    assert_eq!(vault.training_question_trial(&run)?, Some(losing.clone()));
    let refused = refusal(vault.approve_training_question_head(
        &owner,
        &run,
        question,
        question_version,
        SwapChoice::Evaluated,
        std::slice::from_ref(&pin_a),
    ));
    assert!(refused.contains("no won paired trial"), "{refused}");
    assert_eq!(
        vault.training_run(&run)?.expect("run").state,
        TrainingState::Scored
    );
    assert!(
        vault
            .training_question_head(question, question_version)?
            .is_none()
    );
    assert!(vault.training_run_question_head(&run)?.is_none());
    let choice = SwapChoice::ExplicitOverride {
        reason: "owner accepts the head without an incumbent cost receipt".to_owned(),
    };
    let binding = vault.approve_training_question_head(
        &owner,
        &run,
        question,
        question_version,
        choice.clone(),
        std::slice::from_ref(&pin_a),
    )?;
    assert_eq!(binding.trial, Some(losing));
    assert_eq!(binding.choice, choice);
    assert_eq!(
        vault.training_run(&run)?.expect("run").state,
        TrainingState::Bound
    );
    assert_eq!(
        vault.training_question_head(question, question_version)?,
        Some(binding.clone())
    );
    assert_eq!(vault.training_run_question_head(&run)?, Some(binding));
    Ok(())
}

/// A held-out result for `input` on the returned `run`, as an evaluator
/// that kept its verifier log reports it.
fn held_out_result(
    vault: &Vault,
    run: &TrainingRun,
    input: &TrainingEvalInput,
) -> Result<HeldOutResult> {
    let log = vault.keep_training_verifier_log_for_run(
        &run.id,
        "evaluation.json",
        b"{\"passed\":true}",
    )?;
    Ok(HeldOutResult {
        exposure: input.exposure.id,
        checkpoint_blake3: input.checkpoint.content_hash()?,
        held_out_blake3: *blake3::hash(&input.held_out_jsonl).as_bytes(),
        harness: input.harness.clone(),
        cases: run
            .corpus
            .rows
            .iter()
            .filter(|row| row.side == SplitSide::HeldOut)
            .count() as u64,
        metrics: BTreeMap::from([("agreement".to_owned(), 1.0)]),
        calibration: Some(CalibrationResult {
            temperature: 1.0,
            brier_score: 0.0,
            calibration_error: 0.0,
        }),
        verifier_logs: vec![log],
        passed: true,
    })
}

/// LEARN-GRANT = A on the execute path: each writer an execute starts (the
/// dispatch, a hold, the evaluation claim) admits the execute's caller in its
/// own snapshot. A caller it does not admit moves nothing; the owner's own
/// caller dispatches and claims as the Coach does.
#[test]
fn an_execute_caller_the_writer_does_not_admit_moves_no_run() -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime")
        .block_on(caller_the_writer_does_not_admit())
}

async fn caller_the_writer_does_not_admit() -> Result<()> {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault.authenticate_owner(actor, "principal:owner", true, GateDecisionId::now())?;
    let (run, connector, admission) = authorized_question_run(&vault, &owner, 1)?;
    // An agent no Grant names: the writers refuse it.
    let stranger = TrainingRunCaller::new(EntityId::now(), EdgeActorClass::Agent);

    let refused = refusal(
        vault
            .execute_authorized_training_pack_for(
                &run,
                &admission,
                &connector,
                &FixtureTrainer,
                Some(stranger),
            )
            .await,
    );
    assert!(refused.contains("execute caller"), "{refused}");
    let held = refusal(vault.hold_training_run_for(
        &run,
        "training.no_connector",
        "fixture: no trainer adapter",
        7,
        Some(&stranger),
    ));
    assert!(held.contains("execute caller"), "{held}");
    let authorized = vault.training_run(&run)?.expect("run");
    assert_eq!(authorized.state, TrainingState::Authorized);
    assert!(authorized.dispatch.is_none(), "no dispatch was recorded");
    assert!(authorized.hold.is_none(), "no hold was written");

    // The owner's own caller dispatches, under a fresh admission: the
    // refused dispatch's permit never started.
    let owner_caller = TrainingRunCaller::new(actor, EdgeActorClass::Human);
    let returned = vault
        .execute_authorized_training_pack_for(
            &run,
            &question_admission(&authorized, &connector),
            &connector,
            &FixtureTrainer,
            Some(owner_caller),
        )
        .await?;
    assert_eq!(returned.state, TrainingState::Returned);
    let served = vault
        .eval_cohort_exposure(&returned.corpus.cohort.id)?
        .candidates;
    let claim = refusal(vault.claim_training_evaluation(&run, Some(&stranger)));
    assert!(claim.contains("execute caller"), "{claim}");
    assert!(
        vault
            .training_run(&run)?
            .expect("run")
            .eval_exposure
            .is_none(),
        "a refused claim attaches no exposure"
    );
    assert_eq!(
        vault
            .eval_cohort_exposure(&returned.corpus.cohort.id)?
            .candidates,
        served,
        "a refused claim counts no serving"
    );
    assert!(
        vault
            .claim_training_evaluation(&run, Some(&owner_caller))?
            .is_some()
    );
    Ok(())
}

/// D3: one evaluation holds a returned run at a time, whoever asks. A second
/// claim counts no serving and gets none; an evaluator that failed releases
/// its claim, and the next claim is a new counted serving. Only the claim
/// the run holds records a result.
#[test]
fn a_returned_run_serves_its_held_out_to_one_evaluation_at_a_time() -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime")
        .block_on(one_evaluation_at_a_time())
}

async fn one_evaluation_at_a_time() -> Result<()> {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault.authenticate_owner(actor, "principal:owner", true, GateDecisionId::now())?;
    let (run, connector, admission) = authorized_question_run(&vault, &owner, 1)?;
    let returned = vault
        .execute_authorized_training_pack(&run, &admission, &connector, &FixtureTrainer)
        .await?;
    assert_eq!(returned.state, TrainingState::Returned);
    let cohort = returned.corpus.cohort.id;
    let served = vault.eval_cohort_exposure(&cohort)?.candidates;

    let first = vault
        .claim_training_evaluation(&run, None)?
        .expect("the first claim holds the run");
    assert_eq!(vault.eval_cohort_exposure(&cohort)?.candidates, served + 1);
    assert!(
        vault.claim_training_evaluation(&run, None)?.is_none(),
        "a second evaluation waits on the first"
    );
    let open = refusal(vault.open_training_held_out(&run));
    assert!(open.contains("no other evaluation holds"), "{open}");
    assert_eq!(
        vault.eval_cohort_exposure(&cohort)?.candidates,
        served + 1,
        "a claim another evaluation holds counts no serving"
    );
    assert_eq!(
        vault.training_run(&run)?.expect("run").eval_exposure,
        Some(first.exposure.clone())
    );

    // The first evaluator failed: its release lets the next claim serve.
    vault.release_training_evaluation(&run, &first.exposure.id)?;
    let second = vault
        .claim_training_evaluation(&run, None)?
        .expect("a released run is claimed again");
    assert_ne!(second.exposure.id, first.exposure.id);
    assert_eq!(vault.eval_cohort_exposure(&cohort)?.candidates, served + 2);
    // A late release of the first claim leaves the second in place.
    vault.release_training_evaluation(&run, &first.exposure.id)?;
    assert_eq!(
        vault.training_run(&run)?.expect("run").eval_exposure,
        Some(second.exposure.clone())
    );

    let stale = refusal(
        vault.record_training_evaluation(&run, &held_out_result(&vault, &returned, &first)?),
    );
    assert!(stale.contains("exposure"), "{stale}");
    let scored =
        vault.record_training_evaluation(&run, &held_out_result(&vault, &returned, &second)?)?;
    assert_eq!(scored.state, TrainingState::Scored);
    assert!(
        vault.claim_training_evaluation(&run, None)?.is_none(),
        "a scored run serves no further evaluation"
    );
    assert_eq!(vault.eval_cohort_exposure(&cohort)?.candidates, served + 2);
    Ok(())
}
