//! FIX 3864: an unmeasured question head binds only on the owner's reason.
//! The upstream trainer is a local fake; custody and every run write are real.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
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
    QUESTION_LABEL_SCHEMA, QUESTION_RENDERER, QuestionExportCheck, QuestionTarget, SourcePin,
    SplitPolicy, SwapChoice, TrainOutput, TrainRequest, TrainingConnector, TrainingDeclarationPin,
    TrainingFuture, TrainingPackDraft, TrainingPlan, TrainingRun, TrainingState, TrainingTarget,
};
use oneiron::{EntityId, Result, Vault, VaultConfig};
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
) -> Result<(TrainingRun, PaidConnector)> {
    let seat = EvalSeat::Decision;
    let training_yes = EntityId::now().to_hex();
    let training_no = EntityId::now().to_hex();
    let held_out = EntityId::now().to_hex();
    vault.assign_eval_family(
        &seat,
        &BTreeSet::from([training_yes.clone(), training_no.clone()]),
        FamilyPurpose::Development,
        1,
    )?;
    vault.assign_eval_family(
        &seat,
        &BTreeSet::from([held_out.clone()]),
        FamilyPurpose::SealedConfirmation,
        1,
    )?;
    let case = vault.record_eval_case(
        &EvalCaseDraft {
            seat: seat.clone(),
            kind: DerivationKind::Receipt,
            receipts: vec![held_out.clone()],
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
    for (receipt, answer, text) in [
        (training_yes, "yes", "Please help with the report"),
        (training_no, "no", "The report is finished"),
        (held_out, "yes", "Can someone explain this chart?"),
    ] {
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
    let (prepared, connector) = prepare_question_run(&vault, &owner)?;
    let run = prepared.id;
    let declaration = RunDeclaration::declared(BudgetLine {
        limit_units: 1,
        reserve_units: 1,
        unit: connector.cost_unit.clone(),
    })
    .with_connector(connector.connector.clone());
    let admission = RunAdmission::new(
        prepared.admission_ref(),
        declaration.clone(),
        None,
        Arc::new(MemoryReceipts::default()),
    );
    let authorized = vault.authorize_training_pack(
        &owner,
        &run,
        &prepared.spec_blake3,
        TrainingDeclarationPin::of(&declaration)?,
        6,
    )?;
    assert_eq!(authorized.state, TrainingState::Authorized);
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
            cases: 1,
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

    // The approval path keys by id and version without looking up a typed question.
    let question = EntityId::now();
    let question_version = 1;
    let refused = refusal(vault.approve_training_question_head(
        &owner,
        &run,
        question,
        question_version,
        SwapChoice::Evaluated,
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

    let repeated =
        vault.approve_training_question_head(&owner, &run, question, question_version, choice)?;
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
