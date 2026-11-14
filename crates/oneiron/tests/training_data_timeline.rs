//! ARCH-0053 #training-timeline (census L1-22): a run that changes its data
//! mixture or restarts from an earlier checkpoint keeps a data timeline on
//! its result. The receipt records the step and token boundary, the pinned
//! mixture with its weights, and the parent checkpoint with the reason;
//! planned phases stay apart from executed ones, and a failed attempt stays
//! on the record. A timeline whose restart names no reason, or whose phase
//! goes on after a failed one, refuses the completion.
//! The upstream trainer is a local fake; custody and every run write are real.
//! The assertions read the result as JSON, so this file builds on a tree
//! without the typed timeline too.

use std::collections::BTreeSet;
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
    CandleParityCheck, CheckpointFileKind, CheckpointFileUpload, CheckpointUpload, ComputeChoice,
    DetectorCorpusRef, ProbeCase, ProbeMeasurement, QUESTION_LABEL_SCHEMA, QUESTION_RENDERER,
    QuestionExportCheck, QuestionTarget, SourcePin, SplitPolicy, TrainOutput, TrainRequest,
    TrainingConnector, TrainingDeclarationPin, TrainingFuture, TrainingPackDraft, TrainingPlan,
    TrainingRun, TrainingState, TrainingTarget,
};
use oneiron::{EntityId, Result, Vault, VaultConfig};
use serde_json::{Value, json};

fn source_pin() -> SourcePin {
    SourcePin {
        repository: "fixture/timeline".to_owned(),
        revision: "2222222222222222222222222222222222222222".to_owned(),
    }
}

fn json_hash(value: &Value) -> [u8; 32] {
    let bytes = oneiron::llm::canonical_json_bytes(value).expect("canonical fixture JSON");
    *blake3::hash(&bytes).as_bytes()
}

fn hex_digest(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex().to_string()
}

fn checkpoint_upload(model: ModelId) -> CheckpointUpload {
    // Completion checks byte custody, not model loading. No trainer or loader runs.
    let bytes = b"timeline checkpoint custody fixture".to_vec();
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

/// Returns a passing question head with the receipt it was built with; the
/// engine checks and retains it normally.
struct TimelineTrainer {
    receipt: Value,
}

impl TrainingConnector for TimelineTrainer {
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
                receipt: self.receipt.clone(),
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

/// A fresh vault and its owner.
fn owned_vault(dir: &tempfile::TempDir) -> Result<(Vault, AuthenticatedOwner)> {
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault.authenticate_owner(actor, "principal:owner", true, GateDecisionId::now())?;
    Ok((vault, owner))
}

/// A prepared question run on one sealed held-out family, as
/// question_head_binding.rs prepares it.
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
        (held_out, "yes", "Can someone explain chart 0?"),
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
    let connector = PaidConnector {
        connector: "fixture-trainer".to_owned(),
        route: OfferRoute::new("fixture-trainer", "device").expect("local route"),
        locality: ModelLocality::OnDevice,
        payer: Payer::Local,
        credential_binding: None,
        catalog_revision: None,
        custody: KeyCustody::Keyless,
        unit_cost: 1,
        cost_unit: LeaseUnit::new("fixture-units").expect("cost unit"),
        rates: Vec::new(),
    };
    let draft = TrainingPackDraft {
        plan: TrainingPlan {
            target: TrainingTarget::Question { question },
            seat,
            starting_checkpoint,
            purpose: "exercise the run's data timeline".to_owned(),
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
    Ok((run, connector))
}

/// Prepares and authorizes a run, then executes it with a trainer that
/// returns `receipt`: the run's id and what the execution answered.
async fn execute_with_receipt(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    receipt: Value,
) -> Result<(EntityId, Result<TrainingRun>)> {
    let (prepared, connector) = prepare_question_run(vault, owner)?;
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
        owner,
        &prepared.id,
        &prepared.spec_blake3,
        TrainingDeclarationPin::of(&declaration)?,
        6,
    )?;
    assert_eq!(authorized.state, TrainingState::Authorized);
    let executed = vault
        .execute_authorized_training_pack(
            &prepared.id,
            &admission,
            &connector,
            &TimelineTrainer { receipt },
        )
        .await;
    Ok((prepared.id, executed))
}

/// A mixture pinned by the hash of its name, with these source weights.
fn mixture(name: &str, weights: &[(&str, f64)]) -> Value {
    let weights: serde_json::Map<String, Value> = weights
        .iter()
        .map(|(source, weight)| ((*source).to_owned(), json!(weight)))
        .collect();
    json!({"definition_blake3": hex_digest(name), "weights": weights})
}

fn boundary(step: u64, tokens: u64) -> Value {
    json!({"step": step, "tokens": tokens})
}

/// The result's timeline as JSON; null when the result keeps none.
fn result_timeline(run: &TrainingRun) -> Value {
    let result = run
        .result
        .as_ref()
        .expect("a returned run keeps its result");
    let result = serde_json::to_value(result).expect("result JSON");
    result.get("timeline").cloned().unwrap_or(Value::Null)
}

/// This crate's tokio has `macros` only under the `sync` feature, so each
/// test drives its steps on a runtime of its own.
fn block_on<F: std::future::Future<Output = Result<()>>>(future: F) -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime")
        .block_on(future)
}

#[test]
fn a_mixture_change_a_failed_attempt_and_a_restart_stay_on_the_run_result() -> Result<()> {
    block_on(keeps_the_timeline())
}

async fn keeps_the_timeline() -> Result<()> {
    let dir = tempfile::tempdir().expect("temporary vault");
    let (vault, owner) = owned_vault(&dir)?;
    let general = mixture("mixture/general-v1", &[("chat", 0.75), ("docs", 0.25)]);
    let focused = mixture("mixture/focused-v1", &[("chat", 0.5), ("tickets", 0.5)]);
    let timeline = json!({
        "planned": [
            {"from": boundary(0, 0), "mixture": general},
            {"from": boundary(1200, 4_915_200), "mixture": focused},
        ],
        "executed": [
            {
                "from": boundary(0, 0),
                "to": boundary(1200, 4_915_200),
                "mixture": general,
                "outcome": "completed",
            },
            {
                "from": boundary(1200, 4_915_200),
                "to": boundary(1800, 7_372_800),
                "mixture": focused,
                "outcome": "failed",
            },
            {
                "from": boundary(1500, 6_144_000),
                "to": boundary(2400, 9_830_400),
                "mixture": focused,
                "parent": {
                    "step": 1500,
                    "blake3": hex_digest("checkpoint/step-1500"),
                    "reason": "loss diverged after step 1800; restarted from step 1500",
                },
                "outcome": "completed",
            },
        ],
    });
    let receipt = json!({"fixture": "timeline", "timeline": timeline});
    let (run, executed) = execute_with_receipt(&vault, &owner, receipt).await?;
    let returned = executed?;
    assert_eq!(returned.state, TrainingState::Returned);
    assert!(returned.result.as_ref().expect("result").checks.passed());

    // The result keeps the whole timeline: the planned phases apart from
    // the executed ones, the failed attempt, and the restart's parent
    // checkpoint with its reason.
    let kept = result_timeline(&returned);
    assert_eq!(
        kept, timeline,
        "the run's result keeps the trainer's timeline"
    );
    assert_eq!(kept["planned"].as_array().map(Vec::len), Some(2));
    assert_eq!(kept["executed"][1]["outcome"], "failed");
    assert_eq!(
        kept["executed"][2]["parent"]["reason"],
        "loss diverged after step 1800; restarted from step 1500"
    );

    // The stored run row reads the same timeline back.
    let stored = vault.training_run(&run)?.expect("stored run");
    assert_eq!(result_timeline(&stored), timeline);
    Ok(())
}

#[test]
fn a_restart_without_a_reason_or_a_phase_going_on_after_a_failure_refuses_the_completion()
-> Result<()> {
    block_on(refuses_a_malformed_timeline())
}

async fn refuses_a_malformed_timeline() -> Result<()> {
    let general = mixture("mixture/general-v1", &[("chat", 1.0)]);
    let failed = json!({
        "from": boundary(0, 0),
        "to": boundary(1200, 4_915_200),
        "mixture": general,
        "outcome": "failed",
    });
    let cases = [
        (
            "a restart with a blank reason",
            json!({
                "from": boundary(1000, 4_096_000),
                "to": boundary(2000, 8_192_000),
                "mixture": general,
                "parent": {
                    "step": 1000,
                    "blake3": hex_digest("checkpoint/step-1000"),
                    "reason": "   ",
                },
                "outcome": "completed",
            }),
        ),
        (
            "a phase that goes on after a failed one, naming no parent",
            json!({
                "from": boundary(1200, 4_915_200),
                "to": boundary(2000, 8_192_000),
                "mixture": general,
                "outcome": "completed",
            }),
        ),
    ];
    for (case, second) in cases {
        let dir = tempfile::tempdir().expect("temporary vault");
        let (vault, owner) = owned_vault(&dir)?;
        let receipt = json!({
            "fixture": "timeline",
            "timeline": {"executed": [failed.clone(), second]},
        });
        let (run, executed) = execute_with_receipt(&vault, &owner, receipt).await?;
        let refused = executed
            .err()
            .unwrap_or_else(|| panic!("{case}: the completion is refused"))
            .to_string();
        assert!(refused.contains("data timeline"), "{case}: {refused}");
        // The refused completion fails the run as a failed train does and
        // keeps no result.
        let stored = vault.training_run(&run)?.expect("stored run");
        assert_eq!(stored.state, TrainingState::ConnectorFailed, "{case}");
        assert!(stored.result.is_none(), "{case}");
    }
    Ok(())
}
