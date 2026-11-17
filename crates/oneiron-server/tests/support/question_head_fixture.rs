//! The fixture of `tests/question_head_host.rs` (FIX 23586, 23587): a vault
//! holding a scored question run whose upstream trainer is a local fake that
//! returns a tiny loadable question head, a typed yes/no question, and a
//! test seat that answers with fixed numbers and counts what it is asked.
//! Custody, every run write and the head's load are real; the run follows
//! `crates/oneiron/tests/question_head_binding.rs`. Test-only: included
//! through `#[path = "support/question_head_fixture.rs"]`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use candle_core::{DType, Device, Tensor};
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::decision::questions::{
    QuestionActivation, QuestionAudience, QuestionCriteria, QuestionDefinitionInput, QuestionMedia,
    RefreshPolicy, create_question,
};
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionCall, DecisionClass, DecisionDial,
    DecisionPack, DecisionProvider, DecisionQuestionInput, DecisionRung, ProviderDecision,
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
use oneiron::training_pack::{
    CalibrationResult, CandleParityCheck, CheckpointFileKind, CheckpointFileUpload,
    CheckpointUpload, ComputeChoice, DetectorCorpusRef, HeldOutResult, ProbeCase, ProbeMeasurement,
    QUESTION_LABEL_SCHEMA, QUESTION_RENDERER, QuestionExportCheck, QuestionTarget, SourcePin,
    SplitPolicy, SplitSide, TrainOutput, TrainRequest, TrainingConnector, TrainingDeclarationPin,
    TrainingFuture, TrainingPackDraft, TrainingPlan, TrainingRun, TrainingState, TrainingTarget,
};
use oneiron::{EdgeActorClass, EntityId, Error, Vault, WriteActor};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The tiny encoder: as narrow and short as the loader takes. Its window
/// holds [CLS], 30 content tokens and [SEP].
const WIDTH: usize = 2;
const POSITIONS: usize = 32;
/// [UNK], [CLS] and [SEP]: every word of a rendered target reads as [UNK].
const VOCAB: usize = 3;
/// The fitted temperature the fixture's evaluation records.
pub(crate) const TEMPERATURE: f64 = 1.0;

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

fn invalid(detail: impl std::fmt::Display) -> Error {
    Error::InvalidConfig(format!("question head fixture: {detail}"))
}

fn upload(name: &str, kind: CheckpointFileKind, bytes: Vec<u8>) -> CheckpointFileUpload {
    CheckpointFileUpload {
        name: name.to_owned(),
        kind,
        source: source_pin(),
        blake3: *blake3::hash(&bytes).as_bytes(),
        bytes,
    }
}

/// `tensors` as one safetensors file's bytes.
fn safetensors(tensors: Vec<(&str, Tensor)>) -> oneiron::Result<Vec<u8>> {
    let dir = tempfile::tempdir().map_err(invalid)?;
    let path = dir.path().join("tensors.safetensors");
    let tensors: HashMap<&str, Tensor> = tensors.into_iter().collect();
    candle_core::safetensors::save(&tensors, &path).map_err(invalid)?;
    std::fs::read(&path).map_err(invalid)
}

fn zeros(shape: &[usize]) -> oneiron::Result<Tensor> {
    Tensor::zeros(shape, DType::F32, &Device::Cpu).map_err(invalid)
}

/// A one-layer GTE trunk whose every weight is zero: every window pools to
/// zero, so the head's raw logits are its bias.
fn trunk() -> oneiron::Result<Vec<u8>> {
    // `Backbone::load` reads the trunk under `encoder.`, and its layers under
    // `encoder.layer.<n>.` below that.
    let layer = "encoder.encoder.layer.0";
    let shapes: Vec<(String, Vec<usize>)> = vec![
        (
            "encoder.embeddings.word_embeddings.weight".to_owned(),
            vec![VOCAB, WIDTH],
        ),
        (
            "encoder.embeddings.LayerNorm.weight".to_owned(),
            vec![WIDTH],
        ),
        ("encoder.embeddings.LayerNorm.bias".to_owned(), vec![WIDTH]),
        (
            format!("{layer}.attention.qkv_proj.weight"),
            vec![3 * WIDTH, WIDTH],
        ),
        (format!("{layer}.attention.qkv_proj.bias"), vec![3 * WIDTH]),
        (
            format!("{layer}.attention.o_proj.weight"),
            vec![WIDTH, WIDTH],
        ),
        (format!("{layer}.attention.o_proj.bias"), vec![WIDTH]),
        (format!("{layer}.attn_ln.weight"), vec![WIDTH]),
        (format!("{layer}.attn_ln.bias"), vec![WIDTH]),
        // intermediate_size 1: the packed up and gate rows, no bias.
        (format!("{layer}.mlp.up_gate_proj.weight"), vec![2, WIDTH]),
        (format!("{layer}.mlp.down_proj.weight"), vec![WIDTH, 1]),
        (format!("{layer}.mlp.down_proj.bias"), vec![WIDTH]),
        (format!("{layer}.mlp_ln.weight"), vec![WIDTH]),
        (format!("{layer}.mlp_ln.bias"), vec![WIDTH]),
    ];
    let mut tensors = Vec::new();
    for (name, shape) in &shapes {
        tensors.push((name.as_str(), zeros(shape)?));
    }
    safetensors(tensors)
}

fn head(bias: [f32; 2]) -> oneiron::Result<Vec<u8>> {
    safetensors(vec![
        ("head.weight", zeros(&[2, WIDTH])?),
        (
            "head.bias",
            Tensor::new(&bias, &Device::Cpu).map_err(invalid)?,
        ),
    ])
}

fn config() -> Value {
    json!({
        "model_type": "new",
        "hidden_size": WIDTH,
        "num_hidden_layers": 1,
        "num_attention_heads": 1,
        "intermediate_size": 1,
        "vocab_size": VOCAB,
        "max_position_embeddings": POSITIONS,
        "type_vocab_size": 0,
        "layer_norm_eps": 1e-12,
        "hidden_act": "gelu",
        "position_embedding_type": "rope",
        "rope_theta": 10000.0
    })
}

fn special(id: u32, content: &str) -> Value {
    json!({
        "id": id, "content": content, "single_word": false, "lstrip": false,
        "rstrip": false, "normalized": false, "special": true
    })
}

/// A word-level tokenizer that wraps each window in [CLS] and [SEP].
fn tokenizer() -> Value {
    let piece = |kind: &str, id: &str, type_id: u32| json!({kind: {"id": id, "type_id": type_id}});
    json!({
        "version": "1.0",
        "truncation": null,
        "padding": null,
        "added_tokens": [special(0, "[UNK]"), special(1, "[CLS]"), special(2, "[SEP]")],
        "normalizer": null,
        "pre_tokenizer": {"type": "Whitespace"},
        "post_processor": {
            "type": "TemplateProcessing",
            "single": [
                piece("SpecialToken", "[CLS]", 0),
                piece("Sequence", "A", 0),
                piece("SpecialToken", "[SEP]", 0)
            ],
            "pair": [
                piece("SpecialToken", "[CLS]", 0),
                piece("Sequence", "A", 0),
                piece("SpecialToken", "[SEP]", 0),
                piece("Sequence", "B", 1),
                piece("SpecialToken", "[SEP]", 1)
            ],
            "special_tokens": {
                "[CLS]": {"id": "[CLS]", "ids": [1], "tokens": ["[CLS]"]},
                "[SEP]": {"id": "[SEP]", "ids": [2], "tokens": ["[SEP]"]}
            }
        },
        "decoder": null,
        "model": {
            "type": "WordLevel",
            "vocab": {"[UNK]": 0, "[CLS]": 1, "[SEP]": 2},
            "unk_token": "[UNK]"
        }
    })
}

fn json_bytes(value: &Value) -> oneiron::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(invalid)
}

/// The export a question-head trainer returns for `target`
/// (`training_pack/worker.py`, read by `QuestionHead::load`): the tiny trunk
/// and a head whose raw [no, yes] logits are `bias`, pinned by its
/// `classifier.json`. `without` leaves that file out of the load set.
pub(crate) fn head_export(
    target: &QuestionTarget,
    bias: [f32; 2],
    without: Option<&str>,
) -> oneiron::Result<CheckpointUpload> {
    let files = vec![
        upload(
            "config.json",
            CheckpointFileKind::Config,
            json_bytes(&config())?,
        ),
        upload(
            "tokenizer.json",
            CheckpointFileKind::Tokenizer,
            json_bytes(&tokenizer())?,
        ),
        upload("trunk.safetensors", CheckpointFileKind::Weights, trunk()?),
        upload("head.safetensors", CheckpointFileKind::Weights, head(bias)?),
    ];
    let pins: Vec<Value> = files
        .iter()
        .map(|file| {
            json!({
                "name": file.name,
                "sha256": format!("{:x}", Sha256::digest(&file.bytes)),
                "bytes": file.bytes.len(),
            })
        })
        .collect();
    let classifier = json!({
        "format": "oneiron.question-classifier/1",
        "model": target.output_model.as_str(),
        "recipe": "oneiron.frozen-encoder-binary-head/1",
        "renderer": QUESTION_RENDERER,
        "pooling": "window-mean-of-position-means/1",
        "label_order": ["no", "yes"],
        "dtype": "float32",
        "output": "raw_logits",
        "max_positions": POSITIONS,
        "target": {
            "kind": "question",
            "question_id": target.question_id,
            "question_version": target.question_version,
            "definition_blake3": blake3::Hash::from(target.definition_blake3).to_hex().to_string(),
            "family": target.family,
            "corpus_revision": target.corpus_revision,
            "feature_schema": target.feature_schema,
            "label_schema": target.label_schema,
            "renderer": target.renderer,
            "output_model": target.output_model,
        },
        "files": pins,
    });
    let mut files = files;
    files.push(upload(
        "classifier.json",
        CheckpointFileKind::Config,
        json_bytes(&classifier)?,
    ));
    files.retain(|file| Some(file.name.as_str()) != without);
    Ok(CheckpointUpload {
        model: target.output_model.clone(),
        files,
    })
}

/// The starting checkpoint: custody only; the fake trainer never reads it.
fn base_checkpoint() -> CheckpointUpload {
    let bytes = b"question-head base checkpoint custody fixture".to_vec();
    CheckpointUpload {
        model: ModelId::new("local/question-base@v1").expect("base model"),
        files: vec![upload(
            "model.safetensors",
            CheckpointFileKind::Weights,
            bytes,
        )],
    }
}

/// Returns `head_export` as the run's training and exported checkpoint,
/// with the checks a real export passes; the engine checks and keeps it.
pub(crate) struct HeadTrainer {
    pub(crate) bias: [f32; 2],
    pub(crate) without: Option<&'static str>,
}

impl TrainingConnector for HeadTrainer {
    fn train<'a>(
        &'a self,
        request: TrainRequest,
        _admission: &'a RunAdmission,
    ) -> TrainingFuture<'a> {
        Box::pin(async move {
            let TrainingTarget::Question { question } = &request.plan.target else {
                return Err(invalid("the fixture trains question heads only"));
            };
            let training_checkpoint = head_export(question, self.bias, self.without)?;
            let exported_checkpoint = head_export(question, self.bias, self.without)?;
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
                receipt: json!({"fixture": "question-head-host", "returned": true}),
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

/// Training families with a yes and a no row, and `held_out_families`
/// sealed families of one adjudicated yes row each, cut into one cohort.
/// Answers the training families' receipts, the held-out receipts and the
/// cohort.
fn eval_families(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    held_out_families: usize,
) -> oneiron::Result<(String, String, Vec<String>, EntityId)> {
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
                seat,
                from: 0,
                until: 4,
                rubric_revision: "fixture/rubric-v1".to_owned(),
                reference: false,
            }],
        },
        5,
    )?;
    assert_eq!(setup.cohorts_cut.len(), 1, "{setup:?}");
    Ok((training_yes, training_no, held_out, setup.cohorts_cut[0]))
}

/// The run's question target, as a trainer's plan names it.
fn question_target() -> QuestionTarget {
    let definition = json!({"question": "Does this target ask for help?"});
    QuestionTarget {
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
    }
}

/// The corpus rows: the two training rows, then one held-out row per
/// sealed family, each with a target and an empty context.
fn corpus_rows(
    target: &QuestionTarget,
    training_yes: String,
    training_no: String,
    held_out: Vec<String>,
) -> Vec<u8> {
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
            "question_id": target.question_id,
            "question_version": target.question_version,
            "corpus_revision": target.corpus_revision,
            "feature_schema": target.feature_schema,
            "label_schema": target.label_schema,
            "consent": {"basis": "owner", "receipt": "fixture/consent-v1"},
            "label": {"answer": answer, "unit": "target", "adjudication": "fixture/audit-v1"},
            "input": {"target": text, "context": []}
        });
        rows.extend(serde_json::to_vec(&row).expect("fixture row JSON"));
        rows.push(b'\n');
    }
    rows
}

fn prepare_question_run(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    held_out_families: usize,
) -> oneiron::Result<(TrainingRun, PaidConnector)> {
    let (training_yes, training_no, held_out, cohort) =
        eval_families(vault, owner, held_out_families)?;
    let target = question_target();
    let rows = corpus_rows(&target, training_yes, training_no, held_out);
    let corpus = DetectorCorpusRef {
        rows: vault.keep_training_verifier_log(owner, "detector-rows.jsonl", &rows)?,
    };
    let starting_checkpoint = vault.keep_training_checkpoint(owner, &base_checkpoint())?;
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
            target: TrainingTarget::Question { question: target },
            seat: EvalSeat::Decision,
            starting_checkpoint,
            purpose: "exercise the host's question heads".to_owned(),
            settings: json!({"fixture": true}),
            harness: source_pin(),
            probes: vec![ProbeCase {
                id: "fixture/probe".to_owned(),
                input: json!({"target": "Please explain the result", "context": []}),
            }],
            export_logit_tolerance: 0.001,
        },
        split: SplitPolicy {
            held_out_cohort: cohort,
        },
        compute: ComputeChoice::OwnerMachines,
        quantity: 1,
        consented_sources: Vec::new(),
    };
    let run = vault.prepare_question_training_pack(owner, &draft, &corpus, &connector)?;
    assert_eq!(run.state, TrainingState::Prepared);
    Ok((run, connector))
}

/// A question run trained by `trainer`, returned and scored at
/// [`TEMPERATURE`]: ready to bind or to try.
pub(crate) async fn scored_question_run(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    held_out_families: usize,
    trainer: &HeadTrainer,
) -> oneiron::Result<TrainingRun> {
    let (prepared, connector) = prepare_question_run(vault, owner, held_out_families)?;
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
    vault.authorize_training_pack(
        owner,
        &run,
        &prepared.spec_blake3,
        TrainingDeclarationPin::of(&declaration)?,
        6,
    )?;
    let returned = vault
        .execute_authorized_training_pack(&run, &admission, &connector, trainer)
        .await?;
    assert_eq!(returned.state, TrainingState::Returned);
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
                temperature: TEMPERATURE,
                brier_score: 0.0,
                calibration_error: 0.0,
            }),
            verifier_logs: vec![log],
            passed: true,
        },
    )?;
    assert_eq!(scored.state, TrainingState::Scored);
    Ok(scored)
}

/// The owner's typed yes/no question, asked only of the Big rung: a trial's
/// reads of it reach the seat there and no other rung.
pub(crate) fn big_rung_question(vault: &Vault, owner: EntityId) -> oneiron::Result<EntityId> {
    let record = create_question(
        vault,
        WriteActor::new(owner, EdgeActorClass::Human),
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
                first: DecisionRung::Big,
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
    Ok(record.definition.question.id)
}

/// A seat that answers every question with P(yes) `yes` (the first option
/// of a choice, the minimum of a score), or abstains once told to, after
/// `read` of wall clock; it counts the calls and the whole packs it is asked.
pub(crate) struct TestSeat {
    pin: ProviderPin,
    yes: f64,
    cost: Option<f64>,
    read: Duration,
    abstains: AtomicBool,
    calls: AtomicUsize,
    packs: AtomicUsize,
}

impl TestSeat {
    pub(crate) fn new(rung: DecisionRung, model: &str, yes: f64, cost: Option<f64>) -> Self {
        Self {
            pin: ProviderPin {
                rung,
                model: model.to_owned(),
                version: "v1".to_owned(),
            },
            yes,
            cost,
            read: Duration::ZERO,
            abstains: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            packs: AtomicUsize::new(0),
        }
    }

    /// This seat, taking `read` of wall clock for each answer.
    pub(crate) fn reading_for(mut self, read: Duration) -> Self {
        self.read = read;
        self
    }

    pub(crate) fn abstain_from_now(&self) {
        self.abstains.store(true, Ordering::SeqCst);
    }

    /// The single calls asked of it ([`DecisionProvider::decide`]).
    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// The whole packs asked of it ([`DecisionProvider::decide_pack`]).
    pub(crate) fn packs(&self) -> usize {
        self.packs.load(Ordering::SeqCst)
    }

    fn answer(&self, call: &DecisionCall<'_>) -> ProviderDecision {
        std::thread::sleep(self.read);
        let answer = match &call.question.contract {
            _ if self.abstains.load(Ordering::SeqCst) => None,
            AnswerContract::Noul => Some(DecisionAnswer::Noul(self.yes >= 0.5)),
            AnswerContract::Choice { options } => {
                options.first().cloned().map(DecisionAnswer::Choice)
            }
            AnswerContract::Score { min, .. } => Some(DecisionAnswer::Score(*min)),
            _ => None,
        };
        ProviderDecision {
            probability: answer.as_ref().map(|_| self.yes),
            answer: answer.unwrap_or(DecisionAnswer::Abstain),
            paired: None,
            person: None,
            served: None,
            cost_per_thousand: None,
        }
    }
}

impl DecisionProvider for TestSeat {
    fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }

    fn cost_per_thousand(&self) -> Option<f64> {
        self.cost
    }

    fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.answer(call))
    }

    fn decide_pack(&self, pack: &DecisionPack<'_>) -> oneiron::Result<Vec<ProviderDecision>> {
        self.packs.fetch_add(1, Ordering::SeqCst);
        Ok((0..pack.questions.len())
            .filter_map(|index| pack.call(index))
            .map(|call| self.answer(&call))
            .collect())
    }
}
