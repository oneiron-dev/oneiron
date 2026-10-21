//! `oneiron.training-pack.job/1` and its receipt (FIX 7263): the request the
//! question-head worker reads and the `receipt.json` it writes, as
//! `scripts/training_pack/README.md` gives them. Every request object is
//! closed, since the worker refuses any key it does not name. The receipt is
//! read for the facts that bind it to this job; the whole file rides on the
//! result as the producer's evidence, and the engine re-hashes every byte.
use std::path::{Component, Path};

use oneiron::training_pack::{
    CheckpointFileKind, CheckpointFileUpload, CheckpointUpload, DetectorProvenance, ProbeCase,
    ProbeMeasurement, QuestionExportCheck, QuestionTarget, SourcePin, TrainOutput, TrainRequest,
};
use oneiron::{Error, ModelId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::models::TRAINING_SERVICE_UNIT;

const JOB_FORMAT: &str = "oneiron.training-pack.job/1";
const RECEIPT_FORMAT: &str = "oneiron.training-pack.receipt/1";
/// The one recipe the worker trains, as a plan's `settings.recipe` names it.
pub(super) const RECIPE: &str = "oneiron.frozen-encoder-binary-head/1";
/// The compute kind of a job an engine run authorized.
const ENGINE_RUN: &str = "engine_run";
const QUESTION: &str = "question";
/// The two terminal statuses that carry a complete result.
const TRAINED: &str = "trained";
const PARITY_FAILED: &str = "export_parity_failed";

pub(super) fn invalid(reason: impl Into<String>) -> Error {
    Error::InvalidConfig(reason.into())
}

pub(super) fn blake3_hex(bytes: &[u8; 32]) -> String {
    blake3::Hash::from(*bytes).to_hex().to_string()
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// What a job dispatches: the run's question, its corpus's provenance and
/// the run admission its permit was taken under.
pub(super) struct JobFacts<'a> {
    pub(super) request: &'a TrainRequest,
    pub(super) question: &'a QuestionTarget,
    pub(super) provenance: &'a DetectorProvenance,
    /// `compute.reference`: the run admission (`training_pack:<run>`).
    pub(super) reference: &'a str,
}

impl<'a> JobFacts<'a> {
    /// A question run with its corpus's split and consent receipts, or a
    /// refusal before any directory or process exists.
    pub(super) fn of(request: &'a TrainRequest, reference: &'a str) -> oneiron::Result<Self> {
        let question = request
            .plan
            .target
            .question()
            .ok_or_else(|| invalid("this trainer trains a question head, never a role"))?;
        let provenance = request
            .detector
            .as_ref()
            .filter(|provenance| {
                !provenance.split_receipt.trim().is_empty()
                    && !provenance.consent_receipt.trim().is_empty()
            })
            .ok_or_else(|| {
                invalid("a question run needs its corpus's split and consent receipts")
            })?;
        Ok(Self {
            request,
            question,
            provenance,
            reference,
        })
    }
}

/// One file the worker reads, by its name under a pinned directory: its
/// SHA-256, BLAKE3 and size over the bytes written there.
#[derive(Debug, Clone, Serialize)]
pub(super) struct FilePinWire {
    pub(super) file: String,
    pub(super) sha256: String,
    pub(super) blake3: String,
    pub(super) bytes: u64,
}

impl FilePinWire {
    pub(super) fn of(file: &str, bytes: &[u8]) -> Self {
        Self {
            file: file.to_owned(),
            sha256: sha256_hex(bytes),
            blake3: blake3_hex(blake3::hash(bytes).as_bytes()),
            bytes: bytes.len() as u64,
        }
    }
}

/// The starting bundle's four files, by the worker's name for each.
#[derive(Debug, Clone, Serialize)]
pub(super) struct BaseFilesWire {
    pub(super) manifest: FilePinWire,
    pub(super) config: FilePinWire,
    pub(super) tokenizer: FilePinWire,
    pub(super) trunk: FilePinWire,
}

/// What a job's directory holds for the worker, as written there.
pub(super) struct StagedFiles {
    pub(super) base_dir: String,
    pub(super) base_source: SourcePin,
    pub(super) base: BaseFilesWire,
    pub(super) training_path: String,
    pub(super) training: FilePinWire,
}

#[derive(Serialize)]
struct TrainingJob<'a> {
    format: &'static str,
    run: String,
    spec_blake3: String,
    compute: ComputeWire<'a>,
    target: QuestionTargetWire<'a>,
    base: BaseWire<'a>,
    training: TrainingPinWire<'a>,
    provenance: &'a DetectorProvenance,
    settings: &'a Value,
    harness: &'a SourcePin,
    probes: &'a [ProbeCase],
    export_logit_tolerance: f64,
}

#[derive(Serialize)]
struct ComputeWire<'a> {
    kind: &'a str,
    reference: &'a str,
}

/// The job's `target`: the question with `kind`, its digest as hex.
#[derive(Serialize)]
struct QuestionTargetWire<'a> {
    kind: &'static str,
    question_id: &'a str,
    question_version: u32,
    definition: &'a Value,
    definition_blake3: String,
    family: &'a str,
    corpus_revision: &'a str,
    feature_schema: &'a str,
    label_schema: &'a str,
    renderer: &'a str,
    output_model: &'a ModelId,
}

#[derive(Serialize)]
struct BaseWire<'a> {
    model: &'a ModelId,
    source: &'a SourcePin,
    dir: &'a str,
    files: &'a BaseFilesWire,
}

#[derive(Serialize)]
struct TrainingPinWire<'a> {
    path: &'a str,
    sha256: &'a str,
    blake3: &'a str,
    bytes: u64,
}

/// The exact request bytes the worker is handed (`request.json`). Settings,
/// probes and tolerance are the plan's own values, with nothing defaulted.
pub(super) fn build_job(facts: &JobFacts<'_>, staged: &StagedFiles) -> oneiron::Result<Vec<u8>> {
    let (request, question) = (facts.request, facts.question);
    let job = TrainingJob {
        format: JOB_FORMAT,
        run: request.run.to_hex(),
        spec_blake3: blake3_hex(&request.spec_blake3),
        compute: ComputeWire {
            kind: ENGINE_RUN,
            reference: facts.reference,
        },
        target: QuestionTargetWire {
            kind: QUESTION,
            question_id: &question.question_id,
            question_version: question.question_version,
            definition: &question.definition,
            definition_blake3: blake3_hex(&question.definition_blake3),
            family: &question.family,
            corpus_revision: &question.corpus_revision,
            feature_schema: &question.feature_schema,
            label_schema: &question.label_schema,
            renderer: &question.renderer,
            output_model: &question.output_model,
        },
        base: BaseWire {
            model: &request.plan.starting_checkpoint.model,
            source: &staged.base_source,
            dir: &staged.base_dir,
            files: &staged.base,
        },
        training: TrainingPinWire {
            path: &staged.training_path,
            sha256: &staged.training.sha256,
            blake3: &staged.training.blake3,
            bytes: staged.training.bytes,
        },
        provenance: facts.provenance,
        settings: &request.plan.settings,
        harness: &request.plan.harness,
        probes: &request.plan.probes,
        export_logit_tolerance: request.plan.export_logit_tolerance,
    };
    serde_json::to_vec(&job).map_err(|_| invalid("the training job did not encode"))
}

/// What a receipt must echo to be this job's.
pub(super) struct Expected {
    /// SHA-256 and size of the `request.json` bytes the worker was handed.
    pub(super) request_sha256: String,
    pub(super) request_bytes: u64,
    pub(super) base_source: SourcePin,
    pub(super) manifest_sha256: String,
}

#[derive(Deserialize)]
struct StatusWire {
    format: String,
    status: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct ReceiptWire {
    run: String,
    spec_blake3: String,
    settings: Value,
    harness: SourcePin,
    authorization: AuthorizationWire,
    request: RequestWire,
    recipe: RecipeWire,
    load_sets: LoadSetsWire,
    probes: Vec<ProbeWire>,
    export_check: ExportCheckWire,
    service_units: ServiceUnitsWire,
}

#[derive(Deserialize)]
struct AuthorizationWire {
    kind: String,
    reference: String,
}

#[derive(Deserialize)]
struct RequestWire {
    sha256: String,
    bytes: u64,
}

#[derive(Deserialize)]
struct RecipeWire {
    recipe: String,
    renderer: String,
    target: RecipeTargetWire,
    base: RecipeBaseWire,
}

/// The receipt's recipe target: the job's, without its definition.
#[derive(Deserialize, PartialEq)]
struct RecipeTargetWire {
    kind: String,
    question_id: String,
    question_version: u64,
    definition_blake3: String,
    family: String,
    corpus_revision: String,
    feature_schema: String,
    label_schema: String,
    renderer: String,
    output_model: String,
}

impl RecipeTargetWire {
    fn of(question: &QuestionTarget) -> Self {
        Self {
            kind: QUESTION.to_owned(),
            question_id: question.question_id.clone(),
            question_version: u64::from(question.question_version),
            definition_blake3: blake3_hex(&question.definition_blake3),
            family: question.family.clone(),
            corpus_revision: question.corpus_revision.clone(),
            feature_schema: question.feature_schema.clone(),
            label_schema: question.label_schema.clone(),
            renderer: question.renderer.clone(),
            output_model: question.output_model.as_str().to_owned(),
        }
    }
}

#[derive(Deserialize)]
struct RecipeBaseWire {
    model: String,
    source: SourcePin,
    manifest_sha256: String,
}

#[derive(Deserialize)]
struct LoadSetsWire {
    training: LoadSetWire,
    export: LoadSetWire,
}

/// One load set: its model, its files and `PinnedCheckpoint::content_hash`.
#[derive(Deserialize)]
struct LoadSetWire {
    model: String,
    files: Vec<LoadFileWire>,
    load_set_blake3: String,
}

/// One load-set row. `name` is the checkpoint's identity; `path` is only
/// where the file sits under the output directory.
#[derive(Deserialize)]
struct LoadFileWire {
    name: String,
    kind: CheckpointFileKind,
    source: SourcePin,
    path: String,
    blake3: String,
}

#[derive(Deserialize)]
struct ProbeWire {
    probe_id: String,
    input_blake3: String,
    tokens_match: bool,
    training_logits: Vec<f64>,
    export_logits: Vec<f64>,
    training_argmax: u64,
    export_argmax: u64,
    max_logit_difference: f64,
}

#[derive(Deserialize)]
struct ExportCheckWire {
    tolerance: f64,
    finite: bool,
    tokens_match: bool,
    passed: bool,
}

#[derive(Deserialize)]
struct ServiceUnitsWire {
    unit: String,
    quantity: u64,
}

fn not_this_job(what: &str) -> Error {
    invalid(format!("the trainer's receipt is not this job's: {what}"))
}

/// A 64-hex hash in the canonical lowercase form.
fn hash_from_hex(field: &str, value: &str) -> oneiron::Result<[u8; 32]> {
    blake3::Hash::from_hex(value)
        .ok()
        .filter(|hash| hash.to_hex().as_str() == value)
        .map(|hash| *hash.as_bytes())
        .ok_or_else(|| invalid(format!("the trainer's receipt {field} is not a 64-hex hash")))
}

/// The worker's terminal result as the engine's return. A failed or
/// refused receipt, a partial or nonfinite one, or one that names another
/// run, spec, request, authorization, question, base, model or service unit
/// is a connector error; a complete, finite parity failure is a result whose
/// checks fail. Each load-set file is read whole from under `output`.
pub(super) fn decode_output(
    facts: &JobFacts<'_>,
    expected: &Expected,
    output: &Path,
    bytes: &[u8],
) -> oneiron::Result<TrainOutput> {
    let whole: Value =
        serde_json::from_slice(bytes).map_err(|_| invalid("the trainer's receipt is not JSON"))?;
    let status: StatusWire = serde_json::from_slice(bytes)
        .map_err(|_| invalid("the trainer's receipt has no format or status"))?;
    if status.format != RECEIPT_FORMAT {
        return Err(not_this_job("format"));
    }
    if status.status != TRAINED && status.status != PARITY_FAILED {
        return Err(invalid(format!(
            "the trainer ended {}: {}",
            status.status,
            status.reason.as_deref().unwrap_or("no reason given")
        )));
    }
    // A complete result names every field; a non-finite number is written
    // as text, so it does not read as one either.
    let receipt: ReceiptWire = serde_json::from_slice(bytes)
        .map_err(|_| invalid("the trainer's receipt is partial or not finite"))?;
    let (request, question) = (facts.request, facts.question);
    let base = &receipt.recipe.base;
    let check = &receipt.export_check;
    if receipt.run != request.run.to_hex()
        || receipt.spec_blake3 != blake3_hex(&request.spec_blake3)
    {
        return Err(not_this_job("run or spec"));
    }
    if receipt.authorization.kind != ENGINE_RUN
        || receipt.authorization.reference != facts.reference
    {
        return Err(not_this_job("authorization"));
    }
    if receipt.request.sha256 != expected.request_sha256
        || receipt.request.bytes != expected.request_bytes
    {
        return Err(not_this_job("request"));
    }
    if receipt.recipe.recipe != RECIPE
        || receipt.recipe.renderer != question.renderer
        || receipt.recipe.target != RecipeTargetWire::of(question)
    {
        return Err(not_this_job("recipe or question"));
    }
    if base.model != request.plan.starting_checkpoint.model.as_str()
        || base.source != expected.base_source
        || base.manifest_sha256 != expected.manifest_sha256
    {
        return Err(not_this_job("base"));
    }
    let model = question.output_model.as_str();
    if receipt.load_sets.training.model != model || receipt.load_sets.export.model != model {
        return Err(not_this_job("output model"));
    }
    if receipt.service_units.unit != TRAINING_SERVICE_UNIT {
        return Err(not_this_job("service unit"));
    }
    let finite = receipt.probes.iter().all(|probe| {
        probe.max_logit_difference.is_finite()
            && probe.max_logit_difference >= 0.0
            && probe
                .training_logits
                .iter()
                .chain(&probe.export_logits)
                .copied()
                .all(f64::is_finite)
    });
    if !finite || !check.finite {
        return Err(invalid("the trainer measured a non-finite logit"));
    }
    if check.tolerance != request.plan.export_logit_tolerance
        || check.tokens_match != receipt.probes.iter().all(|probe| probe.tokens_match)
        || check.passed != (status.status == TRAINED)
    {
        return Err(invalid(
            "the trainer's export check disagrees with its probes or status",
        ));
    }
    let question_check = QuestionExportCheck {
        finite: check.finite,
        tokens_match: check.tokens_match,
        passed: check.passed,
    };
    let probes = receipt
        .probes
        .into_iter()
        .map(|probe| {
            Ok(ProbeMeasurement {
                input_blake3: hash_from_hex("probe input_blake3", &probe.input_blake3)?,
                probe_id: probe.probe_id,
                training_argmax: probe.training_argmax,
                export_argmax: probe.export_argmax,
                max_logit_difference: probe.max_logit_difference,
            })
        })
        .collect::<oneiron::Result<Vec<_>>>()?;
    let LoadSetsWire { training, export } = receipt.load_sets;
    let probe_training_blake3 =
        hash_from_hex("training load_set_blake3", &training.load_set_blake3)?;
    let probe_export_blake3 = hash_from_hex("export load_set_blake3", &export.load_set_blake3)?;
    Ok(TrainOutput {
        run: request.run,
        spec_blake3: request.spec_blake3,
        probe_training_blake3,
        probe_export_blake3,
        training_checkpoint: upload(output, training, &question.output_model)?,
        exported_checkpoint: upload(output, export, &question.output_model)?,
        probes,
        settings: receipt.settings,
        harness: receipt.harness,
        receipt: whole,
        service_units: receipt.service_units.quantity,
        question_check: Some(question_check),
    })
}

/// One load set's files as returned bytes, each with the producer's BLAKE3,
/// which custody keeps beside what the bytes hash to.
fn upload(output: &Path, set: LoadSetWire, model: &ModelId) -> oneiron::Result<CheckpointUpload> {
    let files = set
        .files
        .into_iter()
        .map(|file| {
            let relative = Path::new(&file.path);
            if file.path.is_empty()
                || !relative
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)))
            {
                return Err(invalid(
                    "a load-set file sits outside the trainer's output directory",
                ));
            }
            Ok(CheckpointFileUpload {
                blake3: hash_from_hex("load-set file blake3", &file.blake3)?,
                bytes: std::fs::read(output.join(relative))?,
                name: file.name,
                kind: file.kind,
                source: file.source,
            })
        })
        .collect::<oneiron::Result<Vec<_>>>()?;
    Ok(CheckpointUpload {
        model: model.clone(),
        files,
    })
}
