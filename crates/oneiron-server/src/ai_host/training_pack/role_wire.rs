//! `oneiron.training-pack.role-job/1` and its receipt (ROLE-TRAINING-RUN,
//! LEARN-TRAIN Q2): the request a role trainer's worker reads and the
//! `receipt.json` it writes, as `scripts/training_pack/README.md` gives
//! them. It is its own closed wire beside the question head's
//! (`wire`), which it never widens: a role job names the role, its seat and
//! the output model, the run's recipe, the starting checkpoint's files as
//! staged and the training split of the consented reservoir pairs. The
//! receipt is read for the facts that bind it to this job, including the
//! training rows the worker read; the whole file rides on the result as the
//! producer's evidence, and the engine re-hashes every returned byte.
use std::path::Path;

use oneiron::ModelId;
use oneiron::llm::manifest::ModelRole;
use oneiron::skill_optimize::EvalSeat;
use oneiron::training_pack::{
    CheckpointFileKind, ProbeCase, ProbeMeasurement, SourcePin, TrainOutput, TrainRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::wire::{
    AuthorizationWire, ENGINE_RUN, LoadSetsWire, RequestWire, ServiceUnitsWire, StatusWire,
    blake3_hex, hash_from_hex, invalid, not_this_job, sha256_hex, upload,
};
use crate::config::models::TRAINING_SERVICE_UNIT;

const JOB_FORMAT: &str = "oneiron.training-pack.role-job/1";
const RECEIPT_FORMAT: &str = "oneiron.training-pack.role-receipt/1";
/// The job target's kind.
const ROLE: &str = "role";
/// The one terminal status that carries a complete result. The engine's
/// own export check judges the probes, so a probe that flips is a result
/// whose check fails, never another status.
const TRAINED: &str = "trained";
/// What a role job's training file holds: the consented reservoir's chosen
/// and rejected pairs as `export_reservoir` writes them, one JSON object a
/// line.
const TRAINING_ROWS: &str = "oneiron.reservoir-pair/1";
/// How far a receipt's stated largest logit difference may sit from the one
/// its own logits give. The engine keeps the one the logits give.
const DIFFERENCE_SLACK: f64 = 1e-9;

/// What a role job dispatches: the run's role and output model, the recipe
/// its plan names and the run admission its permit was taken under.
pub(super) struct RoleJobFacts<'a> {
    pub(super) request: &'a TrainRequest,
    pub(super) role: ModelRole,
    pub(super) output_model: &'a ModelId,
    pub(super) recipe: &'a str,
    /// `compute.reference`: the run admission (`training_pack:<run>`).
    pub(super) reference: &'a str,
}

impl<'a> RoleJobFacts<'a> {
    /// A role run with its recipe, or a refusal before any directory or
    /// process exists.
    pub(super) fn of(request: &'a TrainRequest, reference: &'a str) -> oneiron::Result<Self> {
        let (role, binding) = request
            .plan
            .target
            .role_binding()
            .ok_or_else(|| invalid("this trainer trains a role, never a question head"))?;
        let recipe = recipe_of(&request.plan.settings)
            .ok_or_else(|| invalid("a role run's settings name its recipe"))?;
        Ok(Self {
            request,
            role,
            output_model: &binding.model,
            recipe,
            reference,
        })
    }
}

/// The recipe a plan's settings name (`settings.recipe`).
pub(super) fn recipe_of(settings: &Value) -> Option<&str> {
    settings
        .get("recipe")
        .and_then(Value::as_str)
        .filter(|recipe| !recipe.trim().is_empty())
}

/// One starting-checkpoint file as staged under the job's base directory:
/// its checkpoint name (also its file name there), kind and source, and the
/// SHA-256, BLAKE3 and size of the bytes written.
#[derive(Debug, Clone, Serialize)]
pub(super) struct BaseFileWire {
    pub(super) name: String,
    pub(super) kind: CheckpointFileKind,
    pub(super) source: SourcePin,
    pub(super) sha256: String,
    pub(super) blake3: String,
    pub(super) bytes: u64,
}

impl BaseFileWire {
    pub(super) fn of(
        name: &str,
        kind: CheckpointFileKind,
        source: &SourcePin,
        bytes: &[u8],
    ) -> Self {
        Self {
            name: name.to_owned(),
            kind,
            source: source.clone(),
            sha256: sha256_hex(bytes),
            blake3: blake3_hex(blake3::hash(bytes).as_bytes()),
            bytes: bytes.len() as u64,
        }
    }
}

/// What a role job's directory holds for the worker, as written there.
pub(super) struct RoleStagedFiles {
    pub(super) base_dir: String,
    pub(super) base: Vec<BaseFileWire>,
    pub(super) training_path: String,
    pub(super) training_sha256: String,
    pub(super) training_blake3: String,
    pub(super) training_bytes: u64,
    pub(super) training_rows: u64,
}

#[derive(Serialize)]
struct RoleJob<'a> {
    format: &'static str,
    run: String,
    spec_blake3: String,
    compute: ComputeWire<'a>,
    target: RoleTargetWire<'a>,
    recipe: &'a str,
    base: RoleBaseWire<'a>,
    training: RoleTrainingWire<'a>,
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

#[derive(Serialize)]
struct RoleTargetWire<'a> {
    kind: &'static str,
    role: ModelRole,
    seat: &'a EvalSeat,
    output_model: &'a ModelId,
}

#[derive(Serialize)]
struct RoleBaseWire<'a> {
    model: &'a ModelId,
    dir: &'a str,
    files: &'a [BaseFileWire],
    /// `PinnedCheckpoint::content_hash` of the starting checkpoint, which
    /// the receipt echoes.
    load_set_blake3: String,
}

#[derive(Serialize)]
struct RoleTrainingWire<'a> {
    format: &'static str,
    path: &'a str,
    sha256: &'a str,
    blake3: &'a str,
    bytes: u64,
    rows: u64,
}

/// The exact request bytes a role worker is handed (`request.json`).
/// Settings, probes and tolerance are the plan's own values, with nothing
/// defaulted.
pub(super) fn build_job(
    facts: &RoleJobFacts<'_>,
    staged: &RoleStagedFiles,
) -> oneiron::Result<Vec<u8>> {
    let request = facts.request;
    let plan = &request.plan;
    let job = RoleJob {
        format: JOB_FORMAT,
        run: request.run.to_hex(),
        spec_blake3: blake3_hex(&request.spec_blake3),
        compute: ComputeWire {
            kind: ENGINE_RUN,
            reference: facts.reference,
        },
        target: RoleTargetWire {
            kind: ROLE,
            role: facts.role,
            seat: &plan.seat,
            output_model: facts.output_model,
        },
        recipe: facts.recipe,
        base: RoleBaseWire {
            model: &plan.starting_checkpoint.model,
            dir: &staged.base_dir,
            files: &staged.base,
            load_set_blake3: blake3_hex(&plan.starting_checkpoint.content_hash()?),
        },
        training: RoleTrainingWire {
            format: TRAINING_ROWS,
            path: &staged.training_path,
            sha256: &staged.training_sha256,
            blake3: &staged.training_blake3,
            bytes: staged.training_bytes,
            rows: staged.training_rows,
        },
        settings: &plan.settings,
        harness: &plan.harness,
        probes: &plan.probes,
        export_logit_tolerance: plan.export_logit_tolerance,
    };
    serde_json::to_vec(&job).map_err(|_| invalid("the role training job did not encode"))
}

/// The number of rows a training file holds: its non-empty lines.
pub(super) fn row_count(rows: &[u8]) -> u64 {
    rows.split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .count() as u64
}

/// What a role receipt must echo to be this job's.
pub(super) struct RoleExpected {
    /// SHA-256 and size of the `request.json` bytes the worker was handed.
    pub(super) request_sha256: String,
    pub(super) request_bytes: u64,
    /// SHA-256 and row count of the training rows staged for it.
    pub(super) training_sha256: String,
    pub(super) training_rows: u64,
}

#[derive(Deserialize)]
struct RoleReceiptWire {
    run: String,
    spec_blake3: String,
    settings: Value,
    harness: SourcePin,
    authorization: AuthorizationWire,
    request: RequestWire,
    recipe: RoleRecipeWire,
    training: TrainingReadWire,
    load_sets: LoadSetsWire,
    probes: Vec<RoleProbeWire>,
    service_units: ServiceUnitsWire,
}

#[derive(Deserialize)]
struct RoleRecipeWire {
    recipe: String,
    target: RoleRecipeTargetWire,
    base: RoleRecipeBaseWire,
}

/// The receipt's recipe target: the job's, without its seat.
#[derive(Deserialize)]
struct RoleRecipeTargetWire {
    kind: String,
    role: Value,
    output_model: String,
}

#[derive(Deserialize)]
struct RoleRecipeBaseWire {
    model: String,
    load_set_blake3: String,
}

/// The training rows the worker read: their SHA-256 and their count.
#[derive(Deserialize)]
struct TrainingReadWire {
    sha256: String,
    rows: u64,
}

#[derive(Deserialize)]
struct RoleProbeWire {
    probe_id: String,
    input_blake3: String,
    training_logits: Vec<f64>,
    export_logits: Vec<f64>,
    training_argmax: u64,
    export_argmax: u64,
    max_logit_difference: f64,
}

impl RoleProbeWire {
    /// The probe's largest logit difference, computed from its own finite
    /// logits, when its argmaxes are the ones those logits give and its
    /// stated difference sits within [`DIFFERENCE_SLACK`] of it. The engine's
    /// export check judges this computed difference against the owner's
    /// tolerance, never the worker's summary, and a difference the logits
    /// overflow to is none.
    fn checked_difference(&self) -> Option<f64> {
        let finite = self
            .training_logits
            .iter()
            .chain(&self.export_logits)
            .copied()
            .all(f64::is_finite);
        if !finite
            || self.training_logits.is_empty()
            || self.training_logits.len() != self.export_logits.len()
            || !self.max_logit_difference.is_finite()
            || self.max_logit_difference < 0.0
        {
            return None;
        }
        let difference = self
            .training_logits
            .iter()
            .zip(&self.export_logits)
            .map(|(training, export)| (training - export).abs())
            .fold(0.0_f64, f64::max);
        (difference.is_finite()
            && argmax(&self.training_logits) == Some(self.training_argmax)
            && argmax(&self.export_logits) == Some(self.export_argmax)
            && (self.max_logit_difference - difference).abs()
                <= DIFFERENCE_SLACK * difference.max(1.0))
        .then_some(difference)
    }
}

/// The index of the first largest logit.
fn argmax(logits: &[f64]) -> Option<u64> {
    let mut best: Option<(usize, f64)> = None;
    for (index, logit) in logits.iter().copied().enumerate() {
        if best.is_none_or(|(_, top)| logit > top) {
            best = Some((index, logit));
        }
    }
    best.and_then(|(index, _)| u64::try_from(index).ok())
}

/// The worker's terminal result as the engine's return. A failed or refused
/// receipt, a partial or nonfinite one, one whose probe summary disagrees
/// with its logits, or one that names another run, spec, request,
/// authorization, recipe, role, base, training rows, output model or service
/// unit is a connector error. Each load-set file is read whole from under
/// `output`.
pub(super) fn decode_output(
    facts: &RoleJobFacts<'_>,
    expected: &RoleExpected,
    output: &Path,
    bytes: &[u8],
) -> oneiron::Result<TrainOutput> {
    let whole: Value = serde_json::from_slice(bytes)
        .map_err(|_| invalid("the role trainer's receipt is not JSON"))?;
    let status: StatusWire = serde_json::from_slice(bytes)
        .map_err(|_| invalid("the role trainer's receipt has no format or status"))?;
    if status.format != RECEIPT_FORMAT {
        return Err(not_this_job("format"));
    }
    if status.status != TRAINED {
        return Err(invalid(format!(
            "the role trainer ended {}: {}",
            status.status,
            status.reason.as_deref().unwrap_or("no reason given")
        )));
    }
    let receipt: RoleReceiptWire = serde_json::from_slice(bytes)
        .map_err(|_| invalid("the role trainer's receipt is partial or not finite"))?;
    let request = facts.request;
    let plan = &request.plan;
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
    let role = serde_json::to_value(facts.role).map_err(|_| invalid("a role did not encode"))?;
    let target = &receipt.recipe.target;
    if receipt.recipe.recipe != facts.recipe
        || target.kind != ROLE
        || target.role != role
        || target.output_model != facts.output_model.as_str()
    {
        return Err(not_this_job("recipe or role"));
    }
    let base = &receipt.recipe.base;
    if base.model != plan.starting_checkpoint.model.as_str()
        || base.load_set_blake3 != blake3_hex(&plan.starting_checkpoint.content_hash()?)
    {
        return Err(not_this_job("base"));
    }
    if receipt.training.sha256 != expected.training_sha256
        || receipt.training.rows != expected.training_rows
    {
        return Err(not_this_job("training rows"));
    }
    let model = facts.output_model.as_str();
    if receipt.load_sets.training.model != model || receipt.load_sets.export.model != model {
        return Err(not_this_job("output model"));
    }
    if receipt.service_units.unit != TRAINING_SERVICE_UNIT {
        return Err(not_this_job("service unit"));
    }
    let probes = receipt
        .probes
        .into_iter()
        .map(|probe| {
            let max_logit_difference = probe.checked_difference().ok_or_else(|| {
                invalid("the role trainer's probe summary disagrees with its finite logits")
            })?;
            Ok(ProbeMeasurement {
                input_blake3: hash_from_hex("probe input_blake3", &probe.input_blake3)?,
                tokens_blake3: None,
                probe_id: probe.probe_id,
                training_argmax: probe.training_argmax,
                export_argmax: probe.export_argmax,
                max_logit_difference,
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
        training_checkpoint: upload(output, training, facts.output_model)?,
        exported_checkpoint: upload(output, export, facts.output_model)?,
        probes,
        settings: receipt.settings,
        harness: receipt.harness,
        receipt: whole,
        service_units: receipt.service_units.quantity,
        question_check: None,
        candle_parity: None,
    })
}
