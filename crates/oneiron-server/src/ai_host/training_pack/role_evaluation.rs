//! The role evaluator (ROLE-TRAINING-RUN, RULING TRAIN-ROLE-EVALUATOR = A):
//! a returned role checkpoint is scored by the scorer its role trainer
//! connector names (`scorer`), a local process separate from the trainer,
//! on the role score wire `oneiron.training-pack.role-score/1`
//! (`scripts/training_pack/README.md`). It runs as `<python> -I <scorer>
//! --request <score dir>/request.json --output <score dir>/output`, with no
//! shell and the trainers' environment (`trainer::worker_command`). It reads
//! the held-out rows, then for a probability seat the training rows, on its
//! stdin: each split is exactly the `bytes` its request entry states, in that
//! order, and no split is ever written to a file.
//!
//! The scorer writes one log-likelihood margin per pair, log P(chosen) -
//! log P(rejected) under the returned checkpoint: for every held-out pair,
//! and for a probability seat also for every training pair. The host
//! computes every measurement from those margins. Preference accuracy counts
//! a positive margin as the chosen side ranked first (zero is a miss), and
//! the mean margin is kept beside it. A probability seat (Decision,
//! ExtractionTagger, Router) also gets a temperature fitted on the training
//! margins only, then Brier and ECE on the held-out margins, each pair
//! counted in both orders. `passed` is the plan's authored criterion, never
//! the scorer's word.
//!
//! The score directory is `<jobs_root>/<run>-<spec>.score-<exposure>`,
//! beside the trainer's job directory and never inside it. It holds the
//! request, the exported checkpoint's files, the scorer's output and its
//! error stream only while the scorer runs: the host reads the receipt, then
//! removes the directory whole before it checks anything, whatever the
//! outcome, and refuses the score when it cannot. A scored receipt has
//! exactly the wire's fields, and each of its strings must equal the host's
//! own value, so a kept receipt holds no text the host did not state. A
//! refusal names the scorer's exit status and the receipt's size, never its
//! text. Two run-bound verifier logs go into custody: the host's measurement
//! log and the scorer's receipt as written.
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, ExitStatus, Stdio};

use oneiron::ModelId;
use oneiron::Vault;
use oneiron::llm::manifest::ModelRole;
use oneiron::skill_optimize::EvalSeat;
use oneiron::training_pack::{
    CalibrationResult, CheckpointFilePin, HeldOutResult, SourcePin, TrainingEvalInput, TrainingRun,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::question_evaluation::calibration;
use super::role_trainer::flat_name;
use super::role_wire::{BaseFileWire, RESERVOIR_PAIR_FORMAT, recipe_of};
use super::trainer::{private_dir, utf8, worker_command, write_new};
use super::wire::{StatusWire, blake3_hex, invalid, sha256_hex};
use crate::config::models::RoleTrainerSettings;

const JOB_FORMAT: &str = "oneiron.training-pack.role-score/1";
const RECEIPT_FORMAT: &str = "oneiron.training-pack.role-score-receipt/1";
const LOG_FORMAT: &str = "oneiron.role-held-out/1";
/// The score job target's kind.
const ROLE: &str = "role";
/// The one terminal status that carries margins.
const SCORED: &str = "scored";
const REQUEST_FILE: &str = "request.json";
const CHECKPOINT_DIR: &str = "checkpoint";
const OUTPUT_DIR: &str = "output";
const RECEIPT_FILE: &str = "receipt.json";
/// The scorer's error stream, in its score directory while it runs.
const STDERR_FILE: &str = "scorer.stderr";
/// The verifier logs' names in custody.
const LOG_NAME: &str = "role-held-out.json";
const RECEIPT_LOG_NAME: &str = "role-score-receipt.json";

/// No quality floor is implicit. An authored recipe may request one, as a
/// question recipe may.
#[derive(Default, Serialize)]
struct Criterion {
    minimum_accuracy: Option<f64>,
}

impl Criterion {
    fn from_settings(settings: &Value) -> oneiron::Result<Self> {
        let Some(value) = settings.get("evaluation") else {
            return Ok(Self::default());
        };
        let fields = value
            .as_object()
            .ok_or_else(|| invalid("role evaluation settings must be an object"))?;
        if fields.keys().any(|key| key != "minimum_accuracy") {
            return Err(invalid("unknown role evaluation setting"));
        }
        let minimum_accuracy = fields
            .get("minimum_accuracy")
            .map(|value| {
                value
                    .as_f64()
                    .filter(|value| value.is_finite() && (0.0..=1.0).contains(value))
                    .ok_or_else(|| invalid("minimum_accuracy must be a finite number in 0..=1"))
            })
            .transpose()?;
        Ok(Self { minimum_accuracy })
    }

    fn passed(&self, accuracy: f64) -> bool {
        self.minimum_accuracy
            .is_none_or(|minimum| accuracy >= minimum)
    }
}

/// Whether a seat answers with a probability, so its evaluation also
/// reports calibration (`validate_eval`).
fn probability_seat(seat: &EvalSeat) -> bool {
    matches!(
        seat,
        EvalSeat::Decision | EvalSeat::ExtractionTagger | EvalSeat::Router
    )
}

/// One reservoir pair line of a split: the receipt it names, for the log,
/// and the SHA-256 of its exact bytes, which the scorer's margin echoes.
struct PairRow {
    receipt_ref: String,
    sha256: String,
}

fn pair_rows(bytes: &[u8]) -> oneiron::Result<Vec<PairRow>> {
    let mut rows = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let pair: Value = serde_json::from_slice(line)
            .map_err(|_| invalid("a role evaluation row is not a reservoir pair"))?;
        let receipt_ref = pair
            .get("receipt_ref")
            .and_then(Value::as_str)
            .filter(|receipt| !receipt.trim().is_empty());
        let (Some(receipt_ref), Some(_), Some(_)) =
            (receipt_ref, pair.get("chosen"), pair.get("rejected"))
        else {
            return Err(invalid("a role evaluation row is not a reservoir pair"));
        };
        rows.push(PairRow {
            receipt_ref: receipt_ref.to_owned(),
            sha256: sha256_hex(line),
        });
    }
    if rows.is_empty() {
        return Err(invalid("role evaluation needs a nonempty pinned split"));
    }
    Ok(rows)
}

#[derive(Serialize)]
struct ScoreJob<'a> {
    format: &'static str,
    run: String,
    spec_blake3: String,
    exposure: String,
    target: ScoreTargetWire<'a>,
    recipe: &'a str,
    checkpoint: ScoreCheckpointWire<'a>,
    held_out: PairsWire,
    /// The training split, staged for a probability seat's temperature fit
    /// only.
    training: Option<PairsWire>,
    settings: &'a Value,
    harness: &'a SourcePin,
}

#[derive(Serialize)]
struct ScoreTargetWire<'a> {
    kind: &'static str,
    role: ModelRole,
    seat: &'a EvalSeat,
    output_model: &'a ModelId,
}

#[derive(Serialize)]
struct ScoreCheckpointWire<'a> {
    model: &'a ModelId,
    dir: String,
    files: &'a [BaseFileWire],
    /// `PinnedCheckpoint::content_hash` of the exported checkpoint, which the
    /// receipt echoes.
    load_set_blake3: String,
}

/// One split as the scorer reads it from its stdin: its hashes, its size,
/// which frames it, and its row count.
#[derive(Serialize)]
struct PairsWire {
    format: &'static str,
    sha256: String,
    blake3: String,
    bytes: u64,
    rows: u64,
}

/// A scored receipt: exactly these fields, at every level, so a kept receipt
/// holds no field the host does not check.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScoreReceiptWire {
    format: String,
    status: String,
    run: String,
    spec_blake3: String,
    exposure: String,
    request: RequestReadWire,
    checkpoint: CheckpointReadWire,
    held_out: MarginsWire,
    #[serde(default)]
    training: Option<MarginsWire>,
}

/// The SHA-256 and size of the request bytes the scorer read.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestReadWire {
    sha256: String,
    bytes: u64,
}

/// The checkpoint the scorer loaded: the load set it was handed and each
/// file's SHA-256 as it read the bytes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointReadWire {
    load_set_blake3: String,
    files: Vec<FileReadWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileReadWire {
    name: String,
    sha256: String,
}

/// One split's margins, in the split's row order, with the SHA-256 of the
/// split bytes the scorer read.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MarginsWire {
    sha256: String,
    margins: Vec<MarginWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MarginWire {
    row_sha256: String,
    margin: f64,
}

fn not_this_score(what: &str) -> oneiron::Error {
    invalid(format!(
        "the role scorer's receipt is not this score's: {what}"
    ))
}

/// The margins of one split, in its row order: exactly one finite margin
/// for each row, naming that row's bytes, read from the split's own bytes.
fn split_margins(
    read: &MarginsWire,
    rows: &[PairRow],
    bytes: &[u8],
    split: &str,
) -> oneiron::Result<Vec<f64>> {
    if read.sha256 != sha256_hex(bytes) || read.margins.len() != rows.len() {
        return Err(not_this_score(split));
    }
    read.margins
        .iter()
        .zip(rows)
        .map(|(read, row)| {
            if read.row_sha256 == row.sha256 && read.margin.is_finite() {
                Ok(read.margin)
            } else {
                Err(not_this_score(split))
            }
        })
        .collect()
}

/// Each margin as a binary case in both orders: P(first preferred) for
/// (chosen, rejected), which is true, and for (rejected, chosen), which is
/// false.
fn both_orders(margins: &[f64]) -> Vec<([f64; 2], bool)> {
    margins
        .iter()
        .flat_map(|&margin| [([0.0, margin], true), ([0.0, -margin], false)])
        .collect()
}

/// The score directory, transient as a whole: `remove` takes it away, and
/// refuses the score when it cannot, before the host checks any receipt;
/// Drop removes it on every other way out.
struct ScoreDir {
    path: PathBuf,
    removed: bool,
}

impl ScoreDir {
    fn remove(mut self) -> oneiron::Result<()> {
        let removed = std::fs::remove_dir_all(&self.path);
        self.removed = removed.is_ok();
        removed.map_err(|error| {
            invalid(format!(
                "the role score directory could not be removed ({:?}); nothing is scored",
                error.kind()
            ))
        })
    }
}

impl Drop for ScoreDir {
    fn drop(&mut self) {
        if self.removed {
            return;
        }
        if let Err(error) = std::fs::remove_dir_all(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(kind = ?error.kind(), "a role score directory stayed");
        }
    }
}

/// One split's request entry; its bytes go on the scorer's stdin.
fn pairs_wire(bytes: &[u8], rows: usize) -> PairsWire {
    PairsWire {
        format: RESERVOIR_PAIR_FORMAT,
        sha256: sha256_hex(bytes),
        blake3: blake3_hex(blake3::hash(bytes).as_bytes()),
        bytes: bytes.len() as u64,
        rows: rows as u64,
    }
}

/// Writes each split to the scorer's stdin in order, then closes it.
/// `Ok(false)` when the scorer closed its end before it read them all.
fn feed_splits(stdin: Option<ChildStdin>, splits: &[&[u8]]) -> std::io::Result<bool> {
    let mut stdin =
        stdin.ok_or_else(|| std::io::Error::other("the scorer's stdin is not piped"))?;
    for split in splits {
        match stdin.write_all(split) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

/// Runs the scorer on the request staged in `score`, feeds it `splits` and
/// waits. Returns its exit status, whether it read every split, and its
/// receipt bytes if it wrote one; the score directory is gone when this
/// returns `Ok`.
fn run_scorer(
    trainer: &RoleTrainerSettings,
    scorer: &Path,
    score: ScoreDir,
    splits: &[&[u8]],
) -> oneiron::Result<(ExitStatus, bool, Option<Vec<u8>>)> {
    let dir = score.path.as_path();
    let mut command = worker_command(
        &trainer.python,
        scorer,
        &dir.join(REQUEST_FILE),
        &dir.join(OUTPUT_DIR),
        &dir.join(STDERR_FILE),
    )?;
    // stdout is null and stderr a file, so a scorer that does not read its
    // stdin yet blocks on no pipe of ours.
    let mut child = command.stdin(Stdio::piped()).spawn()?;
    let fed = feed_splits(child.stdin.take(), splits);
    let exit = child.wait()?;
    let fed = fed?;
    let receipt_path = dir.join(OUTPUT_DIR).join(RECEIPT_FILE);
    let receipt = if receipt_path.is_file() {
        Some(std::fs::read(&receipt_path)?)
    } else {
        None
    };
    score.remove()?;
    Ok((exit, fed, receipt))
}

/// The exported checkpoint's files, each staged under its own name in a
/// flat bundle.
fn stage_checkpoint(
    vault: &Vault,
    files: &[CheckpointFilePin],
    dir: &Path,
) -> oneiron::Result<Vec<BaseFileWire>> {
    if files.is_empty() || !files.iter().all(|file| flat_name(&file.name)) {
        return Err(invalid(
            "a role scorer reads a flat checkpoint: plain file names, staged side by side",
        ));
    }
    private_dir(dir, false)?;
    files
        .iter()
        .map(|file| {
            let bytes = vault.read_training_artifact(&file.content)?;
            write_new(&dir.join(&file.name), &bytes)?;
            Ok(BaseFileWire::of(
                &file.name,
                file.kind,
                &file.source,
                &bytes,
            ))
        })
        .collect()
}

#[derive(Serialize)]
struct CaseLog<'a> {
    row: &'a str,
    row_sha256: &'a str,
    margin: f64,
    chosen_first: bool,
    /// P(chosen preferred) at the fitted temperature, for a probability seat.
    chosen_probability: Option<f64>,
}

/// Scores a returned role run on the held-out exposure the caller opened,
/// through `trainer`'s scorer process. Custody and the existing record door
/// keep the measurements; this binds and serves nothing.
pub(super) fn evaluate(
    vault: &Vault,
    trainer: &RoleTrainerSettings,
    run: &TrainingRun,
    input: &TrainingEvalInput,
) -> oneiron::Result<HeldOutResult> {
    let scorer = trainer
        .scorer
        .as_deref()
        .ok_or_else(|| invalid("this role trainer names no scorer"))?;
    let (role, binding) = run
        .plan
        .target
        .role_binding()
        .ok_or_else(|| invalid("this evaluator scores a role, not a question head"))?;
    let recipe = recipe_of(&run.plan.settings)
        .ok_or_else(|| invalid("a role run's settings name its recipe"))?;
    let criterion = Criterion::from_settings(&run.plan.settings)?;
    let returned = run
        .result
        .as_ref()
        .ok_or_else(|| invalid("role evaluation requires a returned checkpoint"))?;
    if input.checkpoint != returned.exported_checkpoint
        || input.harness != run.plan.harness
        || blake3::hash(&input.held_out_jsonl).as_bytes() != &run.corpus.held_out.blake3
    {
        return Err(invalid("role evaluation input differs from its pinned run"));
    }
    let held_out_rows = pair_rows(&input.held_out_jsonl)?;
    let training_jsonl = if probability_seat(&run.plan.seat) {
        Some(vault.read_training_artifact(&run.corpus.training)?)
    } else {
        None
    };
    let training_rows = training_jsonl.as_deref().map(pair_rows).transpose()?;
    let checkpoint_blake3 = input.checkpoint.content_hash()?;
    let scorer_sha256 = sha256_hex(&std::fs::read(scorer)?);

    let dir = trainer.jobs_root.join(format!(
        "{}-{}.score-{}",
        run.id.to_hex(),
        blake3_hex(&run.spec_blake3),
        input.exposure.id.to_hex()
    ));
    private_dir(&trainer.jobs_root, true)?;
    private_dir(&dir, false)?;
    let score = ScoreDir {
        path: dir.clone(),
        removed: false,
    };
    let checkpoint_dir = dir.join(CHECKPOINT_DIR);
    let checkpoint_files = stage_checkpoint(vault, &input.checkpoint.files, &checkpoint_dir)?;
    let held_out = pairs_wire(&input.held_out_jsonl, held_out_rows.len());
    let training = match (&training_jsonl, &training_rows) {
        (Some(bytes), Some(rows)) => Some(pairs_wire(bytes, rows.len())),
        _ => None,
    };
    let job = ScoreJob {
        format: JOB_FORMAT,
        run: run.id.to_hex(),
        spec_blake3: blake3_hex(&run.spec_blake3),
        exposure: input.exposure.id.to_hex(),
        target: ScoreTargetWire {
            kind: ROLE,
            role,
            seat: &run.plan.seat,
            output_model: &binding.model,
        },
        recipe,
        checkpoint: ScoreCheckpointWire {
            model: &input.checkpoint.model,
            dir: utf8(&checkpoint_dir)?,
            files: &checkpoint_files,
            load_set_blake3: blake3_hex(&checkpoint_blake3),
        },
        held_out,
        training,
        settings: &run.plan.settings,
        harness: &run.plan.harness,
    };
    let body =
        serde_json::to_vec(&job).map_err(|_| invalid("the role score job did not encode"))?;
    write_new(&dir.join(REQUEST_FILE), &body)?;
    let mut splits = vec![input.held_out_jsonl.as_slice()];
    splits.extend(training_jsonl.as_deref());
    let (exit, fed, receipt) = run_scorer(trainer, scorer, score, &splits)?;
    if !fed {
        return Err(invalid(format!(
            "the role scorer ended ({exit}) before it read every split; nothing is scored"
        )));
    }
    let Some(receipt) = receipt else {
        return Err(invalid(format!(
            "the role scorer ended ({exit}) with no receipt"
        )));
    };

    let status: StatusWire = serde_json::from_slice(&receipt)
        .map_err(|_| invalid("the role scorer's receipt has no format or status"))?;
    if status.format != RECEIPT_FORMAT {
        return Err(not_this_score("format"));
    }
    if status.status != SCORED {
        // The scorer's own words stay out of the host's error and logs.
        return Err(invalid(format!(
            "the role scorer ended ({exit}) with a receipt of {} bytes that scores nothing",
            receipt.len()
        )));
    }
    let read: ScoreReceiptWire = serde_json::from_slice(&receipt).map_err(|_| {
        invalid("the role scorer's receipt is partial, not finite or has a field the wire does not")
    })?;
    if read.format != RECEIPT_FORMAT
        || read.status != SCORED
        || read.run != job.run
        || read.spec_blake3 != job.spec_blake3
        || read.exposure != job.exposure
    {
        return Err(not_this_score("format, status, run, spec or exposure"));
    }
    if read.request.sha256 != sha256_hex(&body) || read.request.bytes != body.len() as u64 {
        return Err(not_this_score("request"));
    }
    let files_read = read.checkpoint.files.len() == checkpoint_files.len()
        && read
            .checkpoint
            .files
            .iter()
            .zip(&checkpoint_files)
            .all(|(read, staged)| read.name == staged.name && read.sha256 == staged.sha256);
    if read.checkpoint.load_set_blake3 != job.checkpoint.load_set_blake3 || !files_read {
        return Err(not_this_score("checkpoint"));
    }
    let held_out_margins = split_margins(
        &read.held_out,
        &held_out_rows,
        &input.held_out_jsonl,
        "held-out margins",
    )?;
    let training_margins = match (&read.training, &training_rows, &training_jsonl) {
        (Some(margins), Some(rows), Some(bytes)) => {
            Some(split_margins(margins, rows, bytes, "training margins")?)
        }
        (None, None, None) => None,
        _ => return Err(not_this_score("training margins")),
    };

    let count = held_out_margins.len() as u64;
    let correct = held_out_margins
        .iter()
        .filter(|margin| **margin > 0.0)
        .count() as u64;
    let ties = held_out_margins
        .iter()
        .filter(|margin| **margin == 0.0)
        .count() as u64;
    let accuracy = correct as f64 / count as f64;
    let mean_margin = held_out_margins.iter().sum::<f64>() / count as f64;
    if !mean_margin.is_finite() {
        return Err(invalid("the role scorer's held-out margins overflow"));
    }
    let mut metrics = BTreeMap::from([
        ("preference_accuracy".into(), accuracy),
        ("correct".into(), correct as f64),
        ("incorrect".into(), (count - correct) as f64),
        ("ties".into(), ties as f64),
        ("mean_margin".into(), mean_margin),
    ]);
    let fit = training_margins
        .as_deref()
        .map(|training| calibration::fit(&both_orders(training)));
    let calibration = fit.as_ref().map(|fit| {
        let held_out = both_orders(&held_out_margins);
        let at = |temperature: f64| {
            held_out
                .iter()
                .map(|&(logits, yes)| (calibration::yes_probability(logits, temperature), yes))
                .collect::<Vec<_>>()
        };
        let (brier_score, calibration_error) = calibration::metrics(&at(fit.temperature));
        let (raw_brier, raw_ece) = calibration::metrics(&at(1.0));
        metrics.insert("preference_brier".into(), brier_score);
        metrics.insert("preference_ece".into(), calibration_error);
        metrics.insert("uncalibrated_preference_brier".into(), raw_brier);
        metrics.insert("uncalibrated_preference_ece".into(), raw_ece);
        CalibrationResult {
            temperature: fit.temperature,
            brier_score,
            calibration_error,
        }
    });
    let cases: Vec<_> = held_out_rows
        .iter()
        .zip(&held_out_margins)
        .map(|(row, &margin)| CaseLog {
            row: &row.receipt_ref,
            row_sha256: &row.sha256,
            margin,
            chosen_first: margin > 0.0,
            chosen_probability: fit
                .as_ref()
                .map(|fit| calibration::yes_probability([0.0, margin], fit.temperature)),
        })
        .collect();
    let passed = criterion.passed(accuracy);
    let log = json!({
        "format": LOG_FORMAT,
        "run": run.id,
        "spec_blake3": run.spec_blake3,
        "exposure": input.exposure.id,
        "checkpoint_blake3": checkpoint_blake3,
        "training_blake3": run.corpus.training.blake3,
        "held_out_blake3": run.corpus.held_out.blake3,
        "harness": input.harness,
        "role": role,
        "seat": run.plan.seat,
        "recipe": recipe,
        "scorer_sha256": scorer_sha256,
        "scorer_receipt_sha256": sha256_hex(&receipt),
        "criterion": criterion,
        "verdict": "complete_measurement; apply minimum_accuracy only when explicitly set",
        "margin": "log P(chosen) - log P(rejected) as the scorer wrote it",
        "prediction": "chosen first iff margin > 0; a zero margin is a miss",
        "calibration": fit,
        "calibration_fitting_split": fit.as_ref().map(|_| "training"),
        "calibration_cases": "each pair in both orders: (chosen, rejected) true, (rejected, chosen) false",
        "brier_definition": "mean((P(first preferred)-I(first is chosen))^2) on held-out pairs in both orders",
        "ece_definition": "sum_bin(n_bin/N * abs(mean_P - fraction_true)) on held-out pairs in both orders",
        "ece_bins": calibration::ECE_BINS,
        "metrics": metrics,
        "passed": passed,
        "cases": cases,
    });
    let log = serde_json::to_vec(&log)
        .map_err(|_| invalid("the role verifier log could not be serialized"))?;
    let log_pin = vault.keep_training_verifier_log_for_run(&run.id, LOG_NAME, &log)?;
    let receipt_pin =
        vault.keep_training_verifier_log_for_run(&run.id, RECEIPT_LOG_NAME, &receipt)?;
    Ok(HeldOutResult {
        exposure: input.exposure.id,
        checkpoint_blake3,
        held_out_blake3: run.corpus.held_out.blake3,
        harness: input.harness.clone(),
        cases: count,
        metrics,
        calibration,
        verifier_logs: vec![log_pin, receipt_pin],
        passed,
    })
}
