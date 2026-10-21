//! The question-head trainer (FIX 7263), the one `TrainingConnector` this
//! host ships. It runs `scripts/training_pack/worker.py` as a local process
//! on this server's own host: `<python> -I <worker> --request <job json>
//! --output <new dir>`, with no shell. Each run and spec gets one private job
//! directory under the connector's `jobs_root`, holding the starting bundle's
//! files read from custody, the run's training rows and no held-out row.
//!
//! The directory is the job's idempotency key. One that holds a terminal
//! `receipt.json` is read again; one without is an outstanding or unknown
//! job, and no second GPU job starts for it. No time limit cuts a run short,
//! and a lost waiter leaves the process running to its receipt. The files
//! stay for the owner's evidence whatever the outcome.
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;

use oneiron::Vault;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::training_pack::{
    CheckpointFileKind, CheckpointFilePin, SourcePin, TrainOutput, TrainRequest, TrainingConnector,
    TrainingFuture, TrainingPlan,
};
use serde_json::Value;

use super::wire::{
    self, BaseFilesWire, Expected, FilePinWire, JobFacts, StagedFiles, blake3_hex, invalid,
    sha256_hex,
};
use crate::config::models::TrainingConnectorSettings;

/// The starting bundle a question head trains on, in the worker's order
/// (manifest, config, tokenizer, trunk): each file's name and kind in the
/// starting checkpoint.
const BASE_FILES: [(&str, CheckpointFileKind); 4] = [
    ("oneironer.json", CheckpointFileKind::Config),
    ("config.json", CheckpointFileKind::Config),
    ("tokenizer.json", CheckpointFileKind::Tokenizer),
    ("trunk.safetensors", CheckpointFileKind::Weights),
];
const REQUEST_FILE: &str = "request.json";
const BASE_DIR: &str = "base";
const TRAINING_FILE: &str = "training.jsonl";
const OUTPUT_DIR: &str = "output";
const RECEIPT_FILE: &str = "receipt.json";
/// What the worker wrote to its error stream, kept beside its receipt.
const STDERR_FILE: &str = "worker.stderr";

/// A trainer connector's worker process, with the vault whose custody holds
/// the starting files.
pub(super) struct QuestionHeadTrainer {
    vault: Arc<Vault>,
    connector: TrainingConnectorSettings,
}

/// The starting checkpoint's four bundle files and their one source.
struct BaseFiles<'a> {
    manifest: &'a CheckpointFilePin,
    config: &'a CheckpointFilePin,
    tokenizer: &'a CheckpointFilePin,
    trunk: &'a CheckpointFilePin,
    source: &'a SourcePin,
}

impl QuestionHeadTrainer {
    pub(super) fn new(vault: Arc<Vault>, connector: TrainingConnectorSettings) -> Self {
        Self { vault, connector }
    }

    /// Whether this trainer runs `plan`: a question head on the worker's one
    /// recipe. A role run is never routed to it.
    pub(super) fn serves(plan: &TrainingPlan) -> bool {
        plan.target.question().is_some()
            && plan.settings.get("recipe").and_then(Value::as_str) == Some(wire::RECIPE)
    }

    async fn train_job(
        &self,
        request: TrainRequest,
        reference: String,
    ) -> oneiron::Result<TrainOutput> {
        let facts = JobFacts::of(&request, &reference)?;
        let base = base_files(&request.plan.starting_checkpoint.files)?;
        let job = self.connector.jobs_root.join(format!(
            "{}-{}",
            request.run.to_hex(),
            blake3_hex(&request.spec_blake3)
        ));
        if std::fs::symlink_metadata(&job).is_ok() {
            return self.reread(&facts, &base, &job);
        }
        let staged = self.stage(&facts, &base, &job)?;
        let body = wire::build_job(&facts, &staged)?;
        write_new(&job.join(REQUEST_FILE), &body)?;
        let status = self.run_worker(&job).await?;
        let receipt = job.join(OUTPUT_DIR).join(RECEIPT_FILE);
        if !receipt.is_file() {
            return Err(invalid(format!(
                "the trainer ended ({status}) with no receipt; its job directory stays"
            )));
        }
        let expected = Expected {
            request_sha256: sha256_hex(&body),
            request_bytes: body.len() as u64,
            base_source: staged.base_source,
            manifest_sha256: staged.base.manifest.sha256,
        };
        let receipt = std::fs::read(receipt)?;
        wire::decode_output(&facts, &expected, &job.join(OUTPUT_DIR), &receipt)
    }

    /// A job this run's directory already holds: its terminal receipt read
    /// again, or a refusal that starts nothing.
    fn reread(
        &self,
        facts: &JobFacts<'_>,
        base: &BaseFiles<'_>,
        job: &Path,
    ) -> oneiron::Result<TrainOutput> {
        let receipt = job.join(OUTPUT_DIR).join(RECEIPT_FILE);
        if !receipt.is_file() {
            return Err(outstanding());
        }
        let body = std::fs::read(job.join(REQUEST_FILE))?;
        let manifest = self.vault.read_training_artifact(&base.manifest.content)?;
        let expected = Expected {
            request_sha256: sha256_hex(&body),
            request_bytes: body.len() as u64,
            base_source: base.source.clone(),
            manifest_sha256: sha256_hex(&manifest),
        };
        let receipt = std::fs::read(receipt)?;
        wire::decode_output(facts, &expected, &job.join(OUTPUT_DIR), &receipt)
    }

    /// Makes the run's private job directory and writes the starting files
    /// and the training rows into it.
    fn stage(
        &self,
        facts: &JobFacts<'_>,
        base: &BaseFiles<'_>,
        job: &Path,
    ) -> oneiron::Result<StagedFiles> {
        private_dir(&self.connector.jobs_root, true)?;
        match private_dir(job, false) {
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(outstanding());
            }
            made => made?,
        }
        let base_dir = job.join(BASE_DIR);
        private_dir(&base_dir, false)?;
        let files = BaseFilesWire {
            manifest: self.stage_file(&base_dir, base.manifest)?,
            config: self.stage_file(&base_dir, base.config)?,
            tokenizer: self.stage_file(&base_dir, base.tokenizer)?,
            trunk: self.stage_file(&base_dir, base.trunk)?,
        };
        let rows = &facts.request.training_jsonl;
        if blake3::hash(rows).as_bytes() != &facts.request.training_blake3 {
            return Err(invalid("the run's training rows differ from their pin"));
        }
        let training_path = job.join(TRAINING_FILE);
        write_new(&training_path, rows)?;
        Ok(StagedFiles {
            base_dir: utf8(&base_dir)?,
            base_source: base.source.clone(),
            base: files,
            training_path: utf8(&training_path)?,
            training: FilePinWire::of(TRAINING_FILE, rows),
        })
    }

    /// One starting file's bytes, read through custody, written under `dir`.
    fn stage_file(&self, dir: &Path, file: &CheckpointFilePin) -> oneiron::Result<FilePinWire> {
        let bytes = self.vault.read_training_artifact(&file.content)?;
        write_new(&dir.join(&file.name), &bytes)?;
        Ok(FilePinWire::of(&file.name, &bytes))
    }

    /// Runs the worker on the job and waits for it, however long it trains.
    async fn run_worker(&self, job: &Path) -> oneiron::Result<ExitStatus> {
        let stderr = new_file(&job.join(STDERR_FILE))?;
        let mut command: tokio::process::Command =
            oneiron_spawn::command(&self.connector.python).into();
        command
            .arg("-I")
            .arg(&self.connector.worker)
            .arg("--request")
            .arg(job.join(REQUEST_FILE))
            .arg("--output")
            .arg(job.join(OUTPUT_DIR))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr));
        let mut child = command.spawn()?;
        Ok(child.wait().await?)
    }
}

impl TrainingConnector for QuestionHeadTrainer {
    fn train<'a>(
        &'a self,
        request: TrainRequest,
        admission: &'a RunAdmission,
    ) -> TrainingFuture<'a> {
        Box::pin(self.train_job(request, admission.run().to_owned()))
    }
}

fn outstanding() -> oneiron::Error {
    invalid("an outstanding or unknown training job holds this run's directory; none starts again")
}

/// The starting checkpoint as an Oneironer bundle: exactly its manifest,
/// config, tokenizer and trunk, from one source.
fn base_files(files: &[CheckpointFilePin]) -> oneiron::Result<BaseFiles<'_>> {
    let [manifest, config, tokenizer, trunk] = BASE_FILES.map(|(name, kind)| {
        files
            .iter()
            .find(|file| file.name == name && file.kind == kind)
    });
    let refused = || {
        invalid(
            "a question head starts from an Oneironer bundle: exactly oneironer.json, \
             config.json, tokenizer.json and trunk.safetensors, from one source",
        )
    };
    let (Some(manifest), Some(config), Some(tokenizer), Some(trunk)) =
        (manifest, config, tokenizer, trunk)
    else {
        return Err(refused());
    };
    let source = &manifest.source;
    if files.len() != BASE_FILES.len()
        || [config, tokenizer, trunk]
            .iter()
            .any(|file| file.source != *source)
    {
        return Err(refused());
    }
    Ok(BaseFiles {
        manifest,
        config,
        tokenizer,
        trunk,
        source,
    })
}

fn utf8(path: &Path) -> oneiron::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("a training job path is not UTF-8"))
}

/// A directory only this user reads, made new unless `recursive`.
fn private_dir(path: &Path, recursive: bool) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(recursive);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(path)
}

/// A new file only this user reads; an existing one is never overwritten.
fn new_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

fn write_new(path: &Path, bytes: &[u8]) -> oneiron::Result<()> {
    use std::io::Write as _;
    new_file(path)?.write_all(bytes)?;
    Ok(())
}
