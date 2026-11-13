//! The role trainer (ROLE-TRAINING-RUN, LEARN-TRAIN Q2): a local process on
//! this server's own host that trains a model for one manifest role on the
//! owner's consented reservoir pairs, beside the question-head worker
//! (`trainer`), which never sees a role run. A connector under
//! `[models.training.role_trainers]` names the worker and the role recipes
//! it trains; it runs as `<python> -I <worker> --request <job json>
//! --output <new dir>`, with no shell, on the role job wire (`role_wire`).
//!
//! Each run and spec gets one private job directory under the connector's
//! `jobs_root`. It holds the starting checkpoint's pinned files read from
//! custody, the run's training rows and no held-out row. The directory is
//! the job's idempotency key, as for the question worker: one that holds a
//! terminal `receipt.json` is read again, one without is an outstanding or
//! unknown job, and no second job starts for it. No time limit cuts a run
//! short, and a lost waiter leaves the process running to its receipt. The
//! worker's environment is the question worker's (`trainer::spawn_worker`).
use std::path::{Component, Path};
use std::sync::Arc;

use oneiron::llm::run_admission::RunAdmission;
use oneiron::training_pack::{
    CheckpointFilePin, PollFuture, TrainOutput, TrainRequest, TrainingConnector, TrainingFuture,
    TrainingPlan,
};
use oneiron::{EntityId, Vault};

use super::role_wire::{
    self, BaseFileWire, RoleExpected, RoleJobFacts, RoleStagedFiles, recipe_of, row_count,
};
use super::trainer::{outstanding, private_dir, spawn_worker, utf8, write_new};
use super::wire::{blake3_hex, invalid, sha256_hex};
use crate::config::models::RoleTrainerSettings;

const REQUEST_FILE: &str = "request.json";
const BASE_DIR: &str = "base";
const TRAINING_FILE: &str = "training.jsonl";
const OUTPUT_DIR: &str = "output";
const RECEIPT_FILE: &str = "receipt.json";

/// A role trainer connector's worker process, with the vault whose custody
/// holds the starting files.
pub(super) struct RoleTrainer {
    vault: Arc<Vault>,
    trainer: RoleTrainerSettings,
}

impl RoleTrainer {
    pub(super) fn new(vault: Arc<Vault>, trainer: RoleTrainerSettings) -> Self {
        Self { vault, trainer }
    }

    /// Whether `trainer` runs `plan`: a role run on a recipe the connector
    /// lists. A question run is never routed to it.
    pub(super) fn serves(trainer: &RoleTrainerSettings, plan: &TrainingPlan) -> bool {
        plan.target.role_binding().is_some()
            && recipe_of(&plan.settings).is_some_and(|recipe| trainer.recipes.contains(recipe))
    }

    fn job_dir(&self, run: &EntityId, spec_blake3: &[u8; 32]) -> std::path::PathBuf {
        self.trainer
            .jobs_root
            .join(format!("{}-{}", run.to_hex(), blake3_hex(spec_blake3)))
    }

    async fn train_job(
        &self,
        request: TrainRequest,
        reference: String,
    ) -> oneiron::Result<TrainOutput> {
        let facts = RoleJobFacts::of(&request, &reference)?;
        let files = base_files(&request.plan.starting_checkpoint.files)?;
        let job = self.job_dir(&request.run, &request.spec_blake3);
        if std::fs::symlink_metadata(&job).is_ok() {
            return self.reread(&facts, &job);
        }
        let staged = self.stage(&facts, files, &job)?;
        let body = role_wire::build_job(&facts, &staged)?;
        write_new(&job.join(REQUEST_FILE), &body)?;
        let status = spawn_worker(
            &self.trainer.python,
            &self.trainer.worker,
            &job.join(REQUEST_FILE),
            &job.join(OUTPUT_DIR),
            &job,
        )
        .await?;
        let receipt = job.join(OUTPUT_DIR).join(RECEIPT_FILE);
        if !receipt.is_file() {
            return Err(invalid(format!(
                "the role trainer ended ({status}) with no receipt; its job directory stays"
            )));
        }
        let expected = RoleExpected {
            request_sha256: sha256_hex(&body),
            request_bytes: body.len() as u64,
            training_sha256: staged.training_sha256,
            training_rows: staged.training_rows,
        };
        let receipt = std::fs::read(receipt)?;
        role_wire::decode_output(&facts, &expected, &job.join(OUTPUT_DIR), &receipt)
    }

    /// A job this run's directory already holds: its terminal receipt read
    /// again against the request it was handed, or a refusal that starts
    /// nothing.
    fn reread(&self, facts: &RoleJobFacts<'_>, job: &Path) -> oneiron::Result<TrainOutput> {
        let receipt = job.join(OUTPUT_DIR).join(RECEIPT_FILE);
        if !receipt.is_file() {
            return Err(outstanding());
        }
        let body = std::fs::read(job.join(REQUEST_FILE))?;
        let rows = &facts.request.training_jsonl;
        let expected = RoleExpected {
            request_sha256: sha256_hex(&body),
            request_bytes: body.len() as u64,
            training_sha256: sha256_hex(rows),
            training_rows: row_count(rows),
        };
        let receipt = std::fs::read(receipt)?;
        role_wire::decode_output(facts, &expected, &job.join(OUTPUT_DIR), &receipt)
    }

    /// A read-only status check by the job directory's `(run, spec)`
    /// identity: the terminal receipt reread through the same checks when
    /// present, or `None` while the job is unknown or still running. It
    /// never starts work, and a missing receipt is `None`, never an error.
    fn poll_job(
        &self,
        run: EntityId,
        spec_blake3: [u8; 32],
    ) -> oneiron::Result<Option<TrainOutput>> {
        let Some(stored) = self.vault.training_run(&run)? else {
            return Ok(None);
        };
        if stored.spec_blake3 != spec_blake3 {
            return Ok(None);
        }
        let job = self.job_dir(&run, &spec_blake3);
        if !job.join(OUTPUT_DIR).join(RECEIPT_FILE).is_file() {
            return Ok(None);
        }
        let training_jsonl = self.vault.read_training_artifact(&stored.corpus.training)?;
        let reference = stored.admission_ref();
        let request = TrainRequest {
            run,
            spec_blake3,
            plan: stored.plan,
            compute: stored.compute,
            training_jsonl,
            training_blake3: stored.corpus.training.blake3,
            detector: stored.corpus.detector,
        };
        let facts = RoleJobFacts::of(&request, &reference)?;
        self.reread(&facts, &job).map(Some)
    }

    /// Makes the run's private job directory and writes the starting files
    /// and the training rows into it.
    fn stage(
        &self,
        facts: &RoleJobFacts<'_>,
        files: &[CheckpointFilePin],
        job: &Path,
    ) -> oneiron::Result<RoleStagedFiles> {
        private_dir(&self.trainer.jobs_root, true)?;
        match private_dir(job, false) {
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(outstanding());
            }
            made => made?,
        }
        let base_dir = job.join(BASE_DIR);
        private_dir(&base_dir, false)?;
        let base = files
            .iter()
            .map(|file| {
                let bytes = self.vault.read_training_artifact(&file.content)?;
                write_new(&base_dir.join(&file.name), &bytes)?;
                Ok(BaseFileWire::of(
                    &file.name,
                    file.kind,
                    &file.source,
                    &bytes,
                ))
            })
            .collect::<oneiron::Result<Vec<_>>>()?;
        let rows = &facts.request.training_jsonl;
        if blake3::hash(rows).as_bytes() != &facts.request.training_blake3 {
            return Err(invalid("the run's training rows differ from their pin"));
        }
        let training_path = job.join(TRAINING_FILE);
        write_new(&training_path, rows)?;
        Ok(RoleStagedFiles {
            base_dir: utf8(&base_dir)?,
            base,
            training_path: utf8(&training_path)?,
            training_sha256: sha256_hex(rows),
            training_blake3: blake3_hex(blake3::hash(rows).as_bytes()),
            training_bytes: rows.len() as u64,
            training_rows: row_count(rows),
        })
    }
}

impl TrainingConnector for RoleTrainer {
    fn train<'a>(
        &'a self,
        request: TrainRequest,
        admission: &'a RunAdmission,
    ) -> TrainingFuture<'a> {
        Box::pin(self.train_job(request, admission.run().to_owned()))
    }

    fn poll<'a>(&'a self, run: &EntityId, spec_blake3: &[u8; 32]) -> PollFuture<'a> {
        let run = *run;
        let spec_blake3 = *spec_blake3;
        Box::pin(async move { self.poll_job(run, spec_blake3) })
    }
}

/// The starting checkpoint's files, each staged under its own name: a flat
/// bundle whose names are plain file names, so no file lands outside the
/// job's base directory.
fn base_files(files: &[CheckpointFilePin]) -> oneiron::Result<&[CheckpointFilePin]> {
    if files.is_empty() || !files.iter().all(|file| flat_name(&file.name)) {
        return Err(invalid(
            "a role run starts from a flat checkpoint: plain file names, staged side by side",
        ));
    }
    Ok(files)
}

/// Whether a checkpoint file's name is one plain file name, so staging it
/// under its name lands inside its directory. The role scorer stages the
/// exported checkpoint the same way.
pub(super) fn flat_name(name: &str) -> bool {
    let mut parts = Path::new(name).components();
    matches!(parts.next(), Some(Component::Normal(_))) && parts.next().is_none()
}
