//! Owner-requested removal of a completed trainer job's staged inputs.

use std::path::{Path, PathBuf};

use anyhow::{Context, ensure};
use oneiron::training_pack::TrainingState;
use oneiron::{EntityId, Vault};
use serde::Serialize;
use serde_json::Value;

use super::{BASE_DIR, BASE_FILES, OUTPUT_DIR, QuestionHeadTrainer, RECEIPT_FILE, TRAINING_FILE};
use crate::config::models::TrainingSettings;

#[derive(Debug, Serialize)]
pub(crate) struct TrainingInputCleanup {
    run: String,
    job: PathBuf,
    removed_files: Vec<PathBuf>,
}

/// Keeps the job's idempotency directory and every output/evidence file.
/// Reread and poll use custody plus output, never these staging copies.
pub(crate) fn cleanup_training_job_inputs(
    vault: &Vault,
    settings: Option<&TrainingSettings>,
    id: &EntityId,
) -> anyhow::Result<TrainingInputCleanup> {
    let run = vault
        .training_run(id)?
        .context("no training run has this id")?;
    ensure!(
        matches!(
            run.state,
            TrainingState::Returned | TrainingState::Scored | TrainingState::Bound
        ),
        "training inputs stay until the run has a durable result"
    );
    let result = run
        .result
        .as_ref()
        .context("the training run has no result")?;
    ensure!(
        QuestionHeadTrainer::serves(&run.plan),
        "the local question-head trainer did not run this plan"
    );
    let connector = settings
        .and_then(|settings| settings.connector(&run.compute.connector))
        .context("the run's training connector is not configured on this host")?;
    let root = connector
        .jobs_root
        .canonicalize()
        .context("cannot resolve the training job root")?;
    let job = root.join(format!(
        "{}-{}",
        id.to_hex(),
        super::blake3_hex(&run.spec_blake3)
    ));
    ensure!(
        std::fs::symlink_metadata(&job)?.file_type().is_dir(),
        "the training job is not a directory or is a symbolic link"
    );
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(job.join(OUTPUT_DIR).join(RECEIPT_FILE))?)?;
    ensure!(
        receipt == result.connector_receipt,
        "the job's receipt differs from the run's durable result"
    );
    let mut removed_files = Vec::new();
    let base = job.join(BASE_DIR);
    match std::fs::symlink_metadata(&base) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_dir(),
                "the staged base is not a directory or is a symbolic link"
            );
            for (name, _) in BASE_FILES {
                remove_input(&base.join(name), &mut removed_files)?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    remove_input(&job.join(TRAINING_FILE), &mut removed_files)?;
    Ok(TrainingInputCleanup {
        run: id.to_hex(),
        job,
        removed_files,
    })
}

fn remove_input(path: &Path, removed: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => removed.push(path.to_path_buf()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot remove staged input {}", path.display()));
        }
    }
    Ok(())
}
