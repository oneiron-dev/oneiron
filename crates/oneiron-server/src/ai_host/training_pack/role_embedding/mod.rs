//! A frozen native embedder plus a learned ST projection; never an automatic swap.
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::skill_optimize::EvalSeat;
use oneiron::training_pack::{
    PollFuture, TrainOutput, TrainRequest, TrainingConnector, TrainingFuture, TrainingPlan,
};
use oneiron::{EntityId, Vault};
use serde::Deserialize;
use serde_json::{Value, json};

use super::wire::{blake3_hex, invalid, sha256_hex};
use crate::config::{EmbedderConfig, models::TrainingConnectorSettings};
use crate::embedder::CheckpointEmbedder;

mod evaluation;
mod wire;
pub(super) use evaluation::evaluate;

pub(super) const RECIPE: &str = "oneiron.reservoir-pair-projection/1";

pub(super) fn serves(plan: &TrainingPlan) -> bool {
    matches!(
        plan.target.role_binding(),
        Some((ModelRole::RetrievalEmbedder, _))
    ) && plan.seat == EvalSeat::Embedder
        && plan.settings.get("recipe").and_then(Value::as_str) == Some(RECIPE)
}

pub(super) fn host_config(
    settings: &Value,
    host: &EmbedderConfig,
) -> oneiron::Result<EmbedderConfig> {
    let tokens = settings
        .get("max_input_tokens")
        .and_then(Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
        .filter(|n| *n > 0)
        .ok_or_else(|| invalid("projection settings need positive max_input_tokens"))?;
    let mut host = host.clone();
    host.max_input_tokens = tokens;
    Ok(host)
}

pub(super) fn check_name(name: &str) -> oneiron::Result<()> {
    if name.is_empty()
        || name.starts_with('/')
        || name.contains('\\')
        || name.chars().any(char::is_control)
        || name.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(invalid("projection files need relative plain names"));
    }
    Ok(())
}

#[derive(Deserialize)]
pub(super) struct Pair {
    pub(super) chosen: String,
    pub(super) rejected: String,
    pub(super) receipt_ref: String,
}

pub(super) fn pairs(bytes: &[u8]) -> oneiron::Result<Vec<Pair>> {
    let rows = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).map_err(|_| invalid("malformed reservoir pair")))
        .collect::<oneiron::Result<Vec<Pair>>>()?;
    if rows.is_empty() {
        return Err(invalid("projection needs a nonempty split"));
    }
    Ok(rows)
}

pub(super) struct EmbeddingTrainer {
    vault: Arc<Vault>,
    connector: TrainingConnectorSettings,
    host: EmbedderConfig,
}

impl EmbeddingTrainer {
    pub(super) fn new(
        vault: Arc<Vault>,
        connector: TrainingConnectorSettings,
        host: EmbedderConfig,
    ) -> Self {
        Self {
            vault,
            connector,
            host,
        }
    }

    fn job(&self, run: &EntityId, spec: &[u8; 32]) -> PathBuf {
        self.connector
            .jobs_root
            .join(format!("{}-{}", run.to_hex(), blake3_hex(spec)))
    }

    async fn train_job(
        &self,
        request: TrainRequest,
        reference: &str,
    ) -> oneiron::Result<TrainOutput> {
        if !serves(&request.plan) || reference != format!("training_pack:{}", request.run.to_hex())
        {
            return Err(invalid("projection request differs from its role or run"));
        }
        let job = self.job(&request.run, &request.spec_blake3);
        if std::fs::symlink_metadata(&job).is_ok() {
            return self.reread(&request, reference, &job);
        }
        private_dir(&self.connector.jobs_root, true)?;
        private_dir(&job, false)?;
        let base_dir = job.join("base");
        private_dir(&base_dir, false)?;
        let mut base_files = Vec::new();
        for file in &request.plan.starting_checkpoint.files {
            check_name(&file.name)?;
            let bytes = self.vault.read_training_artifact(&file.content)?;
            let path = base_dir.join(&file.name);
            if let Some(parent) = path.parent() {
                private_dir(parent, true)?;
            }
            write_new(&path, &bytes)?;
            base_files.push(json!({
                "name": file.name, "kind": file.kind, "source": file.source,
                "sha256": sha256_hex(&bytes), "blake3": blake3_hex(blake3::hash(&bytes).as_bytes()),
                "bytes": bytes.len(),
            }));
        }
        if blake3::hash(&request.training_jsonl).as_bytes() != &request.training_blake3 {
            return Err(invalid("projection training bytes differ from their pin"));
        }
        let rows = pairs(&request.training_jsonl)?;
        let texts: Vec<_> = rows
            .iter()
            .flat_map(|row| [row.chosen.clone(), row.rejected.clone()])
            .collect();
        let preparation = std::time::Instant::now();
        let config = host_config(&request.plan.settings, &self.host)?;
        let encoder =
            CheckpointEmbedder::load(&self.vault, &request.plan.starting_checkpoint, &config)?;
        let features = encoder.training_features(&texts)?;
        let probe_texts = request
            .plan
            .probes
            .iter()
            .map(|probe| {
                probe
                    .input
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| invalid("projection probe input must be a document string"))
            })
            .collect::<oneiron::Result<Vec<_>>>()?;
        let probe_features = encoder.training_features(&probe_texts)?;
        let feature_bytes = serde_json::to_vec(&json!({
            "pairs": features.chunks_exact(2).map(|pair| json!([pair[0], pair[1]])).collect::<Vec<_>>(),
            "probes": probe_features,
        })).map_err(|_| invalid("projection features did not encode"))?;
        write_new(&job.join("training.jsonl"), &feature_bytes)?;
        let body = json!({
            "format": "oneiron.embedding-projection.job/1", "run": request.run.to_hex(),
            "spec_blake3": blake3_hex(&request.spec_blake3),
            "compute": {"kind": "engine_run", "reference": reference},
            "model": request.plan.target.output_model(), "settings": request.plan.settings,
            "harness": request.plan.harness,
            "base": {"dir": base_dir, "files": base_files},
            "features": {"path": job.join("training.jsonl"), "sha256": sha256_hex(&feature_bytes),
                "blake3": blake3_hex(blake3::hash(&feature_bytes).as_bytes()), "bytes": feature_bytes.len()},
            "training_blake3": blake3_hex(&request.training_blake3),
            "preparation_seconds": preparation.elapsed().as_secs_f64(),
            "encoder": {"checkpoint_blake3": blake3_hex(&encoder.checkpoint_hash()),
                "provenance": encoder.provenance(), "dimensions": encoder.dimensions(),
                "requested_max_input_tokens": config.max_input_tokens},
            "probes": request.plan.probes.iter().map(|p| Ok(json!({"id": p.id,
                "input_blake3": blake3_hex(blake3::hash(&oneiron::llm::canonical_json_bytes(&p.input).map_err(|_| invalid("projection probe did not encode"))?).as_bytes())})))
                .collect::<oneiron::Result<Vec<_>>>()?,
            "export_logit_tolerance": request.plan.export_logit_tolerance,
        });
        write_new(
            &job.join("request.json"),
            &serde_json::to_vec(&body).map_err(|_| invalid("projection job did not encode"))?,
        )?;
        drop(encoder);
        let stderr = new_file(&job.join("worker.stderr"))?;
        let mut command: tokio::process::Command =
            oneiron_spawn::command(&self.connector.python).into();
        command
            .arg("-I")
            .arg(&self.connector.worker)
            .arg("--request")
            .arg(job.join("request.json"))
            .arg("--output")
            .arg(job.join("output"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr));
        for name in [
            "ONEIRON_SECRET",
            "ONEIRON_BINDING_KEY",
            "ONEIRON_TOKEN",
            "ONEIRON_AUTH_SECRET",
        ] {
            command.env_remove(name);
        }
        command.spawn()?.wait().await?;
        self.reread(&request, reference, &job)
    }

    fn reread(
        &self,
        request: &TrainRequest,
        reference: &str,
        job: &Path,
    ) -> oneiron::Result<TrainOutput> {
        let bytes = std::fs::read(job.join("request.json"))?;
        wire::decode(request, reference, &bytes, &job.join("output"))
    }

    fn poll_job(&self, run: EntityId, spec: [u8; 32]) -> oneiron::Result<Option<TrainOutput>> {
        let Some(stored) = self.vault.training_run(&run)? else {
            return Ok(None);
        };
        let job = self.job(&run, &spec);
        if stored.spec_blake3 != spec || !job.join("output/receipt.json").is_file() {
            return Ok(None);
        }
        let reference = stored.admission_ref();
        let request = TrainRequest {
            run,
            spec_blake3: spec,
            training_jsonl: Vec::new(),
            training_blake3: stored.corpus.training.blake3,
            plan: stored.plan,
            compute: stored.compute,
            detector: stored.corpus.detector,
        };
        self.reread(&request, &reference, &job).map(Some)
    }
}

impl TrainingConnector for EmbeddingTrainer {
    fn train<'a>(
        &'a self,
        request: TrainRequest,
        admission: &'a RunAdmission,
    ) -> TrainingFuture<'a> {
        let reference = admission.run().to_owned();
        Box::pin(async move { self.train_job(request, &reference).await })
    }
    fn poll<'a>(&'a self, run: &EntityId, spec: &[u8; 32]) -> PollFuture<'a> {
        let (run, spec) = (*run, *spec);
        Box::pin(async move { self.poll_job(run, spec) })
    }
}

fn private_dir(path: &Path, recursive: bool) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(recursive);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(path)
}
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
