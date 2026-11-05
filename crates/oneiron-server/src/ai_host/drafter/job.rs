//! One drafter training job's private directory (FIX 14974): what the host
//! stages for the worker, the receipt it reads back, and the load set it
//! seals from the worker's output.
//!
//! Each `(version, spec)` gets `<jobs_root>/<version hex>-<spec hex>/`
//! (mode 0700) holding `request.json` (`oneiron.drafter.train-job/1`,
//! `scripts/drafter/README.md`), the training side of the version's corpus
//! (`training.jsonl`, never a held-out example), a continued version's
//! parent trainable files (`parent/`), `worker.pid`, `worker.stderr` and the
//! worker's `output/`: its lock, its `receipt.json` and its `load-set/`.
//! The directory is the only place the training side is plaintext, and only
//! for the job's life: the host removes it once the job ended, and the
//! recovery pass removes every one whose version no longer trains.
//!
//! The directory is the job's idempotency key. One whose worker still holds
//! its lock is running; one with a receipt and no live worker has ended; one
//! with neither is lost. None of them starts a second job.
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use oneiron::drafter::{
    DRAFTER_TRAINABLE_PREFIX, DrafterArtifactFile, DrafterServing, DrafterTrainingJob,
    drafter_file_name_is_plain,
};
use oneiron::{EntityId, Error, Vault};
use serde_json::{Value, json};

use crate::config::models::{DrafterTrainerSettings, TRAINING_SERVICE_UNIT};

const JOB_FORMAT: &str = "oneiron.drafter.train-job/1";
const RECEIPT_FORMAT: &str = "oneiron.drafter.train-receipt/1";
const REQUEST_FILE: &str = "request.json";
const TRAINING_FILE: &str = "training.jsonl";
const PARENT_DIR: &str = "parent";
const OUTPUT_DIR: &str = "output";
const RECEIPT_FILE: &str = "receipt.json";
const LOAD_SET_DIR: &str = "load-set";
/// The lock the worker holds for its whole life (`scripts/drafter/worker.py`).
const LOCK_FILE: &str = "worker.lock";
/// The worker's process id, which is its process group's.
const PID_FILE: &str = "worker.pid";
/// What the worker wrote to its error stream.
const STDERR_FILE: &str = "worker.stderr";
/// A load-set file's role in the receipt: what the serving runtime loads.
const ROLE_SERVING: &str = "serving";
/// The role of a trainable state file a continued version trains from.
const ROLE_TRAINABLE: &str = "trainable";

fn invalid(reason: impl Into<String>) -> Error {
    Error::InvalidConfig(reason.into())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn utf8(path: &Path) -> oneiron::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("a drafter job path is not UTF-8"))
}

/// A directory only this user reads, made new unless `recursive`.
fn private_dir(path: &Path, recursive: bool) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(recursive);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(path)
}

/// A new file only this user reads; an existing one is never overwritten.
pub(super) fn new_file(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

fn write_new(path: &Path, bytes: &[u8]) -> oneiron::Result<()> {
    let mut file = new_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// The plaintext length and BLAKE3 of the file at `path`.
fn file_blake3(path: &Path) -> std::io::Result<(u64, [u8; 32])> {
    let mut input = fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let bytes = std::io::copy(&mut input, &mut hasher)?;
    Ok((bytes, *hasher.finalize().as_bytes()))
}

/// What the host wrote for the worker: the request's BLAKE3 and length,
/// which its receipt must echo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Staged {
    request_blake3: [u8; 32],
    request_bytes: u64,
}

/// One output file of the load set, as the receipt names it and the host
/// hashed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OutputFile {
    name: String,
    bytes: u64,
    blake3: [u8; 32],
}

/// What a receipt that matches its job says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Verified {
    /// It trained, and every output file verified.
    Trained(Vec<OutputFile>),
    /// It failed or refused.
    Failed,
}

/// A receipt read back: its BLAKE3, the GPU seconds it reports and what it
/// says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ReadReceipt {
    pub(super) receipt_blake3: [u8; 32],
    pub(super) gpu_seconds: Option<u64>,
    pub(super) verified: Verified,
}

/// Where a job directory stands for the recovery pass.
pub(super) enum JobState {
    /// Its worker still holds its lock.
    Running,
    /// Its worker is gone and its receipt is there.
    Ended(Staged),
    /// No directory, no request or no receipt, and no live worker.
    Missing,
}

/// One job's directory under its trainer's jobs root.
pub(super) struct JobDir {
    root: PathBuf,
    dir: PathBuf,
}

impl JobDir {
    pub(super) fn of(root: &Path, version: &EntityId, spec_blake3: &[u8; 32]) -> Self {
        Self {
            root: root.to_path_buf(),
            dir: root.join(format!("{}-{}", version.to_hex(), hex(spec_blake3))),
        }
    }

    pub(super) fn request(&self) -> PathBuf {
        self.dir.join(REQUEST_FILE)
    }

    pub(super) fn output(&self) -> PathBuf {
        self.dir.join(OUTPUT_DIR)
    }

    pub(super) fn stderr(&self) -> PathBuf {
        self.dir.join(STDERR_FILE)
    }

    pub(super) fn pid(&self) -> PathBuf {
        self.dir.join(PID_FILE)
    }

    /// Makes the job's private directory and writes the training side, the
    /// parent's trainable files for a continued version, and the request.
    /// A directory that already exists is an outstanding or unknown job, and
    /// nothing is staged over it.
    ///
    /// # Errors
    /// An existing directory, a corpus that does not open or differs from
    /// its pin, a parent that does not open, and I/O faults.
    pub(super) fn stage(
        &self,
        vault: &Vault,
        job: &DrafterTrainingJob,
        generation: u64,
        admission: &str,
        trainer: &DrafterTrainerSettings,
    ) -> oneiron::Result<Staged> {
        private_dir(&self.root, true)?;
        match private_dir(&self.dir, false) {
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(invalid(
                    "an outstanding or unknown drafter job holds this version's directory",
                ));
            }
            made => made?,
        }
        let corpus = vault
            .drafter_training_corpus(&job.version)?
            .ok_or_else(|| invalid("the drafter version's training side does not open"))?;
        if corpus.len() as u64 != job.training_corpus.bytes
            || blake3::hash(&corpus).as_bytes() != &job.training_corpus.blake3
        {
            return Err(invalid("the drafter training side differs from its pin"));
        }
        let training = self.dir.join(TRAINING_FILE);
        write_new(&training, &corpus)?;
        drop(corpus);
        let parent = match job.parent {
            DrafterServing::Stock => json!({
                "kind": "stock",
                "dir": utf8(&trainer.stock_drafter)?,
            }),
            DrafterServing::Version(parent) => {
                let dir = self.dir.join(PARENT_DIR);
                let files = vault.materialize_drafter_parent(job, &dir)?;
                json!({
                    "kind": "version",
                    "version": parent.to_hex(),
                    "dir": utf8(&dir)?,
                    "files": files.iter().map(file_pin).collect::<Vec<_>>(),
                })
            }
        };
        let recipe = serde_json::to_value(&job.recipe)
            .map_err(|_| invalid("the drafter recipe did not encode"))?;
        let target = serde_json::to_value(&job.target)
            .map_err(|_| invalid("the drafter target did not encode"))?;
        let body = json!({
            "format": JOB_FORMAT,
            "version": job.version.to_hex(),
            "spec_blake3": hex(&job.spec_blake3),
            "generation": generation,
            "admission": admission,
            "recipe": recipe,
            "target": target,
            "served_target": utf8(&trainer.served_target)?,
            "tap_model": utf8(&trainer.tap_model)?,
            "converter": utf8(&trainer.converter)?,
            "parent": parent,
            "training": {
                "path": utf8(&training)?,
                "bytes": job.training_corpus.bytes,
                "blake3": hex(&job.training_corpus.blake3),
                "examples": job.training_corpus.examples,
                "form": job.corpus_form,
            },
        });
        let bytes = serde_json::to_vec_pretty(&body)
            .map_err(|_| invalid("the drafter job request did not encode"))?;
        write_new(&self.request(), &bytes)?;
        Ok(Staged {
            request_blake3: *blake3::hash(&bytes).as_bytes(),
            request_bytes: bytes.len() as u64,
        })
    }

    /// Where the job stands, without starting anything.
    pub(super) fn state(&self) -> JobState {
        if worker_alive(&self.output().join(LOCK_FILE)) {
            return JobState::Running;
        }
        if !self.output().join(RECEIPT_FILE).is_file() {
            return JobState::Missing;
        }
        match fs::read(self.request()) {
            Ok(bytes) => JobState::Ended(Staged {
                request_blake3: *blake3::hash(&bytes).as_bytes(),
                request_bytes: bytes.len() as u64,
            }),
            Err(_) => JobState::Missing,
        }
    }

    /// Stops the worker's whole process group, when its pid file names one.
    pub(super) fn stop_worker(&self) {
        let pid = fs::read_to_string(self.pid())
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok());
        if let Some(pid) = pid {
            super::process::kill_group(pid);
        }
    }

    /// Removes the job directory and everything in it; a fault is logged and
    /// the recovery pass removes what is left.
    pub(super) fn remove(&self) {
        match fs::remove_dir_all(&self.dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(%error, "a drafter job directory did not go"),
        }
    }

    /// Reads and checks the ended job's receipt against its job: the format,
    /// the request it echoes, the version, spec and generation, the recipe
    /// and target, and for a trained job every load-set file (plain names,
    /// a serving file and the trainable state, nothing else in the
    /// directory, each file's length and BLAKE3 rehashed here) and the GPU
    /// seconds it measured.
    ///
    /// # Errors
    /// Why the receipt does not verify; the reason quotes no content.
    pub(super) fn read_receipt(
        &self,
        job: &DrafterTrainingJob,
        generation: u64,
        staged: &Staged,
    ) -> Result<ReadReceipt, String> {
        let bytes = fs::read(self.output().join(RECEIPT_FILE))
            .map_err(|error| format!("the receipt does not read: {}", error.kind()))?;
        let receipt_blake3 = *blake3::hash(&bytes).as_bytes();
        let receipt: Value =
            serde_json::from_slice(&bytes).map_err(|_| "the receipt is not JSON".to_owned())?;
        let field = |name: &str| receipt.get(name).cloned().unwrap_or(Value::Null);
        let expect = |ok: bool, what: &str| {
            if ok {
                Ok(())
            } else {
                Err(format!("the receipt's {what} is not the job's"))
            }
        };
        expect(field("format") == json!(RECEIPT_FORMAT), "format")?;
        let request = field("request");
        expect(
            request.get("blake3") == Some(&json!(hex(&staged.request_blake3)))
                && request.get("bytes") == Some(&json!(staged.request_bytes)),
            "request",
        )?;
        expect(field("version") == json!(job.version.to_hex()), "version")?;
        expect(field("spec_blake3") == json!(hex(&job.spec_blake3)), "spec")?;
        expect(field("generation") == json!(generation), "generation")?;
        let recipe = serde_json::to_value(&job.recipe).map_err(|_| "recipe".to_owned())?;
        let target = serde_json::to_value(&job.target).map_err(|_| "target".to_owned())?;
        expect(field("recipe") == recipe, "recipe")?;
        expect(field("target") == target, "target")?;
        let gpu_seconds = gpu_seconds(&field("service_units"))?;
        match field("status").as_str() {
            Some("trained") => {}
            Some("failed" | "refused") => {
                return Ok(ReadReceipt {
                    receipt_blake3,
                    gpu_seconds,
                    verified: Verified::Failed,
                });
            }
            _ => return Err("the receipt names no known status".to_owned()),
        }
        let gpu_seconds = Some(
            gpu_seconds.ok_or_else(|| "a trained receipt measures no GPU seconds".to_owned())?,
        );
        let output = field("output");
        expect(
            output.get("runtime") == Some(&json!(job.target.runtime))
                && output.get("dir") == Some(&json!(LOAD_SET_DIR)),
            "output runtime",
        )?;
        let files = self.output_files(output.get("files"))?;
        Ok(ReadReceipt {
            receipt_blake3,
            gpu_seconds,
            verified: Verified::Trained(files),
        })
    }

    /// The load set the receipt names, checked against the directory: each
    /// a plain name once, serving files and trainable state apart, nothing
    /// else there, each rehashed.
    fn output_files(&self, files: Option<&Value>) -> Result<Vec<OutputFile>, String> {
        let rows = files
            .and_then(Value::as_array)
            .filter(|rows| !rows.is_empty())
            .ok_or_else(|| "the receipt names no output file".to_owned())?;
        let load_set = self.output().join(LOAD_SET_DIR);
        let mut out: Vec<OutputFile> = Vec::new();
        let (mut serving, mut trainable) = (0usize, 0usize);
        for row in rows {
            let name = row
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| drafter_file_name_is_plain(name))
                .ok_or_else(|| "an output file's name is not one plain name".to_owned())?;
            if out.iter().any(|file| file.name == name) {
                return Err("an output file is named twice".to_owned());
            }
            let trainable_name = name.starts_with(DRAFTER_TRAINABLE_PREFIX);
            match row.get("role").and_then(Value::as_str) {
                Some(ROLE_SERVING) if !trainable_name => serving += 1,
                Some(ROLE_TRAINABLE) if trainable_name => trainable += 1,
                _ => return Err("an output file's role does not fit its name".to_owned()),
            }
            let path = load_set.join(name);
            let meta = fs::symlink_metadata(&path)
                .map_err(|_| "an output file the receipt names is missing".to_owned())?;
            if !meta.file_type().is_file() {
                return Err("an output file is not a plain file".to_owned());
            }
            let (bytes, blake3) =
                file_blake3(&path).map_err(|_| "an output file does not read".to_owned())?;
            let named = row.get("bytes").and_then(Value::as_u64) == Some(bytes)
                && row.get("blake3").and_then(Value::as_str) == Some(hex(&blake3).as_str());
            if !named {
                return Err("an output file is not the one its receipt names".to_owned());
            }
            out.push(OutputFile {
                name: name.to_owned(),
                bytes,
                blake3,
            });
        }
        if serving == 0 || trainable == 0 {
            return Err("the load set holds no serving file or no trainable state".to_owned());
        }
        let listed = fs::read_dir(&load_set)
            .map_err(|_| "the load set directory does not read".to_owned())?
            .count();
        if listed != out.len() {
            return Err("the load set directory holds a file its receipt does not name".to_owned());
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

/// The GPU seconds a receipt's `service_units` names: in the training
/// service unit, a whole count; `None` when it names none.
fn gpu_seconds(units: &Value) -> Result<Option<u64>, String> {
    if units.is_null() {
        return Ok(None);
    }
    if units.get("unit") != Some(&json!(TRAINING_SERVICE_UNIT)) {
        return Err(format!(
            "the receipt's service units are not {TRAINING_SERVICE_UNIT}"
        ));
    }
    units
        .get("quantity")
        .and_then(Value::as_u64)
        .map(Some)
        .ok_or_else(|| "the receipt's GPU seconds are not a whole count".to_owned())
}

fn file_pin(file: &DrafterArtifactFile) -> Value {
    json!({ "name": file.name, "bytes": file.bytes, "blake3": hex(&file.blake3) })
}

/// Whether a worker holds the lock at `path`: a lock no one holds, or no
/// lock file, is no live worker.
fn worker_alive(path: &Path) -> bool {
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            false
        }
        Err(fs::TryLockError::WouldBlock) => true,
        Err(fs::TryLockError::Error(_)) => false,
    }
}

/// Seals the verified load set of `job`'s output under the version's own
/// key and publishes it: `begin_drafter_artifact` checks the version is
/// still training at `generation` and mints the key, each file is sealed
/// with `DrafterSealing::seal_file` (its length and BLAKE3 must still be the
/// verified ones), and `publish_drafter_artifact` checks the generation
/// again. On any failure the sealed files go; a refused publication has
/// already retired its key.
///
/// # Errors
/// A version that moved, a file that changed since it was verified, and
/// sealing, custody and I/O faults.
pub(super) fn seal_and_publish(
    vault: &Vault,
    job: &DrafterTrainingJob,
    generation: u64,
    dir: &JobDir,
    files: &[OutputFile],
) -> oneiron::Result<()> {
    let sealing = vault.begin_drafter_artifact(&job.version, generation)?;
    let sealed_dir = vault.drafter_artifact_files_dir(&sealing.artifact());
    let load_set = dir.output().join(LOAD_SET_DIR);
    let sealed = (|| -> oneiron::Result<()> {
        if let Some(parent) = sealed_dir.parent() {
            private_dir(parent, true)?;
        }
        private_dir(&sealed_dir, false)?;
        let mut records = Vec::with_capacity(files.len());
        for file in files {
            let mut input = fs::File::open(load_set.join(&file.name))?;
            let record = sealing.seal_file(&file.name, &mut input, &sealed_dir.join(&file.name))?;
            if record.bytes != file.bytes || record.blake3 != file.blake3 {
                return Err(invalid(
                    "a drafter output file changed since its receipt was verified",
                ));
            }
            records.push(record);
        }
        vault.publish_drafter_artifact(&sealing, records)?;
        Ok(())
    })();
    if sealed.is_err() {
        let _ = fs::remove_dir_all(&sealed_dir);
    }
    sealed
}

/// Removes every job directory under `root` whose version `keep` does not
/// name: a job that ended, or whose version no longer trains (an erased
/// one included). Entries not named as a job are left alone. A worker that
/// still holds its directory's lock (one a killed server left running, on
/// that directory's plaintext and its GPU) has its whole process group
/// stopped first, and the directory, with its pid and lock, stays until the
/// lock is free, so the next pass stops it again rather than losing it.
pub(super) fn sweep(root: &Path, keep: impl Fn(&EntityId) -> bool) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(version) = name
            .to_str()
            .and_then(|name| name.split_once('-'))
            .filter(|(_, spec)| spec.len() == 64 && spec.bytes().all(|b| b.is_ascii_hexdigit()))
            .and_then(|(version, _)| EntityId::from_hex(version).ok())
        else {
            continue;
        };
        if keep(&version) {
            continue;
        }
        let path = entry.path();
        // Only a held lock names a live worker, so a pid is killed only
        // while its worker still runs, never a reused one.
        if worker_alive(&path.join(OUTPUT_DIR).join(LOCK_FILE)) {
            let pid = fs::read_to_string(path.join(PID_FILE))
                .ok()
                .and_then(|text| text.trim().parse::<u32>().ok());
            if let Some(pid) = pid {
                super::process::kill_group(pid);
            }
            tracing::warn!(
                "a drafter job's worker outlived its version; its process group was stopped and the next pass removes its directory"
            );
            continue;
        }
        if let Err(error) = fs::remove_dir_all(&path) {
            tracing::warn!(%error, "a drafter job directory did not go; the next pass retries");
        }
    }
}
