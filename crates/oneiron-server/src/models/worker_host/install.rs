//! A managed worker's install (DESIGN-V2 R2): its weights through the
//! artifact store, its code bundle written from this binary, its Python
//! environment built from a hash-locked lock, its native binary checked by
//! its pinned SHA-256, and the EXL3 digests its verified bytes give.
//!
//! Every step either verifies what is there or puts verified bytes in a
//! directory named by their digest; nothing an earlier install placed is
//! removed or repaired. A step that cannot succeed until the config changes
//! is a permanent failure; a cut transfer or an I/O error is transient.
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use oneiron::llm::{WorkerFailure, WorkerKind};
use oneiron_driver::LaunchFailure;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::bundle::{self, EXL3_LOCK, WORKER_FILES, sha256_hex};
use crate::config::models::{ArtifactSource, NativeServer, WorkerArtifact};
use crate::model_artifacts::ArtifactError;
use crate::model_artifacts::catalog::house_artifact;
use crate::model_artifacts::install::{ArtifactState, ArtifactStore, HubToken};
use crate::model_artifacts::manifest::{ArtifactClass, ArtifactFormat, ArtifactManifest};

/// The interpreter version the embedded EXL3 lock is resolved for.
const EXL3_LOCK_PYTHON: &str = "3.12";

/// The record a built environment holds, written before it is put in place.
const ENV_RECORD: &str = "oneiron-env.json";

/// The files the EXL3 server's tokenizer digest covers, in its order
/// (`cache_usage.TOKENIZER_FILES`).
const EXL3_TOKENIZER_FILES: [&str; 5] = [
    "tokenizer.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
    "added_tokens.json",
    "config.json",
];

/// The longest tail of a failed tool's output a failure reason keeps.
const REASON_TAIL: usize = 2000;

/// One set of verified weights.
#[derive(Clone, Debug)]
pub(super) struct InstalledWeights {
    pub(super) dir: PathBuf,
    /// The install record's digest of the manifest (`ArtifactManifest::digest`).
    pub(super) record_sha256: String,
    pub(super) manifest: ArtifactManifest,
}

impl InstalledWeights {
    /// The first GGUF file the manifest pins, as llama.cpp is given it (a
    /// split set's first part sorts first).
    pub(super) fn gguf(&self) -> Option<(PathBuf, &str)> {
        let mut ggufs: Vec<_> = self
            .manifest
            .files
            .iter()
            .filter(|file| file.path.ends_with(".gguf"))
            .collect();
        ggufs.sort_by(|a, b| a.path.cmp(&b.path));
        ggufs
            .first()
            .map(|file| (self.dir.join(&*file.path), &*file.sha256))
    }
}

/// A built, checked Python environment.
#[derive(Clone, Debug)]
pub(super) struct InstalledEnv {
    pub(super) python: PathBuf,
    pub(super) lock_sha256: String,
    pub(super) freeze_sha256: String,
    pub(super) python_version: String,
}

/// What the EXL3 server's identity will name, from the verified bytes: its
/// weights manifest (written for `--weights-manifest`) and that manifest's
/// digest, and the template and tokenizer digests as the server takes them.
#[derive(Clone, Debug)]
pub(super) struct Exl3Digests {
    pub(super) weights_manifest: PathBuf,
    pub(super) model: String,
    pub(super) template: Option<String>,
    pub(super) tokenizer: Option<String>,
}

/// A built environment's record.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct EnvRecord {
    lock_sha256: String,
    python: String,
    python_version: String,
    freeze_sha256: String,
}

/// The class and format a worker of `kind` loads, as its target or its
/// draft; `None` for a kind no managed launcher loads weights for.
fn loads(kind: WorkerKind, draft: bool) -> Option<(ArtifactClass, ArtifactFormat)> {
    let format = match kind {
        WorkerKind::LlamaCpp => ArtifactFormat::Gguf,
        WorkerKind::Exl3 => ArtifactFormat::Exl3,
        WorkerKind::VoxCpm2 if !draft => ArtifactFormat::VoxCpm2Checkpoint,
        WorkerKind::Asr if !draft => ArtifactFormat::Safetensors,
        _ => return None,
    };
    let class = match kind {
        _ if draft => ArtifactClass::Drafter,
        WorkerKind::VoxCpm2 => ArtifactClass::Voice,
        WorkerKind::Asr => ArtifactClass::Asr,
        _ => ArtifactClass::Llm,
    };
    Some((class, format))
}

/// Makes `artifact`'s weights present and verified: the offline directory
/// checked file by file, or an install through `store`.
pub(super) async fn weights(
    store: Arc<ArtifactStore>,
    artifact: &WorkerArtifact,
    kind: WorkerKind,
    draft: bool,
    hub_token_env: Option<&str>,
) -> Result<InstalledWeights, LaunchFailure> {
    let manifest = match &artifact.source {
        ArtifactSource::Catalog(id) => house_artifact(id).cloned().ok_or_else(|| {
            permanent(
                WorkerFailure::LoadFailed,
                format!("{id} is not a house catalog id"),
            )
        })?,
        ArtifactSource::Manifest(path) => {
            let bytes = std::fs::read(path).map_err(|error| {
                permanent(
                    WorkerFailure::LoadFailed,
                    format!("reading {}: {error}", path.display()),
                )
            })?;
            serde_json::from_slice::<ArtifactManifest>(&bytes).map_err(|error| {
                permanent(
                    WorkerFailure::LoadFailed,
                    format!("{} is not a model manifest: {error}", path.display()),
                )
            })?
        }
    };
    if loads(kind, draft) != Some((manifest.class, manifest.format)) {
        return Err(permanent(
            WorkerFailure::KindMismatch,
            format!(
                "model {}: a {kind:?} worker does not load {:?} {:?} weights{}",
                manifest.id,
                manifest.class,
                manifest.format,
                if draft { " as its draft" } else { "" }
            ),
        ));
    }
    let token = hub_token_env
        .and_then(|env| std::env::var(env).ok())
        .and_then(|token| HubToken::bearer(&token));
    let offline_dir = artifact.offline_dir.clone();
    let placed = tokio::task::spawn_blocking(move || {
        let installed = match &offline_dir {
            Some(dir) => store.verify_dir(&manifest, dir),
            None => {
                note_on_disk(&store, &manifest);
                store.install(&manifest, token.as_ref())
            }
        };
        installed.map(|installed| (installed, manifest))
    })
    .await
    .map_err(|error| transient(WorkerFailure::LoadFailed, error.to_string()))?;
    let (installed, manifest) = placed.map_err(artifact_failure)?;
    tracing::info!(
        model = %manifest.id,
        dir = %installed.dir.display(),
        total_bytes = installed.total_bytes,
        fetched_bytes = installed.fetched_bytes,
        "model worker weights verified"
    );
    Ok(InstalledWeights {
        dir: installed.dir,
        record_sha256: installed.manifest_digest,
        manifest,
    })
}

/// Logs what is on disk for `manifest` before an install starts.
fn note_on_disk(store: &ArtifactStore, manifest: &ArtifactManifest) {
    let target = store
        .install_dir(manifest)
        .map(|dir| dir.display().to_string())
        .unwrap_or_default();
    match store.inspect(manifest) {
        Ok(ArtifactState::Absent) => {
            tracing::info!(model = %manifest.id, %target, "model worker weights: downloading");
        }
        Ok(ArtifactState::Partial { bytes_present }) => {
            tracing::info!(model = %manifest.id, %target, bytes_present, "model worker weights: resuming");
        }
        Ok(ArtifactState::Installed {
            dir,
            manifest_digest,
            total_bytes,
        }) => {
            tracing::info!(
                model = %manifest.id,
                dir = %dir.display(),
                %manifest_digest,
                total_bytes,
                "model worker weights: installed; verifying"
            );
        }
        Ok(ArtifactState::Corrupt { file }) => {
            tracing::warn!(model = %manifest.id, %target, %file, "model worker weights: the installed directory does not match");
        }
        Err(error) => {
            tracing::warn!(model = %manifest.id, %error, "model worker weights: unreadable");
        }
    }
}

fn artifact_failure(error: ArtifactError) -> LaunchFailure {
    let reason = error.to_string();
    match error {
        ArtifactError::Transfer { .. } | ArtifactError::Io { .. } => {
            transient(WorkerFailure::LoadFailed, reason)
        }
        ArtifactError::Mismatch { .. } | ArtifactError::InstalledMismatch { .. } => {
            permanent(WorkerFailure::ModelMismatch, reason)
        }
        _ => permanent(WorkerFailure::LoadFailed, reason),
    }
}

/// Writes the code bundle under `<root>/bundles/<digest>/`, or checks the
/// one there, file by file. Returns its directory and digest.
pub(super) async fn bundle(root: &Path) -> Result<(PathBuf, String), LaunchFailure> {
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let digest = bundle::bundle_sha256();
        let dir = root.join("bundles").join(&digest);
        if dir.is_dir() {
            for (name, bytes) in WORKER_FILES {
                let held = std::fs::read(dir.join(name)).unwrap_or_default();
                if held.as_slice() != *bytes {
                    return Err(permanent(
                        WorkerFailure::BuildMismatch,
                        format!(
                            "{} holds a changed {name}; it was left as it is",
                            dir.display()
                        ),
                    ));
                }
            }
            return Ok((dir, digest));
        }
        let staging = root
            .join("bundles")
            .join(format!(".{digest}.staging-{}", std::process::id()));
        let written = (|| {
            std::fs::create_dir_all(&staging)?;
            for (name, bytes) in WORKER_FILES {
                // A package's files (`exl3_session/`) go in their folder.
                let path = staging.join(name);
                if let Some(folder) = path.parent() {
                    std::fs::create_dir_all(folder)?;
                }
                std::fs::write(path, bytes)?;
            }
            std::fs::rename(&staging, &dir)
        })();
        written.map(|()| (dir, digest)).map_err(|error| {
            transient(
                WorkerFailure::LoadFailed,
                format!("writing the worker bundle: {error}"),
            )
        })
    })
    .await
    .map_err(|error| transient(WorkerFailure::LoadFailed, error.to_string()))?
}

/// A Python worker's environment: built once per lock and interpreter under
/// `<root>/envs/`, from `lock`, and checked against its record at every
/// install. `None` is the embedded EXL3 lock, which only an EXL3 worker
/// takes; a media worker always passes its row's own.
pub(super) async fn environment(
    root: &Path,
    python: &Path,
    lock: Option<&Path>,
    passed_env: &[(String, String)],
) -> Result<InstalledEnv, LaunchFailure> {
    let lock_bytes = match lock {
        Some(path) => std::fs::read(path).map_err(|error| {
            permanent(
                WorkerFailure::LoadFailed,
                format!("reading {}: {error}", path.display()),
            )
        })?,
        None => EXL3_LOCK.to_vec(),
    };
    let lock_sha256 = sha256_hex(&lock_bytes);
    let version = run(
        python,
        &["-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
        passed_env,
    )
    .await
    .map_err(|reason| permanent(WorkerFailure::LoadFailed, reason))?;
    let python_version = String::from_utf8_lossy(&version).trim().to_owned();
    if lock.is_none() && python_version != EXL3_LOCK_PYTHON {
        return Err(permanent(
            WorkerFailure::BuildMismatch,
            format!(
                "{} is Python {python_version}; the EXL3 lock is for Python {EXL3_LOCK_PYTHON}",
                python.display()
            ),
        ));
    }
    let python_name = python.display().to_string();
    let key = sha256_hex(format!("{lock_sha256}\0{python_name}\0{python_version}").as_bytes());
    let envs = root.join("envs");
    let dir = envs.join(&key[..32]);
    let wanted = |freeze_sha256: String| EnvRecord {
        lock_sha256: lock_sha256.clone(),
        python: python_name.clone(),
        python_version: python_version.clone(),
        freeze_sha256,
    };
    if dir.is_dir() {
        let record = std::fs::read(dir.join(ENV_RECORD))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<EnvRecord>(&bytes).ok());
        let freeze = freeze(&dir, passed_env).await?;
        if record.as_ref() != Some(&wanted(freeze.clone())) {
            return Err(permanent(
                WorkerFailure::BuildMismatch,
                format!(
                    "{} no longer matches the environment built from its lock; it was left as it is",
                    dir.display()
                ),
            ));
        }
        return Ok(installed_env(&dir, wanted(freeze)));
    }
    let lock_path = match lock {
        Some(path) => path.to_path_buf(),
        None => {
            let path = root.join("locks").join(format!("{lock_sha256}.txt"));
            std::fs::create_dir_all(root.join("locks"))
                .and_then(|()| std::fs::write(&path, &lock_bytes))
                .map_err(|error| {
                    transient(
                        WorkerFailure::LoadFailed,
                        format!("writing the lock: {error}"),
                    )
                })?;
            path
        }
    };
    let staging = envs.join(format!(".{}.staging", &key[..32]));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .map_err(|error| transient(WorkerFailure::LoadFailed, error.to_string()))?;
    }
    std::fs::create_dir_all(&envs)
        .map_err(|error| transient(WorkerFailure::LoadFailed, error.to_string()))?;
    tracing::info!(env = %dir.display(), "model worker environment: building from its lock");
    let staging_arg = staging.display().to_string();
    run(python, &["-m", "venv", staging_arg.as_str()], passed_env)
        .await
        .map_err(|reason| transient(WorkerFailure::LoadFailed, reason))?;
    let lock_arg = lock_path.display().to_string();
    run(
        &staging.join("bin").join("python"),
        &[
            "-m",
            "pip",
            "install",
            "--require-hashes",
            "--no-deps",
            "--no-input",
            "--disable-pip-version-check",
            "-r",
            lock_arg.as_str(),
        ],
        passed_env,
    )
    .await
    .map_err(|reason| transient(WorkerFailure::LoadFailed, reason))?;
    let record = wanted(freeze(&staging, passed_env).await?);
    let written = serde_json::to_vec(&record)
        .map_err(std::io::Error::other)
        .and_then(|bytes| std::fs::write(staging.join(ENV_RECORD), bytes))
        .and_then(|()| std::fs::rename(&staging, &dir));
    written.map_err(|error| transient(WorkerFailure::LoadFailed, error.to_string()))?;
    Ok(installed_env(&dir, record))
}

fn installed_env(dir: &Path, record: EnvRecord) -> InstalledEnv {
    InstalledEnv {
        python: dir.join("bin").join("python"),
        lock_sha256: record.lock_sha256,
        freeze_sha256: record.freeze_sha256,
        python_version: record.python_version,
    }
}

/// SHA-256 of what the environment's pip lists as installed.
async fn freeze(dir: &Path, passed_env: &[(String, String)]) -> Result<String, LaunchFailure> {
    let listed = run(
        &dir.join("bin").join("python"),
        &[
            "-m",
            "pip",
            "freeze",
            "--all",
            "--disable-pip-version-check",
        ],
        passed_env,
    )
    .await
    .map_err(|reason| permanent(WorkerFailure::BuildMismatch, reason))?;
    Ok(sha256_hex(&listed))
}

/// Runs `program` with `args` and only `passed_env`, and returns its stdout;
/// a failure is its status and the tail of its stderr.
async fn run(
    program: &Path,
    args: &[&str],
    passed_env: &[(String, String)],
) -> Result<Vec<u8>, String> {
    let mut command: tokio::process::Command = oneiron_spawn::command(program).into();
    command
        .args(args)
        .env_clear()
        .envs(passed_env.iter().map(|(name, value)| (name, value)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = command
        .output()
        .await
        .map_err(|error| format!("{}: {error}", program.display()))?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let tail = stderr
        .char_indices()
        .rev()
        .nth(REASON_TAIL)
        .map_or(&*stderr, |(at, _)| &stderr[at..]);
    Err(format!("{} {}: {tail}", program.display(), output.status))
}

/// Checks the native server binary against its pinned SHA-256.
pub(super) async fn native_binary(server: &NativeServer) -> Result<String, LaunchFailure> {
    let binary = server.binary.clone();
    let digest = tokio::task::spawn_blocking(move || hash_file(&binary))
        .await
        .map_err(|error| transient(WorkerFailure::LoadFailed, error.to_string()))?
        .map_err(|error| {
            permanent(
                WorkerFailure::LoadFailed,
                format!("reading {}: {error}", server.binary.display()),
            )
        })?;
    if digest != server.sha256 {
        return Err(permanent(
            WorkerFailure::BuildMismatch,
            format!(
                "{} hashes to {digest}, not its pinned {}",
                server.binary.display(),
                server.sha256
            ),
        ));
    }
    Ok(digest)
}

/// The EXL3 server's model, template and tokenizer digests from the
/// verified target, and its weights manifest written under
/// `<root>/weights/`.
pub(super) async fn exl3_digests(
    root: &Path,
    target: &InstalledWeights,
) -> Result<Exl3Digests, LaunchFailure> {
    let root = root.to_path_buf();
    let target = target.clone();
    tokio::task::spawn_blocking(move || -> std::io::Result<Exl3Digests> {
        let bytes = weights_manifest_bytes(&target.manifest);
        let model = sha256_hex(&bytes);
        let dir = root.join("weights");
        std::fs::create_dir_all(&dir)?;
        let weights_manifest = dir.join(format!("{model}.json"));
        if std::fs::read(&weights_manifest).ok().as_deref() != Some(bytes.as_slice()) {
            std::fs::write(&weights_manifest, &bytes)?;
        }
        let template = std::fs::read(target.dir.join("chat_template.jinja"))
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .map(|text| sha256_hex(text.replace("\r\n", "\n").replace('\r', "\n").as_bytes()));
        Ok(Exl3Digests {
            weights_manifest,
            model,
            template,
            tokenizer: tokenizer_digest(&target.dir),
        })
    })
    .await
    .map_err(|error| transient(WorkerFailure::LoadFailed, error.to_string()))?
    .map_err(|error| {
        transient(
            WorkerFailure::LoadFailed,
            format!("the EXL3 digests: {error}"),
        )
    })
}

/// A media worker's weights manifest (FIX 8318): the exact JSON whose
/// SHA-256 is the install record's digest of the verified weights,
/// written as `<root>/weights/<that digest>.json`. The worker hashes every
/// file it pins again before it loads, and names that digest as its
/// `model`.
pub(super) async fn media_manifest(
    root: &Path,
    weights: &InstalledWeights,
) -> Result<PathBuf, LaunchFailure> {
    let root = root.to_path_buf();
    let weights = weights.clone();
    tokio::task::spawn_blocking(move || {
        let bytes = serde_json::to_vec(&weights.manifest).map_err(|error| {
            permanent(
                WorkerFailure::LoadFailed,
                format!("the weights manifest: {error}"),
            )
        })?;
        if sha256_hex(&bytes) != weights.record_sha256 {
            return Err(permanent(
                WorkerFailure::ModelMismatch,
                format!(
                    "model {}: its manifest does not hash to its install record's digest",
                    weights.manifest.id
                ),
            ));
        }
        let dir = root.join("weights");
        let path = dir.join(format!("{}.json", weights.record_sha256));
        let written = std::fs::create_dir_all(&dir).and_then(|()| {
            if std::fs::read(&path).ok().as_deref() == Some(bytes.as_slice()) {
                Ok(())
            } else {
                std::fs::write(&path, &bytes)
            }
        });
        written.map(|()| path).map_err(|error| {
            transient(
                WorkerFailure::LoadFailed,
                format!("writing the weights manifest: {error}"),
            )
        })
    })
    .await
    .map_err(|error| transient(WorkerFailure::LoadFailed, error.to_string()))?
}

/// `weights_manifest.py`'s canonical manifest of the target's top-level
/// `*.safetensors` shards, from their pins: keys sorted, compact, ASCII.
fn weights_manifest_bytes(manifest: &ArtifactManifest) -> Vec<u8> {
    let mut shards: Vec<_> = manifest
        .files
        .iter()
        .filter(|file| file.path.ends_with(".safetensors") && !file.path.contains('/'))
        .collect();
    shards.sort_by(|a, b| a.path.cmp(&b.path));
    let files: Vec<String> = shards
        .iter()
        .map(|file| {
            format!(
                "{{\"name\":{},\"sha256\":{},\"size\":{}}}",
                serde_json::Value::from(&*file.path),
                serde_json::Value::from(&*file.sha256),
                file.bytes
            )
        })
        .collect();
    format!("{{\"files\":[{}],\"schema_version\":1}}", files.join(",")).into_bytes()
}

/// `cache_usage.tokenizer_digest`: each tokenizer file present, by name,
/// length and bytes; `None` without `tokenizer.json`.
fn tokenizer_digest(dir: &Path) -> Option<String> {
    if !dir.join(EXL3_TOKENIZER_FILES[0]).is_file() {
        return None;
    }
    let mut digest = Sha256::new();
    for name in EXL3_TOKENIZER_FILES {
        let path = dir.join(name);
        if path.is_file() {
            let bytes = std::fs::read(path).ok()?;
            digest.update(format!("{name}\0{}\0", bytes.len()).as_bytes());
            digest.update(&bytes);
        }
    }
    Some(format!("{:x}", digest.finalize()))
}

/// SHA-256 of a file, read in chunks.
fn hash_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut chunk = vec![0_u8; 8 << 20];
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            return Ok(format!("{:x}", digest.finalize()));
        }
        digest.update(&chunk[..read]);
    }
}

pub(super) fn permanent(failure: WorkerFailure, reason: String) -> LaunchFailure {
    LaunchFailure::permanent(failure, reason)
}

pub(super) fn transient(failure: WorkerFailure, reason: String) -> LaunchFailure {
    LaunchFailure::transient(failure, reason)
}
