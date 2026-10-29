//! The managed launcher for the house llama.cpp and EXL3 workers (DESIGN-V2
//! R2): what [`super::install`] verified, bound into one launch manifest per
//! launch, and one process started from it, in its own process group, on its
//! provider's loopback address.
//!
//! An EXL3 worker runs the bundled `exl3_server.py` on the locked
//! environment's interpreter with `--launch-manifest`. A llama.cpp worker
//! runs the pinned `llama-server` under the alias the bundled
//! `llama_identity.py prepare` gives it, and its identity manifest is
//! checked against the pins before the launch. Either way the launch's
//! record goes in the probe's slot first, so the probe checks this launch.
//!
//! A media worker (VoxCPM2 speech or local ASR, FIX 8318) runs its bundled
//! script on its own locked environment's interpreter, as
//! [`super::media_worker`] lays out its launch.
//!
//! A worker gets a cleared environment: the variables in
//! [`WORKER_PASSED_ENV`] from this process, its row's `env`, and
//! `CUDA_VISIBLE_DEVICES` from its `device`. No key or token of this server
//! reaches it, but a media worker's own bearer credential, under its
//! provider's `key_env`.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::llm::{CacheDigest, CacheIdentity, WorkerFailure, WorkerKind, parse_llama_alias};
use oneiron_driver::{LaunchFailure, LauncherFuture, RunningWorker, WorkerLauncher, WorkerSpec};

use super::bundle::{EXL3_SERVER, LLAMA_IDENTITY, sha256_hex};
use super::install::{self, Exl3Digests, InstalledEnv, InstalledWeights, permanent, transient};
use super::launch_manifest::{
    self, BuildSection, LaunchManifest, LaunchRecord, LaunchSlot, launch_nonce,
};
use super::media_worker::StatsRoute;
use crate::config::models::{ManagedLaunch, WorkerConfig};
use crate::model_artifacts::install::{ArtifactStore, artifacts_root};

/// The variables a worker keeps from this process's environment: what an
/// interpreter, CUDA and its caches need, never a credential.
pub(super) const WORKER_PASSED_ENV: [&str; 12] = [
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "XDG_CACHE_HOME",
    "CUDA_HOME",
    "CUDA_PATH",
    "LD_LIBRARY_PATH",
    "TORCH_EXTENSIONS_DIR",
    "TRITON_CACHE_DIR",
];

/// What an environment build adds to [`WORKER_PASSED_ENV`]: the proxy and
/// certificate settings pip needs to reach its indexes.
const INSTALL_PASSED_ENV: [&str; 8] = [
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// The artifact stores, one per artifacts root, shared by every worker on it.
pub(super) type Stores = Mutex<BTreeMap<PathBuf, Arc<ArtifactStore>>>;

/// Everything one install verified, for each launch to bind.
#[derive(Clone)]
pub(super) struct Installation {
    pub(super) runtime_root: PathBuf,
    pub(super) weights: InstalledWeights,
    draft: Option<InstalledWeights>,
    pub(super) bundle_dir: PathBuf,
    pub(super) bundle_sha256: String,
    pub(super) env: Option<InstalledEnv>,
    native_binary_sha256: Option<String>,
    exl3: Option<Exl3Digests>,
    /// A media worker's weights manifest ([`install::media_manifest`]).
    pub(super) media_manifest: Option<PathBuf>,
}

/// One managed worker's launcher.
pub(super) struct ProcessLauncher {
    pub(super) row: WorkerConfig,
    pub(super) launch: ManagedLaunch,
    stores: Arc<Stores>,
    slot: Arc<LaunchSlot>,
    installed: Mutex<Option<Installation>>,
}

impl ProcessLauncher {
    pub(super) fn new(
        row: WorkerConfig,
        launch: ManagedLaunch,
        stores: Arc<Stores>,
        slot: Arc<LaunchSlot>,
    ) -> Self {
        Self {
            row,
            launch,
            stores,
            slot,
            installed: Mutex::new(None),
        }
    }

    fn store(&self, root: &Path) -> Arc<ArtifactStore> {
        let mut stores = self.stores.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(
            stores
                .entry(root.to_path_buf())
                .or_insert_with(|| Arc::new(ArtifactStore::new(root.to_path_buf()))),
        )
    }

    async fn install_all(&self) -> Result<Installation, LaunchFailure> {
        let kind = self.row.kind;
        let artifacts = artifacts_root(self.launch.models_dir.as_deref())
            .map_err(|error| permanent(WorkerFailure::LoadFailed, error.to_string()))?;
        let runtime_root = match &self.launch.runtime_root {
            Some(root) => root.clone(),
            None => artifacts.parent().unwrap_or(&artifacts).join("workers"),
        };
        let store = self.store(&artifacts);
        let token = self.launch.hub_token_env.as_deref();
        let weights =
            install::weights(Arc::clone(&store), &self.launch.weights, kind, false, token).await?;
        let draft = match &self.launch.draft {
            Some(draft) => Some(install::weights(store, draft, kind, true, token).await?),
            None => None,
        };
        let (bundle_dir, bundle_sha256) = install::bundle(&runtime_root).await?;
        let media = matches!(kind, WorkerKind::VoxCpm2 | WorkerKind::Asr);
        // A media worker's environment is its row's own lock, never EXL3's.
        let lock = match self.launch.env_lock.as_deref() {
            None if media => {
                return Err(permanent(
                    WorkerFailure::LoadFailed,
                    "a media worker names its environment lock (env_lock)".to_owned(),
                ));
            }
            lock => lock,
        };
        let env = if kind == WorkerKind::Exl3 || media {
            let passed = passed_env(&INSTALL_PASSED_ENV);
            let python = &self.launch.python;
            Some(install::environment(&runtime_root, python, lock, &passed).await?)
        } else {
            None
        };
        let exl3 = match kind {
            WorkerKind::Exl3 => Some(install::exl3_digests(&runtime_root, &weights).await?),
            _ => None,
        };
        let media_manifest = if media {
            Some(install::media_manifest(&runtime_root, &weights).await?)
        } else {
            None
        };
        let native_binary_sha256 = match &self.launch.server {
            Some(server) => Some(install::native_binary(server).await?),
            None => None,
        };
        Ok(Installation {
            runtime_root,
            weights,
            draft,
            bundle_dir,
            bundle_sha256,
            env,
            native_binary_sha256,
            exl3,
            media_manifest,
        })
    }

    async fn start(&self) -> Result<Box<dyn RunningWorker>, LaunchFailure> {
        let installation = self
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                transient(WorkerFailure::LoadFailed, "nothing is installed".to_owned())
            })?;
        let mut env = passed_env(&[]);
        env.extend(
            self.launch
                .env
                .iter()
                .map(|(name, value)| (name.clone(), value.clone())),
        );
        if let Some(device) = &self.launch.device {
            env.push(("CUDA_VISIBLE_DEVICES".to_owned(), device.clone()));
        }
        // A media worker's activity is read on its bearer `/stats`.
        let mut stats = None;
        let (program, args) = match self.row.kind {
            WorkerKind::Exl3 => self.exl3_launch(&installation)?,
            WorkerKind::LlamaCpp => self.llama_launch(&installation, &env).await?,
            WorkerKind::VoxCpm2 | WorkerKind::Asr => {
                let (name, credential) = super::media_worker::credential(&self.launch)?;
                let route = super::media_worker::stats_route(self.route("/stats"), &credential)?;
                stats = Some(route);
                let command = self.media_launch(&installation, &name)?;
                env.push((name, credential));
                command
            }
            kind => {
                return Err(permanent(
                    WorkerFailure::KindMismatch,
                    format!("no managed launcher runs a {kind:?} worker"),
                ));
            }
        };
        // The socket this launch's record names, if any: its activity poll
        // reads the worker's stats there.
        let native = self
            .slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .and_then(|record| record.native_socket.clone());
        spawn(
            &program,
            &args,
            &installation.bundle_dir,
            &env,
            &self.route("/health"),
            native,
            stats,
        )
    }

    /// The worker's route at `path` on its loopback address.
    fn route(&self, path: &str) -> String {
        let host = &self.launch.listen_host;
        let port = self.launch.listen_port;
        if host.contains(':') {
            format!("http://[{host}]:{port}{path}")
        } else {
            format!("http://{host}:{port}{path}")
        }
    }

    /// Writes the launch manifest and fills the probe's slot, with the
    /// launch's native socket when it has one; returns the manifest's path.
    pub(super) fn record(
        &self,
        installation: &Installation,
        manifest: &LaunchManifest<'_>,
        llama_alias: Option<String>,
        pins: CacheIdentity,
        native_socket: Option<PathBuf>,
    ) -> Result<PathBuf, LaunchFailure> {
        let dir = installation.runtime_root.join("launch").join(&self.row.id);
        let (path, manifest_sha256) = launch_manifest::write(&dir, manifest).map_err(|error| {
            transient(
                WorkerFailure::LoadFailed,
                format!("writing the launch manifest: {error}"),
            )
        })?;
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(LaunchRecord {
            manifest_sha256,
            llama_alias,
            pins,
            native_socket,
        });
        Ok(path)
    }

    /// The EXL3 server's command line, its launch manifest written.
    fn exl3_launch(
        &self,
        installation: &Installation,
    ) -> Result<(PathBuf, Vec<String>), LaunchFailure> {
        let (Some(env), Some(exl3)) = (&installation.env, &installation.exl3) else {
            return Err(transient(
                WorkerFailure::LoadFailed,
                "the EXL3 environment is not installed".to_owned(),
            ));
        };
        let build = BuildSection {
            bundle_sha256: &installation.bundle_sha256,
            env_freeze_sha256: Some(env.freeze_sha256.as_str()),
            env_lock_sha256: Some(env.lock_sha256.as_str()),
            python_version: Some(env.python_version.as_str()),
        };
        let runtime = build.digest();
        let nonce = launch_nonce();
        let socket = native_socket(&installation.runtime_root, &self.row.id, &nonce);
        let manifest = LaunchManifest {
            backend_model: Some(exl3.model.as_str()),
            bundle_sha256: &installation.bundle_sha256,
            draft_record_sha256: installation
                .draft
                .as_ref()
                .map(|draft| draft.record_sha256.as_str()),
            env_freeze_sha256: Some(env.freeze_sha256.as_str()),
            env_lock_sha256: Some(env.lock_sha256.as_str()),
            kind: WorkerKind::Exl3,
            launch_nonce: nonce,
            llama_identity_sha256: None,
            model: self.row.model.as_str(),
            native_binary_sha256: None,
            python_version: Some(env.python_version.as_str()),
            runtime: &runtime,
            schema_version: launch_manifest::schema_version(),
            template_sha256: exl3.template.as_deref(),
            tokenizer_sha256: exl3.tokenizer.as_deref(),
            weights_record_sha256: &installation.weights.record_sha256,
            wire_model: &self.row.binding.model,
            worker_id: &self.row.id,
        };
        let pins = CacheIdentity {
            model: digest(Some(exl3.model.as_str())),
            tokenizer: digest(exl3.tokenizer.as_deref()),
            runtime: digest(Some(runtime.as_str())),
            template: digest(exl3.template.as_deref()),
            ..CacheIdentity::default()
        };
        let path = self.record(installation, &manifest, None, pins, socket.clone())?;
        let mut args = vec![
            installation
                .bundle_dir
                .join(EXL3_SERVER)
                .display()
                .to_string(),
            "--target-dir".to_owned(),
            installation.weights.dir.display().to_string(),
            "--weights-manifest".to_owned(),
            exl3.weights_manifest.display().to_string(),
        ];
        if let Some(draft) = &installation.draft {
            args.extend(["--draft-dir".to_owned(), draft.dir.display().to_string()]);
        }
        args.extend([
            "--model-id".to_owned(),
            self.row.binding.model.clone(),
            "--host".to_owned(),
            self.launch.listen_host.clone(),
            "--port".to_owned(),
            self.launch.listen_port.to_string(),
            "--launch-manifest".to_owned(),
            path.display().to_string(),
        ]);
        if let Some(socket) = &socket {
            args.extend(["--native-socket".to_owned(), socket.display().to_string()]);
        }
        args.extend(self.launch.args.iter().cloned());
        Ok((env.python.clone(), args))
    }

    /// The llama.cpp server's command line: its identity prepared by the
    /// bundled script, its manifest checked against the pins, and the
    /// launch's own manifest written.
    async fn llama_launch(
        &self,
        installation: &Installation,
        env: &[(String, String)],
    ) -> Result<(PathBuf, Vec<String>), LaunchFailure> {
        let server = self.launch.server.as_ref().ok_or_else(|| {
            permanent(
                WorkerFailure::LoadFailed,
                "no llama-server is configured".to_owned(),
            )
        })?;
        let binary_sha256 = install::native_binary(server).await?;
        let (target, target_sha256) = installation.weights.gguf().ok_or_else(|| {
            permanent(
                WorkerFailure::LoadFailed,
                "the weights pin no GGUF file".to_owned(),
            )
        })?;
        let mut args = vec!["--model".to_owned(), target.display().to_string()];
        if let Some((draft, _)) = installation.draft.as_ref().and_then(InstalledWeights::gguf) {
            args.extend(["--model-draft".to_owned(), draft.display().to_string()]);
        }
        args.extend(self.launch.args.iter().cloned());
        args.extend([
            "--host".to_owned(),
            self.launch.listen_host.clone(),
            "--port".to_owned(),
            self.launch.listen_port.to_string(),
        ]);
        let identity_dir = installation
            .runtime_root
            .join("llama-identity")
            .join(&self.row.id);
        let mut prepare = vec![
            installation
                .bundle_dir
                .join(LLAMA_IDENTITY)
                .display()
                .to_string(),
            "prepare".to_owned(),
            "--server".to_owned(),
            server.binary.display().to_string(),
            "--manifest-dir".to_owned(),
            identity_dir.display().to_string(),
            "--configured-wire-id".to_owned(),
            self.row.binding.model.clone(),
            "--".to_owned(),
        ];
        prepare.extend(args.iter().cloned());
        let prepared = prepare_identity(&self.launch.python, &prepare, env).await?;
        let alias_text = prepared
            .windows(2)
            .find(|pair| pair[0] == "--alias")
            .map(|pair| pair[1].clone())
            .ok_or_else(|| {
                permanent(
                    WorkerFailure::LoadFailed,
                    "the identity script gave no alias".to_owned(),
                )
            })?;
        let alias = parse_llama_alias(&alias_text).ok_or_else(|| {
            permanent(
                WorkerFailure::LoadFailed,
                format!("{alias_text:?} is not a launch alias"),
            )
        })?;
        let identity_sha256 = alias.manifest.as_str().to_owned();
        let bytes = std::fs::read(identity_dir.join(format!("{identity_sha256}.json")))
            .map_err(|error| transient(WorkerFailure::LoadFailed, error.to_string()))?;
        let pins = llama_pins(
            &bytes,
            &identity_sha256,
            alias.epoch.as_str(),
            &self.row.binding.model,
            target_sha256,
            &binary_sha256,
        )?;
        let runtime = pins
            .runtime
            .as_ref()
            .map(|runtime| runtime.as_str().to_owned())
            .unwrap_or_default();
        let manifest = LaunchManifest {
            backend_model: Some(target_sha256),
            bundle_sha256: &installation.bundle_sha256,
            draft_record_sha256: installation
                .draft
                .as_ref()
                .map(|draft| draft.record_sha256.as_str()),
            env_freeze_sha256: None,
            env_lock_sha256: None,
            kind: WorkerKind::LlamaCpp,
            launch_nonce: launch_nonce(),
            llama_identity_sha256: Some(identity_sha256.as_str()),
            model: self.row.model.as_str(),
            native_binary_sha256: installation.native_binary_sha256.as_deref(),
            python_version: None,
            runtime: &runtime,
            schema_version: launch_manifest::schema_version(),
            template_sha256: pins.template.as_ref().map(CacheDigest::as_str),
            tokenizer_sha256: pins.tokenizer.as_ref().map(CacheDigest::as_str),
            weights_record_sha256: &installation.weights.record_sha256,
            wire_model: &self.row.binding.model,
            worker_id: &self.row.id,
        };
        let pins = pins.clone();
        self.record(installation, &manifest, Some(alias_text), pins, None)?;
        args.extend(prepared);
        Ok((server.binary.clone(), args))
    }
}

impl WorkerLauncher for ProcessLauncher {
    fn install<'a>(
        &'a self,
        spec: &'a WorkerSpec,
    ) -> LauncherFuture<'a, Result<(), LaunchFailure>> {
        Box::pin(async move {
            let installation = self.install_all().await.map_err(|failure| LaunchFailure {
                reason: format!(
                    "worker {} (model {}): {}",
                    spec.worker_id, spec.model, failure.reason
                ),
                ..failure
            })?;
            *self
                .installed
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(installation);
            Ok(())
        })
    }

    fn launch<'a>(
        &'a self,
        spec: &'a WorkerSpec,
    ) -> LauncherFuture<'a, Result<Box<dyn RunningWorker>, LaunchFailure>> {
        Box::pin(async move {
            self.start().await.map_err(|failure| LaunchFailure {
                reason: format!(
                    "worker {} (model {}): {}",
                    spec.worker_id, spec.model, failure.reason
                ),
                ..failure
            })
        })
    }
}

/// The pins a llama.cpp launch's identity manifest gives, once its bytes
/// hash to the alias's digest and it names the alias's epoch, the
/// configured wire id, the pinned target GGUF and the pinned binary.
fn llama_pins(
    bytes: &[u8],
    digest: &str,
    epoch: &str,
    wire_model: &str,
    target_sha256: &str,
    binary_sha256: &str,
) -> Result<CacheIdentity, LaunchFailure> {
    let contradiction = |what: &str| {
        permanent(
            WorkerFailure::BuildMismatch,
            format!("the launch identity manifest {digest} {what}"),
        )
    };
    if sha256_hex(bytes) != digest {
        return Err(contradiction("does not hash to its name"));
    }
    let manifest: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| contradiction("is not JSON"))?;
    let field = |pointer: &str| {
        manifest
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
    };
    if field("/backend_epoch") != Some(epoch) || field("/configured_wire_id") != Some(wire_model) {
        return Err(contradiction("names another launch"));
    }
    if field("/target/sha256") != Some(target_sha256) {
        return Err(contradiction("names another target GGUF"));
    }
    if field("/build/binary_sha256") != Some(binary_sha256) {
        return Err(contradiction("names another llama-server"));
    }
    let identity = manifest
        .get("identity")
        .cloned()
        .and_then(|identity| serde_json::from_value::<CacheIdentity>(identity).ok())
        .ok_or_else(|| contradiction("has no identity"))?;
    Ok(CacheIdentity {
        model: identity.model,
        tokenizer: identity.tokenizer,
        runtime: identity.runtime,
        template: identity.template,
        ..CacheIdentity::default()
    })
}

/// Runs the identity script and returns the arguments it prints, one per
/// line.
async fn prepare_identity(
    python: &Path,
    args: &[String],
    env: &[(String, String)],
) -> Result<Vec<String>, LaunchFailure> {
    let mut command: tokio::process::Command = oneiron_spawn::command(python).into();
    command
        .args(args)
        .env_clear()
        .envs(env.iter().map(|(name, value)| (name, value)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = command.output().await.map_err(|error| {
        transient(
            WorkerFailure::LoadFailed,
            format!("{}: {error}", python.display()),
        )
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(permanent(
            WorkerFailure::LoadFailed,
            format!("the launch identity was not prepared: {}", stderr.trim()),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .filter(|line| !line.is_empty())
        .collect())
}

/// Starts the worker in the bundle directory with `env` alone; `native` is
/// its native socket and `stats` a media worker's stats route, where its
/// activity is read.
fn spawn(
    program: &Path,
    args: &[String],
    dir: &Path,
    env: &[(String, String)],
    health: &str,
    native: Option<PathBuf>,
    stats: Option<StatsRoute>,
) -> Result<Box<dyn RunningWorker>, LaunchFailure> {
    #[cfg(unix)]
    {
        let mut command: tokio::process::Command = oneiron_spawn::command(program).into();
        command
            .args(args)
            .current_dir(dir)
            .env_clear()
            .envs(env.iter().map(|(name, value)| (name, value)))
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let spawned =
            super::process::ProcessWorker::spawn(command, health.to_owned(), native, stats);
        let worker = spawned.map_err(|error| {
            transient(
                WorkerFailure::LoadFailed,
                format!("starting {}: {error}", program.display()),
            )
        })?;
        Ok(Box::new(worker))
    }
    #[cfg(not(unix))]
    {
        let _ = (program, args, dir, env, health, native, stats);
        Err(permanent(
            WorkerFailure::LoadFailed,
            "managed workers run on Unix only".to_owned(),
        ))
    }
}

/// The hex digits of the launch nonce a native socket's name carries.
#[cfg(unix)]
const SOCKET_LAUNCH_DIGITS: usize = 16;

/// The room a Unix socket address has for its path, the closing NUL
/// included: an operating system's own limit, not a policy.
#[cfg(target_os = "linux")]
const SOCKET_PATH_ROOM: usize = 108;
#[cfg(all(unix, not(target_os = "linux")))]
const SOCKET_PATH_ROOM: usize = 104;

/// An EXL3 launch's native socket (DESIGN-V2 R1),
/// `<runtime root>/sock/<worker id>-<launch>.sock`, `<launch>` the first 16
/// hex digits of its nonce: its folder made this user's alone (0700) and
/// cleared of this worker's earlier launches' sockets. `None`, with a
/// warning naming the worker, when the path does not fit a Unix socket
/// address here or the folder cannot be made: that launch serves over HTTP
/// alone, as before.
fn native_socket(runtime_root: &Path, worker_id: &str, nonce: &str) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        let launch = nonce.get(..SOCKET_LAUNCH_DIGITS).unwrap_or(nonce);
        let dir = runtime_root.join("sock");
        let path = dir.join(format!("{worker_id}-{launch}.sock"));
        let length = path.as_os_str().len();
        if length >= SOCKET_PATH_ROOM {
            tracing::warn!(
                worker = %worker_id,
                length,
                room = SOCKET_PATH_ROOM,
                "the native socket path does not fit a Unix socket address; this launch serves over HTTP alone (a shorter runtime_root gives it one)"
            );
            return None;
        }
        if let Err(error) = socket_dir(&dir, worker_id) {
            tracing::warn!(
                worker = %worker_id,
                %error,
                "the native socket folder could not be made; this launch serves over HTTP alone"
            );
            return None;
        }
        Some(path)
    }
    #[cfg(not(unix))]
    {
        let _ = (runtime_root, worker_id, nonce);
        None
    }
}

/// Makes `dir` this user's alone and removes the sockets of `worker_id`'s
/// earlier launches from it: names of exactly `<worker id>-<16 hex>.sock`,
/// never another worker's whose id `worker_id` begins.
#[cfg(unix)]
fn socket_dir(dir: &Path, worker_id: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    for entry in std::fs::read_dir(dir)?.flatten() {
        let name = entry.file_name();
        let earlier = name
            .to_str()
            .and_then(|name| name.strip_prefix(worker_id))
            .and_then(|rest| rest.strip_prefix('-'))
            .and_then(|rest| rest.strip_suffix(".sock"))
            .is_some_and(|launch| {
                launch.len() == SOCKET_LAUNCH_DIGITS
                    && launch.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
        if earlier {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}

/// `names` from this process's environment, each one set.
fn passed_env(extra: &[&str]) -> Vec<(String, String)> {
    WORKER_PASSED_ENV
        .iter()
        .chain(extra)
        .filter_map(|name| Some(((*name).to_owned(), std::env::var(name).ok()?)))
        .collect()
}

fn digest(hex: Option<&str>) -> Option<CacheDigest> {
    hex.and_then(|hex| CacheDigest::new(hex).ok())
}
