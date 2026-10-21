//! `[models.workers.<id>]`: the model workers this server supervises or
//! probes (FIX 8315, DESIGN-V2 R2).
//!
//! A row binds one worker to one configured model, explicitly: `model`
//! names a provider entry and the wire model its calls name, as a rung does.
//! Nothing is inferred from a loopback URL or a name, so a provider with no
//! row stays what it is today: an endpoint this server only calls. A new row
//! is `managed` unless it says `external`.
//!
//! A managed row names what its supervisor installs and runs: the weights (a
//! house catalog id or an operator's manifest file, with an offline
//! directory to verify instead of downloading), the native server binary and
//! its SHA-256 for llama.cpp, the interpreter and lock for EXL3, and where
//! its runtime files go. It listens where its provider calls: the
//! provider's own loopback `base_url`. An external row is the operator's
//! endpoint, and names only what its answers must show.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use oneiron::llm::{CacheDigest, CacheIdentity, WorkerKind, WorkerMode};
use serde::Deserialize;

use super::levels::ModelRef;
use super::provider::{ProviderConfig, ProviderKind};
use crate::model_artifacts::catalog::house_artifact;

/// The interpreter an EXL3 worker's environment is built with when the row
/// names none: the version its lock is resolved for.
const DEFAULT_EXL3_PYTHON: &str = "python3.12";

/// The interpreter a llama.cpp launch's identity script runs on when the row
/// names none; it needs only the standard library.
const DEFAULT_LLAMA_PYTHON: &str = "python3";

/// `[models.workers.<id>]` as written.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerFile {
    model: Option<String>,
    kind: Option<WorkerKind>,
    mode: Option<WorkerMode>,
    weights: Option<String>,
    weights_manifest: Option<PathBuf>,
    weights_dir: Option<PathBuf>,
    draft: Option<String>,
    draft_manifest: Option<PathBuf>,
    draft_dir: Option<PathBuf>,
    models_dir: Option<PathBuf>,
    runtime_root: Option<PathBuf>,
    hub_token_env: Option<String>,
    python: Option<PathBuf>,
    env_lock: Option<PathBuf>,
    server: Option<PathBuf>,
    server_sha256: Option<String>,
    endpoint: Option<String>,
    device: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    envelope_mib: EnvelopeFile,
    idle_stop_secs: Option<u64>,
    #[serde(default)]
    expected: ExpectedFile,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeFile {
    weights: Option<u64>,
    kv: Option<u64>,
    workspace: Option<u64>,
    load_transient: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedFile {
    model: Option<String>,
    tokenizer: Option<String>,
    runtime: Option<String>,
    template: Option<String>,
}

/// One resolved worker row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerConfig {
    /// The row's key: the worker's stable id, never an epoch.
    pub id: String,
    /// The engine model it serves, `provider/name@revision`.
    pub model: oneiron::ModelId,
    /// The provider entry and wire model its calls name.
    pub binding: ModelRef,
    pub kind: WorkerKind,
    pub mode: WorkerMode,
    /// The pins the config names; a managed supervisor adds the ones its
    /// verified artifacts give.
    pub expected: CacheIdentity,
    /// What a managed worker installs and runs; `None` for an external one.
    pub launch: Option<ManagedLaunch>,
    /// Where an external worker's probe goes; `None` is its provider's
    /// `base_url`.
    pub endpoint: Option<String>,
}

/// What a managed worker's supervisor installs and runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedLaunch {
    pub weights: WorkerArtifact,
    pub draft: Option<WorkerArtifact>,
    /// The models root the artifacts live under, as the embedder's
    /// `models_dir` moves it; `None` is the default root.
    pub models_dir: Option<PathBuf>,
    /// Where the worker's code, environment and launch manifests go; `None`
    /// is `workers/` beside the artifacts under the models root.
    pub runtime_root: Option<PathBuf>,
    /// The environment variable holding a hub read token, for a repository
    /// that needs one. Never the token itself.
    pub hub_token_env: Option<String>,
    /// The interpreter: EXL3's environment is built with it, llama.cpp's
    /// launch identity runs on it.
    pub python: PathBuf,
    /// An EXL3 environment lock in place of the embedded one.
    pub env_lock: Option<PathBuf>,
    /// llama.cpp's `llama-server`, verified by its SHA-256 before each launch.
    pub server: Option<NativeServer>,
    /// The loopback host and port the worker listens on: its provider's.
    pub listen_host: String,
    pub listen_port: u16,
    /// The CUDA device the worker runs on, as `CUDA_VISIBLE_DEVICES` names
    /// it, and the device ledger its declaration goes in.
    pub device: Option<String>,
    /// Arguments after the supervisor's own.
    pub args: Vec<String>,
    /// Environment beside the supervisor's own.
    pub env: BTreeMap<String, String>,
    pub envelope: WorkerEnvelope,
    /// Idle stop after this many seconds; `None`, the default, keeps the
    /// worker up.
    pub idle_stop_secs: Option<u64>,
}

/// One set of weights: a house catalog id or an operator's manifest file,
/// and the directory to verify instead of downloading.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerArtifact {
    pub source: ArtifactSource,
    pub offline_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArtifactSource {
    /// A house catalog id.
    Catalog(String),
    /// An operator's manifest file, an absolute path.
    Manifest(PathBuf),
}

/// A native server binary and the SHA-256 it must hash to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeServer {
    pub binary: PathBuf,
    pub sha256: String,
}

/// A worker's declared device memory, in MiB, part by part; one left out is
/// `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkerEnvelope {
    pub weights_mib: Option<u64>,
    pub kv_mib: Option<u64>,
    pub workspace_mib: Option<u64>,
    pub load_transient_mib: Option<u64>,
}

/// Validates every row against the providers, in id order.
pub(super) fn resolve(
    rows: BTreeMap<String, WorkerFile>,
    providers: &BTreeMap<String, ProviderConfig>,
    base: Option<&Path>,
) -> anyhow::Result<Vec<WorkerConfig>> {
    let mut bound = BTreeSet::new();
    let mut workers = Vec::with_capacity(rows.len());
    for (id, row) in rows {
        let worker = row.resolve(&id, providers, base)?;
        anyhow::ensure!(
            bound.insert(worker.binding.clone()),
            "models.workers.{id}: {} is already bound to another worker",
            worker.binding
        );
        workers.push(worker);
    }
    Ok(workers)
}

impl WorkerFile {
    fn resolve(
        self,
        id: &str,
        providers: &BTreeMap<String, ProviderConfig>,
        base: Option<&Path>,
    ) -> anyhow::Result<WorkerConfig> {
        let field = |name: &str| format!("models.workers.{id}.{name}");
        anyhow::ensure!(
            plain(id),
            "models.workers.{id:?}: a worker id is one plain name: letters, digits, '.', '_' and '-'"
        );
        let model = self
            .model
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("{} is required", field("model")))?;
        let binding = ModelRef::parse(&field("model"), model)?;
        let provider = providers.get(&binding.provider).ok_or_else(|| {
            anyhow::anyhow!(
                "{}: provider {:?} is not in [models.providers]",
                field("model"),
                binding.provider
            )
        })?;
        anyhow::ensure!(
            matches!(
                provider.kind,
                ProviderKind::LocalOpenaiCompat | ProviderKind::OpenaiCompat
            ),
            "{}: a worker serves an OpenAI-compatible provider",
            field("model")
        );
        anyhow::ensure!(
            provider.key_secret.is_none(),
            "{}: a worker's provider cannot hold a key_secret key; its probe reads no broker key",
            field("model")
        );
        let engine = binding.engine_id(&provider.revision)?;
        let kind = self
            .kind
            .ok_or_else(|| anyhow::anyhow!("{} is required", field("kind")))?;
        anyhow::ensure!(
            matches!(kind, WorkerKind::LlamaCpp | WorkerKind::Exl3),
            "{}: only llama_cpp and exl3 workers have a launcher and a probe",
            field("kind")
        );
        let mode = self.mode.unwrap_or_default();
        let expected = self.expected.resolve(&field("expected"))?;
        let launch = match mode {
            WorkerMode::Managed => {
                anyhow::ensure!(
                    self.endpoint.is_none(),
                    "{}: a managed worker listens where its provider calls (its base_url)",
                    field("endpoint")
                );
                Some(self.managed(id, kind, provider, base)?)
            }
            WorkerMode::External => {
                self.refuse_managed_fields(id)?;
                if let Some(endpoint) = &self.endpoint {
                    reqwest::Url::parse(endpoint)
                        .map_err(|error| anyhow::anyhow!("{}: {error}", field("endpoint")))?;
                }
                None
            }
        };
        Ok(WorkerConfig {
            id: id.to_owned(),
            model: engine,
            binding,
            kind,
            mode,
            expected,
            launch,
            endpoint: self.endpoint,
        })
    }

    /// An external row names no artifact, runtime or launch field.
    fn refuse_managed_fields(&self, id: &str) -> anyhow::Result<()> {
        let fields = [
            ("weights", self.weights.is_some()),
            ("weights_manifest", self.weights_manifest.is_some()),
            ("weights_dir", self.weights_dir.is_some()),
            ("draft", self.draft.is_some()),
            ("draft_manifest", self.draft_manifest.is_some()),
            ("draft_dir", self.draft_dir.is_some()),
            ("models_dir", self.models_dir.is_some()),
            ("runtime_root", self.runtime_root.is_some()),
            ("hub_token_env", self.hub_token_env.is_some()),
            ("python", self.python.is_some()),
            ("env_lock", self.env_lock.is_some()),
            ("server", self.server.is_some()),
            ("server_sha256", self.server_sha256.is_some()),
            ("device", self.device.is_some()),
            ("args", !self.args.is_empty()),
            ("env", !self.env.is_empty()),
            ("envelope_mib", self.envelope_mib != EnvelopeFile::default()),
            ("idle_stop_secs", self.idle_stop_secs.is_some()),
        ];
        if let Some((name, _)) = fields.iter().find(|(_, set)| *set) {
            anyhow::bail!(
                "models.workers.{id}.{name}: an external worker is the operator's; it names no artifact, runtime or launch setting"
            );
        }
        Ok(())
    }

    fn managed(
        &self,
        id: &str,
        kind: WorkerKind,
        provider: &ProviderConfig,
        base: Option<&Path>,
    ) -> anyhow::Result<ManagedLaunch> {
        let field = |name: &str| format!("models.workers.{id}.{name}");
        let (listen_host, listen_port) = loopback_listen(&provider.base_url).ok_or_else(|| {
            anyhow::anyhow!(
                "{}: a managed worker listens on its provider's base_url, which must be http://127.0.0.1, [::1] or localhost with a port",
                field("model")
            )
        })?;
        let weights = artifact(
            &field("weights"),
            self.weights.as_deref(),
            self.weights_manifest.as_deref(),
            self.weights_dir.as_deref(),
            base,
        )?
        .ok_or_else(|| anyhow::anyhow!("{} or weights_manifest is required", field("weights")))?;
        let draft = artifact(
            &field("draft"),
            self.draft.as_deref(),
            self.draft_manifest.as_deref(),
            self.draft_dir.as_deref(),
            base,
        )?;
        let server = match (kind, &self.server, &self.server_sha256) {
            (WorkerKind::LlamaCpp, Some(binary), Some(sha256)) => {
                anyhow::ensure!(
                    lower_hex(sha256, 64),
                    "{}: 64 lowercase hex digits",
                    field("server_sha256")
                );
                Some(NativeServer {
                    binary: absolute(&field("server"), binary, base)?,
                    sha256: sha256.clone(),
                })
            }
            (WorkerKind::LlamaCpp, _, _) => anyhow::bail!(
                "{} and server_sha256 are required for a managed llama_cpp worker",
                field("server")
            ),
            (_, None, None) => None,
            _ => anyhow::bail!(
                "{}: only a llama_cpp worker runs a native server binary",
                field("server")
            ),
        };
        anyhow::ensure!(
            kind == WorkerKind::Exl3 || self.env_lock.is_none(),
            "{}: only an exl3 worker builds a Python environment",
            field("env_lock")
        );
        let env_lock = self
            .env_lock
            .as_deref()
            .map(|lock| absolute(&field("env_lock"), lock, base))
            .transpose()?;
        let python = match &self.python {
            Some(python) if python.components().count() == 1 => python.clone(),
            Some(python) => absolute(&field("python"), python, base)?,
            None if kind == WorkerKind::Exl3 => PathBuf::from(DEFAULT_EXL3_PYTHON),
            None => PathBuf::from(DEFAULT_LLAMA_PYTHON),
        };
        if let Some(env) = &self.hub_token_env {
            anyhow::ensure!(
                env_name(env),
                "{} must name an environment variable (A-Z, 0-9, _); the token itself stays in that variable",
                field("hub_token_env")
            );
        }
        if let Some(device) = &self.device {
            anyhow::ensure!(
                !device.is_empty()
                    && device
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._,:-".contains(&byte)),
                "{}: a CUDA device as CUDA_VISIBLE_DEVICES names it",
                field("device")
            );
        }
        for name in self.env.keys() {
            anyhow::ensure!(
                env_name(name) && name != "CUDA_VISIBLE_DEVICES",
                "{}.{name}: an environment variable name (A-Z, 0-9, _); the device is set by `device`",
                field("env")
            );
        }
        anyhow::ensure!(
            self.idle_stop_secs != Some(0),
            "{} must be at least 1; leave it out to keep the worker up",
            field("idle_stop_secs")
        );
        let dir = |name: &str, path: &Option<PathBuf>| {
            path.as_deref()
                .map(|path| absolute(&field(name), path, base))
                .transpose()
        };
        Ok(ManagedLaunch {
            weights,
            draft,
            models_dir: dir("models_dir", &self.models_dir)?,
            runtime_root: dir("runtime_root", &self.runtime_root)?,
            hub_token_env: self.hub_token_env.clone(),
            python,
            env_lock,
            server,
            listen_host,
            listen_port,
            device: self.device.clone(),
            args: self.args.clone(),
            env: self.env.clone(),
            envelope: WorkerEnvelope {
                weights_mib: self.envelope_mib.weights,
                kv_mib: self.envelope_mib.kv,
                workspace_mib: self.envelope_mib.workspace,
                load_transient_mib: self.envelope_mib.load_transient,
            },
            idle_stop_secs: self.idle_stop_secs,
        })
    }
}

impl ExpectedFile {
    fn resolve(&self, field: &str) -> anyhow::Result<CacheIdentity> {
        let digest = |name: &str, value: &Option<String>| {
            value
                .clone()
                .map(|hex| {
                    CacheDigest::new(hex)
                        .map_err(|error| anyhow::anyhow!("{field}.{name}: {error}"))
                })
                .transpose()
        };
        Ok(CacheIdentity {
            model: digest("model", &self.model)?,
            tokenizer: digest("tokenizer", &self.tokenizer)?,
            runtime: digest("runtime", &self.runtime)?,
            template: digest("template", &self.template)?,
            ..CacheIdentity::default()
        })
    }
}

/// One set of weights from its catalog id or manifest file, and its offline
/// directory; `None` when the row names neither.
fn artifact(
    field: &str,
    catalog: Option<&str>,
    manifest: Option<&Path>,
    offline_dir: Option<&Path>,
    base: Option<&Path>,
) -> anyhow::Result<Option<WorkerArtifact>> {
    let source = match (catalog, manifest) {
        (Some(id), None) => {
            anyhow::ensure!(
                house_artifact(id).is_some(),
                "{field} = {id:?} is not a house catalog id"
            );
            ArtifactSource::Catalog(id.to_owned())
        }
        (None, Some(path)) => {
            ArtifactSource::Manifest(absolute(&format!("{field}_manifest"), path, base)?)
        }
        (None, None) => {
            anyhow::ensure!(
                offline_dir.is_none(),
                "{field}_dir needs {field} or {field}_manifest"
            );
            return Ok(None);
        }
        (Some(_), Some(_)) => {
            anyhow::bail!("{field} and {field}_manifest name the same weights twice; keep one")
        }
    };
    let offline_dir = offline_dir
        .map(|dir| absolute(&format!("{field}_dir"), dir, base))
        .transpose()?;
    Ok(Some(WorkerArtifact {
        source,
        offline_dir,
    }))
}

/// `path` against the config file's directory, which must give an absolute
/// path.
fn absolute(field: &str, path: &Path, base: Option<&Path>) -> anyhow::Result<PathBuf> {
    let path = match base {
        Some(base) if path.is_relative() => base.join(path),
        _ => path.to_path_buf(),
    };
    anyhow::ensure!(
        path.is_absolute(),
        "{field} must be an absolute path, or relative to the config file"
    );
    Ok(path)
}

/// The host and port a loopback `http://` base URL names, with its port
/// written out.
fn loopback_listen(base_url: &str) -> Option<(String, u16)> {
    let url = reqwest::Url::parse(base_url).ok()?;
    if url.scheme() != "http" {
        return None;
    }
    let port = url.port()?;
    let host = url.host_str()?;
    if host == "localhost" {
        return Some(("127.0.0.1".to_owned(), port));
    }
    let ip: std::net::IpAddr = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()?;
    ip.is_loopback().then(|| (ip.to_string(), port))
}

fn plain(name: &str) -> bool {
    name.bytes().any(|byte| byte != b'.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn env_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
