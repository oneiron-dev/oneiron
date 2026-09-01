//! ONE-218 eval-side driver for the telemetry-v0 retrieval-outcome loop.
//!
//! * `eval outcome-ingest` applies evaluator-supplied rewards read from JSONL
//!   to already-finalized retrieval runs via `Vault::record_retrieval_outcome`.
//! * `eval tune` runs one explicit bounded retrieval-blend tuning step via
//!   `Vault::tune_retrieval_blend_weights` and prints the weight table entry
//!   it persisted for live scoring to read.
//!
//! Both subcommands are explicit CLI invocations: no timer, no cadence and no
//! automatic trigger drives them. Rewards are never inferred — a row without
//! an evaluator-supplied finite reward and `evaluator`/`source` provenance is
//! refused before any vault call. Turn and session attribution rides the
//! outcome metadata verbatim and is never fabricated here.
//!
//! Both subcommands operate on an already-existing vault and share one
//! explicit vault-open contract ([`VaultOpenArgs`]): the caller names the
//! persisted graph shape and embedding identity, the trusted dictionary roots
//! whose bytes reproduce the vault's analyzer identity, and the LMDB map size
//! to open it with. Nothing is defaulted from a preset and nothing is
//! discovered from the vault's own bytes. The engine's fail-closed
//! `Vault::open_existing` door is the trust boundary — it never creates and
//! compares every persisted identity before it writes — so an absent, empty,
//! swapped, or disagreeing vault is refused before `record_retrieval_outcome`
//! or `tune_retrieval_blend_weights` is reached.
//!
//! Both vault wrappers open their own write transaction and refuse to run
//! inside an active one, so this module opens the vault once and calls them at
//! transaction depth 0, never holding a transaction across a call.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use oneiron::error::VaultRootEntry;
use oneiron::store::{RetrievalBlendTuningConfig, RetrievalOutcome};
use oneiron::{RetrievalRunId, Vault, VaultConfig};
use serde::{Deserialize, Serialize};

const EVAL_OUTCOME_INGEST_CONTRACT_VERSION: &str = "oneiron.eval_outcome_ingest.v1";
const EVAL_OUTCOME_INGEST_RECORD_TYPE: &str = "eval_outcome_ingest";
const METADATA_EVALUATOR_KEY: &str = "evaluator";
const METADATA_SOURCE_KEY: &str = "source";
const RUN_ID_LEN: usize = 16;
/// Explicit "the vault has no such value" token for the two nullable
/// vault-open fields. It can never collide with a real value: an embedding
/// model id must be `org/name@revision`, and a fast-lane prefix is an integer.
const VAULT_CONFIG_NONE: &str = "none";

#[derive(Debug, thiserror::Error)]
pub(crate) enum EvalError {
    #[error("eval usage requested")]
    HelpRequested,
    #[error("missing required eval argument: {0}")]
    MissingArgument(&'static str),
    #[error("invalid eval argument `{0}`")]
    InvalidArgument(String),
    #[error("reward row {row} rejected after {applied} applied row(s): {reason}")]
    RewardRow {
        row: usize,
        applied: usize,
        reason: String,
    },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("oneiron engine error: {0}")]
    Oneiron(#[from] oneiron::Error),
}

type EvalResult<T> = Result<T, EvalError>;

#[derive(Debug, PartialEq, Eq)]
struct OutcomeIngestArgs {
    vault: VaultOpenArgs,
    /// `None` reads the reward rows from stdin (`--rewards -`).
    rewards_path: Option<PathBuf>,
    key: Option<String>,
}

#[derive(Debug, PartialEq)]
struct TuneArgs {
    vault: VaultOpenArgs,
    config: RetrievalBlendTuningConfig,
}

/// Everything reopening an existing vault needs from the operator: the
/// persisted HNSW graph shape (`dimensions`, `fast_dims`, `m_max_0`,
/// `ef_construction`), the persisted embedding model identity, the trusted
/// dictionary roots that reproduce the vault's analyzer identity, and the LMDB
/// map size this process maps.
///
/// Both subcommands require all of them. The engine publishes no seam for
/// reading a vault's persisted configuration back without first opening it,
/// and guessing is strictly worse than refusing: a field taken from the device
/// preset makes `Vault::open` reject every vault not created with that preset.
/// The caller names the whole contract — even a device-shaped one — or the
/// command refuses before it can touch outcome or tuning state. The preset
/// contributes only process-local knobs that carry no persisted identity
/// (reader slots, `ef_search`, off-record budget) and never skips a handshake.
#[derive(Debug, PartialEq, Eq)]
struct VaultOpenArgs {
    path: PathBuf,
    dimensions: usize,
    fast_dims: Option<u16>,
    embedding_model: Option<String>,
    m_max_0: usize,
    ef_construction: usize,
    /// LMDB address space to map. Device sizing can leave a large existing vault
    /// without write headroom, so it is named rather than inherited.
    map_size: usize,
    /// Roots probed for per-language dictionaries at open. Empty is the explicit
    /// `--dict-path none`, never an unstated default.
    dict_search_paths: Vec<PathBuf>,
}

impl VaultOpenArgs {
    /// Lowers the named contract onto a `VaultConfig`. A preset is the only way
    /// to construct that `#[non_exhaustive]` type, but every field the open
    /// gate persists, compares, or reads off disk comes from the flags.
    fn vault_config(&self) -> VaultConfig {
        let mut config = VaultConfig::device();
        config.dimensions = self.dimensions;
        config.fast_dims = self.fast_dims;
        config.embedding_model = self.embedding_model.clone();
        config.hnsw.m_max_0 = self.m_max_0;
        config.hnsw.ef_construction = self.ef_construction;
        config.map_size = self.map_size;
        config.dict_search_paths = self.dict_search_paths.clone();
        config
    }

    /// Opens the named existing vault under the caller's contract.
    ///
    /// `Vault::open_existing` is the trust boundary: it binds the root before
    /// LMDB can see it, never creates, and compares every persisted identity
    /// in read transactions before any write. The pin/verify pair around it and
    /// the doctor comparison below are kept purely as defense in depth; they no
    /// longer carry the refusal, and every refusal precedes both eval APIs.
    fn open_existing_vault(&self) -> EvalResult<Vault> {
        let root = ExistingVaultRoot::pin(&self.path)?;
        let vault = Vault::open_existing(&self.path, self.vault_config())?;
        root.verify_unchanged()?;
        self.verify_persisted_identity(&vault)?;
        Ok(vault)
    }

    /// Re-checks the supplied nullable model identity against the persisted one
    /// via [`Vault::doctor`]. `Vault::open_existing` already compares the two
    /// as exact `Option`s before it writes, so this is a redundant second
    /// reading of the same fact through a different seam, kept because a silent
    /// disagreement here would be worth failing on.
    fn verify_persisted_identity(&self, vault: &Vault) -> EvalResult<()> {
        let persisted = vault.doctor()?.embedding_model_id;
        if persisted.as_deref() == self.embedding_model.as_deref() {
            return Ok(());
        }
        Err(EvalError::InvalidArgument(format!(
            "--embedding-model {} disagrees with the persisted vault model {}",
            self.embedding_model.as_deref().unwrap_or(VAULT_CONFIG_NONE),
            persisted.as_deref().unwrap_or(VAULT_CONFIG_NONE)
        )))
    }
}

/// The two LMDB environment files whose presence makes a directory an existing
/// vault root, pinned by filesystem identity. Defense in depth only: the engine
/// binds and re-checks the same root itself. The names come from
/// [`VaultRootEntry`]'s `Display`; no LMDB page or manifest byte is decoded.
#[derive(Debug, PartialEq, Eq)]
struct ExistingVaultRoot {
    root: PathBuf,
    identities: Vec<RootFileIdentity>,
}

impl ExistingVaultRoot {
    /// Fails closed unless both environment files are already present as
    /// regular, non-symlink files: an absent path, an empty directory, an
    /// unrelated directory, or a half-written root refuses without creating.
    fn pin(root: &Path) -> EvalResult<Self> {
        // Without stable file identity a swapped root cannot be detected.
        if cfg!(not(unix)) {
            return Err(EvalError::InvalidArgument(
                "this platform cannot identify vault root files".to_owned(),
            ));
        }
        Ok(Self {
            root: root.to_path_buf(),
            identities: root_file_identities(root)?,
        })
    }

    /// Re-reads the pinned files. A changed identity means the root was removed,
    /// replaced, or aliased while the existing-only engine open ran.
    fn verify_unchanged(&self) -> EvalResult<()> {
        if root_file_identities(&self.root)? == self.identities {
            return Ok(());
        }
        Err(EvalError::InvalidArgument(format!(
            "vault root {} was replaced while it was being opened",
            self.root.display()
        )))
    }
}

/// Identity of both root files; `symlink_metadata` never follows a link, so a
/// symlinked or non-regular entry is refused rather than counted as a root.
fn root_file_identities(root: &Path) -> EvalResult<Vec<RootFileIdentity>> {
    let mut identities = Vec::with_capacity(2);
    for entry in [VaultRootEntry::Data, VaultRootEntry::Lock] {
        let path = root.join(entry.to_string());
        let refuse = |reason: String| {
            EvalError::InvalidArgument(format!(
                "--vault is not an existing vault root: {}: {reason}",
                path.display()
            ))
        };
        let found = std::fs::symlink_metadata(&path);
        let metadata = found.map_err(|error| refuse(error.to_string()))?;
        if !metadata.file_type().is_file() {
            return Err(refuse("not a regular file".to_owned()));
        }
        identities.push(root_file_identity(&metadata));
    }
    Ok(identities)
}

/// Unix `(dev, ino)` — the identity the engine's own root preflight compares.
/// Elsewhere there is none, so [`ExistingVaultRoot::pin`] refuses instead.
#[cfg(unix)]
type RootFileIdentity = (u64, u64);
#[cfg(not(unix))]
type RootFileIdentity = ();

#[cfg(unix)]
fn root_file_identity(metadata: &std::fs::Metadata) -> RootFileIdentity {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

#[cfg(not(unix))]
fn root_file_identity(_metadata: &std::fs::Metadata) -> RootFileIdentity {}

/// Collects the shared vault-open flags while a subcommand parser walks its
/// own arguments, so both subcommands read one identical contract.
#[derive(Debug, Default)]
struct VaultOpenArgsBuilder {
    path: Option<PathBuf>,
    dimensions: Option<usize>,
    /// Outer `Option` = "the flag was supplied"; inner = the field's value.
    fast_dims: Option<Option<u16>>,
    embedding_model: Option<Option<String>>,
    m_max_0: Option<usize>,
    ef_construction: Option<usize>,
    map_size: Option<usize>,
    /// `Some(empty)` is the explicit `--dict-path none`; otherwise one per flag.
    dict_search_paths: Option<Vec<PathBuf>>,
}

impl VaultOpenArgsBuilder {
    /// Consumes the vault-open flag at `index`, reporting the next index to
    /// read. `None` means the argument belongs to the calling subcommand's own
    /// parser and was not consumed here.
    fn accept(&mut self, args: &[String], index: usize) -> EvalResult<Option<usize>> {
        match args[index].as_str() {
            "--vault" => {
                let value = required_value(args, index, "--vault")?;
                self.path = Some(PathBuf::from(value));
            }
            "--dimensions" => {
                let value = required_value(args, index, "--dimensions")?;
                self.dimensions = Some(parse_positive(value, "--dimensions")?);
            }
            "--fast-dims" => {
                let value = required_value(args, index, "--fast-dims")?;
                self.fast_dims = Some(parse_fast_dims(value)?);
            }
            "--embedding-model" => {
                let value = required_value(args, index, "--embedding-model")?;
                self.embedding_model = Some(parse_embedding_model(value)?);
            }
            "--hnsw-m-max-0" => {
                let value = required_value(args, index, "--hnsw-m-max-0")?;
                self.m_max_0 = Some(parse_positive(value, "--hnsw-m-max-0")?);
            }
            "--hnsw-ef-construction" => {
                let value = required_value(args, index, "--hnsw-ef-construction")?;
                self.ef_construction = Some(parse_positive(value, "--hnsw-ef-construction")?);
            }
            "--map-size" => {
                let value = required_value(args, index, "--map-size")?;
                self.map_size = Some(parse_positive(value, "--map-size")?);
            }
            "--dict-path" => {
                let value = required_value(args, index, "--dict-path")?;
                self.accept_dict_path(value)?;
            }
            _ => return Ok(None),
        }
        Ok(Some(index + 2))
    }

    /// Collects one trusted dictionary root. `none` states that the vault was
    /// built without any and cannot be combined with a real root; every other
    /// value must already be a directory. Dictionary bytes are read and hashed
    /// into the vault's analyzer identity at open, so these roots are supplied
    /// by the operator and never discovered from the vault's own bytes.
    fn accept_dict_path(&mut self, value: &str) -> EvalResult<()> {
        let mixed = || {
            EvalError::InvalidArgument(format!(
                "--dict-path `{VAULT_CONFIG_NONE}` cannot be combined with a dictionary root"
            ))
        };
        let stated_none = self.dict_search_paths.as_ref().is_some_and(Vec::is_empty);
        if value == VAULT_CONFIG_NONE {
            if self.dict_search_paths.is_some() {
                return Err(mixed());
            }
            self.dict_search_paths = Some(Vec::new());
            return Ok(());
        }
        if stated_none {
            return Err(mixed());
        }
        let root = PathBuf::from(value);
        if !root.is_dir() {
            return Err(EvalError::InvalidArgument(format!(
                "--dict-path expects an existing directory or `{VAULT_CONFIG_NONE}`, got `{value}`"
            )));
        }
        let mut roots = self.dict_search_paths.take().unwrap_or_default();
        roots.push(root);
        self.dict_search_paths = Some(roots);
        Ok(())
    }

    /// Fails closed on the first unsupplied field. Nothing is defaulted: an
    /// omitted flag is a missing-argument error, not a device-preset value.
    fn build(self) -> EvalResult<VaultOpenArgs> {
        Ok(VaultOpenArgs {
            path: self.path.ok_or(EvalError::MissingArgument("--vault"))?,
            dimensions: self
                .dimensions
                .ok_or(EvalError::MissingArgument("--dimensions"))?,
            fast_dims: self
                .fast_dims
                .ok_or(EvalError::MissingArgument("--fast-dims"))?,
            embedding_model: self
                .embedding_model
                .ok_or(EvalError::MissingArgument("--embedding-model"))?,
            m_max_0: self
                .m_max_0
                .ok_or(EvalError::MissingArgument("--hnsw-m-max-0"))?,
            ef_construction: self
                .ef_construction
                .ok_or(EvalError::MissingArgument("--hnsw-ef-construction"))?,
            map_size: self
                .map_size
                .ok_or(EvalError::MissingArgument("--map-size"))?,
            dict_search_paths: self
                .dict_search_paths
                .ok_or(EvalError::MissingArgument("--dict-path"))?,
        })
    }
}

/// One evaluator-supplied reward row. `reward` and `accepted` are explicit:
/// a row that omits either is refused rather than defaulted.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RewardRow {
    run_id: String,
    reward: f32,
    accepted: bool,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OutcomeIngestSummary {
    contract_version: String,
    record_type: String,
    ingested: usize,
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    match args {
        [] => {
            print_help();
            ExitCode::SUCCESS
        }
        // `eval --help` is the target the top-level help names, so usage in the
        // subcommand slot succeeds instead of reaching the unknown-subcommand arm.
        [first, ..] if help_requested(std::slice::from_ref(first)) => {
            print_help();
            ExitCode::SUCCESS
        }
        [sub, rest @ ..] if sub == "outcome-ingest" => report(run_outcome_ingest(rest)),
        [sub, rest @ ..] if sub == "tune" => report(run_tune(rest)),
        [sub, ..] => {
            write_diagnostic(&format!("unknown eval subcommand: {sub}"));
            print_help();
            ExitCode::FAILURE
        }
    }
}

/// Writes one diagnostic line to stderr on an explicit handle instead of the
/// `eprintln` macro: same stream, same bytes, same panic on a failed write.
fn write_diagnostic(message: &str) {
    let stderr = std::io::stderr();
    let mut handle = stderr.lock();
    writeln!(handle, "{message}").expect("stderr write");
}

fn report(result: EvalResult<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(EvalError::HelpRequested) => {
            print_help();
            ExitCode::SUCCESS
        }
        Err(error) => {
            write_diagnostic(&format!("eval command failed: {error}"));
            if matches!(
                error,
                EvalError::MissingArgument(_) | EvalError::InvalidArgument(_)
            ) {
                print_help();
            }
            ExitCode::FAILURE
        }
    }
}

fn run_outcome_ingest(args: &[String]) -> EvalResult<()> {
    let args = parse_outcome_ingest_args(args)?;
    let vault = args.vault.open_existing_vault()?;
    let ingested = match &args.rewards_path {
        Some(path) => ingest_outcomes(
            &vault,
            BufReader::new(File::open(path)?),
            args.key.as_deref(),
        )?,
        None => ingest_outcomes(&vault, std::io::stdin().lock(), args.key.as_deref())?,
    };

    let summary = OutcomeIngestSummary {
        contract_version: EVAL_OUTCOME_INGEST_CONTRACT_VERSION.to_owned(),
        record_type: EVAL_OUTCOME_INGEST_RECORD_TYPE.to_owned(),
        ingested,
    };
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    write_json_line(&summary, &mut lock)
}

fn run_tune(args: &[String]) -> EvalResult<()> {
    let args = parse_tune_args(args)?;
    let vault = args.vault.open_existing_vault()?;
    let entry = vault.tune_retrieval_blend_weights(args.config)?;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    write_json_line(&entry, &mut lock)
}

/// Applies reward rows in file order, stopping at the first rejected row.
///
/// Rows already applied stay applied: they are honest, retryable state — the
/// outcome write is idempotent per run id and key — and the returned error
/// names the failing row plus how many rows preceded it.
fn ingest_outcomes(
    vault: &Vault,
    reader: impl BufRead,
    default_key: Option<&str>,
) -> EvalResult<usize> {
    let mut applied = 0_usize;
    for (index, line) in reader.lines().enumerate() {
        match apply_reward_line(vault, line, default_key) {
            Ok(true) => applied += 1,
            Ok(false) => {}
            Err(reason) => {
                return Err(EvalError::RewardRow {
                    row: index + 1,
                    applied,
                    reason,
                });
            }
        }
    }
    Ok(applied)
}

/// Applies one JSONL line, reporting `false` for a blank separator line.
fn apply_reward_line(
    vault: &Vault,
    line: std::io::Result<String>,
    default_key: Option<&str>,
) -> Result<bool, String> {
    let line = line.map_err(|error| error.to_string())?;
    if line.trim().is_empty() {
        return Ok(false);
    }
    let row: RewardRow = serde_json::from_str(&line).map_err(|error| error.to_string())?;
    let outcome = outcome_from_row(&row, default_key)?;
    vault
        .record_retrieval_outcome(outcome)
        .map_err(|error| error.to_string())?;
    Ok(true)
}

/// Vets one row's evaluator-supplied reward and provenance before it can
/// reach the vault.
fn outcome_from_row(
    row: &RewardRow,
    default_key: Option<&str>,
) -> Result<RetrievalOutcome, String> {
    if !row.reward.is_finite() {
        return Err("reward must be a finite evaluator scalar".to_owned());
    }
    require_provenance(&row.metadata, METADATA_EVALUATOR_KEY)?;
    require_provenance(&row.metadata, METADATA_SOURCE_KEY)?;
    let key = resolve_outcome_key(row.key.as_deref(), default_key)?;
    let run_id = parse_run_id(&row.run_id)?;
    Ok(RetrievalOutcome {
        run_id,
        key,
        reward: Some(row.reward),
        accepted: Some(row.accepted),
        metadata: row.metadata.clone(),
    })
}

fn require_provenance(metadata: &BTreeMap<String, String>, field: &str) -> Result<(), String> {
    match metadata.get(field) {
        Some(value) if !value.trim().is_empty() => Ok(()),
        _ => Err(format!("metadata.{field} must be a non-empty string")),
    }
}

/// A per-row `key` overrides `--key`; exactly one key source must resolve.
fn resolve_outcome_key(row_key: Option<&str>, default_key: Option<&str>) -> Result<String, String> {
    match row_key.or(default_key) {
        Some(key) if !key.trim().is_empty() => Ok(key.to_owned()),
        Some(_) => Err("outcome key must not be empty".to_owned()),
        None => Err("no outcome key: supply a row `key` or --key".to_owned()),
    }
}

/// `RetrievalRunId` publishes no byte constructor, so its derived
/// `Deserialize` is the supported route from a hex run id back to the id.
fn parse_run_id(value: &str) -> Result<RetrievalRunId, String> {
    let bytes = parse_run_id_bytes(value)?;
    serde_json::from_value(serde_json::json!({ "bytes": bytes }))
        .map_err(|error| format!("run_id could not be decoded: {error}"))
}

fn parse_run_id_bytes(value: &str) -> Result<[u8; RUN_ID_LEN], String> {
    let raw = value.as_bytes();
    let expected = RUN_ID_LEN * 2;
    if raw.len() != expected {
        return Err(format!("run_id must be {expected} hex characters"));
    }

    let mut bytes = [0_u8; RUN_ID_LEN];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = decode_hex_nibble(raw[index * 2])?;
        let low = decode_hex_nibble(raw[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Ok(bytes)
}

fn decode_hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("run_id contains a non-hex character".to_owned()),
    }
}

fn write_json_line<T: Serialize>(value: &T, writer: &mut impl Write) -> EvalResult<()> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn parse_outcome_ingest_args(args: &[String]) -> EvalResult<OutcomeIngestArgs> {
    if help_requested(args) {
        return Err(EvalError::HelpRequested);
    }

    let mut vault = VaultOpenArgsBuilder::default();
    let mut rewards = None;
    let mut key = None;
    let mut index = 0;
    while index < args.len() {
        if let Some(next) = vault.accept(args, index)? {
            index = next;
            continue;
        }
        match args[index].as_str() {
            "--rewards" => {
                let value = required_value(args, index, "--rewards")?;
                rewards = Some((value != "-").then(|| PathBuf::from(value)));
                index += 2;
            }
            "--key" => {
                let value = required_value(args, index, "--key")?;
                if value.trim().is_empty() {
                    return Err(EvalError::InvalidArgument(
                        "--key must not be empty".to_owned(),
                    ));
                }
                key = Some(value.to_owned());
                index += 2;
            }
            other => return Err(EvalError::InvalidArgument(other.to_owned())),
        }
    }

    Ok(OutcomeIngestArgs {
        vault: vault.build()?,
        rewards_path: rewards.ok_or(EvalError::MissingArgument("--rewards"))?,
        key,
    })
}

fn parse_tune_args(args: &[String]) -> EvalResult<TuneArgs> {
    if help_requested(args) {
        return Err(EvalError::HelpRequested);
    }

    let mut vault = VaultOpenArgsBuilder::default();
    let mut max_runs = None;
    let mut learning_rate = None;
    let mut min_reward_count = None;
    let mut index = 0;
    while index < args.len() {
        if let Some(next) = vault.accept(args, index)? {
            index = next;
            continue;
        }
        match args[index].as_str() {
            "--max-runs" => {
                let value = required_value(args, index, "--max-runs")?;
                max_runs = Some(parse_count(value, "--max-runs")?);
                index += 2;
            }
            "--learning-rate" => {
                let value = required_value(args, index, "--learning-rate")?;
                let rate = value.parse::<f32>().map_err(|_| {
                    EvalError::InvalidArgument(format!(
                        "--learning-rate expects a number, got `{value}`"
                    ))
                })?;
                learning_rate = Some(rate);
                index += 2;
            }
            "--min-reward-count" => {
                let value = required_value(args, index, "--min-reward-count")?;
                min_reward_count = Some(parse_count(value, "--min-reward-count")?);
                index += 2;
            }
            other => return Err(EvalError::InvalidArgument(other.to_owned())),
        }
    }

    // Flags map 1:1 onto the tuning config; unset ones keep the shipped
    // bounded defaults.
    let defaults = RetrievalBlendTuningConfig::default();
    Ok(TuneArgs {
        vault: vault.build()?,
        config: RetrievalBlendTuningConfig {
            max_runs: max_runs.unwrap_or(defaults.max_runs),
            learning_rate: learning_rate.unwrap_or(defaults.learning_rate),
            min_reward_count: min_reward_count.unwrap_or(defaults.min_reward_count),
        },
    })
}

fn parse_count(value: &str, flag: &'static str) -> EvalResult<usize> {
    value.parse::<usize>().map_err(|_| {
        EvalError::InvalidArgument(format!("{flag} expects an integer, got `{value}`"))
    })
}

fn parse_positive(value: &str, flag: &'static str) -> EvalResult<usize> {
    match value.parse::<usize>() {
        Ok(parsed) if parsed > 0 => Ok(parsed),
        _ => Err(EvalError::InvalidArgument(format!(
            "{flag} expects a positive integer, got `{value}`"
        ))),
    }
}

/// `none` names a full-dimension graph. Cross-field consistency
/// (`1 <= fast_dims < dimensions`) stays the storage layer's call, so the
/// engine remains the single authority on graph shape.
fn parse_fast_dims(value: &str) -> EvalResult<Option<u16>> {
    if value == VAULT_CONFIG_NONE {
        return Ok(None);
    }
    match value.parse::<u16>() {
        Ok(parsed) => Ok(Some(parsed)),
        Err(_) => Err(EvalError::InvalidArgument(format!(
            "--fast-dims expects an integer or `{VAULT_CONFIG_NONE}`, got `{value}`"
        ))),
    }
}

/// `none` names a genuinely model-less vault. The `org/name@revision` grammar
/// is validated by the storage layer at open, not restated here.
fn parse_embedding_model(value: &str) -> EvalResult<Option<String>> {
    if value == VAULT_CONFIG_NONE {
        return Ok(None);
    }
    if value.trim().is_empty() {
        return Err(EvalError::InvalidArgument(format!(
            "--embedding-model expects a model id or `{VAULT_CONFIG_NONE}`"
        )));
    }
    Ok(Some(value.to_owned()))
}

fn help_requested(args: &[String]) -> bool {
    args.iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
}

fn required_value<'a>(args: &'a [String], index: usize, flag: &'static str) -> EvalResult<&'a str> {
    args.get(index + 1)
        .map(String::as_str)
        .filter(|value| !value.starts_with("--"))
        .ok_or(EvalError::MissingArgument(flag))
}

/// Writes the usage block to stdout, on an explicit handle for the same reason
/// as [`write_diagnostic`]; the bytes, stream, and trailing newline are as before.
fn print_help() {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    writeln!(
        handle,
        "usage: oneiron-bench eval <subcommand> [flags]\n\
         \n\
         Drives the telemetry-v0 retrieval-outcome loop from the eval side.\n\
         Both subcommands are explicit invocations: nothing here runs on a\n\
         timer, a cadence, or a wake hook.\n\
         \n\
         Both subcommands operate on an already-existing vault and take the\n\
         same required vault-open configuration. Nothing is inferred from a\n\
         preset and nothing is read out of the vault's own bytes: these flags\n\
         name the configuration the vault was created with, and a value that\n\
         disagrees with the persisted vault is refused before any outcome or\n\
         tuning write. A missing flag is an error, never a default, and a path\n\
         that is not already a vault root is refused without creating\n\
         anything in it.\n\
         \n\
         vault configuration (required on both subcommands):\n\
           --vault <PATH>                 existing vault root; never created here\n\
           --dimensions <N>               persisted embedding vector dimension\n\
           --fast-dims <N|none>           persisted MRL fast-lane prefix, or none\n\
           --embedding-model <ID|none>    persisted org/name@revision model id,\n\
                                          or none for a model-less vault\n\
           --hnsw-m-max-0 <N>             persisted HNSW layer-0 neighbor cap\n\
           --hnsw-ef-construction <N>     persisted HNSW construction beam width\n\
           --map-size <BYTES>             LMDB map size to open the vault with\n\
           --dict-path <PATH|none>        trusted dictionary root the vault's\n\
                                          analyzer identity was built from;\n\
                                          repeat per root, none for no roots\n\
         \n\
         subcommands:\n\
           outcome-ingest <VAULT CONFIG> --rewards <PATH>|- [--key <KEY>]\n\
             Applies evaluator-supplied rewards to already-finalized retrieval\n\
             runs, one JSON object per line, in file order. A row carries\n\
             run_id (hex), reward (a finite number), accepted (a bool), an\n\
             optional key that overrides --key, and a metadata object whose\n\
             evaluator and source entries are required; optional turn_id and\n\
             session_id metadata is stored verbatim. Rewards are never\n\
             inferred. Ingest stops at the first rejected row, naming that row\n\
             and the rows already applied, and exits nonzero; success prints\n\
             one JSON summary carrying the ingested count.\n\
           tune <VAULT CONFIG> [--max-runs N] [--learning-rate F] [--min-reward-count N]\n\
             Runs one bounded retrieval-blend tuning step over the persisted\n\
             rewards and prints the weight table entry it persisted."
    )
    .expect("eval help writes to stdout");
}

#[cfg(test)]
mod tests;
