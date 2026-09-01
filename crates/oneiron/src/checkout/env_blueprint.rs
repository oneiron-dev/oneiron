//! Declarative per-repository environment blueprints for checkouts (CSTDY-07).
//!
//! Exactly one [`EnvBlueprint`] exists per commit-stripped canonical repository
//! identity. It declares three stage families — init, maintenance, and
//! knowledge — and persists as one versioned `vault_meta` row keyed by the
//! domain-separated BLAKE3 of that identity.
//!
//! This module declares and validates only. It never executes a step, resolves
//! a secret, or ingests knowledge: those remain the dispatch/sandbox owner's
//! and L1-SECRET's contracts.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::lease::{CheckoutMaterializationOptions, CheckoutTaskClass};

use crate::batch::secret_scan::scan_file_content;
use crate::codebase::RepoRef;
use crate::error::Error;
use crate::vault::Vault;

pub const ENV_BLUEPRINT_SCHEMA_VERSION: u8 = 1;
pub const ENV_BLUEPRINT_KEY_PREFIX: &[u8] = b"checkout:env_blueprint:v1:";
pub const ENV_BLUEPRINT_REPO_KEY_DOMAIN: &[u8] = b"oneiron:checkout-env-blueprint:repo:v1";

/// Repository-root sentinel for [`RepoRelativePath`]. Wire form is exactly `.`.
const REPO_RELATIVE_ROOT: &str = ".";

/// Closed materialization ladder. There is deliberately no copy-on-write, lazy
/// mount, overlay, filesystem-clone, or `Other(String)` rung: a rung that the
/// executor cannot honour must not be representable.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationSpec {
    FullClone = 1,
    #[default]
    Blobless = 2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EnvStepId(String);

impl EnvStepId {
    /// Requires a nonempty value with no NUL or ASCII control byte
    /// (`< 0x20`, `0x7F`).
    pub fn parse(value: impl Into<String>) -> EnvBlueprintResult<Self> {
        let value = value.into();
        check_step_id(&value).map_err(invalid_value("step_id"))?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical repository-relative path. Wire form always uses `/` separators.
///
/// Parsing is pure string-level: it rejects empty, absolute, Windows/drive
/// prefixed, NUL-bearing, backslash-bearing, leading/trailing `/`,
/// empty-segment, and `.`/`..`-segment values. The exact `.` root sentinel
/// returned by [`RepoRelativePath::root`] is the sole exception; no
/// normalization is performed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RepoRelativePath(String);

impl RepoRelativePath {
    pub fn parse(value: impl Into<String>) -> EnvBlueprintResult<Self> {
        let value = value.into();
        check_repo_relative_path(&value).map_err(invalid_value("repo_relative_path"))?;
        Ok(Self(value))
    }

    /// The repository root, whose wire form is exactly `.`.
    pub fn root() -> Self {
        Self(REPO_RELATIVE_ROOT.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Repository-relative glob. Its rejection grammar is exactly the path grammar:
/// no empty value, absolute or Windows/drive prefix, NUL, backslash, leading or
/// trailing `/`, empty segment, or `.`/`..` segment. `*`, `?`, and `**` stay
/// literal data for the later KNOW consumer; nothing is expanded here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RepoRelativeGlob(String);

impl RepoRelativeGlob {
    pub fn parse(value: impl Into<String>) -> EnvBlueprintResult<Self> {
        let value = value.into();
        check_repo_relative_glob(&value).map_err(invalid_value("repo_relative_glob"))?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EnvKey(String);

impl EnvKey {
    /// Accepts `[A-Za-z_][A-Za-z0-9_]*`; rejects empty, control, and NUL keys.
    pub fn parse(value: impl Into<String>) -> EnvBlueprintResult<Self> {
        let value = value.into();
        check_env_key(&value).map_err(invalid_value("env_key"))?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A custody record name, never secret material. The name must be nonempty and
/// free of NUL and ASCII control bytes (`< 0x20`, `0x7F`) before it is checked
/// against the detector contract. The executor later passes [`EnvSecretRef::as_str`]
/// to L1-SECRET's custody contract and receives bytes only at the custody door;
/// nothing here resolves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EnvSecretRef(String);

impl EnvSecretRef {
    pub fn parse_name(value: impl Into<String>) -> EnvBlueprintResult<Self> {
        let value = value.into();
        check_secret_ref(&value).map_err(invalid_value("secret_ref"))?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Maps a context-free `check_*` failure onto the closed public error kind.
fn invalid_value(kind: &'static str) -> impl Fn(&'static str) -> EnvBlueprintError {
    move |reason| EnvBlueprintError::InvalidValue { kind, reason }
}

/// A context-free `check_*` function selected at runtime by input variant.
type ValueChecker = fn(&str) -> Result<(), &'static str>;

/// Nonempty and free of NUL and ASCII control bytes (`< 0x20`, `0x7F`). This is
/// the pre-check every author-controlled identifier passes before the detector,
/// so a rejected id is never echoed with control bytes intact.
fn check_printable_identifier(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("must not be empty");
    }
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7F) {
        return Err("must not contain NUL or ASCII control bytes");
    }
    Ok(())
}

fn check_step_id(value: &str) -> Result<(), &'static str> {
    check_printable_identifier(value)
}

fn check_secret_ref(value: &str) -> Result<(), &'static str> {
    check_printable_identifier(value)
}

fn check_knowledge_source_id(value: &str) -> Result<(), &'static str> {
    check_printable_identifier(value)
}

fn check_repo_relative_path(value: &str) -> Result<(), &'static str> {
    if value == REPO_RELATIVE_ROOT {
        return Ok(());
    }
    check_repo_relative_segments(value)
}

fn check_repo_relative_glob(value: &str) -> Result<(), &'static str> {
    check_repo_relative_segments(value)
}

/// The shared containment grammar for paths and globs. `*`, `?`, and `**` are
/// ordinary bytes here: this checker contains traversal, it does not match.
fn check_repo_relative_segments(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("must not be empty");
    }
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7F) {
        return Err("must not contain NUL or ASCII control bytes");
    }
    if value.contains('\\') {
        return Err("must not contain a backslash separator");
    }
    if value.starts_with('/') {
        return Err("must be repository-relative, not absolute");
    }
    if value.ends_with('/') {
        return Err("must not end with a separator");
    }
    if has_windows_drive_prefix(value) {
        return Err("must not use a Windows drive prefix");
    }
    for segment in value.split('/') {
        if segment.is_empty() {
            return Err("must not contain an empty segment");
        }
        if segment == "." || segment == ".." {
            return Err("must not contain a `.` or `..` segment");
        }
    }
    Ok(())
}

fn has_windows_drive_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn check_env_key(value: &str) -> Result<(), &'static str> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err("must not be empty");
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return Err("must start with an ASCII letter or underscore");
    }
    if !bytes.all(is_env_key_byte) {
        return Err("must contain only ASCII letters, digits, or underscores");
    }
    Ok(())
}

fn is_env_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum EnvValue {
    /// Non-secret configuration. NUL-bearing literals are rejected by a typed,
    /// non-echoing error before the detector sees them; the remaining bytes are
    /// swept through the ONE-1921 detector wrapper.
    Literal(String),
    /// Custody name only. It is checked against the detector contract but never
    /// resolved here.
    SecretRef(EnvSecretRef),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvStep {
    pub id: EnvStepId,
    /// Complete argv, including the executable at index 0. Never shell text.
    pub argv: Vec<String>,
    pub cwd: RepoRelativePath,
    pub timeout_secs: u64,
    /// Exact environment allowlist. The executor starts from an empty
    /// environment and materializes only these keys; there is no
    /// ambient-inheritance switch.
    pub env: BTreeMap<EnvKey, EnvValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum KnowledgeInput {
    Path(RepoRelativePath),
    Glob(RepoRelativeGlob),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeSourceSpec {
    /// Nonempty author-controlled identifier with no NUL or ASCII control byte
    /// (`< 0x20`, `0x7F`), grammar-checked before detector scanning.
    pub id: String,
    pub inputs: Vec<KnowledgeInput>,
    /// An addressing hint for the later KNOW consumer, not a new corpus id or
    /// entity reference minted by CSTDY.
    pub corpus_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EnvBlueprintStages {
    #[serde(default)]
    pub init: Vec<EnvStep>,
    #[serde(default)]
    pub maintenance: Vec<EnvStep>,
    #[serde(default)]
    pub knowledge: Vec<KnowledgeSourceSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvBlueprint {
    pub schema_version: u8,
    pub repo_ref: RepoRef,
    /// Applies only to `Edit`/`Effect`. `Build`/`Verify` ignore it and stay
    /// [`MaterializationSpec::FullClone`].
    pub light_checkout_materialization: MaterializationSpec,
    pub stages: EnvBlueprintStages,
}

/// Private persisted wire row. `RepoRef` has no serde contract, so v1 stores
/// exactly `RepoRef::canonical()` and reconstructs it with `RepoRef::parse`.
#[derive(Serialize, Deserialize)]
struct EnvBlueprintRowV1 {
    schema_version: u8,
    repo_ref: String,
    light_checkout_materialization: MaterializationSpec,
    stages: EnvBlueprintStages,
}

impl EnvBlueprint {
    /// Unchecked construction sugar. `put`, decoded `get`, and `checkout_plan`
    /// validate before anything becomes durable or executable.
    pub fn new(repo_ref: RepoRef, stages: EnvBlueprintStages) -> Self {
        Self {
            schema_version: ENV_BLUEPRINT_SCHEMA_VERSION,
            repo_ref,
            light_checkout_materialization: MaterializationSpec::Blobless,
            stages,
        }
    }

    /// The single deterministic validation pass. It is the containment gate for
    /// hand-forged decoded rows as well as for freshly authored blueprints,
    /// because the serde-transparent newtypes do not parse on decode.
    pub fn validate(&self) -> EnvBlueprintResult<()> {
        validate_blueprint(self)
    }

    pub fn resolve_materialization(&self, task_class: CheckoutTaskClass) -> MaterializationSpec {
        resolve_materialization(task_class, Some(self.light_checkout_materialization))
    }

    /// The only executor-facing projection. Knowledge has no field in the
    /// returned plan, so it cannot be executed through this API.
    pub fn checkout_plan(
        &self,
        task_class: CheckoutTaskClass,
    ) -> EnvBlueprintResult<CheckoutEnvPlan> {
        CheckoutEnvPlan::from_blueprint(self, task_class)
    }

    pub fn knowledge_sources(&self) -> &[KnowledgeSourceSpec] {
        &self.stages.knowledge
    }
}

/// Closed policy table. `light_preference` is consulted only for `Edit` and
/// `Effect`; `Build` and `Verify` are always fully materialized.
pub const fn resolve_materialization(
    task_class: CheckoutTaskClass,
    light_preference: Option<MaterializationSpec>,
) -> MaterializationSpec {
    match task_class {
        CheckoutTaskClass::Build | CheckoutTaskClass::Verify => MaterializationSpec::FullClone,
        CheckoutTaskClass::Edit | CheckoutTaskClass::Effect => match light_preference {
            Some(spec) => spec,
            None => MaterializationSpec::Blobless,
        },
    }
}

/// Materialization handoff for the dispatch owner.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CheckoutEnvPlan {
    pub materialization: CheckoutMaterializationOptions,
    pub init: Vec<EnvStep>,
    pub maintenance: Vec<EnvStep>,
}

impl CheckoutEnvPlan {
    /// No blueprint row: preserve the ONE-1901 path exactly.
    pub fn legacy() -> Self {
        Self::default()
    }

    pub fn from_blueprint(
        blueprint: &EnvBlueprint,
        task_class: CheckoutTaskClass,
    ) -> EnvBlueprintResult<Self> {
        blueprint.validate()?;
        let spec = blueprint.resolve_materialization(task_class);
        Ok(Self {
            materialization: CheckoutMaterializationOptions::resolved(spec),
            init: blueprint.stages.init.clone(),
            maintenance: blueprint.stages.maintenance.clone(),
        })
    }

    pub fn is_legacy(&self) -> bool {
        self.materialization.spec.is_none() && self.init.is_empty() && self.maintenance.is_empty()
    }
}

fn validate_blueprint(blueprint: &EnvBlueprint) -> EnvBlueprintResult<()> {
    if blueprint.schema_version != ENV_BLUEPRINT_SCHEMA_VERSION {
        return Err(EnvBlueprintError::UnsupportedSchemaVersion {
            found: blueprint.schema_version,
        });
    }
    scan_value("repo_ref", &blueprint.repo_ref.canonical())?;
    validate_step_ids(&blueprint.stages)?;
    for step in &blueprint.stages.init {
        validate_step(step)?;
    }
    for step in &blueprint.stages.maintenance {
        validate_step(step)?;
    }
    validate_knowledge(&blueprint.stages.knowledge)
}

/// Passes one author-controlled payload through the ONE-1921 detector wrapper.
/// `location` is the pinned positional label and doubles as the wrapper's
/// opaque `path` argument; `Some(reason)` rejects fail-closed and `None` is
/// clean. No rendered error carries the scanned bytes.
fn scan_value(location: &str, value: &str) -> EnvBlueprintResult<()> {
    match scan_file_content(location, value.as_bytes()) {
        Some(reason) => Err(EnvBlueprintError::SecretShapedBytes {
            location: location.to_owned(),
            reason: reason.to_owned(),
        }),
        None => Ok(()),
    }
}

/// Step ids are grammar-checked, detector-checked, and unique across the union
/// of `init` and `maintenance`: moving a step between stages cannot mint a
/// second executable identity.
fn validate_step_ids(stages: &EnvBlueprintStages) -> EnvBlueprintResult<()> {
    let mut seen = BTreeSet::new();
    for (stage, steps) in [("init", &stages.init), ("maintenance", &stages.maintenance)] {
        for (index, step) in steps.iter().enumerate() {
            let id = step.id.as_str();
            check_step_id(id).map_err(invalid_value("step_id"))?;
            scan_value(&format!("step_id:{stage}[{index}]"), id)?;
            if !seen.insert(id) {
                return Err(EnvBlueprintError::DuplicateStepId { id: id.to_owned() });
            }
        }
    }
    Ok(())
}

fn validate_step(step: &EnvStep) -> EnvBlueprintResult<()> {
    let step_id = step.id.as_str();
    validate_argv(step_id, &step.argv)?;
    validate_cwd(step_id, &step.cwd)?;
    validate_env(step_id, &step.env)
}

fn validate_argv(step_id: &str, argv: &[String]) -> EnvBlueprintResult<()> {
    let Some(executable) = argv.first() else {
        return Err(EnvBlueprintError::EmptyArgv {
            step_id: step_id.to_owned(),
        });
    };
    if executable.trim().is_empty() {
        return Err(EnvBlueprintError::InvalidArgv {
            step_id: step_id.to_owned(),
            reason: "argv[0] must not be blank",
        });
    }
    if argv.iter().any(|argument| argument.contains('\0')) {
        return Err(EnvBlueprintError::InvalidArgv {
            step_id: step_id.to_owned(),
            reason: "argv must not contain a NUL byte",
        });
    }
    if argv.len() == 1 && is_shell_string(executable) {
        return Err(EnvBlueprintError::ShellStringCommand {
            step_id: step_id.to_owned(),
        });
    }
    if uses_command_string_interpreter(argv) {
        return Err(EnvBlueprintError::ShellInterpreterCommand {
            step_id: step_id.to_owned(),
        });
    }
    for (index, argument) in argv.iter().enumerate() {
        scan_value(&format!("step:{step_id}:argv[{index}]"), argument)?;
    }
    Ok(())
}

/// Shell control syntax that only means anything to a shell parser. A single
/// argv element carrying whitespace plus one of these is a smuggled shell
/// string, not an executable with arguments.
const SHELL_CONTROL_TOKENS: [&str; 9] = ["&&", "||", ";", "|", ">", "<", "\n", "`", "$("];

fn is_shell_string(command: &str) -> bool {
    command.chars().any(char::is_whitespace)
        && SHELL_CONTROL_TOKENS
            .iter()
            .any(|token| command.contains(*token))
}

/// Closed interpreter basename set for the command-string lint. This is a lint
/// against obvious shell-string and interpreter smuggling, not an execution
/// sandbox: residual forms such as `python -c` stay the dispatch/sandbox
/// boundary's contract.
fn is_command_string_interpreter(basename: &str) -> bool {
    matches!(
        basename,
        "sh" | "dash" | "ksh" | "bash" | "zsh" | "fish" | "cmd" | "powershell" | "pwsh"
    )
}

fn uses_command_string_interpreter(argv: &[String]) -> bool {
    let rest = match argv.split_first() {
        Some((first, tail)) if executable_basename(first) == "env" => tail,
        _ => argv,
    };
    let candidate = rest
        .iter()
        .position(|arg| is_candidate_executable(arg.as_str()));
    let Some(candidate) = candidate else {
        return false;
    };
    if !is_command_string_interpreter(&executable_basename(&rest[candidate])) {
        return false;
    }
    rest[candidate + 1..]
        .iter()
        .any(|arg| is_command_string_option(arg.as_str()))
}

/// The candidate executable is the first element that is neither a leading
/// `KEY=value` assignment nor an option such as `env`'s `-i`.
fn is_candidate_executable(argument: &str) -> bool {
    !argument.starts_with('-') && !is_env_assignment(argument)
}

/// Final path component, ASCII-lowercased, with one trailing `.exe` stripped.
fn executable_basename(argument: &str) -> String {
    let component = argument.rsplit(['/', '\\']).next().unwrap_or(argument);
    let lowered = component.to_ascii_lowercase();
    if let Some(stripped) = lowered.strip_suffix(".exe") {
        return stripped.to_owned();
    }
    lowered
}

fn is_env_assignment(argument: &str) -> bool {
    let Some((key, _)) = argument.split_once('=') else {
        return false;
    };
    !key.is_empty() && key.bytes().all(is_env_key_byte)
}

fn is_command_string_option(argument: &str) -> bool {
    if argument == "-c" || argument == "/c" || argument == "/C" {
        return true;
    }
    if is_command_switch(argument) {
        return true;
    }
    let Some(cluster) = argument.strip_prefix('-') else {
        return false;
    };
    !cluster.is_empty()
        && cluster.bytes().all(|byte| byte.is_ascii_alphabetic())
        && cluster.bytes().any(|byte| byte.eq_ignore_ascii_case(&b'c'))
}

/// `-Command` / `-EncodedCommand`, ASCII case-folded.
fn is_command_switch(argument: &str) -> bool {
    argument.eq_ignore_ascii_case("-command") || argument.eq_ignore_ascii_case("-encodedcommand")
}

/// The detector verdict is computed before the value-bearing `InvalidCwd`, so a
/// secret-shaped cwd can never be echoed back through a grammar error.
fn validate_cwd(step_id: &str, cwd: &RepoRelativePath) -> EnvBlueprintResult<()> {
    scan_value(&format!("step:{step_id}:cwd"), cwd.as_str())?;
    check_repo_relative_path(cwd.as_str()).map_err(|_| EnvBlueprintError::InvalidCwd {
        step_id: step_id.to_owned(),
        cwd: cwd.as_str().to_owned(),
    })
}

fn validate_env(step_id: &str, env: &BTreeMap<EnvKey, EnvValue>) -> EnvBlueprintResult<()> {
    for (index, (key, value)) in env.iter().enumerate() {
        let key = key.as_str();
        scan_value(&format!("step:{step_id}:env_key[{index}]"), key)?;
        check_env_key(key).map_err(|_| EnvBlueprintError::InvalidEnvKey {
            step_id: step_id.to_owned(),
            key: key.to_owned(),
        })?;
        validate_env_value(step_id, key, value)?;
    }
    Ok(())
}

fn validate_env_value(step_id: &str, key: &str, value: &EnvValue) -> EnvBlueprintResult<()> {
    match value {
        EnvValue::Literal(literal) => {
            if literal.contains('\0') {
                return Err(EnvBlueprintError::InvalidValue {
                    kind: "env_value",
                    reason: "must not contain a NUL byte",
                });
            }
            scan_value(&format!("step:{step_id}:env:{key}"), literal)
        }
        EnvValue::SecretRef(secret_ref) => {
            let name = secret_ref.as_str();
            if name.is_empty() {
                return Err(EnvBlueprintError::EmptySecretRef {
                    step_id: step_id.to_owned(),
                    key: key.to_owned(),
                });
            }
            check_secret_ref(name).map_err(invalid_value("secret_ref"))?;
            scan_value(&format!("step:{step_id}:secret_ref:{key}"), name)
        }
    }
}

fn validate_knowledge(sources: &[KnowledgeSourceSpec]) -> EnvBlueprintResult<()> {
    let mut seen = BTreeSet::new();
    for (index, source) in sources.iter().enumerate() {
        let source_id = source.id.as_str();
        check_knowledge_source_id(source_id).map_err(invalid_value("knowledge_source_id"))?;
        scan_value(&format!("knowledge_id:{index}"), source_id)?;
        if !seen.insert(source_id) {
            return Err(EnvBlueprintError::DuplicateKnowledgeSourceId {
                id: source_id.to_owned(),
            });
        }
        if source.inputs.is_empty() {
            return Err(EnvBlueprintError::InvalidKnowledgeSource {
                id: source_id.to_owned(),
                reason: "must declare at least one repository-relative path or glob",
            });
        }
        for (input_index, input) in source.inputs.iter().enumerate() {
            validate_knowledge_input(source_id, input_index, input)?;
        }
        if let Some(hint) = &source.corpus_hint {
            scan_value(&format!("knowledge:{source_id}:corpus_hint"), hint)?;
            if hint.trim().is_empty() {
                return Err(EnvBlueprintError::InvalidKnowledgeSource {
                    id: source_id.to_owned(),
                    reason: "corpus hint must not be blank",
                });
            }
        }
    }
    Ok(())
}

/// Serde-transparent newtypes never call `parse` on decode, so this re-check is
/// the containment gate that rejects a hand-forged `../` knowledge input.
fn validate_knowledge_input(
    source_id: &str,
    index: usize,
    input: &KnowledgeInput,
) -> EnvBlueprintResult<()> {
    let (value, checked): (&str, ValueChecker) = match input {
        KnowledgeInput::Path(path) => (path.as_str(), check_repo_relative_path),
        KnowledgeInput::Glob(glob) => (glob.as_str(), check_repo_relative_glob),
    };
    scan_value(&format!("knowledge:{source_id}:input[{index}]"), value)?;
    checked(value).map_err(|reason| EnvBlueprintError::InvalidKnowledgeSource {
        id: source_id.to_owned(),
        reason,
    })
}

pub trait EnvBlueprintStore {
    /// Validates, encodes, and atomically replaces the one row addressed by the
    /// blueprint repository's commit-stripped canonical identity. The row keeps
    /// the submitted full canonical `RepoRef` as last-put provenance.
    fn put(&self, blueprint: &EnvBlueprint) -> EnvBlueprintResult<()>;

    /// Decodes and validates by commit-stripped identity. Unknown schema
    /// versions and repository-identity/key mismatch are errors; a differing
    /// commit still hits.
    fn get(&self, repo_ref: &RepoRef) -> EnvBlueprintResult<Option<EnvBlueprint>>;
}

pub struct VaultEnvBlueprintStore<'a> {
    vault: &'a Vault,
}

impl<'a> VaultEnvBlueprintStore<'a> {
    pub fn new(vault: &'a Vault) -> Self {
        Self { vault }
    }
}

impl EnvBlueprintStore for VaultEnvBlueprintStore<'_> {
    fn put(&self, blueprint: &EnvBlueprint) -> EnvBlueprintResult<()> {
        blueprint.validate()?;
        let key = env_blueprint_key(&blueprint.repo_ref);
        let row = encode_env_blueprint(blueprint)?;
        self.vault
            .try_with_write_txn::<_, _, EnvBlueprintError>(|txn| {
                self.vault.store.vault_meta.put(txn, &key, &row)?;
                Ok(())
            })
    }

    fn get(&self, repo_ref: &RepoRef) -> EnvBlueprintResult<Option<EnvBlueprint>> {
        let key = env_blueprint_key(repo_ref);
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let Some(raw) = self.vault.store.vault_meta.get(&txn, &key)? else {
            return Ok(None);
        };
        let blueprint = decode_env_blueprint(&raw)?;
        let requested = env_blueprint_repo_identity(repo_ref);
        if env_blueprint_repo_identity(&blueprint.repo_ref) != requested {
            return Err(EnvBlueprintError::RepoKeyMismatch);
        }
        blueprint.validate()?;
        Ok(Some(blueprint))
    }
}

/// Commit-stripped canonical repository identity. Both `RepoRef` variants end
/// in `#<commit>`, so truncating immediately before the final `#` yields
/// exactly `local:<path>` or `github:<owner>/<repo>`. Distinct local-path
/// spellings stay distinct; v1 performs no alias normalization.
pub(crate) fn env_blueprint_repo_identity(repo_ref: &RepoRef) -> String {
    let mut canonical = repo_ref.canonical();
    let commit_separator = canonical
        .rfind('#')
        .expect("RepoRef::canonical() always ends in #<commit>");
    canonical.truncate(commit_separator);
    canonical
}

/// Domain-separated BLAKE3 of exactly the commit-stripped canonical identity's
/// UTF-8 bytes — never the commit-bearing canonical value, `Debug`/`Display`
/// text, or a materialized checkout path.
pub(crate) fn env_blueprint_repo_hash(repo_ref: &RepoRef) -> [u8; 32] {
    let identity = env_blueprint_repo_identity(repo_ref);
    let mut hasher = blake3::Hasher::new();
    hasher.update(ENV_BLUEPRINT_REPO_KEY_DOMAIN);
    hasher.update(identity.as_bytes());
    *hasher.finalize().as_bytes()
}

pub(crate) fn env_blueprint_key(repo_ref: &RepoRef) -> Vec<u8> {
    let hash = env_blueprint_repo_hash(repo_ref);
    let mut key = Vec::with_capacity(ENV_BLUEPRINT_KEY_PREFIX.len() + hash.len());
    key.extend_from_slice(ENV_BLUEPRINT_KEY_PREFIX);
    key.extend_from_slice(&hash);
    key
}

/// Corrupt MessagePack and an unparsable persisted canonical repository string
/// both land in the one typed encoding class.
fn encode_error(error: impl std::fmt::Display) -> EnvBlueprintError {
    EnvBlueprintError::Encode(error.to_string())
}

/// Row byte 0 is always [`ENV_BLUEPRINT_SCHEMA_VERSION`]; the remainder is
/// rmp-serde MessagePack of the private row, whose repeated schema version must
/// agree with that leading byte.
pub(crate) fn encode_env_blueprint(blueprint: &EnvBlueprint) -> EnvBlueprintResult<Vec<u8>> {
    let row = EnvBlueprintRowV1 {
        schema_version: blueprint.schema_version,
        repo_ref: blueprint.repo_ref.canonical(),
        light_checkout_materialization: blueprint.light_checkout_materialization,
        stages: blueprint.stages.clone(),
    };
    let body = rmp_serde::to_vec_named(&row).map_err(encode_error)?;
    let mut raw = Vec::with_capacity(body.len() + 1);
    raw.push(ENV_BLUEPRINT_SCHEMA_VERSION);
    raw.extend_from_slice(&body);
    Ok(raw)
}

pub(crate) fn decode_env_blueprint(raw: &[u8]) -> EnvBlueprintResult<EnvBlueprint> {
    let Some((&header, body)) = raw.split_first() else {
        return Err(EnvBlueprintError::EmptyRow);
    };
    if header != ENV_BLUEPRINT_SCHEMA_VERSION {
        return Err(EnvBlueprintError::UnsupportedSchemaVersion { found: header });
    }
    let row: EnvBlueprintRowV1 = rmp_serde::from_slice(body).map_err(encode_error)?;
    let repo_ref = RepoRef::parse(&row.repo_ref).map_err(encode_error)?;
    if row.schema_version != header {
        return Err(EnvBlueprintError::SchemaVersionMismatch {
            header,
            body: row.schema_version,
        });
    }
    Ok(EnvBlueprint {
        schema_version: row.schema_version,
        repo_ref,
        light_checkout_materialization: row.light_checkout_materialization,
        stages: row.stages,
    })
}

pub type EnvBlueprintResult<T> = Result<T, EnvBlueprintError>;

#[derive(Debug, thiserror::Error)]
pub enum EnvBlueprintError {
    #[error("environment blueprint row is empty")]
    EmptyRow,
    #[error("unsupported environment blueprint schema version {found}")]
    UnsupportedSchemaVersion { found: u8 },
    #[error("environment blueprint schema header/body mismatch: {header}/{body}")]
    SchemaVersionMismatch { header: u8, body: u8 },
    #[error("environment blueprint repository identity does not match its key")]
    RepoKeyMismatch,
    #[error("invalid {kind}: {reason}")]
    InvalidValue {
        kind: &'static str,
        reason: &'static str,
    },
    #[error("environment step id is duplicated")]
    DuplicateStepId { id: String },
    #[error("environment step argv is empty")]
    EmptyArgv { step_id: String },
    #[error("environment step argv is invalid")]
    InvalidArgv {
        step_id: String,
        reason: &'static str,
    },
    #[error("environment step uses a shell-string command")]
    ShellStringCommand { step_id: String },
    #[error("environment step uses a command-string interpreter")]
    ShellInterpreterCommand { step_id: String },
    #[error("environment step cwd is invalid")]
    InvalidCwd { step_id: String, cwd: String },
    #[error("environment key is invalid")]
    InvalidEnvKey { step_id: String, key: String },
    #[error("environment secret reference is empty")]
    EmptySecretRef { step_id: String, key: String },
    #[error("environment blueprint contains secret-shaped bytes")]
    SecretShapedBytes { location: String, reason: String },
    #[error("knowledge source id is duplicated")]
    DuplicateKnowledgeSourceId { id: String },
    #[error("knowledge source is invalid")]
    InvalidKnowledgeSource { id: String, reason: &'static str },
    #[error("environment blueprint row encoding is invalid")]
    Encode(String),
    #[error(transparent)]
    Store(#[from] crate::error::Error),
}

#[cfg(test)]
mod tests;
