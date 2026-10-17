//! `[models]`: which model serves each role, at three levels of detail.
//!
//! * HIGH — `default = "<provider>:<model>"` (and an optional `prompt`): one
//!   model for every model-backed seat.
//! * MID — `local`, `cloud` and `prefer_local`: a two-rung ladder for every
//!   seat, local first or cloud first; `local` also binds `local_reasoner`.
//! * DETAILED — `[models.roles.<role>]`: the ladder itself, a list of rungs
//!   with a fallback order and a prompt per rung.
//!
//! HIGH and MID expand to the DETAILED form. Role keys are the manifest's
//! (ARCH-0036). Providers are data (`[models.providers.<name>]`), so a model
//! is swapped by editing one string and no vendor appears in code. Absent
//! `[models]`, the server runs every model-free path and reports each seat
//! as unconfigured.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use oneiron::llm::manifest::ModelRole;
use oneiron_code_check::{BackendKind, CheckMode};
use serde::Deserialize;

mod compaction;
mod decision_read;
mod decisions;
mod levels;
mod media;
mod planner;
mod provider;
#[cfg(test)]
mod tests;
mod voice;

pub use compaction::CompactionSettings;
pub use decision_read::{
    DecisionReadRecipe, DecisionReadSettings, ProbeQuestions, ReadPrompt, RenderRefusal,
};
pub use decisions::{
    BigReply, BigSettings, BookingParseSettings, ConnectorSlateSettings, DecisionsSettings,
    ImagePickSettings, SeatPickSettings, SystemOneSettings,
};
pub use levels::{ModelRef, Rung, SHORTHAND_ROLES, role_key};
pub use media::{LiveAsrOptions, MediaSeatConfig, MediaSettings};
pub use planner::{PlannerSeatSetting, PlannerSettings};
pub use provider::{
    OutputLimitField, ProviderConfig, ProviderKind, RequestCodec, RequestCompression,
    ResponseFormatWire, ResponsesSocket,
};
pub use voice::VoiceSettings;

use levels::{RoleFile, Shorthand};
use provider::ProviderFile;

/// `[models]` as written in the config file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModelsFile {
    default: Option<String>,
    prompt: Option<String>,
    prompt_file: Option<PathBuf>,
    local: Option<String>,
    cloud: Option<String>,
    prefer_local: Option<bool>,
    extraction_egress: Option<bool>,
    raw_budget_units: Option<u64>,
    #[serde(default)]
    providers: BTreeMap<String, ProviderFile>,
    #[serde(default)]
    roles: BTreeMap<ModelRole, RoleFile>,
    #[serde(default)]
    aliases: BTreeMap<String, String>,
    #[serde(default)]
    dreamer: DreamerFile,
    #[serde(default)]
    chat: ChatFile,
    #[serde(default)]
    workflows: WorkflowFile,
    #[serde(default)]
    code_mode: CodeModeFile,
    #[serde(default)]
    recall: RecallFile,
    broker: Option<BrokerFile>,
    decision_read: Option<decision_read::DecisionReadFile>,
    #[serde(default)]
    decisions: decisions::DecisionsFile,
    media: Option<media::MediaFile>,
    #[serde(default)]
    voice: voice::VoiceFile,
    #[serde(default)]
    planner: planner::PlannerFile,
}

/// `[models.broker]`: where the credential broker listens and the OS user it
/// runs as, or, with neither, how this server starts its same-user child.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerFile {
    socket: Option<PathBuf>,
    uid: Option<u32>,
    program: Option<PathBuf>,
    #[serde(default)]
    extra_roots: Vec<PathBuf>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct DreamerFile {
    enabled: Option<bool>,
    idle_floor_secs: Option<u64>,
    session_ceiling_secs: Option<u64>,
    pass_budget_units: Option<u64>,
    summary_prompt: Option<String>,
    summary_prompt_file: Option<PathBuf>,
    resident_prompt: Option<String>,
    resident_prompt_file: Option<PathBuf>,
    task_prompt: Option<String>,
    task_prompt_file: Option<PathBuf>,
    person_about_prompt: Option<String>,
    person_about_prompt_file: Option<PathBuf>,
    /// The owner's BYO runner seats (OF-137): ordered named runners, the
    /// official seats registered as named providers, and what a spent seat
    /// does. Labels and custody handles only; no vendor login can be
    /// written here.
    runner_seats: Option<crate::runtime::seat_login::RunnerSeatPolicySettings>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatFile {
    history_turns: Option<usize>,
    turn_budget_units: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecallFile {
    rerank_budget_units: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowFile {
    enabled: Option<bool>,
    step_budget_units: Option<u64>,
    retry_backoff_secs: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeModeFile {
    prompt_package: Option<PathBuf>,
    budget_units: Option<u64>,
    max_runs: Option<usize>,
    #[serde(default)]
    compaction: compaction::CompactionFile,
    #[serde(default)]
    check: CodeCheckFile,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeCheckFile {
    mode: Option<String>,
    backend: Option<String>,
    microsoft_tsc: Option<PathBuf>,
}

/// The resolved `[models]` section: providers plus one ladder per role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelsConfig {
    pub providers: BTreeMap<String, ProviderConfig>,
    pub roles: BTreeMap<ModelRole, Vec<Rung>>,
    /// The roles whose work never leaves the device (`leave_device =
    /// "never"`): no rung off it serves them, first or as a fallback.
    pub stays_on_device: BTreeSet<ModelRole>,
    /// The owner's aliases (`[models.aliases]`): a name an app sends, such
    /// as a stock vendor model name, and the configured model it calls.
    /// None is built in.
    pub aliases: BTreeMap<String, oneiron::ModelId>,
    /// Owner opt-in for the Dreamer's extraction calls to leave the device.
    /// Off by default: personal-data extraction stays local unless the owner
    /// says otherwise (ARCH-0036 counter-arrow).
    pub extraction_egress: bool,
    /// Process-lifetime meter for the raw `/v1/llm` routes.
    pub raw_budget_units: u64,
    pub dreamer: DreamerSettings,
    pub chat: ChatSettings,
    pub workflows: WorkflowSettings,
    pub code_mode: CodeModeSettings,
    pub recall: RecallModelSettings,
    /// The credential broker that sends every `key_secret` provider's calls.
    pub broker: BrokerConfig,
    /// The house model's decision read on the `local_reasoner` rung.
    pub decision_read: Option<DecisionReadSettings>,
    /// The host's own questions and the System One seat on its decision
    /// ladder (`[models.decisions]`).
    pub decisions: DecisionsSettings,
    /// The media seats (`[models.media]`): image, video, speech,
    /// transcription and embedding ladders, and their meter.
    pub media: MediaSettings,
    /// The server's own voice loop (`[models.voice]`).
    pub voice: VoiceSettings,
    /// The seats a leased agent's planned spawns choose among
    /// (`[models.planner]`); none lends no planner.
    pub planner: PlannerSettings,
}

/// The credential broker (ARCH-0069 `#broker-design`): a separate process
/// that adds a provider key to one request and sends it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerConfig {
    /// It runs as its own OS user (OSH-2), the first choice.
    /// `oneiron-broker serve --socket <socket> --client-uid <this server's
    /// uid>` runs it.
    SeparateUser {
        /// Its Unix socket, an absolute path.
        socket: PathBuf,
        /// The OS user it runs as. Each connection checks the peer is this
        /// user, and this server refuses a broker that runs as its own user.
        uid: u32,
    },
    /// With no `socket` and `uid`, as where no separate user exists: this
    /// server starts the broker as its own child, under its own uid
    /// (`#broker-same-user-open`). Receipts say `same_user`.
    SameUser {
        /// The broker binary, an absolute path; by default the
        /// `oneiron-broker` beside this server's binary.
        program: Option<PathBuf>,
        /// PEM files of roots the child trusts beside the system's, absolute
        /// paths.
        extra_roots: Vec<PathBuf>,
    },
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self::SameUser {
            program: None,
            extra_roots: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DreamerSettings {
    pub enabled: bool,
    /// A sitting with no activity for this long ends, and its turns dream.
    pub idle_floor_secs: u64,
    /// Hard ceiling on one session's life, independent of activity.
    pub session_ceiling_secs: u64,
    /// Budget units each wake pass may spend.
    pub pass_budget_units: u64,
    /// The instruction the Dreamer writes declared scope summaries with.
    /// Without one, summary declarations are refused (ARCH-0006a: only the
    /// Dreamer writes a summary body).
    pub summary_instruction: Option<String>,
    /// The instruction each resident's own dreaming writes its diary entry
    /// with (OF-490). Without one, no resident dreams.
    pub resident_instruction: Option<String>,
    /// The wording a TASK routed to the Dreamer realizes with. Without one,
    /// the engine's own (`dreamer.task_realize`).
    pub task_instruction: Option<String>,
    /// The wording a PERSON's `about` lines are written with (ARCH-0067).
    /// Without one, the engine's own (`PERSON_ABOUT_INSTRUCTION`).
    pub person_about_instruction: Option<String>,
    /// The owner's BYO runner-seat policy (OF-137), validated at load: the
    /// ordered named runners Dreamer work may be dispatched to and where
    /// the work goes when a seat's quota is spent. Without one, the
    /// Dreamer runs only on its internal model roles.
    pub runner_seats: Option<crate::runtime::seat_login::RunnerSeatPolicySettings>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatSettings {
    /// Earlier turns of the conversation sent with each chat turn.
    pub history_turns: usize,
    pub turn_budget_units: u64,
}

/// `[models.recall]`: what recall at high, xhigh and max may spend on the
/// `reranker` role's calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecallModelSettings {
    /// Each recall's own line: the rerank calls one recall makes, a second
    /// one for a block that changed included.
    pub rerank_budget_units: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkflowSettings {
    pub enabled: bool,
    pub step_budget_units: u64,
    /// Wait before a failed step's next try, times the tries so far.
    pub retry_backoff_secs: u64,
}

/// MCP `execute_code`: generated programs on the generative seat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeModeSettings {
    /// The deployed prompt package the executor's wire prompt resolves from.
    /// Code mode is served only when one is named.
    pub prompt_package: Option<PathBuf>,
    /// Process-lifetime meter for code mode's model calls.
    pub budget_units: u64,
    /// `execute_code` runs at once, across every credential: a row sized
    /// from this machine's cores and memory by default. Past it, runs wait
    /// their turn, round-robin across credentials.
    pub max_runs: usize,
    pub compaction: CompactionSettings,
    pub check: CodeCheckSettings,
}

/// `[models.code_mode.check]`: an optional type check of each generated
/// program before it runs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CodeCheckSettings {
    /// `off` (the default), or `shadow`: check every program and record what
    /// the check found, blocking nothing. `enforce` is reserved.
    pub mode: CheckMode,
    /// `tsc-rs` in process (the default), or `microsoft`.
    pub backend: BackendKind,
    /// Microsoft's native `tsc` at the pinned version: the `microsoft`
    /// backend, and tsc-rs's fallback when it is set.
    pub microsoft_tsc: Option<PathBuf>,
}

const DEFAULT_SESSION_CEILING_SECS: u64 = 12 * 60 * 60;
const DEFAULT_PASS_BUDGET_UNITS: u64 = 400_000;
const DEFAULT_TURN_BUDGET_UNITS: u64 = 64_000;
const DEFAULT_STEP_BUDGET_UNITS: u64 = 64_000;
const DEFAULT_STEP_RETRY_BACKOFF_SECS: u64 = 30;
const DEFAULT_RAW_BUDGET_UNITS: u64 = 10_000_000;
const DEFAULT_CODE_MODE_BUDGET_UNITS: u64 = 10_000_000;
/// Two scorings of a 50-candidate block at about 300 tokens a candidate.
const DEFAULT_RERANK_BUDGET_UNITS: u64 = 32_000;
const DEFAULT_HISTORY_TURNS: usize = 24;

impl ModelsFile {
    /// Validates and expands the section. `base` is the config file's
    /// directory, against which relative `prompt_file` paths resolve.
    pub(crate) fn resolve(self, base: Option<&Path>) -> anyhow::Result<ModelsConfig> {
        let providers = self
            .providers
            .into_iter()
            .map(|(name, file)| Ok((name.clone(), file.resolve(&name)?)))
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
        let stays_on_device = levels::stays_on_device(&self.roles)?;
        let roles = levels::expand(
            Shorthand {
                default: self.default,
                prompt: self.prompt,
                prompt_file: self.prompt_file,
                local: self.local,
                cloud: self.cloud,
                prefer_local: self.prefer_local.unwrap_or(true),
            },
            self.roles,
            base,
        )?;
        validate_ladders(&providers, &roles)?;
        let aliases = resolve_aliases(self.aliases, &providers, &roles)?;
        let dreamer = DreamerSettings {
            enabled: self.dreamer.enabled.unwrap_or(true),
            idle_floor_secs: self
                .dreamer
                .idle_floor_secs
                .unwrap_or(oneiron_driver::DEFAULT_SESSION_IDLE_FLOOR_SECS),
            session_ceiling_secs: self
                .dreamer
                .session_ceiling_secs
                .unwrap_or(DEFAULT_SESSION_CEILING_SECS),
            pass_budget_units: self
                .dreamer
                .pass_budget_units
                .unwrap_or(DEFAULT_PASS_BUDGET_UNITS),
            summary_instruction: levels::prompt_text(
                "models.dreamer.summary_prompt",
                self.dreamer.summary_prompt,
                self.dreamer.summary_prompt_file,
                base,
            )?,
            resident_instruction: levels::prompt_text(
                "models.dreamer.resident_prompt",
                self.dreamer.resident_prompt,
                self.dreamer.resident_prompt_file,
                base,
            )?,
            task_instruction: levels::prompt_text(
                "models.dreamer.task_prompt",
                self.dreamer.task_prompt,
                self.dreamer.task_prompt_file,
                base,
            )?,
            person_about_instruction: levels::prompt_text(
                "models.dreamer.person_about_prompt",
                self.dreamer.person_about_prompt,
                self.dreamer.person_about_prompt_file,
                base,
            )?,
            runner_seats: self.dreamer.runner_seats,
        };
        if let Some(runner_seats) = &dreamer.runner_seats {
            runner_seats
                .policy()
                .map_err(|error| anyhow::anyhow!("models.dreamer.runner_seats: {error}"))?;
        }
        if dreamer.idle_floor_secs == 0 || dreamer.session_ceiling_secs <= dreamer.idle_floor_secs {
            anyhow::bail!(
                "models.dreamer: idle_floor_secs must be > 0 and session_ceiling_secs must exceed it"
            );
        }
        let chat = ChatSettings {
            history_turns: self.chat.history_turns.unwrap_or(DEFAULT_HISTORY_TURNS),
            turn_budget_units: self
                .chat
                .turn_budget_units
                .unwrap_or(DEFAULT_TURN_BUDGET_UNITS),
        };
        let workflows = WorkflowSettings {
            enabled: self.workflows.enabled.unwrap_or(true),
            step_budget_units: self
                .workflows
                .step_budget_units
                .unwrap_or(DEFAULT_STEP_BUDGET_UNITS),
            retry_backoff_secs: self
                .workflows
                .retry_backoff_secs
                .unwrap_or(DEFAULT_STEP_RETRY_BACKOFF_SECS),
        };
        let raw_budget_units = self.raw_budget_units.unwrap_or(DEFAULT_RAW_BUDGET_UNITS);
        let code_mode = CodeModeSettings {
            prompt_package: self.code_mode.prompt_package.map(|path| match base {
                Some(base) if path.is_relative() => base.join(path),
                _ => path,
            }),
            budget_units: self
                .code_mode
                .budget_units
                .unwrap_or(DEFAULT_CODE_MODE_BUDGET_UNITS),
            max_runs: self
                .code_mode
                .max_runs
                .unwrap_or_else(crate::mcp::CodeRunLimits::runs_for_this_machine),
            compaction: self.code_mode.compaction.resolve()?,
            check: self.code_mode.check.resolve(base)?,
        };
        let recall = RecallModelSettings {
            rerank_budget_units: self
                .recall
                .rerank_budget_units
                .unwrap_or(DEFAULT_RERANK_BUDGET_UNITS),
        };
        if [
            dreamer.pass_budget_units,
            chat.turn_budget_units,
            workflows.step_budget_units,
            raw_budget_units,
            code_mode.budget_units,
            recall.rerank_budget_units,
        ]
        .contains(&0)
        {
            anyhow::bail!("models budget units must be greater than zero");
        }
        if code_mode.max_runs == 0 {
            anyhow::bail!("models.code_mode.max_runs must be at least 1");
        }
        // Every try of a step reserves one call's units, the same amount
        // whatever this config later becomes, so its retries can replay
        // exactly what the earlier tries were charged.
        if workflows.step_budget_units < oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS {
            anyhow::bail!(
                "models.workflows.step_budget_units must cover one call's reservation ({} units)",
                oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS
            );
        }
        let broker = self.broker.unwrap_or_default().resolve()?;
        let media = self.media.unwrap_or_default().resolve(&providers)?;
        let decisions = self.decisions.resolve()?;
        let voice = self.voice.resolve(base)?;
        let planner = self.planner.resolve()?;
        let mut models = ModelsConfig {
            providers,
            roles,
            stays_on_device,
            aliases,
            extraction_egress: self.extraction_egress.unwrap_or(false),
            raw_budget_units,
            dreamer,
            chat,
            workflows,
            code_mode,
            recall,
            broker,
            decision_read: None,
            decisions,
            media,
            voice,
            planner,
        };
        if let Some(file) = self.decision_read {
            models.decision_read = Some(file.resolve(base, &models)?);
        }
        Ok(models)
    }
}

impl BrokerFile {
    fn resolve(self) -> anyhow::Result<BrokerConfig> {
        let absolute = |path: &PathBuf, field: &str| {
            anyhow::ensure!(
                path.is_absolute(),
                "models.broker.{field} must be an absolute path"
            );
            Ok(())
        };
        match (self.socket, self.uid) {
            (Some(socket), Some(uid)) => {
                absolute(&socket, "socket")?;
                anyhow::ensure!(
                    self.program.is_none() && self.extra_roots.is_empty(),
                    "models.broker.program and extra_roots are for the same-user child; a separate-user broker takes its own flags"
                );
                Ok(BrokerConfig::SeparateUser { socket, uid })
            }
            (None, None) => {
                if let Some(program) = &self.program {
                    absolute(program, "program")?;
                }
                for roots in &self.extra_roots {
                    absolute(roots, "extra_roots")?;
                }
                Ok(BrokerConfig::SameUser {
                    program: self.program,
                    extra_roots: self.extra_roots,
                })
            }
            _ => anyhow::bail!(
                "models.broker.socket and uid name a separate-user broker together; with neither, this server starts a same-user child"
            ),
        }
    }
}

impl CodeCheckFile {
    fn resolve(self, base: Option<&Path>) -> anyhow::Result<CodeCheckSettings> {
        let mode = match self.mode.as_deref() {
            None => CheckMode::Off,
            Some(mode) => mode
                .parse()
                .map_err(|error| anyhow::anyhow!("models.code_mode.check.mode: {error}"))?,
        };
        let backend = match self.backend.as_deref() {
            None => BackendKind::TscRs,
            Some(backend) => backend
                .parse()
                .map_err(|error| anyhow::anyhow!("models.code_mode.check.backend: {error}"))?,
        };
        let microsoft_tsc = self.microsoft_tsc.map(|path| match base {
            Some(base) if path.is_relative() => base.join(path),
            _ => path,
        });
        if backend == BackendKind::Microsoft && microsoft_tsc.is_none() {
            anyhow::bail!("models.code_mode.check: the microsoft backend needs microsoft_tsc");
        }
        Ok(CodeCheckSettings {
            mode,
            backend,
            microsoft_tsc,
        })
    }
}

fn validate_ladders(
    providers: &BTreeMap<String, ProviderConfig>,
    roles: &BTreeMap<ModelRole, Vec<Rung>>,
) -> anyhow::Result<()> {
    // Two provider spellings that map to one engine id would share one
    // catalog row: one of them would silently run as the other.
    let mut engine_ids: BTreeMap<oneiron::ModelId, &ModelRef> = BTreeMap::new();
    for rung in roles.values().flatten() {
        let Some(provider) = providers.get(&rung.model.provider) else {
            continue;
        };
        let id = rung.model.engine_id(&provider.revision)?;
        if let Some(other) = engine_ids.insert(id.clone(), &rung.model)
            && other != &rung.model
        {
            anyhow::bail!(
                "models {other} and {} both become engine id {id}; rename one",
                rung.model
            );
        }
    }
    for (role, ladder) in roles {
        let key = role_key(*role);
        if *role == ModelRole::RetrievalEmbedder {
            anyhow::bail!(
                "models.roles.{key}: the retrieval embedder is configured in [embedder] (provider = \"endpoint\" takes any OpenAI-compatible /v1/embeddings server)"
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        for rung in ladder {
            let provider = providers.get(&rung.model.provider).ok_or_else(|| {
                anyhow::anyhow!(
                    "models.roles.{key}: {} names provider {:?}, which [models.providers] does not define",
                    rung.model,
                    rung.model.provider
                )
            })?;
            if provider.kind.media_only() {
                anyhow::bail!(
                    "models.roles.{key}: {} is on a media provider, which serves [models.media] seats only",
                    rung.model
                );
            }
            let tagger_role = *role == ModelRole::ExtractionEncoder;
            if tagger_role != (provider.kind == ProviderKind::Oneironer) {
                anyhow::bail!(
                    "models.roles.{key}: {} is a {} provider; extraction_encoder takes a tagger (kind = \"oneironer\") and every other role takes a generating provider",
                    rung.model,
                    if provider.kind.generates() {
                        "generating"
                    } else {
                        "tagger"
                    }
                );
            }
            if *role == ModelRole::Reranker && !provider.kind.reranks() {
                anyhow::bail!(
                    "models.roles.{key}: {} is not on an OpenAI-compatible provider; the reranker is called over /v1/rerank",
                    rung.model
                );
            }
            if !seen.insert(&rung.model) {
                anyhow::bail!(
                    "models.roles.{key}: {} appears twice in one ladder",
                    rung.model
                );
            }
        }
    }
    Ok(())
}

/// `[models.aliases]`: each target is the engine id
/// (`provider/name@revision`) of a model a ladder names.
fn resolve_aliases(
    aliases: BTreeMap<String, String>,
    providers: &BTreeMap<String, ProviderConfig>,
    roles: &BTreeMap<ModelRole, Vec<Rung>>,
) -> anyhow::Result<BTreeMap<String, oneiron::ModelId>> {
    let configured = roles
        .values()
        .flatten()
        .filter_map(|rung| {
            let provider = providers.get(&rung.model.provider)?;
            rung.model.engine_id(&provider.revision).ok()
        })
        .collect::<BTreeSet<_>>();
    aliases
        .into_iter()
        .map(|(alias, target)| {
            let id = target.parse::<oneiron::ModelId>().map_err(|error| {
                anyhow::anyhow!(
                    "models.aliases.{alias}: {target:?} is not a provider/name@revision model id: {error}"
                )
            })?;
            anyhow::ensure!(
                configured.contains(&id),
                "models.aliases.{alias}: {id} is not a model [models] configures"
            );
            // An alias spelled as a configured id would silently reroute it.
            anyhow::ensure!(
                !configured.iter().any(|model| model.as_str() == alias),
                "models.aliases.{alias}: the alias is a configured model's own id"
            );
            Ok((alias, id))
        })
        .collect()
}

impl ModelsConfig {
    /// A `[models]` section's body on its own, as a host that embeds this
    /// crate writes it. `base` resolves relative prompt files.
    pub fn from_toml(text: &str, base: Option<&Path>) -> anyhow::Result<Self> {
        let file: ModelsFile = toml::from_str(text)?;
        file.resolve(base)
    }

    /// The ladder for `role`, if any rung serves it.
    #[must_use]
    pub fn ladder(&self, role: ModelRole) -> Option<&[Rung]> {
        self.roles
            .get(&role)
            .map(Vec::as_slice)
            .filter(|ladder| !ladder.is_empty())
    }
}
