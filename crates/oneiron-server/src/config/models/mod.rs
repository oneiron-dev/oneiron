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
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use oneiron::llm::manifest::ModelRole;
use serde::Deserialize;

mod levels;
mod provider;
#[cfg(test)]
mod tests;

pub use levels::{ModelRef, Rung, SHORTHAND_ROLES, role_key};
pub use provider::{OutputLimitField, ProviderConfig, ProviderKind};

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
    dreamer: DreamerFile,
    #[serde(default)]
    chat: ChatFile,
    #[serde(default)]
    workflows: WorkflowFile,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct DreamerFile {
    enabled: Option<bool>,
    idle_floor_secs: Option<u64>,
    session_ceiling_secs: Option<u64>,
    pass_budget_units: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatFile {
    history_turns: Option<usize>,
    turn_budget_units: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowFile {
    enabled: Option<bool>,
    step_budget_units: Option<u64>,
    retry_backoff_secs: Option<u64>,
}

/// The resolved `[models]` section: providers plus one ladder per role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelsConfig {
    pub providers: BTreeMap<String, ProviderConfig>,
    pub roles: BTreeMap<ModelRole, Vec<Rung>>,
    /// Owner opt-in for the Dreamer's extraction calls to leave the device.
    /// Off by default: personal-data extraction stays local unless the owner
    /// says otherwise (ARCH-0036 counter-arrow).
    pub extraction_egress: bool,
    /// Process-lifetime meter for the raw `/v1/llm` routes.
    pub raw_budget_units: u64,
    pub dreamer: DreamerSettings,
    pub chat: ChatSettings,
    pub workflows: WorkflowSettings,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DreamerSettings {
    pub enabled: bool,
    /// A sitting with no activity for this long ends, and its turns dream.
    pub idle_floor_secs: u64,
    /// Hard ceiling on one session's life, independent of activity.
    pub session_ceiling_secs: u64,
    /// Budget units each wake pass may spend.
    pub pass_budget_units: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatSettings {
    /// Earlier turns of the conversation sent with each chat turn.
    pub history_turns: usize,
    pub turn_budget_units: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkflowSettings {
    pub enabled: bool,
    pub step_budget_units: u64,
    /// Wait before a failed step's next try, times the tries so far.
    pub retry_backoff_secs: u64,
}

const DEFAULT_SESSION_CEILING_SECS: u64 = 12 * 60 * 60;
const DEFAULT_PASS_BUDGET_UNITS: u64 = 400_000;
const DEFAULT_TURN_BUDGET_UNITS: u64 = 64_000;
const DEFAULT_STEP_BUDGET_UNITS: u64 = 64_000;
const DEFAULT_STEP_RETRY_BACKOFF_SECS: u64 = 30;
const DEFAULT_RAW_BUDGET_UNITS: u64 = 10_000_000;
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
        };
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
        if [
            dreamer.pass_budget_units,
            chat.turn_budget_units,
            workflows.step_budget_units,
            raw_budget_units,
        ]
        .contains(&0)
        {
            anyhow::bail!("models budget units must be greater than zero");
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
        Ok(ModelsConfig {
            providers,
            roles,
            extraction_egress: self.extraction_egress.unwrap_or(false),
            raw_budget_units,
            dreamer,
            chat,
            workflows,
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

impl ModelsConfig {
    /// The ladder for `role`, if any rung serves it.
    #[must_use]
    pub fn ladder(&self, role: ModelRole) -> Option<&[Rung]> {
        self.roles
            .get(&role)
            .map(Vec::as_slice)
            .filter(|ladder| !ladder.is_empty())
    }
}
