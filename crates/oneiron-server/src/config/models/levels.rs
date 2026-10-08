//! The three config levels and their expansion into per-role ladders.
//!
//! HIGH and MID are shorthands: each expands to the DETAILED form, a ladder
//! of rungs per role key. A role written out in DETAILED replaces whatever a
//! shorthand gave it.
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use oneiron::llm::manifest::ModelRole;
use serde::Deserialize;

/// The model-backed seats a shorthand fills: chat and agent work, typed
/// checks, and the Dreamer. Other roles are named only in DETAILED.
pub const SHORTHAND_ROLES: [ModelRole; 3] = [
    ModelRole::GenerativeReasoner,
    ModelRole::Checker,
    ModelRole::DreamerCurrent,
];

/// `"<provider>:<model>"`: a provider entry and the model id that provider
/// expects, verbatim (it may hold `/` or `:`, as proxies and local servers
/// spell their models).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModelRef {
    pub provider: String,
    pub model: String,
}

impl ModelRef {
    pub(super) fn parse(field: &str, value: &str) -> anyhow::Result<Self> {
        let (provider, model) = value.trim().split_once(':').ok_or_else(|| {
            anyhow::anyhow!("{field} = {value:?} must read \"<provider>:<model>\"")
        })?;
        if provider.is_empty() || model.trim().is_empty() {
            anyhow::bail!("{field} = {value:?} must read \"<provider>:<model>\"");
        }
        Ok(Self {
            provider: provider.to_owned(),
            model: model.trim().to_owned(),
        })
    }
}

impl fmt::Display for ModelRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.provider, self.model)
    }
}

/// One rung of a ladder: a model, and an optional instruction prepended to
/// every call this rung serves. A rung that fails hands the call to the next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rung {
    pub model: ModelRef,
    pub prompt: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RungFile {
    model: String,
    prompt: Option<String>,
    prompt_file: Option<PathBuf>,
}

/// `[models.roles.<role>]`: either one `model` or a `rungs` list.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RoleFile {
    model: Option<String>,
    prompt: Option<String>,
    prompt_file: Option<PathBuf>,
    #[serde(default)]
    rungs: Vec<RungFile>,
}

/// The HIGH and MID keys of `[models]`.
pub(super) struct Shorthand {
    pub(super) default: Option<String>,
    pub(super) prompt: Option<String>,
    pub(super) prompt_file: Option<PathBuf>,
    pub(super) local: Option<String>,
    pub(super) cloud: Option<String>,
    pub(super) prefer_local: bool,
}

pub(super) fn expand(
    shorthand: Shorthand,
    roles: BTreeMap<ModelRole, RoleFile>,
    base: Option<&Path>,
) -> anyhow::Result<BTreeMap<ModelRole, Vec<Rung>>> {
    let prompt = prompt_text(
        "models.prompt",
        shorthand.prompt,
        shorthand.prompt_file,
        base,
    )?;
    let rung = |field: &str, value: &str| -> anyhow::Result<Rung> {
        Ok(Rung {
            model: ModelRef::parse(field, value)?,
            prompt: prompt.clone(),
        })
    };
    let mut ladders = BTreeMap::new();
    match (&shorthand.default, &shorthand.local, &shorthand.cloud) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => anyhow::bail!(
            "models.default (one model) and models.local/models.cloud (a local and a cloud model) are two levels of the same setting; pick one"
        ),
        (Some(default), None, None) => {
            let ladder = vec![rung("models.default", default)?];
            for role in SHORTHAND_ROLES {
                ladders.insert(role, ladder.clone());
            }
        }
        (None, local, cloud) => {
            let local = local
                .as_deref()
                .map(|value| rung("models.local", value))
                .transpose()?;
            let cloud = cloud
                .as_deref()
                .map(|value| rung("models.cloud", value))
                .transpose()?;
            let ordered = if shorthand.prefer_local {
                [local.clone(), cloud]
            } else {
                [cloud, local.clone()]
            };
            let ladder: Vec<Rung> = ordered.into_iter().flatten().collect();
            if !ladder.is_empty() {
                for role in SHORTHAND_ROLES {
                    ladders.insert(role, ladder.clone());
                }
            }
            if let Some(local) = local {
                ladders.insert(ModelRole::LocalReasoner, vec![local]);
            }
        }
    }
    for (role, file) in roles {
        ladders.insert(role, role_ladder(role, file, base)?);
    }
    Ok(ladders)
}

fn role_ladder(role: ModelRole, file: RoleFile, base: Option<&Path>) -> anyhow::Result<Vec<Rung>> {
    let key = role_key(role);
    let field = format!("models.roles.{key}");
    match (file.model, file.rungs.is_empty()) {
        (Some(_), false) => anyhow::bail!("{field}: set `model` or `rungs`, not both"),
        (None, true) => anyhow::bail!("{field}: set `model` or `rungs`"),
        (Some(model), true) => Ok(vec![Rung {
            model: ModelRef::parse(&format!("{field}.model"), &model)?,
            prompt: prompt_text(&field, file.prompt, file.prompt_file, base)?,
        }]),
        (None, false) => {
            if file.prompt.is_some() || file.prompt_file.is_some() {
                anyhow::bail!("{field}: with `rungs`, set each rung's own prompt");
            }
            file.rungs
                .into_iter()
                .enumerate()
                .map(|(index, rung)| {
                    let field = format!("{field}.rungs[{index}]");
                    Ok(Rung {
                        model: ModelRef::parse(&format!("{field}.model"), &rung.model)?,
                        prompt: prompt_text(&field, rung.prompt, rung.prompt_file, base)?,
                    })
                })
                .collect()
        }
    }
}

fn prompt_text(
    field: &str,
    inline: Option<String>,
    file: Option<PathBuf>,
    base: Option<&Path>,
) -> anyhow::Result<Option<String>> {
    match (inline, file) {
        (Some(_), Some(_)) => anyhow::bail!("{field}: set `prompt` or `prompt_file`, not both"),
        (Some(text), None) => Ok(Some(text).filter(|text| !text.trim().is_empty())),
        (None, Some(path)) => {
            let path = match base {
                Some(base) if path.is_relative() => base.join(path),
                _ => path,
            };
            let text = std::fs::read_to_string(&path).map_err(|error| {
                anyhow::anyhow!("{field}: read prompt_file {}: {error}", path.display())
            })?;
            Ok(Some(text).filter(|text| !text.trim().is_empty()))
        }
        (None, None) => Ok(None),
    }
}

/// The manifest's own spelling of a role key (`dreamer_current`).
#[must_use]
pub fn role_key(role: ModelRole) -> String {
    serde_json::to_value(role)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{role:?}"))
}
