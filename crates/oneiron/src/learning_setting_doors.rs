//! The owner's doors over learning-setting rows (ARCH-0003
//! #learning-settings): list, put and clear a seed or a pin at the vault, a
//! project or a task type. The owner routes (`/v1/owner/settings/learning`),
//! the host verbs `vault.settings.learning`, `.put` and `.clear`, and the
//! `oneiron learning-settings` command all call these. Each takes the owner's
//! proof and revalidates it; the writers in `learning_setting` check the
//! owner again in their own write. Catalog bounds and the seed and pin rules
//! stay the writers'.

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::learning::TypeRef;
use crate::learning_setting::{self, SETTING_CATALOG, SettingMode, SettingRow, SettingScope};
use crate::{EdgeActorClass, EntityId, Error, Result, Vault, WriteActor};

/// A seed (a prior the vault's fit starts from, with a weight in runs) or a
/// pin (the value, whatever the fit says).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LearningSettingMode {
    Seed,
    Pin,
}

impl From<LearningSettingMode> for SettingMode {
    fn from(mode: LearningSettingMode) -> Self {
        match mode {
            LearningSettingMode::Seed => Self::Seed,
            LearningSettingMode::Pin => Self::Pin,
        }
    }
}

impl From<SettingMode> for LearningSettingMode {
    fn from(mode: SettingMode) -> Self {
        match mode {
            SettingMode::Seed => Self::Seed,
            SettingMode::Pin => Self::Pin,
        }
    }
}

/// Where a row applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LearningSettingScope {
    Vault,
    Project,
    TaskType,
}

/// `vault.settings.learning`'s input: the whole catalog and every row, or
/// one key's.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningSettingsRequest {
    /// Only this catalog key.
    #[serde(default)]
    pub key: Option<String>,
}

/// `vault.settings.learning.put`'s input: one seed or pin. A row names a
/// project or a task type, or neither for the vault.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningSettingPut {
    /// A catalog key, e.g. `health.loop.repeats`.
    pub key: String,
    pub mode: LearningSettingMode,
    /// Within the key's catalog bounds.
    pub value: f64,
    /// A seed's weight in runs, positive; a pin carries none.
    #[serde(default)]
    pub weight_runs: Option<f64>,
    /// The owner's reason, kept as written (at most 1 KiB).
    pub why: String,
    /// A project's id (32 hex): the row steers that project's work.
    #[serde(default)]
    pub project: Option<String>,
    /// A task type's node: the row steers that type's work at any tree
    /// version.
    #[serde(default)]
    pub task_type: Option<String>,
}

/// `vault.settings.learning.clear`'s input: the row of one key, mode and
/// scope. Clearing an absent row succeeds.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningSettingClear {
    pub key: String,
    pub mode: LearningSettingMode,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub task_type: Option<String>,
}

/// One owner row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningSettingRowView {
    pub key: String,
    pub mode: LearningSettingMode,
    pub scope: LearningSettingScope,
    /// The project, 32 hex, for a project row.
    pub project: Option<String>,
    /// The task type's node, for a type row.
    pub task_type: Option<String>,
    pub value: f64,
    pub weight_runs: Option<f64>,
    /// The owner who set it, 32 hex.
    pub by: String,
    /// Unix seconds it was set.
    pub at: u64,
    pub why: String,
}

/// One catalog knob: its bounds and seed, and what the vault reads for it
/// now (a vault pin, else the vault fit, else a vault seed, else the seed).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningSettingSpecView {
    pub key: String,
    pub min: f64,
    pub max: f64,
    pub seed: f64,
    pub value: f64,
}

/// `vault.settings.learning`'s answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningSettingsView {
    pub catalog: Vec<LearningSettingSpecView>,
    pub rows: Vec<LearningSettingRowView>,
}

fn bad(message: &'static str) -> Error {
    Error::InvalidClaimBody(message)
}

fn scope_of(project: Option<&str>, task_type: Option<&str>) -> Result<SettingScope> {
    match (project, task_type) {
        (None, None) => Ok(SettingScope::Vault),
        (Some(project), None) => EntityId::from_hex(project)
            .map(SettingScope::Project)
            .map_err(|_| bad("project is a project's id, 32 hex")),
        (None, Some(node)) => {
            let type_ref = TypeRef {
                node_id: node.to_owned(),
                tree_version: 0,
            };
            type_ref
                .validate()
                .map_err(|_| bad("task_type is a task type's node id"))?;
            Ok(SettingScope::Type(type_ref))
        }
        (Some(_), Some(_)) => Err(bad("a row names a project or a task type, not both")),
    }
}

/// The owner's writer, from a proof revalidated now.
fn owner_actor(vault: &Vault, owner: &AuthenticatedOwner) -> Result<WriteActor> {
    Ok(WriteActor::new(owner.revalidate(vault)?, EdgeActorClass::Human))
}

fn row_view(scope: SettingScope, row: SettingRow, by: String) -> LearningSettingRowView {
    let (kind, project, task_type) = match scope {
        SettingScope::Vault => (LearningSettingScope::Vault, None, None),
        SettingScope::Project(project) => {
            (LearningSettingScope::Project, Some(project.to_hex()), None)
        }
        SettingScope::Type(type_ref) => (LearningSettingScope::TaskType, None, Some(type_ref.node_id)),
    };
    LearningSettingRowView {
        key: row.key,
        mode: row.mode.into(),
        scope: kind,
        project,
        task_type,
        value: row.value,
        weight_runs: row.weight_runs,
        by,
        at: row.at,
        why: row.why,
    }
}

/// The catalog and the owner's rows, or one key's. Owner-only: a row keeps
/// the owner's own reason.
///
/// # Errors
///
/// A proof that no longer holds; storage errors.
pub fn learning_settings_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &LearningSettingsRequest,
) -> Result<LearningSettingsView> {
    owner.revalidate(vault)?;
    let wanted = |key: &str| input.key.as_deref().is_none_or(|wanted| wanted == key);
    let mut catalog = Vec::new();
    for spec in SETTING_CATALOG.iter().filter(|spec| wanted(spec.key)) {
        catalog.push(LearningSettingSpecView {
            key: spec.key.to_owned(),
            min: spec.min,
            max: spec.max,
            seed: spec.seed,
            value: learning_setting::setting_value(vault, spec)?,
        });
    }
    let rows = learning_setting::list_setting_rows(vault)?
        .into_iter()
        .filter(|(_, row, _)| wanted(&row.key))
        .map(|(scope, row, by)| row_view(scope, row, by))
        .collect();
    Ok(LearningSettingsView { catalog, rows })
}

/// Lays one seed or pin, replacing the row of the same key, mode and scope,
/// and answers with the key's catalog and rows.
///
/// # Errors
///
/// A bad scope; the writer's refusals (a key outside the catalog, a value
/// outside its bounds, a pin with a weight or a seed without one, a reason
/// over 1 KiB, a writer that is not the owner); storage errors.
pub fn put_learning_setting_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: LearningSettingPut,
) -> Result<LearningSettingsView> {
    let scope = scope_of(input.project.as_deref(), input.task_type.as_deref())?;
    let actor = owner_actor(vault, owner)?;
    let key = input.key.clone();
    learning_setting::put_scoped_setting_row(
        vault,
        &actor,
        &scope,
        &SettingRow {
            key: input.key,
            mode: input.mode.into(),
            value: input.value,
            weight_runs: input.weight_runs,
            at: crate::unix_seconds_now(),
            why: input.why,
        },
    )?;
    learning_settings_as_owner(vault, owner, &LearningSettingsRequest { key: Some(key) })
}

/// Clears one row and answers with the key's catalog and rows.
///
/// # Errors
///
/// A bad scope; a writer that is not the owner; storage errors.
pub fn clear_learning_setting_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: LearningSettingClear,
) -> Result<LearningSettingsView> {
    let scope = scope_of(input.project.as_deref(), input.task_type.as_deref())?;
    let actor = owner_actor(vault, owner)?;
    learning_setting::clear_scoped_setting_row(
        vault,
        &actor,
        &scope,
        &input.key,
        input.mode.into(),
    )?;
    learning_settings_as_owner(
        vault,
        owner,
        &LearningSettingsRequest {
            key: Some(input.key),
        },
    )
}
