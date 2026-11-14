//! The owner's doors over learning-setting rows (ARCH-0003
//! #learning-settings): list, put and clear a seed or a pin at the vault, a
//! project's goal, a project or a task type, over a catalog knob or a spawn
//! choice (`model`, `width`, `pattern`, `budget`). The owner routes (`/v1/owner/settings/learning`),
//! the host verbs `vault.settings.learning`, `.put` and `.clear`, and the
//! `oneiron learning-settings` command all call these. Each takes the owner's
//! proof and revalidates it; the writers in `learning_setting` check the
//! owner again in their own write. Catalog bounds and the seed and pin rules
//! stay the writers' ([`crate::learning_setting`],
//! [`crate::learning_setting_choice`]).

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::learning::{PriorOrigin, TypeRef};
use crate::learning_setting::{self, SETTING_CATALOG, SettingMode, SettingRow, SettingScope};
use crate::learning_setting_choice::{self as choice, ChoiceRow, ChoiceValue, SpawnChoice};
use crate::{EdgeActorClass, EntityId, Result, Vault, WriteActor};

#[doc(hidden)]
use oneiron_verb_wire::learning_setting_doors::bad;
#[doc(hidden)]
pub use oneiron_verb_wire::learning_setting_doors::{
    LearningSettingClear, LearningSettingMode, LearningSettingScope, LearningSettingSpecView,
    LearningSettingsRequest,
};

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

/// A spawn choice's value, in its own type: what a `model`, `width`,
/// `pattern` or `budget` row sets on a spawn the call left unset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LearningChoiceValue {
    /// A model id (`provider/name@revision`). A seed counts only where a
    /// seat serves that model. A pin stands even where none does: the spawn
    /// is then refused as unavailable, never given another model.
    Model(String),
    /// Agents in the spawn, at least one.
    Width(u32),
    /// A coordination pattern: `solo`, `ceo_decides`, `committee`, `vote`,
    /// `market` or `rotation`.
    Pattern(String),
    /// The spawn's hard spend cap in lease units, at least one; it only ever
    /// narrows the caller's budget.
    Budget(u64),
}

impl LearningChoiceValue {
    fn engine(self) -> Result<ChoiceValue> {
        Ok(match self {
            Self::Model(model) => ChoiceValue::Model(
                oneiron_model::llm::ModelId::new(model)
                    .map_err(|_| bad("model is a model id, provider/name@revision"))?,
            ),
            Self::Width(width) => ChoiceValue::Width(width),
            Self::Pattern(token) => ChoiceValue::Pattern(
                crate::team::team_shape::CoordinationPattern::from_token(&token)
                    .map_err(|_| bad("pattern is a coordination pattern token"))?,
            ),
            Self::Budget(units) => ChoiceValue::Budget(units),
        })
    }
}

impl From<ChoiceValue> for LearningChoiceValue {
    fn from(value: ChoiceValue) -> Self {
        match value {
            ChoiceValue::Model(model) => Self::Model(model.as_str().to_owned()),
            ChoiceValue::Width(width) => Self::Width(width),
            ChoiceValue::Pattern(pattern) => Self::Pattern(pattern.as_str().to_owned()),
            ChoiceValue::Budget(units) => Self::Budget(units),
        }
    }
}

/// `vault.settings.learning.put`'s input: one seed or pin. A row names a
/// goal, a project or a task type, or none of them for the vault. A catalog
/// knob's row carries `value`; a spawn choice's carries `choice`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningSettingPut {
    /// A catalog key, e.g. `health.loop.repeats`, or a spawn choice:
    /// `model`, `width`, `pattern` or `budget`.
    pub key: String,
    pub mode: LearningSettingMode,
    /// A catalog knob's value, within its bounds.
    #[serde(default)]
    pub value: Option<f64>,
    /// A spawn choice's value, of the choice `key` names.
    #[serde(default)]
    pub choice: Option<LearningChoiceValue>,
    /// A seed's weight in runs, positive; a pin carries none.
    #[serde(default)]
    pub weight_runs: Option<f64>,
    /// The owner's reason, kept as written (at most 1 KiB).
    pub why: String,
    /// A project's intake goal, by its goal claim's id (32 hex): the row
    /// steers that project's work while the goal stands.
    #[serde(default)]
    pub goal: Option<String>,
    /// A project's id (32 hex): the row steers that project's work.
    #[serde(default)]
    pub project: Option<String>,
    /// A task type's node: the row steers that type's work at any tree
    /// version.
    #[serde(default)]
    pub task_type: Option<String>,
}

/// One owner row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningSettingRowView {
    pub key: String,
    pub mode: LearningSettingMode,
    pub scope: LearningSettingScope,
    /// The goal claim, 32 hex, for a goal row.
    pub goal: Option<String>,
    /// The project, 32 hex, for a project row.
    pub project: Option<String>,
    /// The task type's node, for a type row.
    pub task_type: Option<String>,
    /// A catalog knob's value.
    pub value: Option<f64>,
    /// A spawn choice's value.
    pub choice: Option<LearningChoiceValue>,
    pub weight_runs: Option<f64>,
    /// The owner who set it, 32 hex, or "erased" once that owner was erased.
    pub by: String,
    /// Unix seconds it was set.
    pub at: u64,
    pub why: String,
    /// What the planner learned under a spawn choice where this row applies
    /// (FIX 3159), beside the owner's value and never it; `None` for a
    /// catalog knob's row, and for a choice row whose learning could not be
    /// read.
    pub learned: Option<LearnedChoiceView>,
}

/// What the planner learned under one spawn choice in a row's scope, from
/// the anchored outcomes of its team runs: the learned value beside the
/// owner's seed or pin. A pin is never read as one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearnedChoiceView {
    /// Each value the runs used, in the planner's shared ranking order.
    pub values: Vec<LearnedChoiceValueView>,
    /// The scope's own runs, faded at the learning window; zero when the
    /// vault's runs stand in.
    pub own_runs: f64,
    /// `shipped` over the scope's own runs (or none yet); `parent` when the
    /// vault's runs stand in for a scope with none of its own.
    pub origin: PriorOrigin,
}

/// One value's learned weight: the counts of its runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearnedChoiceValueView {
    pub choice: LearningChoiceValue,
    /// Its anchored runs, faded at the learning window.
    pub runs: f64,
    /// Its runs over the runs of every value of the choice.
    pub share: f64,
}

impl From<crate::team::LearnedChoice> for LearnedChoiceView {
    fn from(learned: crate::team::LearnedChoice) -> Self {
        Self {
            values: learned
                .values
                .into_iter()
                .map(|value| LearnedChoiceValueView {
                    choice: value.value.into(),
                    runs: value.runs,
                    share: value.share,
                })
                .collect(),
            own_runs: learned.own_runs,
            origin: learned.origin,
        }
    }
}

/// `vault.settings.learning`'s answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearningSettingsView {
    pub catalog: Vec<LearningSettingSpecView>,
    pub rows: Vec<LearningSettingRowView>,
}

fn scope_of(
    goal: Option<&str>,
    project: Option<&str>,
    task_type: Option<&str>,
) -> Result<SettingScope> {
    match (goal, project, task_type) {
        (None, None, None) => Ok(SettingScope::Vault),
        (Some(goal), None, None) => EntityId::from_hex(goal)
            .map(SettingScope::Goal)
            .map_err(|_| bad("goal is a goal claim's id, 32 hex")),
        (None, Some(project), None) => EntityId::from_hex(project)
            .map(SettingScope::Project)
            .map_err(|_| bad("project is a project's id, 32 hex")),
        (None, None, Some(node)) => {
            let type_ref = TypeRef {
                node_id: node.to_owned(),
                tree_version: 0,
            };
            type_ref
                .validate()
                .map_err(|_| bad("task_type is a task type's node id"))?;
            Ok(SettingScope::Type(type_ref))
        }
        _ => Err(bad(
            "a row names one of a goal, a project or a task type, or none",
        )),
    }
}

/// The owner's writer, from a proof revalidated now.
fn owner_actor(vault: &Vault, owner: &AuthenticatedOwner) -> Result<WriteActor> {
    Ok(WriteActor::new(
        owner.revalidate(vault)?,
        EdgeActorClass::Human,
    ))
}

/// A row's scope as the views spell it: its kind, then its goal, project
/// and task type, the one that applies set.
fn scope_view(
    scope: SettingScope,
) -> (
    LearningSettingScope,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    match scope {
        SettingScope::Vault => (LearningSettingScope::Vault, None, None, None),
        SettingScope::Goal(goal) => (LearningSettingScope::Goal, Some(goal.to_hex()), None, None),
        SettingScope::Project(project) => (
            LearningSettingScope::Project,
            None,
            Some(project.to_hex()),
            None,
        ),
        SettingScope::Type(type_ref) => (
            LearningSettingScope::TaskType,
            None,
            None,
            Some(type_ref.node_id),
        ),
    }
}

fn row_view(scope: SettingScope, row: SettingRow, by: String) -> LearningSettingRowView {
    let (kind, goal, project, task_type) = scope_view(scope);
    LearningSettingRowView {
        key: row.key,
        mode: row.mode.into(),
        scope: kind,
        goal,
        project,
        task_type,
        value: Some(row.value),
        choice: None,
        weight_runs: row.weight_runs,
        by,
        at: row.at,
        why: row.why,
        learned: None,
    }
}

fn choice_view(
    scope: SettingScope,
    row: ChoiceRow,
    by: String,
    learned: Option<LearnedChoiceView>,
) -> LearningSettingRowView {
    let (kind, goal, project, task_type) = scope_view(scope);
    LearningSettingRowView {
        key: row.value.choice().as_str().to_owned(),
        mode: row.mode.into(),
        scope: kind,
        goal,
        project,
        task_type,
        value: None,
        choice: Some(row.value.into()),
        weight_runs: row.weight_runs,
        by,
        at: row.at,
        why: row.why,
        learned,
    }
}

/// The catalog and the owner's rows, or one key's. Owner-only: a row keeps
/// the owner's own reason. A spawn choice's row carries what the planner
/// learned under it in its scope, read in the rows' snapshot (FIX 3159).
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
    learning_settings(vault, input)
}

/// [`learning_settings_as_owner`] for a holder of `engine.controls` (untangle
/// 6.6c, the read side of the dials it may tune), checked at this read.
///
/// # Errors
///
/// A caller who holds no such grant; storage errors.
pub fn learning_settings_as_holder(
    vault: &Vault,
    reader: WriteActor,
    input: &LearningSettingsRequest,
) -> crate::memory::MemoryResult<LearningSettingsView> {
    crate::federation::admit_substrate_read_by(
        vault,
        reader,
        "vault.settings.learning",
        crate::federation::SubstrateRead::Dials,
    )?;
    Ok(learning_settings(vault, input)?)
}

/// `vault.settings.learning` on a bound handle: the embedded owner reads
/// under its own proof, any other caller as an `engine.controls` holder.
///
/// # Errors
///
/// As [`learning_settings_as_owner`] and [`learning_settings_as_holder`].
pub fn learning_settings_embedded(
    memory: &crate::memory::Memory<'_>,
    input: &LearningSettingsRequest,
) -> crate::memory::MemoryResult<LearningSettingsView> {
    match memory.embedded_owner("vault.settings.learning") {
        Ok(owner) => Ok(learning_settings_as_owner(memory.vault(), &owner, input)?),
        Err(_) => learning_settings_as_holder(
            memory.vault(),
            WriteActor::new(memory.actor(), memory.actor_class()),
            input,
        ),
    }
}

fn learning_settings(
    vault: &Vault,
    input: &LearningSettingsRequest,
) -> Result<LearningSettingsView> {
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
    let rtxn = vault.store.env.read_txn()?;
    let mut rows: Vec<LearningSettingRowView> =
        learning_setting::list_setting_rows_in_txn(vault, &rtxn)?
            .into_iter()
            .filter(|(_, row, _)| wanted(&row.key))
            .map(|(scope, row, by)| row_view(scope, row, by))
            .collect();
    let choices: Vec<_> = choice::list_choice_rows_in_txn(vault, &rtxn)?
        .into_iter()
        .filter(|(_, row, _)| wanted(row.value.choice().as_str()))
        .collect();
    if !choices.is_empty() {
        // What was learned is shown beside the rows, never in their place: a
        // read of it that fails leaves it out with a WARN, and the rows stand.
        let learning = crate::team::ChoiceLearning::read_in_txn(
            vault,
            &rtxn,
            crate::unix_seconds_now(),
        )
        .inspect_err(|error| {
            tracing::warn!(%error, "the owner's choice rows answer without what was learned");
        })
        .ok();
        rows.extend(choices.into_iter().map(|(scope, row, by)| {
            let learned = learning
                .as_ref()
                .map(|learning| learning.learned(row.value.choice(), &scope).into());
            choice_view(scope, row, by, learned)
        }));
    }
    Ok(LearningSettingsView { catalog, rows })
}

/// Lays one seed or pin, replacing the row of the same key, mode and scope,
/// and answers with the key's catalog and rows. A spawn choice's key takes a
/// `choice` of its own kind; any other key a `value`.
///
/// # Errors
///
/// A bad scope; a value or choice that does not fit the key; the writers'
/// refusals (a key outside the catalog, a value outside its bounds, a width
/// or budget of zero, a pin with a weight or a seed without one, a reason
/// over 1 KiB, a writer that is not the owner); storage errors.
pub fn put_learning_setting_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: LearningSettingPut,
) -> Result<LearningSettingsView> {
    let scope = scope_of(
        input.goal.as_deref(),
        input.project.as_deref(),
        input.task_type.as_deref(),
    )?;
    let actor = owner_actor(vault, owner)?;
    let key = input.key.clone();
    let at = crate::unix_seconds_now();
    match (SpawnChoice::from_key(&input.key), input.value, input.choice) {
        (Some(wanted), None, Some(value)) => {
            let value = value.engine()?;
            if value.choice() != wanted {
                return Err(bad("a choice row's value is of the choice its key names"));
            }
            choice::put_choice_row(
                vault,
                &actor,
                &scope,
                &ChoiceRow {
                    mode: input.mode.into(),
                    value,
                    weight_runs: input.weight_runs,
                    at,
                    why: input.why,
                },
            )?;
        }
        (None, Some(value), None) => learning_setting::put_scoped_setting_row(
            vault,
            &actor,
            &scope,
            &SettingRow {
                key: input.key,
                mode: input.mode.into(),
                value,
                weight_runs: input.weight_runs,
                at,
                why: input.why,
            },
        )?,
        (Some(_), _, _) => return Err(bad("a spawn choice's row carries a choice, not a value")),
        (None, _, _) => return Err(bad("a catalog knob's row carries a value, not a choice")),
    }
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
    let scope = scope_of(
        input.goal.as_deref(),
        input.project.as_deref(),
        input.task_type.as_deref(),
    )?;
    let actor = owner_actor(vault, owner)?;
    match SpawnChoice::from_key(&input.key) {
        Some(wanted) => {
            choice::clear_choice_row(vault, &actor, &scope, wanted, input.mode.into())?;
        }
        None => learning_setting::clear_scoped_setting_row(
            vault,
            &actor,
            &scope,
            &input.key,
            input.mode.into(),
        )?,
    }
    learning_settings_as_owner(
        vault,
        owner,
        &LearningSettingsRequest {
            key: Some(input.key),
        },
    )
}

/// [`put_learning_setting_as_owner`] for a holder of `engine.controls`
/// (untangle 6.6d; owner 9 Nov 22:47, every substrate control is a public
/// verb behind a grant): one seed or pin on a learning dial a holder may
/// tune ([`crate::learning_setting::ENGINE_CONTROL_SETTINGS`]). The writer
/// checks the grant, keeps the owner's pins and work-budget caps, and writes
/// the engine-control receipt. A spawn choice stays the owner's to set.
/// Answers with the key's catalog and rows, read under the same grant.
///
/// # Errors
///
/// A bad scope; a spawn choice, or a row with no value; the holder door's
/// refusals (no live `engine.controls`, a key the owner keeps, a value
/// outside its bounds, a row the owner's rows stand over); storage errors.
pub fn put_learning_setting_as_holder(
    vault: &Vault,
    holder: WriteActor,
    input: LearningSettingPut,
) -> crate::memory::MemoryResult<LearningSettingsView> {
    let scope = scope_of(
        input.goal.as_deref(),
        input.project.as_deref(),
        input.task_type.as_deref(),
    )?;
    if SpawnChoice::from_key(&input.key).is_some() {
        return Err(bad("a spawn choice is the owner's to set").into());
    }
    let (Some(value), None) = (input.value, input.choice) else {
        return Err(bad("a catalog knob's row carries a value, not a choice").into());
    };
    let key = input.key.clone();
    vault.put_setting_row_as_holder(
        holder.entity_ref(),
        &scope,
        &SettingRow {
            key: input.key,
            mode: input.mode.into(),
            value,
            weight_runs: input.weight_runs,
            at: crate::unix_seconds_now(),
            why: input.why,
        },
    )?;
    learning_settings_as_holder(vault, holder, &LearningSettingsRequest { key: Some(key) })
}

/// [`clear_learning_setting_as_owner`] for a holder of `engine.controls`
/// (untangle 6.6d): withdraws one seed or pin on a learning dial a holder
/// may tune; the owner's pins and work-budget rows stand.
///
/// # Errors
///
/// As [`put_learning_setting_as_holder`].
pub fn clear_learning_setting_as_holder(
    vault: &Vault,
    holder: WriteActor,
    input: LearningSettingClear,
) -> crate::memory::MemoryResult<LearningSettingsView> {
    let scope = scope_of(
        input.goal.as_deref(),
        input.project.as_deref(),
        input.task_type.as_deref(),
    )?;
    if SpawnChoice::from_key(&input.key).is_some() {
        return Err(bad("a spawn choice is the owner's to set").into());
    }
    vault.clear_setting_row_as_holder(
        holder.entity_ref(),
        &scope,
        &input.key,
        input.mode.into(),
    )?;
    learning_settings_as_holder(
        vault,
        holder,
        &LearningSettingsRequest {
            key: Some(input.key),
        },
    )
}

/// `vault.settings.learning.put` on a bound handle: the embedded owner under
/// its own proof, any other caller as a holder of `engine.controls`.
///
/// # Errors
///
/// As [`put_learning_setting_as_owner`] and [`put_learning_setting_as_holder`].
pub fn put_learning_setting_embedded(
    memory: &crate::memory::Memory<'_>,
    input: LearningSettingPut,
) -> crate::memory::MemoryResult<LearningSettingsView> {
    match memory.embedded_owner("vault.settings.learning.put") {
        Ok(owner) => Ok(put_learning_setting_as_owner(
            memory.vault(),
            &owner,
            input,
        )?),
        Err(_) => put_learning_setting_as_holder(
            memory.vault(),
            WriteActor::new(memory.actor(), memory.actor_class()),
            input,
        ),
    }
}

/// `vault.settings.learning.clear` on a bound handle: the embedded owner
/// under its own proof, any other caller as a holder of `engine.controls`.
///
/// # Errors
///
/// As [`clear_learning_setting_as_owner`] and
/// [`clear_learning_setting_as_holder`].
pub fn clear_learning_setting_embedded(
    memory: &crate::memory::Memory<'_>,
    input: LearningSettingClear,
) -> crate::memory::MemoryResult<LearningSettingsView> {
    match memory.embedded_owner("vault.settings.learning.clear") {
        Ok(owner) => Ok(clear_learning_setting_as_owner(
            memory.vault(),
            &owner,
            input,
        )?),
        Err(_) => clear_learning_setting_as_holder(
            memory.vault(),
            WriteActor::new(memory.actor(), memory.actor_class()),
            input,
        ),
    }
}
