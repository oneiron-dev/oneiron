//! Learned settings (ARCH-0003 #learning-settings; Setting stage 3): the learned knobs are
//! catalogue keys, each a `setting_keys!` row of the module that reads it with a learned kind
//! (`Kind::learned(min, max)`), and every reader reads one through the Setting walk
//! ([`crate::setting`]): the owner's pin, else the narrowest seed or fit (at one scope the fit
//! first, once it has runs of its own), else the shipped seed. An owner or a holder of the knob's
//! `engine.controls` class sets a seed or a pin with `settings.set`; a seed is a value row with its
//! weight in runs.
//!
//! What stays here is what the walk does not do: the fitting checks and the key each scope's fit is
//! cached under ([`record_setting_check`]; the projector folds them over the seed,
//! `Setting::seed_in_txn`), the typed list the fitter finds a knob in ([`LEARNED_SETTINGS`]), the
//! readers' places ([`known_in_txn`]), the hook that refolds a knob's fits when its seed moves
//! ([`refold_fits_on_change`]), and the owner rows' key shape the spawn choices keep
//! ([`crate::learning_setting_choice`]).

use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::{LearnedRange, Setting, SettingChange};

mod fit;
mod scope_erase;
mod sourced;
mod subject;
pub use fit::{SettingCheck, global_setting_subject, record_setting_check};
pub(crate) use fit::{record_setting_check_in_txn, setting_fit_key};
pub(crate) use scope_erase::{erase_setting_fits_in_txn, project_row_keys};
pub(crate) use sourced::setting_value_in_scope_sourced_in_txn;

use crate::agent_dispatch::planner::setting_keys as planner;
use crate::blob_artifact::esign::setting_keys as esign;
use crate::dreamer_runner::maintenance::agent_health::setting_keys as health;
use crate::dreamer_runner::maintenance::coach::setting_keys as coach;
use crate::learning::setting_keys as learning;
use crate::llm::decision::questions::setting_keys as questions;
use crate::self_heal::setting_keys as self_heal;
use crate::skill_attribution::setting_keys as attribution;
use crate::skill_optimize::audit_rate::setting_keys as audit;
use crate::skill_optimize::eval_set::setting_keys as eval_set;
use crate::skill_optimize::exploration_trial::setting_keys as exploration;
use crate::store::group_commit::setting_keys as group_commit;
use crate::tagging::setting_keys as tagging;

/// Every learned knob the engine reads, typed: the fitter finds the knob a setting cell learns by
/// its name ([`learned_setting`]). The catalogue's learned keys and this list are the same set
/// (unit test `learned_settings_are_the_catalogue_learned_keys`).
pub(crate) static LEARNED_SETTINGS: [&Setting<f64>; 40] = [
    &attribution::ATTRIBUTION_UNCLEAR_FLOOR,
    &attribution::CONTRIBUTION_CHECK_RATE,
    &attribution::CREDIT_DECAY,
    &attribution::CREDIT_ENABLED,
    &attribution::CREDIT_DEPTH_CAP,
    &attribution::CREDIT_CHECK_EVERY_HOP,
    &group_commit::GROUP_COMMIT_WINDOW_MS,
    &group_commit::GROUP_COMMIT_MAX_WRITES,
    &learning::LEARNING_WINDOW_HALF_LIFE_DAYS,
    &learning::LEARNING_SHIPPED_PRIOR_RUNS,
    &learning::LEARNING_BORROWED_PRIOR_RUNS,
    &planner::PLANNER_SOLO_SUCCESS_FLOOR,
    &planner::PLANNER_SOLO_MARGIN,
    &planner::PLANNER_BIG_PLAN_WIDTH,
    &audit::AUDIT_RATE,
    &exploration::EXPLORATION_ASK_CLIMB_HOURS,
    &exploration::EXPLORATION_ASK_LAPSE_HOURS,
    &eval_set::EVAL_FLOOR_MIN_FAMILIES,
    &eval_set::EVAL_FLOOR_MIN_FAMILIES_PER_SLICE,
    &health::HEALTH_REVIEW,
    &health::HEALTH_LOOP_REPEATS,
    &health::HEALTH_CHECK_FAILS,
    &health::HEALTH_WAIT_SHARE,
    &health::HEALTH_WAIT_MINUTES,
    &health::HEALTH_SILENT_MINUTES,
    &health::HEALTH_WIDEN_DENIALS,
    &health::HEALTH_COST_SPIKE,
    &health::HEALTH_ESCALATE_TTL_HOURS,
    &health::HEALTH_CARD_FLOOR,
    &health::HEALTH_DUP_MIN_COST,
    &health::HEALTH_OWNER_COPY,
    &health::HEALTH_REVIEW_WINDOW_HOURS,
    &health::HEALTH_COST_MIN_RUNS,
    &health::HEALTH_TREND_PERIOD_DAYS,
    &coach::TRADEOFF_REMINDER_HOURS,
    &coach::ATTRIBUTION_LABEL_RECEIPTS,
    &esign::ESIGN_ASK_CLIMB_HOURS,
    &questions::QUESTION_CALL_BUDGET_MS,
    &self_heal::DETECTOR_CENTROID_MIN_SIMILARITY,
    &tagging::LINKER_VECTOR_MARGIN,
];

/// The learned knob named `name`, if the engine reads one.
#[must_use]
pub(crate) fn learned_setting(name: &str) -> Option<&'static Setting<f64>> {
    LEARNED_SETTINGS
        .iter()
        .copied()
        .find(|key| key.spec.name == name)
}

/// The range every row and every fit of the learned knob `key` stays in.
#[must_use]
pub(crate) fn knob_bounds(key: &Setting<f64>) -> LearnedRange {
    key.spec.kind.learned_range().unwrap_or(LearnedRange {
        min: f64::NEG_INFINITY,
        max: f64::INFINITY,
    })
}

/// The value the learned knob `key` ships with: the catalogue default, in force until an owner's
/// seed or pin, or a fit, decides.
#[must_use]
pub(crate) fn knob_seed(key: &Setting<f64>) -> f64 {
    key.kind.default_typed()
}

/// The places a read under `project` and `type_ref` knows, for a learned knob's walk: the
/// project's current intake goal ([`project_goal_in_txn`]), the project, and the task type unless
/// it is the root (the fits of the root type are the untyped cells). The vault is always the last
/// place of the walk.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn known_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<crate::entity_id::EntityId>,
    type_ref: Option<&crate::learning::TypeRef>,
) -> Result<Vec<crate::setting::SettingScope>> {
    use crate::setting::SettingScope as Place;
    let goal = match project {
        Some(project) => project_goal_in_txn(vault, txn, project)?,
        None => None,
    };
    Ok(goal
        .map(Place::Goal)
        .into_iter()
        .chain(project.map(Place::Project))
        .chain(
            type_ref
                .filter(|type_ref| !type_ref.is_root())
                .map(|type_ref| Place::TaskType(type_ref.node_id.clone())),
        )
        .collect())
}

/// The value in force for the learned knob `key` for the whole vault: the owner's pin, else the
/// vault-scope fit once it has runs of its own, else the vault's seed, else the shipped seed.
///
/// # Errors
///
/// Storage errors.
pub fn setting_value(vault: &Vault, key: &Setting<f64>) -> Result<f64> {
    let rtxn = vault.store.env.read_txn()?;
    setting_value_in_txn(&vault.store, &rtxn, key)
}

/// [`setting_value`] inside a transaction the caller already holds, from the store alone.
pub(crate) fn setting_value_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    key: &Setting<f64>,
) -> Result<f64> {
    Ok(key.read_in_dbs_txn(store, txn, &[], None)?.value)
}

/// The value in force for the learned knob `key` where `project` and `type_ref` apply: the walk
/// over the project's goal, the project, the task type and the vault ([`known_in_txn`]). With
/// neither named it is [`setting_value`].
///
/// # Errors
///
/// Storage errors.
pub fn setting_value_scoped(
    vault: &Vault,
    key: &Setting<f64>,
    project: Option<crate::entity_id::EntityId>,
    type_ref: Option<&crate::learning::TypeRef>,
) -> Result<f64> {
    let rtxn = vault.store.env.read_txn()?;
    setting_value_in_scope_in_txn(vault, &rtxn, key, project, type_ref)
}

/// [`setting_value_scoped`] inside a transaction the caller already holds.
pub(crate) fn setting_value_in_scope_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &Setting<f64>,
    project: Option<crate::entity_id::EntityId>,
    type_ref: Option<&crate::learning::TypeRef>,
) -> Result<f64> {
    let known = known_in_txn(vault, txn, project, type_ref)?;
    Ok(key.read_in_txn(vault, txn, &known, None)?.value)
}

/// Every learned knob's `on_change`: a value row is a seed, the prior its scope's fits fold from,
/// so a change of one (a set or a clear) refolds the knob's fits in the same write. A pin moves no
/// prior: the fit keeps learning beside it.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn refold_fits_on_change(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    change: &SettingChange,
) -> Result<()> {
    if change.mode != crate::setting::SettingMode::Value {
        return Ok(());
    }
    crate::learning::project::reproject_setting_cells_in_txn(vault, wtxn, &change.key, change.at)
}

// The owner's rows over the spawn choices (`crate::learning_setting_choice`) keep the row shape the
// learned knobs had before stage 3: a seed or a pin at the vault, a project's goal, a project or a
// task type, keyed by `choice "\0" mode`, then the scope.

/// How an owner row steers its setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SettingMode {
    /// Replaces the shipped seed; a fit, once built, keeps learning from it.
    Seed,
    /// Fixes the value in force; a fit may propose a change, never apply it.
    Pin,
}

impl SettingMode {
    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::Pin => "pin",
        }
    }
}

/// Where an owner row applies. A goal, project or task-type row steers only
/// the reads that name that goal's project, that project or that type
/// (`learning_setting_choice`'s read); every other read sees the vault's row.
#[derive(Debug, Clone, PartialEq)]
pub enum SettingScope {
    Vault,
    /// A project's intake goal, by its goal claim's id: the row steers that
    /// project's work while the goal stands, and not its successor's.
    Goal(crate::entity_id::EntityId),
    Project(crate::entity_id::EntityId),
    /// A task type's node, at whatever tree version the read names.
    Type(crate::learning::TypeRef),
}

/// Longest reason a row keeps, in bytes: a sentence for the record, not a
/// document.
const MAX_WHY_BYTES: usize = 1024;

fn row_key(key: &str, mode: SettingMode) -> String {
    format!("{key}\0{}", mode.as_str())
}

/// An owner row's key: `key "\0" mode`, then its scope's tag and id unless
/// it is the vault's. The choice rows share it.
pub(crate) fn scoped_row_key(key: &str, mode: SettingMode, scope: &SettingScope) -> String {
    match scope {
        SettingScope::Vault => row_key(key, mode),
        SettingScope::Goal(goal) => format!("{}\0goal\0{}", row_key(key, mode), goal.to_hex()),
        SettingScope::Project(project) => {
            format!("{}\0project\0{}", row_key(key, mode), project.to_hex())
        }
        SettingScope::Type(type_ref) => {
            format!("{}\0type\0{}", row_key(key, mode), type_ref.node_id)
        }
    }
}

/// [`scoped_row_key`] read back: the key, the mode and the scope. A type
/// row's key names its node only, so its scope reads `tree_version` 0.
pub(crate) fn parse_row_key(stored_key: &str) -> Option<(&str, SettingMode, SettingScope)> {
    let parts: Vec<&str> = stored_key.split('\0').collect();
    let mode = match parts.get(1).copied() {
        Some("seed") => SettingMode::Seed,
        Some("pin") => SettingMode::Pin,
        _ => return None,
    };
    let id = |hex: &str| crate::entity_id::EntityId::from_hex(hex).ok();
    let scope = match parts.as_slice() {
        [_, _] => SettingScope::Vault,
        [_, _, "goal", hex] => SettingScope::Goal(id(hex)?),
        [_, _, "project", hex] => SettingScope::Project(id(hex)?),
        [_, _, "type", node] => SettingScope::Type(crate::learning::TypeRef {
            node_id: (*node).to_owned(),
            tree_version: 0,
        }),
        _ => return None,
    };
    Some((parts[0], mode, scope))
}

const fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

/// The terms every owner row keeps, whatever it steers: a reason of at most
/// 1 KiB, and a seed with a positive weight in runs or a pin with none.
pub(crate) fn check_row_terms(
    mode: SettingMode,
    weight_runs: Option<f64>,
    why: &str,
) -> Result<()> {
    if why.len() > MAX_WHY_BYTES {
        return Err(invalid(
            "a setting row's reason is a sentence, not a document",
        ));
    }
    match (mode, weight_runs) {
        (SettingMode::Pin, None) => Ok(()),
        (SettingMode::Seed, Some(weight)) if weight.is_finite() && weight > 0.0 => Ok(()),
        _ => Err(invalid(
            "a seed carries a positive weight in runs and a pin carries none",
        )),
    }
}

/// The goal a read under `project` serves: the goal claim the project's goal
/// pointer names, its current intake goal (OF-542). Goal intake alone moves
/// that pointer, so a goal row steers the project's work while its goal
/// stands and none of a successor goal's.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn project_goal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: crate::entity_id::EntityId,
) -> Result<Option<crate::entity_id::EntityId>> {
    Ok(vault
        .visible_project_in_txn(txn, project)?
        .and_then(|record| record.goal)
        .and_then(|hex| crate::entity_id::EntityId::from_hex(&hex).ok()))
}

/// The scopes a read under `project` and `type_ref` walks, narrowest first:
/// the project's goal, the project, the type, the vault.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn read_scopes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<crate::entity_id::EntityId>,
    type_ref: Option<&crate::learning::TypeRef>,
) -> Result<Vec<SettingScope>> {
    let goal = match project {
        Some(project) => project_goal_in_txn(vault, txn, project)?,
        None => None,
    };
    Ok(read_scopes(goal, project, type_ref))
}

fn read_scopes(
    goal: Option<crate::entity_id::EntityId>,
    project: Option<crate::entity_id::EntityId>,
    type_ref: Option<&crate::learning::TypeRef>,
) -> Vec<SettingScope> {
    goal.map(SettingScope::Goal)
        .into_iter()
        .chain(project.map(SettingScope::Project))
        .chain(type_ref.cloned().map(SettingScope::Type))
        .chain([SettingScope::Vault])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::LEARNED_SETTINGS;

    #[test]
    fn learned_settings_are_the_catalogue_learned_keys() {
        let mut catalogue: Vec<&str> = crate::setting::catalogue()
            .into_iter()
            .filter(|spec| spec.is_learned() && !spec.name.starts_with("test."))
            .map(|spec| spec.name)
            .collect();
        let mut listed: Vec<&str> = LEARNED_SETTINGS.iter().map(|key| key.spec.name).collect();
        catalogue.sort_unstable();
        listed.sort_unstable();
        assert_eq!(listed, catalogue);
    }
}
