//! Learned keys (ARCH-0003 `#learning-settings`; DESIGN 15-setting-primitive, stage 3): a number
//! a fit learns under the stored rows. A value row of a learned key is its seed, the prior its fit
//! starts from, with a weight in runs; the owner's pin fixes the value against the fit; once a
//! cell's fit has runs of its own it decides at its scope, before the seed there.

use serde::{Deserialize, Serialize};

use oneiron_setting_contract::{FitCell, FoundFit, RowKey};

use super::read::{StoredRow, table_of};
use super::{EncodedValue, ScopeKind, SetSetting, Setting, SettingMode, SettingScope, SettingSpec};
use crate::error::{Error, Result};
use crate::side_table::SideTableDbs;

/// A learned key's range: every row of the key and every fit it reads stays in `[min, max]`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LearnedRange {
    pub min: f64,
    pub max: f64,
}

impl LearnedRange {
    /// Whether `value` lies in the range.
    #[must_use]
    pub fn contains(self, value: f64) -> bool {
        (self.min..=self.max).contains(&value)
    }
}

/// The scope kinds a learned key may sit at: the places a fit's cell is keyed by.
pub const LEARNED_SCOPES: [ScopeKind; 4] = [
    ScopeKind::Goal,
    ScopeKind::Project,
    ScopeKind::TaskType,
    ScopeKind::Vault,
];

/// A learned key's fit as a read shows it, beside the value in force: the narrowest fit on the
/// read's chain, also when a pin decides (ARCH-0003 `#learning-settings`: "A pin fixes the value
/// used, while the estimate and its own run count remain visible").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettingFitView {
    /// The fit, as JSON, inside the key's range.
    pub value: serde_json::Value,
    /// The runs it is learned from.
    pub runs: f64,
    pub cell: FitCell,
}

/// One fit the walk found: its place on the chain, its value encoded, its cell and its runs.
pub(super) struct LoadedFit {
    pub(super) found: FoundFit<EncodedValue>,
    pub(super) cell: FitCell,
    pub(super) runs: f64,
}

/// The cells a fit at each place of `chain` is learned in, narrowest place first, and at one
/// place the cell of the chain's task type before the untyped one: a goal's (with the chain's
/// project), a project's, a task type's, the vault's. Any other place keys no cell.
fn cells(chain: &[SettingScope]) -> Vec<(usize, FitCell)> {
    let project = chain.iter().find_map(|scope| match scope {
        SettingScope::Project(project) => Some(*project),
        _ => None,
    });
    let task_type = chain.iter().find_map(|scope| match scope {
        SettingScope::TaskType(node) => Some(node.clone()),
        _ => None,
    });
    let cell = |project, goal, task_type| FitCell {
        project,
        goal,
        task_type,
    };
    let mut cells = Vec::new();
    for (at, scope) in chain.iter().enumerate() {
        let (project, goal) = match scope {
            SettingScope::Goal(goal) => (project, Some(*goal)),
            SettingScope::Project(project) => (Some(*project), None),
            SettingScope::TaskType(node) => {
                cells.push((at, cell(None, None, Some(node.clone()))));
                continue;
            }
            SettingScope::Vault => (None, None),
            _ => continue,
        };
        if (goal.is_some() || project.is_some())
            && let Some(node) = &task_type
        {
            cells.push((at, cell(project, goal, Some(node.clone()))));
        }
        cells.push((at, cell(project, goal, None)));
    }
    cells
}

/// The fits of `spec` on `chain`, at most one per place: at each place the first of its cells
/// whose fit has runs of its own, clamped into the key's range. Empty for a key that is not
/// learned. The fits are cached by the learning projector
/// (`learning::project::SETTING_FIT`), keyed by the key's name and the cell.
///
/// # Errors
///
/// Storage errors; a cached fit that does not decode.
pub(super) fn fits_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    chain: &[SettingScope],
) -> Result<Vec<LoadedFit>> {
    let Some(range) = spec.kind.learned_range() else {
        return Ok(Vec::new());
    };
    let mut fits: Vec<LoadedFit> = Vec::new();
    for (at, cell) in cells(chain) {
        if fits.last().is_some_and(|fit| fit.found.at == at) {
            continue;
        }
        let key = crate::learning_setting::setting_fit_key(
            spec.name,
            cell.project,
            cell.goal,
            cell.task_type.as_deref(),
        );
        let Some(fit) = crate::learning::project::SETTING_FIT
            .get(dbs, txn, &key)?
            .filter(|fit| fit.runs > 0.0 && fit.value.is_finite())
        else {
            continue;
        };
        // A fit never leaves the key's range, so it never widens a floor.
        let value = EncodedValue::encode(&fit.value.clamp(range.min, range.max))?;
        fits.push(LoadedFit {
            found: FoundFit { at, value },
            cell,
            runs: fit.runs,
        });
    }
    Ok(fits)
}

/// The narrowest of `fits`, as a read shows it.
pub(super) fn fit_view(spec: &SettingSpec, fits: &[LoadedFit]) -> Option<SettingFitView> {
    let fit = fits.iter().min_by_key(|fit| fit.found.at)?;
    Some(SettingFitView {
        value: spec.kind.to_json(&fit.found.value)?,
        runs: fit.runs,
        cell: fit.cell.clone(),
    })
}

/// The weight in runs `request` stores on its row. A learned key's value row is a seed, and a
/// seed carries its weight: finite and above zero (ARCH-0003 `#learning-settings`: "A seed
/// overrides the prior with the owner's value and an explicit weight in runs"). A pin is a seed
/// of infinite weight, so it names none; nor does a clear, nor a row of a key that is not learned.
///
/// # Errors
///
/// `InvalidConfig` for a seed with no weight or a weight that is not finite and above zero, and
/// for a weight on a pin, a clear or a key that is not learned.
pub(super) fn checked_weight(spec: &SettingSpec, request: &SetSetting) -> Result<Option<f64>> {
    let seed = spec.is_learned() && request.mode == SettingMode::Value && request.value.is_some();
    match (seed, request.weight_runs) {
        (true, Some(weight)) if weight.is_finite() && weight > 0.0 => Ok(Some(weight)),
        (true, _) => Err(Error::InvalidConfig(format!(
            "a seed of the learned key `{}` carries a weight in runs, finite and above zero",
            spec.name
        ))),
        (false, None) => Ok(None),
        (false, Some(_)) => Err(Error::InvalidConfig(format!(
            "only a seed of a learned key carries a weight in runs; this change of `{}` is a \
             pin, a clear or a row of a key that is not learned",
            spec.name
        ))),
    }
}

impl Setting<f64> {
    /// The seed a fit of this learned key starts from, for a cell on the places `known`: the
    /// narrowest value row on their chain whose value lies in the key's range, with its weight
    /// in runs. `None` where no such row stands, or for a key that is not learned. A pin is no
    /// seed: it fixes the value read, and the fit keeps learning beside it.
    ///
    /// # Errors
    ///
    /// A place the key does not admit; storage errors.
    #[cfg_attr(
        not(all(oneiron_test_support, feature = "test-support")),
        allow(dead_code)
    )]
    pub(crate) fn seed_in_txn(
        &self,
        dbs: &impl SideTableDbs,
        txn: &heed::RoTxn<'_>,
        known: &[SettingScope],
    ) -> Result<Option<(f64, f64)>> {
        let Some(range) = self.spec.kind.learned_range() else {
            return Ok(None);
        };
        let chain = SettingScope::chain(known, self.spec.scopes)?;
        let table = table_of(self.spec);
        for scope in chain {
            let key = RowKey {
                name: self.spec.name.to_owned(),
                item: None,
                mode: SettingMode::Value,
                scope,
            };
            let Some(bytes) = table.get_bytes(dbs, txn, &key.encode())? else {
                continue;
            };
            if let Some(seed) = rmp_serde::from_slice::<StoredRow>(&bytes)
                .ok()
                .and_then(|row| Some((row.value.decode::<f64>()?, row.weight_runs?)))
                .filter(|(value, _)| range.contains(*value))
            {
                return Ok(Some(seed));
            }
        }
        Ok(None)
    }
}
