//! The value types of the `code_mode.view.*` keys: the verb-tree view's base list,
//! expansion list and token budget.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::setting::SettingValue;

/// A list of verb-tree paths: the value of `code_mode.view.base` and
/// `code_mode.view.expanded`. Each entry is a dotted lowercase path; the view
/// reports one the tree does not hold, so set time checks the spelling only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ViewPaths(pub(crate) Vec<String>);

impl ViewPaths {
    /// These paths, owned: the constructor the `code_mode.view.base` default
    /// in `crate::verbs::setting_keys` builds from its const slice.
    pub(crate) fn from_strs(paths: &[&str]) -> Self {
        Self(paths.iter().copied().map(str::to_owned).collect())
    }

    /// No path: `code_mode.view.expanded`'s default.
    pub(crate) fn empty() -> Self {
        Self(Vec::new())
    }
}

impl SettingValue for ViewPaths {
    fn check(self) -> Result<Self> {
        for entry in &self.0 {
            check_view_path(entry).map_err(|reason| {
                Error::InvalidConfig(format!("code_mode.view: {reason}: {entry:?}"))
            })?;
        }
        Ok(self)
    }
}

/// Whether `path` is a dotted lowercase path: one or more parts of
/// `[a-z][a-z0-9_]*` joined by dots. A branch (`tasks`) is one part; the tree
/// itself is not consulted.
fn check_view_path(path: &str) -> std::result::Result<(), &'static str> {
    if path.is_empty() {
        return Err("a view path is not empty");
    }
    if path.split('.').all(valid_view_segment) {
        Ok(())
    } else {
        Err("a view path is dotted lowercase, each part [a-z][a-z0-9_]*")
    }
}

fn valid_view_segment(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    first.is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

/// The default `code_mode.view.budget_tok`: the whole default view in tokens.
pub(crate) const DEFAULT_VIEW_BUDGET_TOK: u32 = 4000;

/// The view's token budget: the value of `code_mode.view.budget_tok`. Zero is
/// refused: no view fits in zero tokens.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct ViewBudgetTok(pub(crate) u32);

impl ViewBudgetTok {
    /// The default budget: [`DEFAULT_VIEW_BUDGET_TOK`].
    pub(crate) const fn default_budget() -> Self {
        Self(DEFAULT_VIEW_BUDGET_TOK)
    }
}

impl SettingValue for ViewBudgetTok {
    fn check(self) -> Result<Self> {
        if self.0 >= 1 {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(
                "code_mode.view.budget_tok: the view budget is at least one token".into(),
            ))
        }
    }
}
