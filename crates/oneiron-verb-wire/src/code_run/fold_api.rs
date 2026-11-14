//! Moved from `crates/oneiron/src/code_run/fold_api.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunAttachRequest {
    pub run: String,
    #[serde(default)]
    pub rebind: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunAttached {
    pub live_run: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldMarkRequest {
    pub live_run: String,
    pub from: u64,
    pub through: u64,
    #[serde(default)]
    pub note: Option<String>,
    /// Folds only this kind of content in each step of the span, such as
    /// `repl_output`; absent folds whole steps.
    #[serde(default)]
    pub kind: Option<crate::compaction::fold_kinds::FoldKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldCompactRequest {
    pub live_run: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldUnfoldRequest {
    pub live_run: String,
    pub fold: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldRunRequest {
    pub live_run: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldHistoryRequest {
    pub live_run: String,
    /// First durable step to read, inclusive.
    pub from: u64,
    /// Maximum number of durable steps in this page; must be positive.
    pub limit: usize,
}
