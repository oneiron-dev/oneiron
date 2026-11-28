//! The result of a partial `vault.hydrate` read.

use serde::{Deserialize, Serialize};

use super::EntityView;
use crate::claim::ScopedReadResult;

/// The found records and the misses of one hydrate read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HydrateResult {
    /// Found records in request order, with the read's narrowing receipt.
    #[serde(flatten)]
    pub read: ScopedReadResult<Vec<EntityView>>,
    /// Refs with no view, in request order. Empty when every ref resolved.
    pub missing: Vec<HydrateMiss>,
}

/// One ref that did not produce a view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HydrateMiss {
    /// The exact ref the caller supplied, including any revision suffix.
    #[serde(rename = "ref")]
    pub reference: String,
    /// What can be said about the miss without exposing a withheld record.
    pub reason: HydrateMissReason,
}

/// Why this read returned no view for a ref.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HydrateMissReason {
    /// No readable view. Absent and withheld records share this reason so
    /// the miss cannot reveal which records exist.
    NotFound,
    /// The ref or its revision suffix failed the syntax check.
    Malformed,
}
