//! Storage-independent recalc seam: pure over cell maps, no vault, no
//! filesystem, no clock. [`crate::engine::FormualizerEngine`] implements it;
//! the corpus runner in [`crate::measure`] drives it.
//!
//! [`EngineId`] names who computed a set of cached values. At the edit-session
//! boundary it becomes the core's `CalcEngineStamp`, which every recalculated
//! artifact version records.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Which engine computed a set of cached values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineId {
    /// Engine name, e.g. `formualizer-workbook`.
    pub engine: String,
    /// Engine version.
    pub version: String,
}

impl EngineId {
    /// Full stamp line for reports: `engine/version`.
    #[must_use]
    pub fn stamp(&self) -> String {
        format!("{}/{}", self.engine, self.version)
    }
}

/// A staged or evaluated cell value, independent of any engine type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CalcValue {
    Blank,
    Number(f64),
    Text(String),
    Bool(bool),
    Error(String),
    Array(Vec<Vec<CalcValue>>),
}

/// What one in-process recalculation produced, plus who computed it.
#[derive(Debug, Clone, PartialEq)]
pub struct CalcReport {
    /// Engine that computed the cached values.
    pub engine: EngineId,
    /// Evaluated scalar at the anchor cell.
    pub value: CalcValue,
    /// Optional rectangular spill result.
    pub grid: Option<Vec<Vec<CalcValue>>>,
}

/// The recalc seam. Pure over cell maps: no vault, no filesystem, no clock.
pub trait RecalcEngine {
    /// Backend failure type; surfaces as a typed error, never a panic.
    type Error: std::fmt::Display;
    /// Evaluate `formula` at `anchor` over `setup` cells (A1 addresses to
    /// values; setup formulas start with `=`).
    fn evaluate(
        &mut self,
        setup: &BTreeMap<String, CalcSetup>,
        formula: &str,
        anchor: &str,
        read_range: Option<&str>,
    ) -> std::result::Result<CalcReport, Self::Error>;
    /// Engine identity for version stamps.
    fn engine_id(&self) -> EngineId;
}

/// A setup-cell value before staging.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CalcSetup {
    Number(f64),
    Text(String),
    Bool(bool),
    Blank,
    Formula(String),
}

/// Where a workbook must be recalculated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RouteDecision {
    /// Safe for the in-process engine: no external references found.
    InProcess,
    /// Keep on the caller's link-preserving fallback session; the reason names
    /// the signal (`external-links-part`, `external-rels-target`, or
    /// `external-formula-reference`). The workbook crosses unchanged.
    Openpyxl {
        /// Stable machine key for the routing signal.
        reason: &'static str,
    },
}

impl RouteDecision {
    /// True only for the in-process route.
    #[must_use]
    pub const fn is_in_process(self) -> bool {
        matches!(self, Self::InProcess)
    }
}
