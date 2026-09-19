//! Storage-independent recalc seam for the xlsx formula engine.
//!
//! The docedit pipeline calls [`RecalcEngine`], never an engine crate: the
//! trait is pure over cell maps (no vault, no filesystem, no clock), and the
//! in-process implementation lives in `oneiron-xlsx-formula`, which depends
//! on this organ, never the reverse. The pipeline keeps its `EditSession`
//! seam; a session that recalcs in-process holds a `RecalcEngine` and stamps
//! [`EngineId`] on its report, while external-link workbooks stay on the
//! openpyxl/LibreOffice route per [`RouteDecision`].
//!
//! [`EngineId`] is the step-25 version stamp: every artifact version records
//! which engine computed its cached values, so a silent divergence stays
//! attributable. Stored as plain strings; old rows without a stamp decode.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Which engine computed a set of cached values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineId {
    /// Engine name: `formualizer-workbook`, `libreoffice`, or `none`.
    pub engine: String,
    /// Engine version (`0.9.3`, the LO build id, or `"1"` for none).
    pub version: String,
}

impl EngineId {
    /// Validate an attributable bounded engine/version pair.
    pub fn validate(&self) -> crate::Result<()> {
        if self.engine.trim().is_empty()
            || self.version.trim().is_empty()
            || self.engine.len() > 128
            || self.version.len() > 256
            || self
                .engine
                .chars()
                .chain(self.version.chars())
                .any(char::is_control)
        {
            return Err(crate::Error::InvalidManifest(
                "invalid document engine stamp",
            ));
        }
        Ok(())
    }

    /// Imported bytes have no attested authoring/recalc engine.
    #[must_use]
    pub fn imported() -> Self {
        Self {
            engine: "unattested-import".to_owned(),
            version: "1".to_owned(),
        }
    }
    /// The openpyxl/LibreOffice precision route (current default).
    #[must_use]
    pub fn libreoffice(version: impl Into<String>) -> Self {
        Self {
            engine: "libreoffice".to_owned(),
            version: version.into(),
        }
    }

    /// No recalc ran (values untouched or session cannot recalc).
    #[must_use]
    pub fn none() -> Self {
        Self {
            engine: "none".to_owned(),
            version: "1".to_owned(),
        }
    }

    /// Full stamp line for receipts: `engine/version`.
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
    /// Backend failure type; surfaces through `EditFailed`, never panics.
    type Error: std::fmt::Display;
    /// Evaluate `formula` at `anchor` over `setup` cells (A1 addresses to
    /// values; setup formulas start with `=`). One call per proposal stage.
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

/// Where a workbook must be recalculated (step 25 routing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RouteDecision {
    /// Safe for the in-process engine: no external references found.
    InProcess,
    /// Keep on the openpyxl/LibreOffice path; the reason names the signal
    /// (`external-links-part`, `external-rels-target`, or
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

#[cfg(test)]
mod tests {
    use super::*;

    struct Stub {
        id: EngineId,
    }

    impl RecalcEngine for Stub {
        type Error = &'static str;
        fn evaluate(
            &mut self,
            _setup: &BTreeMap<String, CalcSetup>,
            formula: &str,
            _anchor: &str,
            _read_range: Option<&str>,
        ) -> std::result::Result<CalcReport, Self::Error> {
            if formula.is_empty() {
                return Err("empty formula");
            }
            Ok(CalcReport {
                engine: self.engine_id(),
                grid: None,
                value: CalcValue::Number(42.0),
            })
        }
        fn engine_id(&self) -> EngineId {
            self.id.clone()
        }
    }

    #[test]
    fn seam_reports_its_engine_and_stays_storage_free() {
        let id = EngineId {
            engine: "formualizer-workbook".to_owned(),
            version: "0.9.3".to_owned(),
        };
        let mut stub = Stub { id: id.clone() };
        let report = stub
            .evaluate(&BTreeMap::new(), "=40+2", "F1", None)
            .expect("stub evaluates");
        assert_eq!(report.engine, id);
        assert_eq!(report.value, CalcValue::Number(42.0));
        assert!(stub.evaluate(&BTreeMap::new(), "", "F1", None).is_err());
        assert_eq!(EngineId::none().stamp(), "none/1");
    }

    #[test]
    fn routing_defaults_closed() {
        assert!(RouteDecision::InProcess.is_in_process());
        assert!(
            !RouteDecision::Openpyxl {
                reason: "external-links-part"
            }
            .is_in_process()
        );
    }
}
