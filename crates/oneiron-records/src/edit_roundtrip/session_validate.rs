//! Moved from `crates/oneiron/src/edit_roundtrip/session_validate.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Serialize;
use std::collections::BTreeSet;

/// One corruption-gate check result. Serializes into receipts/viewer payloads;
/// the `&'static str` check name means it does not round-trip back through
/// `Deserialize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationCheck {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

/// The corruption-gate report. `ok` is the conjunction of all checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationReport {
    pub ok: bool,
    pub checks: Vec<ValidationCheck>,
}

impl ValidationReport {
    pub fn single_failure(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            checks: vec![ValidationCheck {
                name,
                passed: false,
                detail: detail.into(),
            }],
        }
    }
}
