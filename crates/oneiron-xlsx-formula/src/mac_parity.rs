//! Workbook-local function masking for functions without recorded truth, never global overrides.
use std::sync::Arc;

use formualizer_common::{ExcelError, ExcelErrorKind, LiteralValue};
use formualizer_workbook::{CustomFnOptions, Workbook};

use crate::{FormulaError, Result};

/// Functions the engine answers with `#NAME?` before formualizer runs: ENCODEURL
/// and WEBSERVICE have no corpus use and no recorded truth (ARCH-0075 section 6
/// edge table). FILTERXML left this list on 2026-10-02: where Excel for Windows
/// and Excel for Mac differ, Windows is the reference (owner ruling 2026-10-01),
/// its truth is recorded on Excel for Windows 16.0.20430, and the fork
/// implements it (0.9.3-oneiron.3).
const MAC_ABSENT_FUNCTIONS: &[&str] = &["ENCODEURL", "WEBSERVICE"];

pub(super) fn apply(workbook: &mut Workbook) -> Result<()> {
    for name in MAC_ABSENT_FUNCTIONS {
        workbook
            .register_custom_function(
                name,
                CustomFnOptions {
                    allow_override_builtin: true,
                    thread_safe: true,
                    ..CustomFnOptions::default()
                },
                Arc::new(|_: &[LiteralValue]| Err(ExcelError::new(ExcelErrorKind::Name))),
            )
            .map_err(|error| FormulaError::Engine(error.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::MAC_ABSENT_FUNCTIONS;

    #[test]
    fn mac_absent_set_is_exactly_the_oracle_edges() {
        assert_eq!(MAC_ABSENT_FUNCTIONS, ["ENCODEURL", "WEBSERVICE"]);
        for present in ["XLOOKUP", "SUM", "FILTER", "FILTERXML"] {
            assert!(!MAC_ABSENT_FUNCTIONS.contains(&present), "{present}");
        }
    }
}
