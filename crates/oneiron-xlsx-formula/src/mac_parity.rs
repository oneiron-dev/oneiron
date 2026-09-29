//! Workbook-local Excel-for-Mac function availability, never global overrides.
use std::sync::Arc;

use formualizer_common::{ExcelError, ExcelErrorKind, LiteralValue};
use formualizer_workbook::{CustomFnOptions, Workbook};

use crate::{FormulaError, Result};

/// Windows-only functions absent on Mac Excel and the web. The session returns
/// `#NAME?` for them, which is parity with the Mac oracle (ARCH-0075 section
/// 6 edge table), not a missing-function defect.
const MAC_ABSENT_FUNCTIONS: &[&str] = &["ENCODEURL", "FILTERXML", "WEBSERVICE"];

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
