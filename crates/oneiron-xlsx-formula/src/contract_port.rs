//! The document contract's recalculation port (ARCH-0075 section 2): a host
//! serving `oneiron_docedit::contract` runs `xlsx.recalc` through this engine,
//! since the contract crate cannot depend on it. The caller's clock and
//! location reach the engine exactly as the edit round trip passes them.

use crate::engine::FormualizerEngine;
use crate::{DocumentLocation, FormulaError, RecalcClock};
use oneiron_docedit::contract::{
    ContractError, DocumentLocationArgs, ErrorCode, RecalcClockArgs, RecalcPort, Recalculated,
};
use oneiron_docedit::retained_opc::Limits;

impl RecalcPort for FormualizerEngine {
    fn recalculate(
        &self,
        workbook: &[u8],
        limits: Limits,
        clock: &RecalcClockArgs,
        location: Option<&DocumentLocationArgs>,
    ) -> Result<Recalculated, ContractError> {
        let now = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(clock.now_ms)
            .ok_or_else(|| bad("clock.now_ms is outside the representable range"))?;
        let clock = RecalcClock::new(now, clock.utc_offset_minutes, clock.seed)
            .ok_or_else(|| bad("clock.utc_offset_minutes is beyond ±14 hours"))?;
        let location = location
            .map(|location| {
                DocumentLocation::new(location.directory.clone(), location.file_name.clone())
                    .ok_or_else(|| bad("location needs a folder ending in a separator"))
            })
            .transpose()?;
        let recalc = self
            .recalculate_xlsx(workbook, limits, &clock, location.as_ref())
            .map_err(refusal)?;
        Ok(Recalculated {
            bytes: recalc.bytes,
            engine: recalc.engine.engine,
            version: recalc.engine.version,
            formula_count: recalc.formula_count,
        })
    }
}

fn bad(detail: &str) -> ContractError {
    ContractError::new(ErrorCode::BadRequest, detail)
}

/// A refused workbook names the precision fallback; malformed content is the
/// caller's document, not the engine's failure.
fn refusal(error: FormulaError) -> ContractError {
    let code = match &error {
        FormulaError::UnsupportedWorkbook(_) => ErrorCode::NeedsFallback,
        FormulaError::InvalidWorkbook(_) | FormulaError::Package(_) => ErrorCode::InvalidDocument,
        FormulaError::InvalidAddress(_)
        | FormulaError::UnsupportedValue(_)
        | FormulaError::InvalidCorpus(_) => ErrorCode::BadRequest,
        FormulaError::Engine(_) => ErrorCode::Internal,
    };
    ContractError::new(code, error.to_string())
}
