//! The precision fallback for workbooks the native formula engine refuses
//! (ARCH-0075 xlsx row; FIX 2462, OF-505 = A).
//! Entry: `Vault::install_xlsx_precision_recalc`.
//!
//! A served host with LibreOffice installs its recalculator here, once per
//! open vault, never process-global. An export, a preview or a live read
//! whose workbook the native engine refuses then recalculates through it,
//! and the version carries its calculator as it carries the native
//! engine's. With none installed, or when it fails, the workbook is marked
//! to recalculate when it is opened, as before.

use std::sync::{Arc, PoisonError};

use oneiron_docedit::contract::{RecalcClockArgs, RecalcPort};
use oneiron_docedit::retained_opc::Limits;
use oneiron_xlsx_formula::FormulaError;

use super::OfficeRecalcZone;
use crate::Vault;
use crate::blob_artifact::CalcEngineStamp;

/// A host's precision recalculator, as a vault holds it.
pub type XlsxPrecisionRecalc = dyn RecalcPort + Send + Sync;

impl Vault {
    /// Installs the host's precision recalculator on this vault handle,
    /// replacing one installed before. In memory only.
    pub fn install_xlsx_precision_recalc(&self, port: Arc<XlsxPrecisionRecalc>) {
        *self
            .xlsx_precision_recalc
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(port);
    }

    /// The installed precision recalculator; `None` when the host installed
    /// none.
    pub(crate) fn xlsx_precision_recalc(&self) -> Option<Arc<XlsxPrecisionRecalc>> {
        self.xlsx_precision_recalc
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Whether a workbook the native engine refused with `error` goes to the
/// precision fallback: every refusal but a malformed or over-limit package,
/// invalid workbook content, and a resource refusal. A machine short of the
/// memory or time the native engine needed has less for LibreOffice, so that
/// workbook keeps today's fullCalcOnLoad stamp. An engine call (CALLS, FIX
/// 2462).
pub(super) fn takes_precision_fallback(error: &FormulaError) -> bool {
    !matches!(
        error,
        FormulaError::Package(_) | FormulaError::InvalidWorkbook(_) | FormulaError::Resource(_)
    )
}

/// `bytes` recalculated through `port` at `at` in `zone`, seeded by `seed`,
/// and the calculator that did it; the reason when it did not.
pub(super) fn precision_recalc(
    port: &XlsxPrecisionRecalc,
    bytes: &[u8],
    limits: Limits,
    (at, zone): (u64, &OfficeRecalcZone),
    seed: u64,
) -> Result<(Vec<u8>, CalcEngineStamp), String> {
    let now_ms = i64::try_from(at)
        .ok()
        .and_then(|at| at.checked_mul(1000))
        .ok_or_else(|| "the recalculation time is out of range".to_owned())?;
    let clock = RecalcClockArgs {
        now_ms,
        utc_offset_minutes: zone.utc_offset_minutes,
        seed,
    };
    let done = port
        .recalculate_in_zone(bytes, limits, &clock, None, zone.iana_timezone.as_deref())
        .map_err(|error| error.to_string())?;
    let stamp =
        CalcEngineStamp::new(done.engine, done.version).map_err(|error| error.to_string())?;
    Ok((done.bytes, stamp))
}
