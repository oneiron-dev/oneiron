//! Owned result-set action output conversion (FIX 12936).

use super::{Lift, OneironError, WireJson, lift_record};

impl Lift<oneiron::lens::LensResultSetActionResult> for crate::LensResultSetActionResult {
    fn lift(value: oneiron::lens::LensResultSetActionResult) -> Result<Self, OneironError> {
        let oneiron::lens::LensResultSetActionResult {
            outcome,
            read_receipt,
        } = value;
        let outcome = WireJson::lift(outcome)?;
        Ok(Self {
            outcome,
            read_receipt: lift_record("vault.lenses.result_set.action:readReceipt", &read_receipt)?,
        })
    }
}
