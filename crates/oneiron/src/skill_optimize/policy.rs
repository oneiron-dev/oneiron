//! Calibration policy row in trusted Gate manifests.

use crate::Vault;
use crate::error::{Error, Result};

pub(crate) use crate::gate::judge_calibration::{JudgeCalibrationPolicy, MANIFEST_KEY};

/// Resolve against the same transaction that admits or delivers the ask.
/// A malformed loaded manifest does not quietly restore permissive defaults.
pub(crate) fn resolved_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<JudgeCalibrationPolicy> {
    crate::gate::resolve_policy_manifest(&vault.store, txn)?
        .judge_calibration_policy()
        .ok_or(Error::InvalidConfig(
            "judge calibration policy manifest is invalid".into(),
        ))
}
