//! Calibration policy row in trusted Gate manifests.

use rmpv::Value;

use crate::Vault;
use crate::error::{Error, Result};

/// Top-level policy-manifest row name. Absence retains the shipped defaults.
pub(crate) const MANIFEST_KEY: &str = "judge_calibration";

/// Behavior-deciding limits for active-learning questions. Multiple trusted
/// manifests compose restrictively: higher ask cost and lower context limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JudgeCalibrationPolicy {
    pub(crate) ask_minutes: u32,
    pub(crate) max_context_bytes: u32,
}

impl Default for JudgeCalibrationPolicy {
    fn default() -> Self {
        Self {
            ask_minutes: 1,
            max_context_bytes: 512,
        }
    }
}

impl JudgeCalibrationPolicy {
    pub(crate) fn decode(value: &Value) -> Option<Self> {
        let Value::Map(entries) = value else {
            return None;
        };
        if entries.len() != 2 {
            return None;
        }
        let mut ask_minutes = None;
        let mut max_context_bytes = None;
        for (key, value) in entries {
            let number = u32::try_from(value.as_u64()?).ok().filter(|n| *n > 0)?;
            match key.as_str()? {
                "ask_minutes" if ask_minutes.is_none() => ask_minutes = Some(number),
                "max_context_bytes" if max_context_bytes.is_none() => {
                    max_context_bytes = Some(number);
                }
                _ => return None,
            }
        }
        Some(Self {
            ask_minutes: ask_minutes?,
            max_context_bytes: max_context_bytes?,
        })
    }

    pub(crate) fn restrict(self, other: Self) -> Self {
        Self {
            ask_minutes: self.ask_minutes.max(other.ask_minutes),
            max_context_bytes: self.max_context_bytes.min(other.max_context_bytes),
        }
    }
}

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
