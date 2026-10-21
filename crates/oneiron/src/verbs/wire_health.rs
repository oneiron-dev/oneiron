//! Typed detection policy for the owner's wire-health doors (OF-520).
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// The device-local detection policy row, never a rate refusal.
#[doc(hidden)]
pub const WIRE_THRESHOLDS_MANIFEST: &str = "manifest:rc42:wire-observation:v1";

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireThresholds {
    pub window_secs: u64,
    pub per_verb: u64,
    pub per_actor: u64,
}

impl Default for WireThresholds {
    fn default() -> Self {
        Self {
            window_secs: 60,
            per_verb: 50_000_000,
            per_actor: 1_000_000,
        }
    }
}

impl WireThresholds {
    /// Every detection row and its window must be positive.
    pub fn validate(&self) -> Result<()> {
        if self.window_secs == 0 || self.per_verb == 0 || self.per_actor == 0 {
            Err(Error::InvalidConfig(
                "RC42 thresholds must be positive".into(),
            ))
        } else {
            Ok(())
        }
    }
}

/// The policy replaced and the policy installed by one owner edit.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WireThresholdsReceipt {
    pub previous: WireThresholds,
    pub thresholds: WireThresholds,
}

/// Installs only the wire detection policy, with owner authority checked in
/// the host's transaction that also flushes its active observation window.
#[doc(hidden)]
#[cfg(feature = "sync")]
pub fn set_wire_thresholds_as_owner_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &crate::consent::AuthenticatedOwner,
    thresholds: &WireThresholds,
) -> Result<WireThresholdsReceipt> {
    owner.revalidate_in_txn(vault, txn)?;
    thresholds.validate()?;
    let previous: WireThresholds = vault
        .sync_state_get_in_write_txn(txn, WIRE_THRESHOLDS_MANIFEST)?
        .map(|bytes| {
            rmp_serde::from_slice(&bytes).map_err(|_| Error::CorruptedIndex("wire observation"))
        })
        .transpose()?
        .unwrap_or_default();
    previous.validate()?;
    let bytes = rmp_serde::to_vec_named(thresholds)
        .map_err(|_| Error::CorruptedIndex("wire observation"))?;
    vault.sync_state_put_in_write_txn(txn, WIRE_THRESHOLDS_MANIFEST, &bytes)?;
    Ok(WireThresholdsReceipt {
        previous,
        thresholds: thresholds.clone(),
    })
}
