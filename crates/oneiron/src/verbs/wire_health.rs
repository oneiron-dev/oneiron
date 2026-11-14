//! Typed detection policy for the owner's wire-health doors (OF-520).

use crate::{Error, Result};

/// The device-local detection policy row, never a rate refusal.
#[doc(hidden)]
pub const WIRE_THRESHOLDS_MANIFEST: &str = "manifest:rc42:wire-observation:v1";

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::wire_health::{WireThresholds, WireThresholdsReceipt};

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
