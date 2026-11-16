//! The owner's screening policy: weights and threshold, the value of the setting
//! `dreamer.prefilter`, and its Vault reads.

use crate::Vault;
use crate::error::Result;

#[doc(hidden)]
pub use oneiron_records::dreamer_prefilter::config::{
    PrefilterConfig, PrefilterWeights, validate_prefilter_config,
};

impl Vault {
    /// Reads the active screening policy; an absent row IS the compiled
    /// [`PrefilterConfig::default`].
    ///
    /// # Errors
    ///
    /// Storage errors; `InvalidConfig` when the landed row is out of range; `CorruptedIndex` when
    /// it does not decode.
    pub fn prefilter_config(&self) -> Result<PrefilterConfig> {
        let rtxn = self.store.env.read_txn()?;
        self.prefilter_config_in_txn(&rtxn)
    }

    /// [`Vault::prefilter_config`] through a caller-owned write transaction,
    /// so the in-transaction session-close planner screens under exactly the
    /// policy its own commit will be judged by.
    pub(super) fn prefilter_config_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<PrefilterConfig> {
        // The value is checked on the way out as well as on the way in: a corrupt or foreign
        // row must not hand the planner a NaN threshold.
        let config = super::setting_keys::PREFILTER
            .read_in_txn(self, txn, &[], None)?
            .value;
        validate_prefilter_config(&config)?;
        Ok(config)
    }
}
