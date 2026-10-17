//! The owner's model settings (OF-305): the standing quota fallbacks. Each
//! one names the model that a parked offer's calls go to while that offer is
//! parked, and is set when the owner answers a quota question
//! `use_fallback`. This is owner policy, kept apart from the deployment's
//! runtime cooldowns: a checkpoint keeps it, and a restore keeps the live
//! vault's rows.

use crate::Vault;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};

/// The owner's standing fallback for each offer, by the offer's key: the
/// engine model id its calls go to while it is parked. Key: hex64.
const FALLBACKS: SideTable<String, String, Raw> = SideTable::new(&side_table::MODEL_OWNER_FALLBACK);

impl Vault {
    /// The engine id of the model the owner named for the offer whose key is
    /// `offer` (hex64), for use while that offer is parked. `None` if the
    /// owner named none.
    pub fn model_fallback(&self, offer: &str) -> Result<Option<String>> {
        let txn = self.store.env.read_txn()?;
        FALLBACKS.get(&self.store, &txn, &offer.to_owned())
    }

    /// Names `model` (an engine model id) as the owner's fallback for the
    /// offer whose key is `offer` (hex64), for use while it is parked.
    pub fn set_model_fallback(&self, offer: &str, model: &str) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        FALLBACKS.put(self, &mut txn, &offer.to_owned(), &model.to_owned())?;
        txn.commit()?;
        Ok(())
    }
}
