//! Whether this vault's authority fold holds a position another machine
//! read from its own fold (pass 33, EM-11 = B).
//!
//! The issuer signs its main-log heads into each job submit
//! (`Vault::authority_main_log_heads`, lower hex); the node launches the job
//! only once its own fold holds every one of them. An entry folds only once
//! every parent it names has folded (`entry_transition.rs`: a parent with no
//! state keeps the entry waiting), and `valid_entries` is exactly the folded
//! set, so a head this fold holds brings its whole history with it: a revoke
//! the issuer had folded when it signed is folded here too.

use crate::Vault;
use crate::error::Result;

impl Vault {
    /// Whether this vault's authority fold holds every one of `heads`, each
    /// an authority entry hash in lower hex. A head that is not a 32-byte
    /// lower-hex hash is never held, so a launch waiting on it waits until
    /// its own limit refuses it.
    ///
    /// # Errors
    ///
    /// The store's read error.
    pub fn authority_folds_main_log_heads(&self, heads: &[String]) -> Result<bool> {
        let Some(wanted) = heads
            .iter()
            .map(|head| oneiron_hex::decode::<32>(head))
            .collect::<Option<Vec<_>>>()
        else {
            return Ok(false);
        };
        let txn = self.store.env.read_txn()?;
        let view = self.authority_view_readonly_in_txn(&txn)?;
        Ok(wanted.iter().all(|hash| view.valid_entries.contains(hash)))
    }
}
