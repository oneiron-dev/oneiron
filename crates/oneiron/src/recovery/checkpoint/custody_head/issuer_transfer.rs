//! Explicit protected issuer-seed transfer to a synced install's current
//! custody. No restore, source namespace takeover or new seed is involved.

use serde::Serialize;

use super::{CUSTODY_HEAD_WRAP_CONTEXT, CustodyRecovery};
use crate::consent::AuthenticatedOwner;
use crate::store::custody_protocol::Lineage;
use crate::{Result, Vault};

/// What an explicit head transfer kept in current local custody. These
/// counts do not assert that a keystore exists or that this install can sign.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IssuerSeedTransferReport {
    pub candidates: usize,
    pub published_generations: usize,
    pub already_held: usize,
    /// The archive or the destination's current root did not select them.
    pub not_selected: usize,
    /// Rollback is not proven when the source had no configured anchor.
    pub custody_note: Option<String>,
}

impl Vault {
    /// Admits one published protected head and transfers only live issuer
    /// seeds whose keys are this vault's current live root. The source
    /// lineage is explicit: a replica's local custody namespace need not
    /// equal its source's. Its head seal and anchor/log checks still apply.
    ///
    /// The current owner is checked before the head is read and again in
    /// each escrow writer, beside the current-root check. No other custody
    /// entry, source binding, writer epoch or authority row is installed.
    /// The existing create-only keystore recovery pass runs afterward;
    /// a missing keystore or seed remains its ordinary logged condition.
    ///
    /// # Errors
    /// A stale owner proof, failed protected-head admission or storage fault.
    /// Earlier committed generations remain if a later operation fails.
    pub fn transfer_published_issuer_seed_as(
        &self,
        owner: &AuthenticatedOwner,
        lineage: Lineage,
        recovery: &CustodyRecovery<'_>,
    ) -> Result<IssuerSeedTransferReport> {
        {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_in_txn(self, &txn)?;
        }
        // A kit can open the head without this install holding its data key,
        // just as in ordinary custody publication/recovery.
        let data_key = self
            .unlock_vault_key()
            .and_then(|()| self.vault_subkey(CUSTODY_HEAD_WRAP_CONTEXT))
            .ok();
        let admitted =
            crate::store::admit_published_host_issuer_seeds(lineage, &recovery.source(), data_key)?;
        let mut report = IssuerSeedTransferReport {
            candidates: admitted.seeds.len(),
            published_generations: 0,
            already_held: 0,
            not_selected: 0,
            custody_note: admitted.note.map(str::to_owned),
        };
        for seed in admitted.seeds.values() {
            match self.escrow_transferred_host_issuer_seed_as(owner, seed)? {
                Some(true) => report.published_generations += 1,
                Some(false) => report.already_held += 1,
                None => report.not_selected += 1,
            }
        }
        self.prepare_host_issuer_custody_logged();
        Ok(report)
    }
}
