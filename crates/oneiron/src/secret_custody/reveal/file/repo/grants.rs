//! Whether the owner's live grant covers a repo file read now (FIX 7608
//! pre-flip, FIX 9328 and 10271): the same target, the same keys' classes
//! and the same evaluator [`Vault::repo_file_sight`] judges a read with, in
//! the caller's transaction and with nothing written.
//!
//! It asks nothing, spends nothing and delivers nothing: a Git exchange
//! plans which marked files it may release from it, and a held proposal's
//! clearance asks it of each held file. Only a standing grant answers it;
//! an approve-once answer is a single read's, never a plan's or a hold's.
//! Every class the file's keys hold must be covered, and its opaque residue
//! by the sealed class, exactly as the read groups them.

use heed::RoTxn;

use super::super::{SEALED_FILE_CLASS, admitted_keys_in_txn, class_groups};
use super::{RepoFileKeys, RepoFileRevealTarget};
use crate::consent::load_active_standing_grants;
use crate::error::Result;
use crate::secret_custody::reveal::RevealAsker;
use crate::vault::Vault;

impl Vault {
    /// Whether a standing grant covers `asker`'s read of the marked repo
    /// file `target` names, whose keys are `keys`, for every group the
    /// read would ask in, in `txn`. A key that no longer admits, or a file
    /// with no key and no residue, is not covered.
    ///
    /// # Errors
    /// A store failure, or a selector the consent bound refuses.
    pub(crate) fn repo_file_reveal_granted_in_txn(
        &self,
        txn: &RoTxn<'_>,
        asker: &RevealAsker,
        target: &RepoFileRevealTarget,
        keys: &RepoFileKeys,
    ) -> Result<bool> {
        let mut classes = Vec::new();
        if !keys.custody.is_empty() {
            let custody = keys.custody.iter().copied();
            let Some(admitted) = admitted_keys_in_txn(self, txn, custody)? else {
                return Ok(false);
            };
            classes.extend(class_groups(admitted)?.into_iter().map(|group| group.class));
        }
        if keys.opaque {
            classes.push(SEALED_FILE_CLASS);
        }
        if classes.is_empty() {
            return Ok(false);
        }
        let grants = load_active_standing_grants(&self.store, txn)?;
        let connection = asker.connection();
        for class in classes {
            let covering = target.covering_grant(
                &connection,
                class,
                asker.project,
                asker.run.as_deref(),
                &grants,
            )?;
            if covering.is_none() {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
