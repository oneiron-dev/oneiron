//! The settle of kept export secret copies (FIX 12064): a sealed copy kept
//! under its request's entry, on its holder or on an install a window
//! relayed it to, is forgotten once its secret ended here: an admitted
//! revoke names it, or an erase here fenced it. Its window rows leave on
//! the same signals (`relay`'s `row_done`); this settles what each install
//! keeps. The owner work drain runs it beside the custody input settle.

use super::OUTPUTS;
use crate::Vault;
use crate::authority::{AuthorityEntryHash, AuthorityFold, OwnerWorkBody};
use crate::entity_id::EntityId;
use crate::error::Result;

/// The secret the export secret request signed as entry `request` is for,
/// as `fold` holds it: `None` when it folds no export secret request there.
fn requested_secret(fold: &AuthorityFold, request: &AuthorityEntryHash) -> Option<EntityId> {
    match &fold.owner_work_request(request)?.work {
        OwnerWorkBody::ExportSecret(work) => Some(work.secret),
        _ => None,
    }
}

impl Vault {
    /// Forgets every kept export secret copy whose secret an admitted revoke
    /// ended or an erase here fenced. A copy whose request this install does
    /// not fold stays. Returns how many copies it forgot.
    pub(crate) fn settle_export_outputs(&self) -> Result<usize> {
        let ended: Vec<AuthorityEntryHash> = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            OUTPUTS
                .scan_keys(&self.store, &txn, &[])?
                .into_iter()
                .filter(|request| {
                    requested_secret(&fold, request).is_some_and(|secret| {
                        fold.custody_revoked(&secret)
                            || self.store.credential_fenced_in_txn(&txn, &secret)
                    })
                })
                .collect()
        };
        if ended.is_empty() {
            return Ok(0);
        }
        // A revoke stays admitted and a fence stays put, and neither copy
        // keeper takes a copy of an ended secret, so none returns between
        // the read and this writer.
        self.with_write_txn(|txn| {
            let mut forgot = 0;
            for request in &ended {
                if OUTPUTS.delete(&self.store, txn, request)? {
                    forgot += 1;
                }
            }
            Ok(forgot)
        })
    }
}
