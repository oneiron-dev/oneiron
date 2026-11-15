//! The owner's erase of one subject's authority attribution (census L5-22
//! PR 1b; DEC-0005 #vault:8; RULING L5-22-ERASE-WHO = A, an owner act).
//!
//! "Erasure destroys the relevant overlay keys and plaintext caches without
//! rewriting the signed scaffold", and "Statutory erasure must not wait for
//! checkpoint quorum": the door retires the subject's overlay keys, deletes
//! the overlay rows that name it, marks those rows erased and leaves the
//! subject's erasure standing, in one writer of this vault, on the Owner's
//! own proof. It reads no checkpoint and asks no quorum, and no
//! AUTHORITY_LOG byte or row hash changes. A subject of which this vault
//! knows nothing is erased all the same: a key of it that arrives later is
//! refused, and the erasure travels to the vault's other machines
//! (`crate::sync::authority_overlay_custody`).

use crate::Vault;
use crate::check_in::{ActClass, AppliedCheckIn, owner_act_decision_in_txn};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::authority_overlay_custody::subject_erased_at_in_txn;

use oneiron_verb_wire::verbs::authority_attribution_erase::AuthorityAttributionErased;

impl Vault {
    /// The Owner erases `subject`'s authority attribution on this vault
    /// (census L5-22 PR 1b), on the check-in decision the act runs on: the
    /// Owner's own proof, and with `applied` an asker's approved check-in
    /// for this erase, spent in the same writer. One writer revalidates the
    /// proof, decides, and erases (`erase_authority_overlay_subject_in_txn`):
    /// from its commit on no row of `subject` opens here and nothing it made
    /// counts. Then custody's finisher destroys the keys. Erasing a subject
    /// again deletes what arrived since and keeps the first erase's time.
    ///
    /// # Errors
    /// A proof that no longer holds; an applied check-in that is not this
    /// act's, or is spent; an archived vault; custody and storage faults.
    pub(crate) fn erase_authority_attribution_as(
        &self,
        owner: &AuthenticatedOwner,
        subject: &EntityId,
        applied: Option<&AppliedCheckIn<'_>>,
    ) -> Result<AuthorityAttributionErased> {
        let erasure = self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let check_in = owner_act_decision_in_txn(self, txn, ActClass::Erase, applied)?;
            let rows_erased =
                super::erase_authority_overlay_subject_in_txn(&self.store, txn, subject, &[])?;
            let at = subject_erased_at_in_txn(&self.store, txn, subject)?.ok_or(
                Error::CorruptedIndex("an authority attribution erase left no erasure"),
            )?;
            Ok(AuthorityAttributionErased {
                rows_erased,
                at,
                check_in,
            })
        })?;
        self.finish_erasable_retirements_after_commit();
        Ok(erasure)
    }
}
