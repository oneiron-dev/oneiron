//! FIX 7929: a guest's read stays inside its grant's current effective scope
//! at every row, in the serving snapshot. A key whose view was taken before
//! a pact narrowing keeps reading the rows still inside the narrowed scope;
//! only the rows the narrowing excluded stop. Owner, co-Owner, member,
//! own-device and in-Grant agent keys are no guest's and pass untouched, and
//! so does a guest view still inside its scope.

use super::*;
use crate::federation::record_scope::note_world;

impl ScopedRead<'_> {
    /// Whether the stored row `raw` of `id` stands inside the current
    /// effective scope of the guest grant this read's credential names.
    pub(super) fn guest_bound_admits_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> bool {
        // A NOTE carries every world it is in; the guest's current scope
        // holds it at one of them (FIX-LIST 9433).
        self.actor_key
            .guest_bound_admits_at(self.vault, txn, || match self.session_view {
                Some(view) => note_world::blob_scope_every_world(view, txn, *id, raw),
                None => note_world::blob_scope_every_world(&self.vault.store, txn, *id, raw),
            })
    }
}

impl ScopedReadActorKey {
    /// Whether a row at `position` stands inside the current effective scope
    /// of the guest grant this key's credential names, in `txn`: the one
    /// guest bound of a stored row and of a claim's access class (FIX 11915).
    /// `position` is read only once a narrowing reached past the view.
    pub(super) fn guest_bound_admits_at(
        &self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        position: impl FnOnce() -> Result<Option<crate::federation::Scope>>,
    ) -> bool {
        let Some(proof) = self.proof.as_ref() else {
            return true;
        };
        vault.guest_row_admitted_in_txn(txn, proof.claims(), position)
    }
}
