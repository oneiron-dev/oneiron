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
        let Some(proof) = self.actor_key.proof.as_ref() else {
            return true;
        };
        // A NOTE carries every world it is in; the guest's current scope
        // holds it at one of them (FIX-LIST 9433).
        self.vault
            .guest_row_admitted_in_txn(txn, proof.claims(), || match self.session_view {
                Some(view) => note_world::blob_scope_every_world(view, txn, *id, raw),
                None => note_world::blob_scope_every_world(&self.vault.store, txn, *id, raw),
            })
    }
}
