//! What a scoped door hands out for a row it admitted (FIX 3677, FIX 5397):
//! a file-plane ASSET leaves as its body, never the manifest its row keeps,
//! and a world key's pad row as its carrier, never the reference it rests as
//! (KS-5).
use heed::RoTxn;

use crate::{EntityId, Vault, error::Result};

impl Vault {
    /// `raw`, the stored row `id` that a scoped door (the scoped read, the
    /// scoped export, the memory timeline) admitted in `txn`, as that door
    /// hands it out: a file-plane ASSET carries its body in place of its
    /// manifest; any other row comes back as it is. Admission judges the
    /// stored row; this only materializes what already leaves, in the same
    /// transaction, and never withholds a row.
    ///
    /// # Errors
    ///
    /// [`Vault::materialized_row_in_txn`]'s errors: a missing or
    /// mismatched body file, and storage errors.
    pub(crate) fn scoped_row_bytes_in_txn(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
        raw: Vec<u8>,
    ) -> Result<Vec<u8>> {
        if let Some(carrier) = crate::world_keys::image_pad_row(&self.store, &raw) {
            return Ok(carrier);
        }
        self.materialized_row_in_txn(txn, id, raw)
    }
}
