//! Body files with keys in them (FIX 5507). An ASSET put whose body lives in
//! its file reaches the batch door as its manifest, so the mask, which reads
//! a put's bytes, never reads the file. A file the stream finder marked in
//! the put's transaction, or an earlier put of the same bytes, is banded as
//! a marked row is: its mark is found by the admitted file's digest, never
//! the manifest's, and the record is raised to the mark's band once it is
//! stamped. The file's bytes stay as they are; a serving door masks them by
//! that mark (`secret_custody::sighted_file`).

use std::collections::HashMap;

use heed::RoTxn;

use super::MaskedFiles;
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_ASSET;
use crate::secret_custody::masked_file_in_txn;
use crate::store::{AssetBodyFacts, Store};

impl MaskedFiles {
    /// These files, and each ASSET put in `ops` whose body is the file
    /// `files` admits for it, with a mark on that file's digest.
    pub(in crate::batch) fn with_marked_body_files(
        mut self,
        store: &Store,
        txn: &RoTxn<'_>,
        ops: &[BatchOp],
        files: &HashMap<EntityId, AssetBodyFacts>,
    ) -> Result<Self> {
        for op in ops {
            if let BatchOp::Put {
                id, entity_type, ..
            } = op
                && *entity_type == ENTITY_TYPE_ASSET
                && !self.0.contains(id)
                && let Some(facts) = files.get(id)
                && masked_file_in_txn(store, txn, &facts.blake3)?.is_some()
            {
                self.0.push(*id);
            }
        }
        Ok(self)
    }
}
