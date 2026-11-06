//! Who wrote each MEMORIES row (BOARD-LAYOUT add-on 2): the actor a board
//! layout's `who` filter matches a memory row by.

use std::collections::BTreeMap;

use heed::RoTxn;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_NOTE};

impl Vault {
    /// The writer of each of `rows`, read in one transaction: the actor its
    /// stamped birth names; else, for a CLAIM, the actor its write envelope
    /// stamped into its evidence; else, for a NOTE, its engine-stamped
    /// author. A row with no recorded writer (an unstamped row, an erased
    /// author) is absent from the map, so no `who` filter keeps it. The
    /// writer is the row's maker, never its subject, assignee or last editor.
    ///
    /// # Errors
    ///
    /// Storage errors, or a stored birth that does not decode.
    pub fn memory_row_writers(&self, rows: &[EntityId]) -> Result<BTreeMap<EntityId, EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let mut writers = BTreeMap::new();
        for row in rows {
            if writers.contains_key(row) {
                continue;
            }
            if let Some(writer) = self.memory_row_writer_in_txn(&rtxn, row)? {
                writers.insert(*row, writer);
            }
        }
        Ok(writers)
    }

    fn memory_row_writer_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        row: &EntityId,
    ) -> Result<Option<EntityId>> {
        if let Some(birth) = crate::store::birth_record::row_birth_in_txn(&self.store, rtxn, row)? {
            return Ok(Some(birth.made_by.process.actor));
        }
        let Some(header) = self.entity_header_in_txn(rtxn, row)? else {
            return Ok(None);
        };
        match header.entity_type {
            ENTITY_TYPE_CLAIM => Ok(self
                .get_claim_in_txn(rtxn, row)?
                .as_ref()
                .and_then(crate::store::claim_projection::session_claim_producer)),
            ENTITY_TYPE_NOTE => Ok(self
                .get_in_txn(rtxn, row)?
                .and_then(|body| crate::store::note_body::decode_note_body(&body).ok())
                .and_then(|body| body.author_ref.id())),
            _ => Ok(None),
        }
    }
}
