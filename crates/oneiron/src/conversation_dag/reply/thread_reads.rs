//! What a scoped read reaches of a DAG thread (FIX 5545): a record of a
//! private thread its caller stands in now is a place in that thread even
//! when the caller reads none of it, having been added after it. The place
//! carries no word of the record.

use super::*;
use crate::claim::ScopedRead;

impl Vault {
    /// Whether `read` reaches the thread record `record`: it reads it, or
    /// `record` is a turn of a private thread `read`'s caller stands in now
    /// (the CURRENT rule) that sits before some member's add, hung off a
    /// trunk record `read` reads. Such a record selects its thread and is
    /// never served: its words stay the CONTENT rule's.
    pub fn thread_record_reached(&self, read: &ScopedRead<'_>, record: EntityId) -> Result<bool> {
        if read.is_entity_readable(&record)? {
            return Ok(true);
        }
        let anchor = {
            let txn = self.store.env.read_txn()?;
            if !crate::workspace_roster::turn_held_back_for_in(read, &txn, record)? {
                return Ok(false);
            }
            match live_entity_row_in_txn(&read.store_read(), &txn, &record)? {
                LiveEntityRow::Live {
                    entity_type: ENTITY_TYPE_TURN,
                    body,
                } => crate::workspace_roster::thread_binding(&body)?
                    .and_then(|binding| binding.anchor),
                _ => None,
            }
        };
        match anchor {
            Some(anchor) => read.is_entity_readable(&anchor),
            None => Ok(false),
        }
    }
}
