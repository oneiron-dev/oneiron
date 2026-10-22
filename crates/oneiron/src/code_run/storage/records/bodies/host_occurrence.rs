//! A host parent run's record and whose it is (FIX 9019). A run a host
//! makes only to hold a scoped child's lent inputs and the outputs the host
//! stages beside them (a thing's `thing/input`, `thing/draft` and
//! `thing/checkpoint`) has no executor, so no run start stamps whose
//! content it holds. Its record's put stamps that owner row, the host's
//! actor's run (the record's own), in the same writer: the actor scrub and
//! the hard erase of that actor find the record by that row
//! (`response_erase`), the record's checkpoint image names that actor among
//! its owners (`replay_bodies::replay_owners`), and every later write of it
//! meets the erase (`fence_replay_in_txn`). Its bodies stay the run's own
//! occurrences in the one routed result store; nothing here is a second
//! store.

use std::borrow::Cow;

use super::super::REPLAY_RECORDS;
use crate::code_run::CodeRunReplayRecord;
use crate::code_run::storage::response_erase::fence_replay_in_txn;
use crate::code_run::storage::response_owners::stamp_response_owner_in_txn;
use crate::{EntityId, Result, Vault};

impl Vault {
    /// Puts host parent run `record` with its owner row, `actor`'s run,
    /// stamped first in the same writer unless it has one (the first stamp
    /// stands, and an erased one stays erased), then fenced as every replay
    /// write is: a record whose owner is erased or gone is written in its
    /// erased form.
    ///
    /// # Errors
    ///
    /// Storage and custody errors.
    pub(crate) fn put_host_run_record(
        &self,
        record: &CodeRunReplayRecord,
        actor: EntityId,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        stamp_response_owner_in_txn(self, &mut wtxn, record.run_id, record.run_id, actor)?;
        let record = fence_replay_in_txn(self, &mut wtxn, Cow::Borrowed(record))?;
        REPLAY_RECORDS.put(self, &mut wtxn, &record.run_id, &record)?;
        Ok(wtxn.commit()?)
    }
}
