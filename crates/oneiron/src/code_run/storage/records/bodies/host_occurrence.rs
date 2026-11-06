//! A host parent run's record and whose it is (FIX 9019). A run a host
//! makes only to hold a scoped child's lent inputs and the outputs the host
//! stages beside them has no executor. Its first publication stamps the
//! host actor before the native replay erase fence, and each owned body
//! commits with its membership in the fresh parent record (FIX 9348).

use std::borrow::Cow;

use super::super::REPLAY_RECORDS;
use super::finish_output_sourced;
use crate::code_run::storage::response_erase::fence_replay_in_txn;
use crate::code_run::storage::response_owners::stamp_response_owner_in_txn;
use crate::code_run::{CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayRecord};
use crate::{EntityId, Error, Result, Vault};

impl Vault {
    /// Keeps an empty host's first record and actor stamp in one writer.
    /// A concurrent publication's record is already the host's record and
    /// is never replaced by an empty snapshot.
    pub(crate) fn ensure_host_run_record(&self, run: EntityId, actor: EntityId) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        if self
            .get_code_run_replay_record_in_txn(&wtxn, &run)?
            .is_some()
        {
            return Ok(());
        }
        let record = CodeRunReplayRecord::new(run, CodeRunDeterminism::new(0, [0; 32]));
        stamp_response_owner_in_txn(self, &mut wtxn, run, run, actor)?;
        let record = fence_replay_in_txn(self, &mut wtxn, Cow::Owned(record))?;
        REPLAY_RECORDS.put(self, &mut wtxn, &run, &record)?;
        Ok(wtxn.commit()?)
    }

    /// Publishes one host output and its replay membership in the same
    /// writer. A stored path answers its first output and source rows
    /// without scanning the caller's unused bytes. `actor` permits a host's
    /// first record and stamps it before the native erase fence; a staged
    /// output has no actor to stamp and requires an existing record.
    pub(crate) fn publish_host_run_output(
        &self,
        run: EntityId,
        actor: Option<EntityId>,
        path: String,
        body: &[u8],
        input_rows: Option<Vec<EntityId>>,
    ) -> Result<CodeRunRawOutput> {
        let stored = self.get_code_run_replay_record(&run)?;
        if let Some(output) = stored
            .as_ref()
            .and_then(|record| record.outputs.iter().find(|output| output.path == path))
        {
            return Ok(output.clone());
        }
        if stored.is_none() && actor.is_none() {
            return Err(staged_record_missing());
        }
        // Finishing can spill and take custody reads, so it precedes the
        // writer. Its pin holds the finished file through commit or abort.
        let mut sink = self.code_run_output_sink()?;
        sink.write(body)?;
        let finished = finish_output_sourced(
            path.clone(),
            sink,
            true,
            input_rows,
            self.limit_watch(),
            |digest| self.pin_result_body(digest),
        )?;
        let mut wtxn = self.store.env.write_txn()?;
        let mut record = match self.get_code_run_replay_record_in_txn(&wtxn, &run)? {
            Some(record) => record,
            None if actor.is_some() => {
                CodeRunReplayRecord::new(run, CodeRunDeterminism::new(0, [0; 32]))
            }
            None => return Err(staged_record_missing()),
        };
        if let Some(output) = record.outputs.iter().find(|output| output.path == path) {
            return Ok(output.clone());
        }
        self.put_code_run_output_in_txn(&mut wtxn, &finished, &finished.output, Some(run))?;
        record.outputs.push(finished.output.clone());
        if let Some(actor) = actor {
            stamp_response_owner_in_txn(self, &mut wtxn, run, run, actor)?;
        }
        let record = fence_replay_in_txn(self, &mut wtxn, Cow::Owned(record))?;
        REPLAY_RECORDS.put(self, &mut wtxn, &run, &record)?;
        let output = record
            .outputs
            .iter()
            .find(|output| output.path == path)
            .cloned()
            .ok_or(Error::InvariantViolation(
                "published host output missing from replay record",
            ))?;
        wtxn.commit()?;
        Ok(output)
    }
}

fn staged_record_missing() -> Error {
    Error::InvalidConfig("a staged output needs its run's record".to_owned())
}
