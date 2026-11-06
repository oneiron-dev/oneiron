//! Context outputs published with the replay record that holds them.

use super::{BodySink, CodeRunRawOutput, EntityId, Result, Vault, finish_output_sourced};
use crate::{Error, ErrorKind};

impl Vault {
    /// Publishes an output and links it to the fresh retained replay record in
    /// the same writer. A run without a retained record keeps standalone storage.
    pub(crate) fn publish_code_run_output_for_replay(
        &self,
        path: String,
        sink: BodySink,
        complete: bool,
        run: EntityId,
        input_rows: Option<Vec<EntityId>>,
    ) -> Result<CodeRunRawOutput> {
        let finished = finish_output_sourced(
            path,
            sink,
            complete,
            input_rows,
            self.limit_watch(),
            |digest| self.pin_result_body(digest),
        )?;
        let mut wtxn = self.store.env.write_txn()?;
        let record = self.get_code_run_replay_record_in_txn(&wtxn, &run)?;
        let owner = record.as_ref().map(|_| run);
        self.put_code_run_output_in_txn(&mut wtxn, &finished, &finished.output, owner)?;
        let published = if let Some(mut record) = record {
            if !record.outputs.contains(&finished.output) {
                record.outputs.push(finished.output.clone());
            }
            self.put_code_run_replay_record_in_txn(&mut wtxn, &record)?;
            // The native writer may have erased replies while linking them.
            match self.get_code_run_replay_record_in_txn(&wtxn, &run) {
                Ok(Some(record)) => record
                    .outputs
                    .into_iter()
                    .find(|output| output == &finished.output)
                    .ok_or_else(|| {
                        crate::store::result_body_erasure::response_erased_error(
                            "a context output's kept body",
                        )
                    }),
                Ok(None) => {
                    return Err(Error::InvariantViolation("linked replay record missing"));
                }
                Err(error) if error.kind() == ErrorKind::ResponseErased => Err(error),
                Err(error) => return Err(error),
            }
        } else {
            self.record_unowned_output_sources_in_txn(&mut wtxn, &finished.output)?;
            Ok(finished.output.clone())
        };
        wtxn.commit()?;
        published
    }
}
