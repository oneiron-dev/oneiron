//! Bringing an off-record result body into the vault's `bodies/`.

use super::{RAW_OUTPUT_SECRETS, ResultBodyPin, raw_output_handle};
use crate::code_run::ResultOccurrence;
use crate::memory::MessageResultAttachment;
use crate::side_table::SideTableDbs;
use crate::{EntityId, Error, Result, Vault};

impl Vault {
    /// Copies the result body `digest`, of `len` bytes, from the body
    /// directory of the off-record session `session_ref` into the vault's
    /// `bodies/`, checked against its digest and synced, and keeps the room's
    /// secret mark (`secret`: the occurrence the base row will name, and the
    /// scan's reason) on that occurrence in the base vault: all before any
    /// base row names it. A body `bodies/` holds already stays as
    /// it is. The returned pin keeps the collector off the body until the
    /// caller's row naming it has committed.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] when neither directory holds the body or the
    /// copy does not match its digest; storage errors as they occur.
    pub(crate) fn promote_off_record_result_body(
        &self,
        session_ref: &str,
        digest: &[u8; 32],
        len: u64,
        secret: Option<(ResultOccurrence, &str)>,
    ) -> Result<ResultBodyPin> {
        let pin = self.pin_result_body(*digest);
        let target = self.store.body_dir()?;
        let source = match self.store.session_body_dir(session_ref, false)? {
            Some(dir) => dir.open_body(digest, len)?,
            None => None,
        };
        match source {
            Some(mut file) => target.import(digest, len, &mut file)?,
            None if target.open_body(digest, len)?.is_some() => {}
            None => return Err(Error::CorruptedIndex("off-record result body missing")),
        }
        if let Some((occurrence, reason)) = secret {
            let key = occurrence.mark_key(&raw_output_handle(digest));
            self.with_write_txn_grouped(|txn| {
                RAW_OUTPUT_SECRETS.put(&self.store, txn, &key, &reason.to_owned())
            })?;
        }
        Ok(pin)
    }

    /// The body a result MESSAGE holds, before a save keeps the MESSAGE out
    /// of the off-record session `session_ref` as `message` (FIX 365): a
    /// body the room spilled to a file comes into `bodies/` through
    /// [`Self::promote_off_record_result_body`], with the room's secret mark
    /// on the producer's occurrence (read through `room`, the room's
    /// composed view) kept on the MESSAGE's. An inline body travels in its
    /// row, which the save copies in its own transaction. Either way the pin
    /// keeps the collector off the body until that transaction commits.
    ///
    /// # Errors
    ///
    /// As [`Self::promote_off_record_result_body`].
    pub(crate) fn promote_off_record_message_result_body(
        &self,
        session_ref: &str,
        room: &impl SideTableDbs,
        message: EntityId,
        attachment: &MessageResultAttachment,
    ) -> Result<ResultBodyPin> {
        let output = attachment.output()?;
        let spilled = match self.store.session_body_dir(session_ref, false)? {
            Some(dir) => dir.open_body(&output.raw_blake3, output.raw_len)?.is_some(),
            None => false,
        };
        if !spilled {
            return Ok(self.pin_result_body(output.raw_blake3));
        }
        let producer = ResultOccurrence::of(Some(attachment.source.run_id), &output)?;
        let secret = {
            let rtxn = self.store.env.read_txn()?;
            RAW_OUTPUT_SECRETS.get(room, &rtxn, &producer.mark_key(&output.handle))?
        };
        let held = ResultOccurrence::of(Some(message), &output)?;
        self.promote_off_record_result_body(
            session_ref,
            &output.raw_blake3,
            output.raw_len,
            secret.as_deref().map(|reason| (held, reason)),
        )
    }
}
