//! Bringing an off-record result body into the vault's `bodies/`.

use super::ResultBodyPin;
use crate::memory::MessageResultAttachment;
use crate::side_table::SideTableDbs;
use crate::store::{BodyKeyRow, body_key_row_in_txn};
use crate::{Error, Result, Vault};

impl Vault {
    /// Copies the result body `digest`, of `len` bytes, from the body
    /// directory of the off-record session `session_ref` into the vault's
    /// `bodies/`, checked against its digest and synced, before any base row
    /// names it; its marks come with that row, in the save's checked
    /// transaction (FIX 3633). A body `bodies/` holds already stays as it is.
    /// Any other comes in as a new vault instance, minted here, before the save's
    /// transaction opens: sealed again under its key on a sealed vault (the
    /// session's key, `key` its row in the room, is never copied or wrapped
    /// again), plain on a plain one. The save's transaction commits its row
    /// (KS-2A). The returned pin keeps the collector off the body, and the
    /// instance where the save's transaction reads it, until the caller's
    /// row naming it has committed.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] when neither directory holds the body or the
    /// copy does not match its digest; storage and custody errors as they
    /// occur.
    pub(crate) fn promote_off_record_result_body(
        &self,
        session_ref: &str,
        digest: &[u8; 32],
        len: u64,
        key: Option<&BodyKeyRow>,
    ) -> Result<ResultBodyPin> {
        let held = self.pin_result_body(*digest);
        let target = self.store.body_dir()?;
        let source = match self.store.session_body_dir(session_ref, false)? {
            Some(dir) => dir.open_reader(digest, len, key)?,
            None => None,
        };
        let vault_row = {
            let rtxn = self.store.env.read_txn()?;
            body_key_row_in_txn(&self.store, &rtxn, digest)?
        };
        match source {
            _ if target.holds_pair(digest, vault_row.as_ref())? => Ok(held),
            Some(file) => {
                let instance = self.store.body_mint()?.mint()?;
                let promoted = *instance.instance();
                target.import_promoted(digest, len, file, instance)?;
                Ok(self.pin_promoted_result_body(*digest, promoted))
            }
            None => Err(Error::CorruptedIndex("off-record result body missing")),
        }
    }

    /// The body a result MESSAGE holds, before a save keeps the MESSAGE out
    /// of the off-record session `session_ref` (FIX 365): a
    /// body the room spilled to a file (its key row read through `room`, the
    /// room's composed view) comes into `bodies/` through
    /// [`Self::promote_off_record_result_body`]. An inline body travels in its
    /// row, which the save copies in its own transaction. Either way the pin
    /// keeps the collector off the body until that transaction commits, and
    /// the room's marks on the producer's occurrence come onto the MESSAGE's
    /// only there (FIX 3633).
    ///
    /// # Errors
    ///
    /// As [`Self::promote_off_record_result_body`].
    pub(crate) fn promote_off_record_message_result_body(
        &self,
        session_ref: &str,
        room: &impl SideTableDbs,
        attachment: &MessageResultAttachment,
    ) -> Result<ResultBodyPin> {
        let output = attachment.output()?;
        let key = {
            let rtxn = self.store.env.read_txn()?;
            body_key_row_in_txn(room, &rtxn, &output.raw_blake3)?
        };
        let spilled = match self.store.session_body_dir(session_ref, false)? {
            Some(dir) => dir
                .open_reader(&output.raw_blake3, output.raw_len, key.as_ref())?
                .is_some(),
            None => false,
        };
        if !spilled {
            return Ok(self.pin_result_body(output.raw_blake3));
        }
        self.promote_off_record_result_body(
            session_ref,
            &output.raw_blake3,
            output.raw_len,
            key.as_ref(),
        )
    }
}
