//! A run's reply bodies masked at write (FIX 5718 part 3, Engine rulings 3
//! and 4). A verb's or a callable skill's answer too large for one reply
//! spools raw as it streams ([`Vault::code_run_reply_spool`]), then the
//! side-row wall's spool adapter admits it in the writer that publishes it:
//! its custody records, its row, the mark of a hit its scan still finds and
//! its descriptor commit together, and its manifest, digest and preview are
//! the admitted bytes'. A body past the inline bound still spills whole,
//! into an instance minted before that writer opened.
//!
//! A secret the wall cannot place stores nothing of the answer: the call
//! ran, and the guest gets typed unavailable content in its place (ruling
//! 4). A whole-vault import's result bodies take the same admission in the
//! import's own writer.

use std::sync::Arc;

use super::*;
use crate::batch::secret_scan::{BodySpool, SpoolAdmission, admit_spool_in_txn};
use crate::secret_custody::KnownValues;

/// Where the custody records the wall mints from a run's reply body name
/// what they lifted, beside the occurrence's id (CALLS C5718-19).
const REPLY_PLACE: &str = "side:CODE_RUN_RAW_OUTPUT:reply";

/// What publishing one reply body came to.
pub(crate) enum ReplyBody {
    /// Published from its admitted bytes.
    Published(CodeRunRawOutput),
    /// A secret in it the wall cannot place (ruling 4): nothing of it is
    /// stored. Its length, whether it was text, and the door's reason.
    Unplaceable {
        bytes: u64,
        text: bool,
        reason: &'static str,
    },
}

impl Vault {
    /// A spool for one reply body of a run, into this vault's `bodies/`:
    /// kept in memory up to the inline bound, past it in a temp file that is
    /// never published. Nothing is swept as it streams; the body is admitted
    /// whole when it is published
    /// ([`Self::publish_admitted_code_run_output`]).
    pub(crate) fn code_run_reply_spool(&self) -> Result<BodySink> {
        Ok(BodySink::spooling(
            self.store.body_dir()?,
            self.code_result_inline_bytes(),
        ))
    }

    /// Publishes the reply body `spool` took as run `owner`'s output at
    /// `path`, admitted in the writer that publishes it (see the module
    /// notes). An admitted body that spills where its spool did not takes
    /// the writer again with an instance minted first: a writer never mints
    /// one.
    ///
    /// # Errors
    ///
    /// Storage, custody and filesystem errors. A secret the wall cannot
    /// place is no error: it is [`ReplyBody::Unplaceable`].
    pub(crate) fn publish_admitted_code_run_output(
        &self,
        path: String,
        spool: BodySink,
        complete: bool,
        owner: EntityId,
    ) -> Result<ReplyBody> {
        let spool = spool.into_spool()?;
        let occurrence = ResultOccurrence::owned(owner, &path)?.id();
        let at = (REPLY_PLACE, occurrence.as_bytes().as_slice());
        let bound = self.code_result_inline_bytes();
        let mut reserved = usize::from(spool.len() > bound);
        loop {
            let mint = self.store.body_mint()?.reserve(reserved)?;
            let mut wtxn = self.store.env.write_txn()?;
            let known = KnownValues::load_in_writer(&self.store, &wtxn)?.map(Arc::new);
            let admitted = admit_spool_in_txn(self, &mut wtxn, at, &spool, (known.as_ref(), true))?;
            if let SpoolAdmission::Unplaceable(reason) = admitted {
                return Ok(ReplyBody::Unplaceable {
                    bytes: spool.len(),
                    text: spool.text(),
                    reason,
                });
            }
            if admitted.len().is_some_and(|len| len > bound) && reserved == 0 {
                reserved = 1;
                continue;
            }
            let mut sink = BodySink::new(self.store.body_dir()?, bound, Some(mint));
            admitted.feed(&mut sink)?;
            let finished = finish_output(path, sink, complete, self.limit_watch())?;
            self.put_code_run_output_in_txn(&mut wtxn, &finished, &finished.output, Some(owner))?;
            wtxn.commit()?;
            return Ok(ReplyBody::Published(finished.output));
        }
    }

    /// The bytes a whole-vault import stages for run `owner`'s result at
    /// `path`, `bytes` as the archive holds them, admitted in the import's
    /// writer `wtxn` with `known`, the values custody holds as it read them
    /// (FIX 5718 part 3): the copy the wall masks, its custody minted there,
    /// or the bytes as they came when the door places nothing in them. A
    /// body the wall cannot place, and a copy that would spill where the
    /// import minted it no instance (`may_spill` false), are staged as they
    /// came, as before, and nothing is minted for them: an import refuses
    /// nothing for a secret (CALLS C5718-22).
    ///
    /// # Errors
    ///
    /// Storage and custody errors.
    pub(crate) fn admit_imported_result_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        path: &str,
        bytes: Vec<u8>,
        known: Option<&Arc<KnownValues>>,
        may_spill: bool,
    ) -> Result<Vec<u8>> {
        let spool = BodySpool::of_bytes(bytes);
        let occurrence = ResultOccurrence::owned(owner, path)?.id();
        let at = (REPLY_PLACE, occurrence.as_bytes().as_slice());
        let bound = self.code_result_inline_bytes();
        let mut savepoint = self.store.env.nested_write_txn(wtxn)?;
        let copy = match admit_spool_in_txn(self, &mut savepoint, at, &spool, (known, true))? {
            SpoolAdmission::Copy(copy) if may_spill || copy.len() as u64 <= bound => Some(copy),
            _ => None,
        };
        match copy {
            Some(copy) => {
                savepoint.commit()?;
                Ok(copy)
            }
            None => {
                drop(savepoint);
                spool.into_bytes()
            }
        }
    }
}
