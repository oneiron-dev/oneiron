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
//!
//! A session-bound run's reply takes this same admission ([`ReplySpool`])
//! in its routed writer (FIX 6647, FIX 5718 part 3). An off-record room
//! holds no custody of its own yet, so a reply there with a fresh key is
//! withheld until room-local custody exists.

use std::sync::Arc;

use super::*;
use crate::batch::secret_scan::{AdmissionCustody, BodySpool, SpoolAdmission, admit_spool_in_txn};
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

/// One reply body spooled raw for admission, as the vault's writer and a
/// session's routed writer admit it alike (FIX 5718 part 3, FIX 6647): the
/// occurrence its custody records name, and the inline bound of the
/// directory it is published into.
pub(crate) struct ReplySpool {
    spool: BodySpool,
    occurrence: EntityId,
    bound: u64,
}

/// What admitting a reply body in one writer came to.
pub(crate) enum ReplyAdmission<'s> {
    /// The admitted body, to publish in that writer, which holds the
    /// custody records minted for it.
    Admitted(SpoolAdmission<'s>),
    /// A secret no door on the writer's route can place (ruling 4, FIX
    /// 6647): nothing was minted, and nothing of the answer is stored.
    Unplaceable(ReplyBody),
    /// The admitted copy spills past the inline bound where its writer holds
    /// no instance for it: nothing of the admission stays, and the writer is
    /// taken again with one reserved first (a writer never mints one).
    Spills,
}

impl ReplySpool {
    /// The reply body `sink` spooled, as run `owner`'s output at `path`,
    /// for a directory whose inline bound is `bound`.
    ///
    /// # Errors
    ///
    /// A swept sink, which is no spool, and its filesystem and sealing
    /// errors.
    pub(crate) fn of(sink: BodySink, owner: EntityId, path: &str, bound: u64) -> Result<Self> {
        Ok(Self {
            spool: sink.into_spool()?,
            occurrence: ResultOccurrence::owned(owner, path)?.id(),
            bound,
        })
    }

    /// The instances a vault writer that publishes it reserves before it
    /// opens: one for a spool past the inline bound.
    pub(crate) fn reserves(&self) -> usize {
        usize::from(self.spool.len() > self.bound)
    }

    /// The inline bound its admitted body spills past.
    pub(crate) const fn bound(&self) -> u64 {
        self.bound
    }

    /// Admits the body in `wtxn`, the writer that publishes it, through
    /// `custody`, with the known values that writer reads from the base
    /// index (KS-3). With `may_spill` false the writer holds no instance for
    /// a spilled body, and an admitted copy past the inline bound is
    /// [`ReplyAdmission::Spills`]. The custody records the admission minted
    /// stay in `wtxn` only for an admitted body.
    ///
    /// # Errors
    ///
    /// Storage, custody and the spool's read errors.
    pub(crate) fn admit_in_txn(
        &self,
        custody: AdmissionCustody<'_>,
        wtxn: &mut heed::RwTxn<'_>,
        may_spill: bool,
    ) -> Result<ReplyAdmission<'_>> {
        let known = custody.known_in_writer(wtxn)?;
        let at = (REPLY_PLACE, self.occurrence.as_bytes().as_slice());
        custody.in_savepoint(wtxn, |savepoint| {
            let admitted =
                admit_spool_in_txn(custody, savepoint, at, &self.spool, (known.as_ref(), true))?;
            Ok(match admitted {
                SpoolAdmission::Unplaceable(reason) => {
                    let body = ReplyBody::Unplaceable {
                        bytes: self.spool.len(),
                        text: self.spool.text(),
                        reason,
                    };
                    (ReplyAdmission::Unplaceable(body), false)
                }
                admitted if !may_spill && admitted.len().is_some_and(|len| len > self.bound) => {
                    (ReplyAdmission::Spills, false)
                }
                admitted => (ReplyAdmission::Admitted(admitted), true),
            })
        })
    }
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
        let reply = ReplySpool::of(spool, owner, &path, self.code_result_inline_bytes())?;
        let mut reserved = reply.reserves();
        loop {
            let mint = self.store.body_mint()?.reserve(reserved)?;
            let mut wtxn = self.store.env.write_txn()?;
            let custody = AdmissionCustody::vault(self);
            let admitted = match reply.admit_in_txn(custody, &mut wtxn, reserved > 0)? {
                ReplyAdmission::Admitted(admitted) => admitted,
                ReplyAdmission::Unplaceable(body) => return Ok(body),
                ReplyAdmission::Spills => {
                    reserved = 1;
                    continue;
                }
            };
            let mut sink = BodySink::new(self.store.body_dir()?, reply.bound(), Some(mint));
            admitted.feed(&mut sink)?;
            let finished = finish_output(path, sink, complete, self.limit_watch(), |digest| {
                self.pin_result_body(digest)
            })?;
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
        let custody = AdmissionCustody::vault(self);
        let copy = match admit_spool_in_txn(custody, &mut savepoint, at, &spool, (known, true))? {
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
