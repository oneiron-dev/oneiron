//! A session-bound run's reply bodies, admitted as the vault's are (FIX
//! 6647, FIX 5718 part 3). A reply spools raw into the body directory of the
//! run's route; nothing is swept as it streams. The side-row wall then admits
//! it whole in the routed writer that publishes it, which checks the
//! participant, the route and, on record, the saver. Its row, its key row,
//! the mark of a hit its scan still finds and an on-record stretch's
//! descriptor commit in that writer together, and its manifest, digest and
//! preview are the admitted bytes'.
//!
//! The base vault decides the admission on either route. On record the body
//! lands in base, and base custody mints a fresh key's record, as on the
//! vault. Off record the room holds no custody door: a value base custody
//! already holds still takes its handle there, but a reply that holds a
//! fresh key is withheld until room-local custody exists. Its typed
//! unavailable content stands in for it, and nothing of it is stored.

use super::*;
use crate::code_run::storage::records::{ReplyAdmission, ReplySpool, finish_output};

/// What one routed writer made of a reply body.
enum RoutedReply {
    /// Published from its admitted bytes. Its pin holds the body's file
    /// until the writer has committed.
    Published(FinishedOutput),
    /// Withheld: nothing of it is stored.
    Withheld(ReplyBody),
    /// Its admitted copy spills where the writer holds no instance for it.
    Spills,
}

impl SessionBinding<'_> {
    /// A raw spool for one reply body, into the body directory of the run's
    /// route, kept in memory up to the inline bound: see the module notes.
    pub(super) fn reply_spool(&self) -> Result<BodySink> {
        let dir = self.answered(|| self.session.body_dir(self.route.target()))?;
        Ok(BodySink::spooling(dir, self.reply_inline_bound()))
    }

    /// Publishes the reply body `sink` spooled as run `owner`'s complete
    /// output at `path`, admitted in the routed writer that publishes it
    /// (see the module notes). An on-record body that the admission makes
    /// spill where its spool did not takes a new routed writer, with a vault
    /// instance reserved before it opens: a writer never mints one.
    ///
    /// # Errors
    ///
    /// A run no longer in its room, a stale route or a lapsed saver, and
    /// storage, custody and filesystem errors. A secret the wall cannot
    /// place on the route is no error: it is [`ReplyBody::Unplaceable`].
    pub(super) fn publish_admitted_reply(
        &self,
        path: String,
        sink: BodySink,
        owner: EntityId,
    ) -> Result<ReplyBody> {
        let reply = ReplySpool::of(sink, owner, &path, self.reply_inline_bound())?;
        let target = self.route.target();
        let mut reserved = reply.reserves();
        loop {
            // As in `script_sink`: an on-record body spills into a vault
            // instance minted before any writer opens (KS-2A); an off-record
            // room's spills into its own directory with none.
            let mint = match target {
                RouteTarget::Base => Some(
                    self.answered(|| {
                        self.session
                            .read_composed(|view, rtxn| crate::store::body_mint_in(view, rtxn))
                    })?
                    .reserve(reserved)?,
                ),
                RouteTarget::Overlay | RouteTarget::Discard => None,
            };
            let may_spill = mint.is_none() || reserved > 0;
            let dir = self.answered(|| self.session.body_dir(target))?;
            let key_dir = self.answered(|| self.session.body_dir(target))?;
            let routed = self.answered(|| {
                self.session
                    .routed_admission_txn(&self.route, |txn, read, write, custody| {
                        let admitted = match reply.admit_in_txn(custody, txn, may_spill)? {
                            ReplyAdmission::Admitted(admitted) => admitted,
                            ReplyAdmission::Unplaceable(body) => {
                                return Ok(RoutedReply::Withheld(body));
                            }
                            ReplyAdmission::Spills => return Ok(RoutedReply::Spills),
                        };
                        let mut sink = BodySink::new(dir, reply.bound(), mint);
                        admitted.feed(&mut sink)?;
                        let watch = self.session.limit_watch();
                        let finished = finish_output(path.clone(), sink, true, watch, |digest| {
                            self.session.pin_result_body(digest)
                        })?;
                        mark_secret_in_txn(txn, write, &finished, owner)?;
                        let output = &finished.output;
                        let rows = (read, write);
                        put_output_row_in_txn(txn, rows, Some(&key_dir), &finished, output, owner)?;
                        Ok(RoutedReply::Published(finished))
                    })
            })?;
            match routed {
                RoutedReply::Published(finished) => {
                    return Ok(ReplyBody::Published(finished.output));
                }
                RoutedReply::Withheld(body) => return Ok(body),
                RoutedReply::Spills => reserved = 1,
            }
        }
    }

    /// The inline bound of the run's result bodies: one past it spills.
    fn reply_inline_bound(&self) -> u64 {
        self.session
            .limit_watch()
            .bound(EngineLimit::CodeResultInlineBytes)
    }
}

/// The mark of run `owner`'s occurrence of the body `finished` holds, when
/// the scan of its admitted bytes still hits, written in `txn` along
/// `write` beside its row: as [`SessionBinding::mark_secret`] marks one, in
/// the same transaction. An off-record room files no lift proposal.
fn mark_secret_in_txn(
    txn: &mut heed::RwTxn<'_>,
    write: RoutedDbs<'_>,
    finished: &FinishedOutput,
    owner: EntityId,
) -> Result<()> {
    let Some(reason) = finished.secret else {
        return Ok(());
    };
    let output = &finished.output;
    let key = ResultOccurrence::of(Some(owner), output)?.mark_key(&output.handle);
    RAW_OUTPUT_SECRETS.put(&write, txn, &key, &reason.to_owned())
}
