//! A session-bound run's result bodies: the sinks they stream through, the
//! routed rows that publish one and the reads that open one (moved out of
//! the routing module whole).

use super::super::records::{
    ReplyBody, code_run_body_held_in_txn, owned_body, raw_put_publishes_descriptor,
};
use super::*;
use crate::code_run::result_read::unplaced_answer;
use crate::provenance::body::{owned_body_in_txn, publish_body_in_txn};
use crate::side_table::RoutedDbs;

impl ExecutorStorage<'_> {
    /// A spool for one reply body of the run (FIX 5718 part 3): on the
    /// vault, a raw spool the wall admits whole when it is published
    /// ([`Self::publish_code_run_reply`]); in a session, its own sink, as
    /// before.
    pub(crate) fn code_run_reply_spool(&self) -> Result<BodySink> {
        match self {
            Self::Canonical(vault) => vault.code_run_reply_spool(),
            Self::Session(binding) => binding.output_sink(),
        }
    }

    /// Publishes the reply body `spool` took as run `owner`'s complete output
    /// at `path` (FIX 5718 part 3, Engine rulings 3 and 4). On the vault it
    /// is admitted in the writer that publishes it; `Err` holds the typed
    /// unavailable content that stands in for an answer with a secret the
    /// side-row wall cannot place, of which nothing is stored. A session's
    /// body is published as before.
    pub(crate) fn publish_code_run_reply(
        &self,
        path: String,
        spool: BodySink,
        owner: EntityId,
    ) -> Result<std::result::Result<CodeRunRawOutput, serde_json::Value>> {
        match self {
            Self::Canonical(vault) => {
                let published = vault.publish_admitted_code_run_output(path, spool, true, owner)?;
                Ok(match published {
                    ReplyBody::Published(output) => Ok(output),
                    ReplyBody::Unplaceable {
                        bytes,
                        text,
                        reason,
                    } => Err(unplaced_answer(bytes, text, reason)),
                })
            }
            Self::Session(binding) => binding.publish_output(path, spool, true, owner).map(Ok),
        }
    }
}

impl SessionBinding<'_> {
    /// A writer for one result body: into the session's own body directory
    /// while the room is off record, the vault's `bodies/` once on record.
    /// Each value custody knows is replaced by its handle as it streams
    /// (OF-560 C), as on the canonical vault.
    pub(super) fn output_sink(&self) -> Result<BodySink> {
        let known = self.answered(|| self.session.known_source())?;
        Ok(self.script_sink()?.sweeping(known))
    }

    /// [`Self::output_sink`] with no sweep, for a step's program, which a
    /// resumed step runs again as stored.
    pub(super) fn script_sink(&self) -> Result<BodySink> {
        let target = self.route.target();
        let dir = self.answered(|| self.session.body_dir(target))?;
        // A body bound for the vault's `bodies/` spills into a vault
        // instance minted here, before any writer opens (KS-2A); an
        // off-record room's keys stay in its overlay.
        let mint = match target {
            RouteTarget::Base => Some(self.answered(|| {
                self.session
                    .read_composed(|view, rtxn| crate::store::body_mint_in(view, rtxn))
            })?),
            RouteTarget::Overlay | RouteTarget::Discard => None,
        };
        Ok(BodySink::new(
            dir,
            self.session
                .limit_watch()
                .bound(EngineLimit::CodeResultInlineBytes),
            mint,
        ))
    }

    pub(super) fn publish_output(
        &self,
        path: String,
        sink: BodySink,
        complete: bool,
        owner: EntityId,
    ) -> Result<CodeRunRawOutput> {
        let finished = finish_output(path, sink, complete, self.session.limit_watch(), |digest| {
            self.session.pin_result_body(digest)
        })?;
        self.mark_secret(&finished.output, owner, finished.secret)?;
        self.put_output_row(&finished, &finished.output, owner)?;
        Ok(finished.output)
    }

    /// Marks the occurrence of a body the secret scan hit that run `owner`
    /// holds, on the session's route, before its row is written. An
    /// off-record room files no lift proposal: nothing of it reaches the
    /// base vault.
    pub(super) fn mark_secret(
        &self,
        output: &CodeRunRawOutput,
        owner: EntityId,
        secret: Option<&'static str>,
    ) -> Result<()> {
        let Some(reason) = secret else {
            return Ok(());
        };
        let key = ResultOccurrence::of(Some(owner), output)?.mark_key(&output.handle);
        self.answered(|| {
            self.session.side_table_put_routed(
                &self.route,
                &RAW_OUTPUT_SECRETS,
                &key,
                &reason.to_owned(),
            )
        })
    }

    pub(super) fn put_raw_output(
        &self,
        owner: EntityId,
        output: &CodeRunRawOutput,
        raw: &[u8],
    ) -> Result<()> {
        let mut sink = self.output_sink()?;
        sink.write(raw)?;
        let finished = finish_output(
            output.path.clone(),
            sink,
            true,
            self.session.limit_watch(),
            |digest| self.session.pin_result_body(digest),
        )?;
        if finished.output != *output {
            return Err(invalid_code_run_replay(
                "raw output metadata does not match bytes",
            ));
        }
        self.mark_secret(output, owner, finished.secret)?;
        self.put_output_row(&finished, output, owner)
    }

    /// The row of the body `finished` holds, as `output`, and the
    /// instance row of the file it wrote, both on the run's route in ONE
    /// transaction (FIX 5348, KS-2A; FIX 5475): no stop between them leaves
    /// a key row whose file no row names. A vault instance's row pins the
    /// custody binding in that transaction. A key row the route's scope
    /// holds for the digest already stays, its file serving the body, and
    /// the body's row is written all the same. On an on-record stretch the
    /// same transaction publishes the body in base as run `owner`'s
    /// occurrence, as a canonical raw put does: the row takes no hold of its
    /// own and a hold it kept before stays (FIX 7363). Off record, and where
    /// `raw_put_publishes_descriptor` keeps the put as it was, no descriptor
    /// holds the body, so its row holds it on its own (FIX 5399b).
    pub(super) fn put_output_row(
        &self,
        finished: &super::super::records::FinishedOutput,
        output: &CodeRunRawOutput,
        owner: EntityId,
    ) -> Result<()> {
        self.answered(|| {
            let dir = finished
                .key
                .as_ref()
                .map(|_| self.session.body_dir(self.route.target()))
                .transpose()?;
            self.session
                .routed_side_txn(&self.route, |txn, read, write| {
                    if let (Some(key), Some(dir)) = (finished.key.as_ref(), dir.as_ref()) {
                        let kept = match BODY_KEYS.get(&read, txn, key.digest())? {
                            Some(held) => key.keeps(&held, dir)?,
                            None => false,
                        };
                        if !kept {
                            if let crate::side_table::RoutedDbs::Base(vault) = &write {
                                crate::store::pin_body_custody_in_txn(&vault.store, txn)?;
                            }
                            BODY_KEYS.put(&write, txn, key.digest(), key.row())?;
                        }
                    }
                    // On an on-record stretch the run's descriptor is published
                    // in base beside the row, with no second body key, custody
                    // pin or secret mark (FIX 7363). An overlay row carries
                    // none: a room save takes no overlay descriptor to base.
                    let published = match write {
                        RoutedDbs::Base(vault) => {
                            let body = owned_body(owner, output, &finished.body)?;
                            let prior =
                                owned_body_in_txn(&vault.store, txn, &owner, &body.occurrence);
                            raw_put_publishes_descriptor(&prior, &body).then_some((vault, body))
                        }
                        RoutedDbs::Session(_) => None,
                    };
                    let held = published.is_none()
                        || code_run_body_held_in_txn(&write, txn, &output.raw_blake3)?;
                    RAW_OUTPUTS.put(&write, txn, &output.handle, &finished.body.holding(held))?;
                    match published {
                        Some((vault, body)) => publish_body_in_txn(&vault.store, txn, &body),
                        None => Ok(()),
                    }
                })
        })
    }

    pub(super) fn get_raw_output(&self, output: &CodeRunRawOutput) -> Result<Option<Vec<u8>>> {
        validate_raw_output(output)?;
        let _pin = self.session.pin_result_body(output.raw_blake3);
        let Some((body, key)) = self.answered(|| {
            self.session.read_composed(|view, rtxn| {
                let Some(body) = RAW_OUTPUTS.get(view, rtxn, &output.handle)? else {
                    return Ok(None);
                };
                Ok(Some((
                    body,
                    body_key_row_in_txn(view, rtxn, &output.raw_blake3)?,
                )))
            })
        })?
        else {
            return Ok(None);
        };
        load_whole_body(output, body, key.as_ref(), || self.session.body_dirs()).map(Some)
    }

    pub(super) fn read_raw_output_range(
        &self,
        output: &CodeRunRawOutput,
        offset: u64,
        len: usize,
    ) -> Result<Option<Vec<u8>>> {
        validate_raw_output(output)?;
        let _pin = self.session.pin_result_body(output.raw_blake3);
        self.answered(|| {
            self.session.read_composed(|view, rtxn| {
                let Some(row) = RAW_OUTPUTS.get_borrowed(view, rtxn, &output.handle)? else {
                    return Ok(None);
                };
                let key = body_key_row_in_txn(view, rtxn, &output.raw_blake3)?;
                read_body_row_range(output, &row, key.as_ref(), offset, len, || {
                    self.session.body_dirs()
                })
                .map(Some)
            })
        })
    }
}
