//! A session-bound run's result bodies: the sinks they stream through, the
//! routed rows that publish one and the reads that open one (moved out of
//! the routing module whole).

use super::*;

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
        let finished = finish_output(path, sink, complete, self.session.limit_watch())?;
        self.mark_secret(&finished.output, owner, finished.secret)?;
        self.put_body_key(&finished)?;
        self.answered(|| {
            self.session.side_table_put_routed(
                &self.route,
                &RAW_OUTPUTS,
                &finished.output.handle,
                &finished.body,
            )
        })?;
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
        let finished = finish_output(output.path.clone(), sink, true, self.session.limit_watch())?;
        if finished.output != *output {
            return Err(invalid_code_run_replay(
                "raw output metadata does not match bytes",
            ));
        }
        self.mark_secret(output, owner, finished.secret)?;
        self.put_body_key(&finished)?;
        self.answered(|| {
            self.session.side_table_put_routed(
                &self.route,
                &RAW_OUTPUTS,
                &output.handle,
                &finished.body,
            )
        })
    }

    /// The instance row of the file `finished` wrote, on the run's route,
    /// before the row naming it (FIX 5348, KS-2A): a vault instance's row
    /// pins the custody binding in the same transaction. A row the route's
    /// scope holds for the digest already stays: its file serves the body.
    pub(super) fn put_body_key(
        &self,
        finished: &super::super::records::FinishedOutput,
    ) -> Result<()> {
        let Some(key) = finished.key.as_ref() else {
            return Ok(());
        };
        self.answered(|| {
            let dir = self.session.body_dir(self.route.target())?;
            self.session
                .routed_side_txn(&self.route, |txn, read, write| {
                    if let Some(held) = BODY_KEYS.get(&read, txn, key.digest())?
                        && key.keeps(&held, &dir)?
                    {
                        return Ok(());
                    }
                    if let crate::side_table::RoutedDbs::Base(vault) = &write {
                        crate::store::pin_body_custody_in_txn(&vault.store, txn)?;
                    }
                    BODY_KEYS.put(&write, txn, key.digest(), key.row())
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
