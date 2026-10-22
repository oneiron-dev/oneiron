//! Stored result binding, admission and reads for one JS host.
//! Entry: `RecordingJsHost::read_result`.
//! `RecordingJsHost` and `ResolvedResult` are defined by `engine_executor::host`.

use super::*;

impl RecordingJsHost<'_, '_> {
    /// The run's live result names, oldest first: this step's binds over
    /// the record's.
    pub(super) fn live_bindings(&self) -> Vec<&CodeRunResultBinding> {
        let mut live: Vec<_> = self
            .bindings
            .iter()
            .filter(|binding| !self.bound.iter().any(|held| held.name == binding.name))
            .collect();
        live.extend(&self.bound);
        live
    }

    /// The next free automatic name: `r<n>`, counting from one past the
    /// live names, past any name taken.
    pub(super) fn next_auto_name(&self) -> String {
        let live = self.live_bindings();
        (live.len() + 1..)
            .map(|n| format!("r{n}"))
            .find(|name| !live.iter().any(|binding| binding.name == *name))
            .unwrap_or_default()
    }

    /// Binds `name` to the result `handle` for the record; a rebind replaces
    /// the name's entry in place.
    pub(super) fn bind(&mut self, name: String, handle: String) {
        let binding = CodeRunResultBinding::new(name, handle);
        match self.bound.iter_mut().find(|held| held.name == binding.name) {
            Some(held) => *held = binding,
            None => self.bound.push(binding),
        }
    }

    /// The run's result a reference names, and the live name bound to it.
    /// Only this run's results resolve: a handle names nothing else.
    pub(super) fn resolve_result(
        &self,
        reference: &JsResultRef,
    ) -> Option<(CodeRunRawOutput, Option<String>)> {
        crate::code_run::resolve_result(
            self.results.iter().chain(&self.captured),
            &self.live_bindings(),
            reference,
        )
    }

    /// The refusal for a reference to no result of this run, with the live
    /// names it could have meant.
    pub(super) fn unknown_handle(&self) -> serde_json::Value {
        crate::code_run::unknown_handle(&self.live_bindings())
    }

    /// The rows the run's results were served from: the conservative union
    /// of every row its recorded and this step's verb answers were served
    /// from, each stored skill its callables loaded and the rows of each
    /// other run's result they read (FIX 5460), or none known when one kept
    /// no set.
    pub(in crate::engine_executor) fn result_rows(&self) -> Option<Vec<EntityId>> {
        let (skills, read) = &self.callable_rows;
        self.verb_rows()
            .zip(read.as_deref())
            .map(|(verbs, read)| [verbs.as_slice(), read, skills.as_slice()].concat())
    }

    /// The rows the run's recorded and this step's verb answers were served
    /// from, or none known when one answer kept no set.
    pub(super) fn verb_rows(&self) -> Option<Vec<EntityId>> {
        self.recorded_rows
            .as_ref()
            .zip(agent_verb_rows_of(&self.bridge_calls))
            .map(|(recorded, step)| [recorded.as_slice(), step.as_slice()].concat())
    }

    /// Whether the run's results stay on this device for its door's caller
    /// now (DEC-0005), by [`Self::result_rows`].
    pub(super) fn withholds_results(&self) -> Result<bool> {
        self.withholds_rows(self.result_rows())?
            .map_err(|code| Error::InvalidConfig(format!("stored result read refused: {code}")))
    }

    /// Whether a result served from `rows` stays on this device for the
    /// door's caller now. A scoped child's door that refuses the read on its
    /// authority answers that refusal's code (`scoped_child_authority_lapsed`
    /// or `scoped_child_parent_lease_lost`, FIX 7734), for the read to name;
    /// any other refusal is an error, as before.
    pub(super) fn withholds_rows(
        &self,
        rows: Option<Vec<EntityId>>,
    ) -> Result<std::result::Result<bool, &'static str>> {
        match self.gated_write.withholds_retained(rows.as_deref()) {
            Ok(withheld) => Ok(Ok(withheld)),
            Err(refusal) => match scoped_child_read_refusal(&refusal.code) {
                Some(code) => Ok(Err(code)),
                None => Err(Error::InvalidConfig(format!(
                    "stored result read refused: {}",
                    refusal.code
                ))),
            },
        }
    }

    /// `store(value, name?)`: the value the program just streamed, stored as
    /// a result of the run and bound to a name. Not gated: the value is the
    /// run's own, as a file it writes is. A halted bridge, or a run whose
    /// TASK was declined, stores nothing.
    ///
    /// With `sources` (results it was made from) or a fold `receipt` (the
    /// inputs a fold names), the stored body inherits the taint of every
    /// occurrence named; a receipt is computed by the host from the jobs it
    /// names and written with the binding at the step's checkpoint. Any input
    /// the run may not name is refused with nothing stored.
    pub(super) fn store_result(
        &mut self,
        name: Option<String>,
        sources: &[String],
        receipt: Option<&StoreReceiptInput>,
    ) -> Result<serde_json::Value> {
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor result storage unavailable".into(),
        ))?;
        let sink = self
            .streamed
            .take_store()
            .ok_or(Error::InvalidConfig("store sent no body".into()))?;
        if self.hard_failure.is_some() || self.left_a_gap {
            return Ok(result_refusal("host_bridge_halted"));
        }
        if self.declined.is_some() {
            return Ok(result_refusal("task_declined"));
        }
        if name
            .as_deref()
            .is_some_and(|name| !CodeRunResultBinding::is_valid_name(name))
        {
            return Ok(result_refusal("invalid_result_name"));
        }
        let mut inherit = Vec::with_capacity(sources.len());
        for source in sources {
            match self.checked_read(&JsResultTarget::parse(source))? {
                Ok((read, _)) => inherit.push((read.owner(), read.output().clone())),
                Err(refused) => return Ok(refused),
            }
        }
        let mut receipt = match receipt {
            Some(input) => match self.fold_receipt(storage, input)? {
                Ok((receipt, named)) => {
                    inherit.extend(named);
                    Some(receipt)
                }
                Err(refused) => return Ok(refused),
            },
            None => None,
        };
        let (output, mut card) = self.bind_stored_with(storage, sink, name, &inherit)?;
        if let Some(mut receipt) = receipt.take() {
            receipt.folded = OccurrenceRef::new(self.run_id, &output.path, &output.handle)?;
            card["receipt"] = receipt.card();
            self.receipts
                .retain(|held| held.folded.occurrence != receipt.folded.occurrence);
            self.receipts.push(receipt);
        }
        Ok(json!({"output": card}))
    }

    /// Publishes the body `sink` wrote as a stored value of the run, named
    /// by its digest, and binds it to `name`, or to the next free `r<n>`:
    /// its card. The same bytes stored twice are one output.
    pub(super) fn bind_stored(
        &mut self,
        storage: &ExecutorStorage<'_>,
        sink: BodySink,
        name: Option<String>,
    ) -> Result<serde_json::Value> {
        Ok(self.bind_stored_with(storage, sink, name, &[])?.1)
    }

    /// [`Self::bind_stored`], the body first marked with the taint of every
    /// occurrence in `inherit` (each by the run that holds it): the stored
    /// output and its card.
    pub(super) fn bind_stored_with(
        &mut self,
        storage: &ExecutorStorage<'_>,
        mut sink: BodySink,
        name: Option<String>,
        inherit: &[(EntityId, CodeRunRawOutput)],
    ) -> Result<(CodeRunRawOutput, serde_json::Value)> {
        // The sweep's tail goes through first, so the path names the digest
        // the body is published under (FIX 5399b).
        sink.finalize_sweep()?;
        let path = store_result_output_path(&sink.digest()?);
        let output = storage.publish_code_run_output(path, sink, true, self.run_id)?;
        if !inherit.is_empty() {
            storage.inherit_code_run_result_marks(self.run_id, &output, inherit)?;
        }
        if !self
            .results
            .iter()
            .chain(&self.captured)
            .any(|held| held.path == output.path)
        {
            self.captured.push(output.clone());
        }
        let name = name.unwrap_or_else(|| self.next_auto_name());
        self.bind(name.clone(), output.handle.clone());
        let card = result_card(storage, self.run_id, &output, Some(name.as_str()))?;
        Ok((output, card))
    }

    /// The result `target` names, read as every read of a result is:
    /// resolved for this run, admitted as a read of its recorded outputs, and
    /// its rows and its taint checked now. A refusal is the reply the guest
    /// gets in its place.
    ///
    /// A reader child also reads its parent's source, as `src` or by its
    /// handle, inside the range its parent delegated, while its job is live;
    /// a parent also reads its children's settled findings by their handles.
    /// Any other handle names nothing: a guessed handle grants nothing.
    pub(super) fn checked_result(
        &mut self,
        target: &JsResultTarget,
    ) -> Result<std::result::Result<ResultRead, serde_json::Value>> {
        Ok(self
            .checked_read_counting(target, true)?
            .map(|(read, _)| read))
    }

    /// [`Self::checked_result`] for an act over the run's results, with the
    /// rows the read was checked against: its gate counts the callable rows
    /// only while [`ACT_GATES_COUNT_CALLABLE_ROWS`].
    pub(super) fn checked_read(
        &mut self,
        target: &JsResultTarget,
    ) -> Result<std::result::Result<(ResultRead, Option<Vec<EntityId>>), serde_json::Value>> {
        self.checked_read_counting(target, ACT_GATES_COUNT_CALLABLE_ROWS)
    }

    /// The read both gates take, with the rows it was checked against: the
    /// run's own and the ones its owner's answers were served from, with the
    /// callable rows when `callable`. Only a read the caller may take adds
    /// another run's rows to the callable rows.
    pub(super) fn checked_read_counting(
        &mut self,
        target: &JsResultTarget,
        callable: bool,
    ) -> Result<std::result::Result<(ResultRead, Option<Vec<EntityId>>), serde_json::Value>> {
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor result storage unavailable".into(),
        ))?;
        let Some(found) = self.resolve_for_read(storage, &target.reference)? else {
            return Ok(Err(self.unknown_handle()));
        };
        if let (Some((start, end)), Some((from, to))) = (found.within, target.range)
            && (from < start || to > end)
        {
            return Ok(Err(result_refusal("outside_delegated_range")));
        }
        if found.child_source && !self.gated_write.reader_job_live()? {
            return Ok(Err(result_refusal("reader_task_settled")));
        }
        self.admit_result_read(storage)?;
        let own = if callable {
            self.result_rows()
        } else {
            self.verb_rows()
        };
        let rows = match found.rows.clone() {
            None => own,
            Some(extra) => own.zip(extra).map(|(run, extra)| [run, extra].concat()),
        };
        match self.withholds_rows(rows.clone())? {
            Ok(false) => {}
            Ok(true) => return Ok(Err(result_refusal("result_withheld"))),
            Err(code) => return Ok(Err(result_refusal(code))),
        }
        if let Some(extra) = &found.rows {
            // Another run's result reaches this one (FIX 6130).
            let cause = crate::code_run::ReadWorldUnknown::RetainedResult;
            self.gated_write.read_worlds_unknown(self.run_id, cause);
            let held = self.callable_rows.1.take();
            self.callable_rows.1 = held
                .zip(extra.clone())
                .map(|(held, extra)| [held, extra].concat());
        }
        let whole = found
            .within
            .is_some_and(|range| range == (0, found.output.raw_len));
        let range = target.range.or(found.within.filter(|_| !whole));
        Ok(
            ResultRead::new(storage, found.owner, found.output, found.name, range)?
                .map(|read| (read, rows)),
        )
    }

    /// What `reference` names for a read by this run: its own result first,
    /// then a reader child's source (a scoped child's lent inputs, each by
    /// its name or handle, FIX 7507), then a finding of one of its children.
    pub(super) fn resolve_for_read(
        &self,
        storage: &ExecutorStorage<'_>,
        reference: &JsResultRef,
    ) -> Result<Option<ResolvedResult>> {
        if let Some((output, name)) = self.resolve_result(reference) {
            return Ok(Some(ResolvedResult {
                output,
                name,
                owner: self.run_id,
                rows: None,
                within: None,
                child_source: false,
            }));
        }
        if let Some(child) = self.gated_write.reader_child() {
            let named = match reference {
                JsResultRef::Name(name) => child.delegated(true, name),
                JsResultRef::Handle(handle) => child.delegated(false, handle),
            };
            let Some((name, source)) = named else {
                return Ok(None);
            };
            let Some(output) =
                recorded_output(storage, source.owner, &source.path, &source.handle)?
            else {
                return Ok(None);
            };
            return Ok(Some(ResolvedResult {
                output,
                name: Some(name.to_owned()),
                owner: source.owner,
                rows: Some(source.rows.clone()),
                within: Some(source.range),
                child_source: true,
            }));
        }
        let JsResultRef::Handle(handle) = reference else {
            return Ok(None);
        };
        let Some(finding) = storage
            .reader_finding(self.run_id, handle)?
            .and_then(|job| job.finding)
        else {
            return Ok(None);
        };
        let Some(output) = recorded_output(storage, finding.owner, &finding.path, &finding.handle)?
        else {
            return Ok(None);
        };
        Ok(Some(ResolvedResult {
            output,
            name: None,
            owner: finding.owner,
            rows: Some(finding.rows),
            within: None,
            child_source: false,
        }))
    }

    /// `describe(r)`: the card of one of the run's results, or of a range
    /// of one.
    pub(super) fn describe_result(&mut self, target: &JsResultTarget) -> Result<serde_json::Value> {
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor result storage unavailable".into(),
        ))?;
        Ok(match self.checked_result(target)? {
            Ok(read) => {
                let mut card = read.card(storage)?;
                // A whole fold result's card says what the fold covered, as
                // its store's did: this step's receipt, or its committed one.
                if read.range().is_none() {
                    let output = read.output();
                    let occurrence =
                        OccurrenceRef::new(read.owner(), &output.path, &output.handle)?;
                    let staged = self
                        .receipts
                        .iter()
                        .find(|held| held.folded.occurrence == occurrence.occurrence)
                        .cloned();
                    let receipt = match staged {
                        Some(receipt) => Some(receipt),
                        None => storage.code_run_reader_fold(read.owner(), &output.path)?,
                    };
                    if let Some(receipt) =
                        receipt.filter(|receipt| receipt.folded.handle == output.handle)
                    {
                        card["receipt"] = receipt.card();
                    }
                }
                json!({ "output": card })
            }
            Err(refused) => refused,
        })
    }

    /// `can({read: r})`: the verdict of the checks a read of `target` makes
    /// (resolved in this run, admitted as a read of its recorded outputs,
    /// its rows and its taint), for this run as the reader, with no preview
    /// and no byte of the body. A refused admission halts the bridge as a
    /// read's does.
    ///
    /// With `child`, a readable result is also checked as a spawn's source
    /// would be, writing nothing: the run's own result, then the seat, the
    /// clock and the scope. The verdict names the children's cutoff and the
    /// meter they spend on (`scope`, with what it may still spend, or
    /// `host`, the host's own meter, with no figure), or why a spawn would be
    /// refused.
    pub(super) fn can_read_result(
        &mut self,
        target: &JsResultTarget,
        child: bool,
    ) -> Result<serde_json::Value> {
        let mut verdict = match self.checked_result(target)? {
            Ok(read) => read.preflight(),
            Err(refused) => result_cannot(refused),
        };
        if !child || verdict["can"] != json!(true) {
            return Ok(json!({"output": verdict}));
        }
        if self.resolve_result(&target.reference).is_none() {
            return Ok(json!({"output": {"can": false, "reason": "unknown_handle"}}));
        }
        match self
            .gated_write
            .preflight_reader_spawn(self.run_id, crate::unix_millis_now())?
        {
            Ok((cutoff, available)) => {
                let (window_tokens, memory_bytes) = self
                    .gated_write
                    .reader_spawn_seat()
                    .map_or((0, 0), |seat| (seat.window_tokens, seat.memory_bytes));
                let meter = if available.is_some() { "scope" } else { "host" };
                verdict["child"] = json!({
                    "cutoff_unix_ms": cutoff,
                    "meter": meter,
                    "window_tokens": window_tokens,
                    "memory_bytes": memory_bytes,
                });
                if let Some(available) = available {
                    verdict["child"]["spend_available_units"] = json!(available);
                }
            }
            Err(reason) => verdict = json!({"can": false, "reason": reason}),
        }
        Ok(json!({"output": verdict}))
    }

    /// One facet of one of the run's results, checked as `describe` is. A
    /// query whose selection is past one reply is stored as a new result of
    /// the run, as `store` stores a value, and answered by its card. It is
    /// read only from a clean body, and its own bytes are scanned for
    /// secrets as they are stored.
    pub(super) fn read_result(
        &mut self,
        target: &JsResultTarget,
        facet: ResultFacet,
        input: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor result storage unavailable".into(),
        ))?;
        let read = match self.checked_result(target)? {
            Ok(read) => read,
            Err(refused) => return Ok(refused),
        };
        let mut sink = match facet {
            ResultFacet::Query => Some(storage.code_run_output_sink()?),
            _ => None,
        };
        Ok(match read.read(storage, facet, input, sink.as_mut())? {
            ResultReply::Output(output) => json!({"output": output}),
            ResultReply::Denied(refused) => refused,
            ResultReply::Spilled { count, next } => {
                let sink = sink.ok_or(Error::InvariantViolation(
                    "a result read spilled with no sink",
                ))?;
                let card = self.bind_stored(storage, sink, None)?;
                let mut output = json!({"derived": card, "count": count, "done": next.is_none()});
                if let Some(next) = next {
                    output["next"] = next;
                }
                json!({"output": output})
            }
        })
    }

    /// One chunk of a stored result of this run, read by range, while the
    /// rows it was served from may reach the door's caller.
    pub(super) fn read_stored_result(
        &self,
        storage: &ExecutorStorage<'_>,
        path: &str,
    ) -> Result<Option<Vec<u8>>> {
        if self.withholds_results()? {
            return Err(Error::InvalidConfig(
                "stored result read refused: result_withheld".into(),
            ));
        }
        for output in self.results.iter().chain(&self.captured) {
            let base = result_read_path(output.output_ref());
            let Some(offset) = path.strip_prefix(&format!("{base}/chunk/")) else {
                continue;
            };
            let offset = offset
                .parse::<u64>()
                .ok()
                .filter(|parsed| offset == parsed.to_string())
                .ok_or(Error::InvalidConfig(
                    "invalid stored result reference".into(),
                ))?;
            if offset > output.raw_len {
                return Err(Error::InvalidConfig(
                    "stored result offset exceeds its body".into(),
                ));
            }
            return storage
                .read_code_run_raw_output_range(output, offset, RECOVERABLE_OUTPUT_CHUNK_BYTES)?
                .ok_or(Error::CorruptedIndex("executor replay output bytes"))
                .map(Some);
        }
        Err(Error::InvalidConfig(
            "stored result is outside this run".into(),
        ))
    }

    /// A recorded-output read answers where the step's next bridge call
    /// would: a step that can no longer close reads nothing more, past a
    /// halted bridge or past a write that did not meet its receipt, in this
    /// attempt or before. A bound door then rules on it as on any other call
    /// the run serves.
    pub(super) fn admit_recorded_read(&self) -> Result<()> {
        let refused =
            |code: &str| Error::InvalidConfig(format!("recorded output read refused: {code}"));
        if self.hard_failure.is_some() || self.left_a_gap {
            return Err(refused("host_bridge_halted"));
        }
        if self.declined.is_some() {
            return Err(refused("task_declined"));
        }
        let site = ExecutorCallSite {
            run_id: self.run_id,
            seq: self.next_seq,
            step_start: self.step_start,
            earlier: &self.bridge_calls,
        };
        if let Some(refusal) = self.gated_write.refusal_past_an_unmet_write(site, None)? {
            return Err(refused(&refusal.outcome));
        }
        self.gated_write
            .admit_run_call(RunCall::RecordedOutput)?
            .map_err(|refusal| refused(&refusal.code))?;
        Ok(())
    }

    /// Admits one read of the run's recorded outputs, answered as a call is,
    /// so a run whose participant left the room hears `NotInRoom`, never the
    /// door's verdict. A gate's rejection halts the bridge, as at a call.
    pub(super) fn admit_result_read(&mut self, storage: &ExecutorStorage<'_>) -> Result<()> {
        if let Err(err) = storage.answered(|| self.admit_recorded_read()) {
            let Error::Gate(GateError::GateWriteRejected { outcome, .. }) = &err else {
                return Err(err);
            };
            let refused = Error::InvalidConfig(format!("recorded output read refused: {outcome}"));
            self.hard_failure = Some(err);
            return Err(refused);
        }
        Ok(())
    }
}

/// The output at `path` with `handle` in `run`'s committed record.
pub(super) fn recorded_output(
    storage: &ExecutorStorage<'_>,
    run: EntityId,
    path: &str,
    handle: &str,
) -> Result<Option<CodeRunRawOutput>> {
    Ok(storage
        .get_code_run_replay_record(&run)?
        .and_then(|record| {
            record
                .outputs
                .into_iter()
                .find(|output| output.path == path && output.handle == handle)
        }))
}
