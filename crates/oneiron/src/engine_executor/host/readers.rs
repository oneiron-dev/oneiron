//! Reader sources, findings and summaries bound by the recording host.
//! Entry: `RecordingJsHost::spawn_reader`.
//! Reader request and receipt definitions belong to `code_run`.

use super::*;

impl RecordingJsHost<'_, '_> {
    /// The source of a `self.spawn`: one of this run's own results, read as
    /// every read of it is, its range the ref's or the whole body. A source
    /// the run may not read now is refused as that read would be.
    pub(super) fn delegate_source(
        &mut self,
        source: &str,
    ) -> Result<std::result::Result<DelegatedSource, String>> {
        let target = JsResultTarget::parse(source);
        if self.resolve_result(&target.reference).is_none() {
            return Ok(Err("unknown_handle".to_owned()));
        }
        let read = match self.checked_read(&target)?.map(|(read, _)| read) {
            Ok(read) => read,
            Err(refused) => {
                let code = refused
                    .get("denied")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("denied");
                return Ok(Err(code.to_owned()));
            }
        };
        if read.is_tainted() {
            return Ok(Err("tainted".to_owned()));
        }
        let output = read.output();
        Ok(Ok(DelegatedSource {
            owner: self.run_id,
            path: output.path.clone(),
            handle: output.handle.clone(),
            range: read.range().unwrap_or((0, output.raw_len)),
            rows: self.result_rows(),
        }))
    }

    /// `self.spawn(...)`: the source resolved in this run, then the spawn
    /// dispatched with it bound; the run's record keeps the guest's call. A
    /// reader child's spawn goes straight to its refusal.
    pub(super) fn spawn_reader(
        &mut self,
        seq: u64,
        mut spawn: SelfReaderSpawnCall,
    ) -> Result<SelfDispatchOutcome> {
        if self.gated_write.reader_child().is_none() {
            match self.delegate_source(&spawn.source)? {
                Ok(source) => spawn.bound = Some(source),
                Err(reason) => {
                    return Ok(SelfDispatchOutcome::Denied(SelfDeniedResult {
                        effect: SelfEffect::ReaderSpawn,
                        outcome: reason,
                        reason_codes: Vec::new(),
                    }));
                }
            }
        }
        let site = ExecutorCallSite {
            run_id: self.run_id,
            seq,
            step_start: self.step_start,
            earlier: &self.bridge_calls,
        };
        self.gated_write
            .dispatch_for_executor_run(site, SelfCall::ReaderSpawn(Box::new(spawn)))
    }

    /// `summarize(r, {group?, ...})`: every member resolved in this run and
    /// read-checked as a read of it is, in order, then the call dispatched
    /// with them bound; the run's record keeps the guest's call. A tainted
    /// member answers the reply its read would, so a withheld body is never
    /// summarized; any other refusal answers its own reason. A reader
    /// child's call goes straight to its refusal.
    pub(super) fn summarize(
        &mut self,
        seq: u64,
        mut call: SelfSummarizeCall,
    ) -> Result<SelfDispatchOutcome> {
        if self.gated_write.reader_child().is_none() {
            let members: Vec<String> = call.members().into_iter().map(str::to_owned).collect();
            let mut bound = Vec::with_capacity(members.len());
            for member in &members {
                let (read, rows) = match self.checked_read(&JsResultTarget::parse(member))? {
                    Ok(found) => found,
                    Err(refused) => {
                        let code = refused
                            .get("denied")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("denied");
                        return Ok(SelfDispatchOutcome::Denied(SelfDeniedResult {
                            effect: SelfEffect::Summarize,
                            outcome: code.to_owned(),
                            reason_codes: Vec::new(),
                        }));
                    }
                };
                if read.is_tainted() {
                    return Ok(SelfDispatchOutcome::Summarize(SummarizeReply::Withheld {
                        reply: read.withheld(),
                    }));
                }
                let output = read.output();
                bound.push(DelegatedSource {
                    owner: read.owner(),
                    path: output.path.clone(),
                    handle: output.handle.clone(),
                    range: read.range().unwrap_or((0, output.raw_len)),
                    rows,
                });
            }
            call.bound = Some(bound);
        }
        let site = ExecutorCallSite {
            run_id: self.run_id,
            seq,
            step_start: self.step_start,
            earlier: &self.bridge_calls,
        };
        self.gated_write
            .dispatch_for_executor_run(site, SelfCall::Summarize(Box::new(call)))
    }

    /// A reader child's `tasks.update({task_ref, resultRef})`: its finding
    /// resolved among its own results only, a whole stored JSON value, then
    /// the report dispatched with it bound. Its parent's source is not its
    /// own and is refused.
    pub(super) fn report_finding(
        &mut self,
        seq: u64,
        mut report: SelfReaderReportCall,
    ) -> Result<SelfDispatchOutcome> {
        let failed = |code: &str| {
            SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: SelfEffect::ReaderReport,
                error: code.to_owned(),
            })
        };
        if self.gated_write.reader_child().is_some() {
            let storage = self.storage.ok_or(Error::InvalidConfig(
                "executor result storage unavailable".into(),
            ))?;
            let target = JsResultTarget::parse(&report.result_ref);
            let Some((output, _)) = self
                .resolve_result(&target.reference)
                .filter(|_| target.range.is_none())
            else {
                return Ok(failed("finding_not_own"));
            };
            let card = result_card(storage, self.run_id, &output, None)?;
            if card["taint"]["state"] != "clean" {
                return Ok(failed("finding_tainted"));
            }
            if card["shape"]["format"] != "json" {
                return Ok(failed("finding_not_json"));
            }
            report.bound = Some(ReaderFindingRef {
                owner: self.run_id,
                path: output.path,
                handle: output.handle,
                bytes: output.raw_len,
                rows: self.result_rows(),
            });
        }
        let site = ExecutorCallSite {
            run_id: self.run_id,
            seq,
            step_start: self.step_start,
            earlier: &self.bridge_calls,
        };
        self.gated_write
            .dispatch_for_executor_run(site, SelfCall::ReaderReport(report))
    }
}
