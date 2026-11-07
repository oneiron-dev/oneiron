//! Reader sources, findings and summaries bound by the recording host, and
//! the source bytes a scoped child's reads were shown (FIX 7735).
//! Entry: `RecordingJsHost::spawn_reader`.
//! Reader request and receipt definitions belong to `code_run`.

use super::*;
use crate::code_run::DeliveredRanges;

impl RecordingJsHost<'_, '_> {
    /// Commits to this run's job witness the ranges of its primary source
    /// that `read`'s reply shows (`delivered`), when this run is a scoped
    /// child and `read` is of that source (FIX 7735). Its caller commits a
    /// reply only once the reply passed its secret, taint and final
    /// live-cutoff checks, and before the reply leaves: a storage error fails
    /// the read before any byte of it leaves. A read of any other result, or
    /// by any other run, commits nothing. A job no longer live at the claimed
    /// generation keeps its witness as it is, and the reply is unchanged.
    pub(super) fn commit_source_delivery(
        &self,
        storage: &ExecutorStorage<'_>,
        read: &ResultRead,
        delivered: &DeliveredRanges,
    ) -> Result<()> {
        let Some(child) = self
            .gated_write
            .reader_child()
            .filter(|child| child.scoped.is_some())
        else {
            return Ok(());
        };
        let (source, output) = (&child.source, read.output());
        if delivered.ranges().is_empty()
            || read.owner() != source.owner
            || output.path != source.path
            || output.handle != source.handle
        {
            return Ok(());
        }
        storage.commit_source_delivery(
            child.task,
            child.generation,
            read.owner(),
            output,
            delivered.ranges(),
            crate::unix_millis_now(),
        )?;
        Ok(())
    }

    /// The source of a `self.spawn`: one of this run's own results, read as
    /// every read of it is, its range the ref's or the whole body. A source
    /// the run may not read now is refused as that read would be. Its
    /// origins are this run's ledger, frozen now (FIX 7084).
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
            origins: self.gated_write.frozen_result_origins(self.run_id),
        }))
    }

    /// `self.spawn(...)`: the source resolved in this run, then the spawn
    /// dispatched with it bound; the run's record keeps the guest's call. A
    /// reader child may delegate only its own results, never its inherited input.
    pub(super) fn spawn_reader(
        &mut self,
        seq: u64,
        mut spawn: SelfReaderSpawnCall,
    ) -> Result<(SelfDispatchOutcome, Option<SelfCall>)> {
        if self.gated_write.reader_child().is_none()
            || self.gated_write.reader_spawn_seat().is_some()
        {
            match self.delegate_source(&spawn.source)? {
                Ok(source) => spawn.bound = Some(source),
                Err(reason) => {
                    return Ok((
                        SelfDispatchOutcome::Denied(SelfDeniedResult {
                            effect: SelfEffect::ReaderSpawn,
                            outcome: reason,
                            reason_codes: Vec::new(),
                        }),
                        None,
                    ));
                }
            }
        }
        let site = ExecutorCallSite {
            run_id: self.run_id,
            seq,
            step_start: self.step_start,
            earlier: &self.bridge_calls,
        };
        Ok((
            self.gated_write
                .dispatch_for_executor_run(site, SelfCall::ReaderSpawn(Box::new(spawn)))?
                .0,
            None,
        ))
    }

    /// `summarize(r, {group?, ...})`: every member resolved in this run and
    /// read-checked as a read of it is, in order, then the call dispatched
    /// with them bound; the run's record keeps the guest's call. A tainted
    /// member answers the reply its read would, so a withheld body is never
    /// summarized; any other refusal answers its own reason. A reader
    /// child's call goes straight to its refusal. Each member's origins are
    /// this run's ledger as its read left it, frozen then: a member another
    /// run holds noted its own frozen origins there in that read (FIX 7084).
    pub(super) fn summarize(
        &mut self,
        seq: u64,
        mut call: SelfSummarizeCall,
    ) -> Result<(SelfDispatchOutcome, Option<SelfCall>)> {
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
                        return Ok((
                            SelfDispatchOutcome::Denied(SelfDeniedResult {
                                effect: SelfEffect::Summarize,
                                outcome: code.to_owned(),
                                reason_codes: Vec::new(),
                            }),
                            None,
                        ));
                    }
                };
                if read.is_tainted() {
                    return Ok((
                        SelfDispatchOutcome::Summarize(SummarizeReply::Withheld {
                            reply: read.withheld(),
                        }),
                        None,
                    ));
                }
                let output = read.output();
                bound.push(DelegatedSource {
                    owner: read.owner(),
                    path: output.path.clone(),
                    handle: output.handle.clone(),
                    range: read.range().unwrap_or((0, output.raw_len)),
                    rows,
                    origins: self.gated_write.frozen_result_origins(self.run_id),
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
        Ok((
            self.gated_write
                .dispatch_for_executor_run(site, SelfCall::Summarize(Box::new(call)))?
                .0,
            None,
        ))
    }

    /// A reader child's `tasks.update({task_ref, resultRef})`: its finding
    /// resolved among its own results only, a whole stored JSON value, then
    /// the report dispatched with it bound. Its parent's source is not its
    /// own and is refused. Its origins are the child's ledger, frozen now
    /// (FIX 7084).
    pub(super) fn report_finding(
        &mut self,
        seq: u64,
        mut report: SelfReaderReportCall,
    ) -> Result<(SelfDispatchOutcome, Option<SelfCall>)> {
        let failed = |code: &str| {
            (
                SelfDispatchOutcome::Failed(SelfFailedResult {
                    effect: SelfEffect::ReaderReport,
                    error: code.to_owned(),
                    code: None,
                    disk_floor: None,
                }),
                None,
            )
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
                origins: self.gated_write.frozen_result_origins(self.run_id),
            });
        }
        let site = ExecutorCallSite {
            run_id: self.run_id,
            seq,
            step_start: self.step_start,
            earlier: &self.bridge_calls,
        };
        Ok((
            self.gated_write
                .dispatch_for_executor_run(site, SelfCall::ReaderReport(report))?
                .0,
            None,
        ))
    }
}
