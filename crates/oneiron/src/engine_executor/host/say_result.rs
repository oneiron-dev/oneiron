//! A code run's plain `say(result)` (L8-25), resolved where its results are.
//! Entry: `RecordingJsHost::say_result`.

use super::*;
use crate::code_run::{SaidResult, SelfSayResultCall};

impl RecordingJsHost<'_, '_> {
    /// `say(result)`: the ref resolved among this run's own results, the
    /// typed-result bubble's attachment built as a large trailing answer's
    /// is (FIX 365), then the call dispatched with it bound, so the bound
    /// door, the hooks and the witness rule on it as on the run's
    /// `self.speak`. The run's record keeps the guest's call. A ref naming
    /// no result of the run (`unknown_handle`), or a range of one
    /// (`say_result_range`: a bubble says a whole result), answers its
    /// refusal with nothing said.
    pub(super) fn say_result(
        &mut self,
        seq: u64,
        say: SelfSayResultCall,
    ) -> Result<(SelfDispatchOutcome, Option<SelfCall>)> {
        let target = JsResultTarget::parse(&say.result);
        let resolved = if target.range.is_some() {
            Err("say_result_range")
        } else {
            self.resolve_result(&target.reference)
                .map(|(output, _)| output)
                .ok_or("unknown_handle")
        };
        let output = match resolved {
            Ok(output) => output,
            Err(code) => {
                return Ok((
                    SelfDispatchOutcome::Denied(SelfDeniedResult {
                        hook_notice: None,
                        effect: SelfEffect::Speak,
                        outcome: code.to_owned(),
                        reason_codes: Vec::new(),
                    }),
                    None,
                ));
            }
        };
        let storage = self.storage.ok_or(Error::InvalidConfig(
            "executor result storage unavailable".into(),
        ))?;
        let said = SaidResult {
            attachment: super::super::store::message_result_attachment(
                storage,
                self.run_id,
                &output,
            )?,
            served_rows: self.verb_rows(),
        };
        let site = ExecutorCallSite {
            run_id: self.run_id,
            seq,
            step_start: self.step_start,
            earlier: &self.bridge_calls,
            reply_publisher: None,
        };
        Ok((
            self.gated_write
                .dispatch_for_executor_run(site, SelfCall::SayResult(say.with_bound(said)))?
                .0,
            None,
        ))
    }
}
