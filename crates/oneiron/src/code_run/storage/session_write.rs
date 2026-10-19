//! One write a run bound to an off-record session stages in its room, kept
//! on its receipt in the same segment (WILL L11-01, S01-2a).
//!
//! The receipt is the run's own AgentVerb write receipt, in the run's replay
//! records: one segment of the run's captured route compares it, stages the
//! write's rows and keeps the write's answer as its first row. A write whose
//! receipt cannot be kept stages nothing, so the room holds no row a replay
//! of the step would make again.

use std::cell::Cell;

use crate::code_run::replay::{CodeRunBridgeCall, CodeRunReplayGeneration, CodeRunReplayRecord};
use crate::code_run::types::{SelfAgentVerbCall, SelfCall, SelfDispatchOutcome};
use crate::session_overlay::JournalEntry;
use crate::{Error, Result};

use super::records::{REPLAY_RECORDS, replay_generation_matches};
use super::routing::SessionBinding;

impl SessionBinding<'_> {
    /// `call`, one write of the run, staged by `stage` in ONE segment of the
    /// run's captured route. With `receipt`, the same segment first compares
    /// the receipt's stored generation with the one given, then keeps the
    /// receipt with the write's answer as its first row, so the rows and
    /// their receipt commit together or not at all. A route that flipped or
    /// went stale refuses inside the segment; nothing re-targets.
    ///
    /// The outer error is the receipt's: a changed generation, or a receipt
    /// that could not be kept. The inner one is the write's own refusal
    /// (the room's, its route's or `stage`'s), with nothing staged.
    pub(crate) fn stage_session_write(
        &self,
        call: &SelfAgentVerbCall,
        receipt: Option<(&CodeRunReplayRecord, Option<CodeRunReplayGeneration>)>,
        stage: impl FnOnce(
            &mut heed::RwTxn<'_>,
            &dyn Fn(&mut heed::RwTxn<'_>, JournalEntry) -> Result<()>,
        ) -> Result<SelfDispatchOutcome>,
    ) -> Result<std::result::Result<SelfDispatchOutcome, Error>> {
        let unkept = Cell::new(false);
        let kept = |step: Result<()>| step.inspect_err(|_| unkept.set(true));
        let written = self
            .session
            .overlay_write_routed(&self.route, |wtxn, apply| {
                if let Some((receipt, expected)) = receipt {
                    let current =
                        REPLAY_RECORDS.get(&self.session.read_view()?, wtxn, &receipt.run_id);
                    kept(current.and_then(|current| {
                        replay_generation_matches(current.as_ref(), expected)
                    }))?;
                }
                let outcome = stage(wtxn, apply)?;
                if let Some((receipt, _)) = receipt {
                    let mut answered = receipt.clone();
                    kept(
                        CodeRunBridgeCall::record(
                            0,
                            &SelfCall::AgentVerb(call.clone()),
                            &outcome,
                            0,
                            0,
                        )
                        .map(|row| answered.bridge_calls.push(row)),
                    )?;
                    let view = self.session.read_view()?;
                    kept(REPLAY_RECORDS.put(&view, wtxn, &answered.run_id, &answered))?;
                }
                Ok(outcome)
            });
        match written {
            Ok(outcome) => Ok(Ok(outcome)),
            Err(error) if unkept.get() => Err(error),
            Err(error) => Ok(Err(error)),
        }
    }
}
