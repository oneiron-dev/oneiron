//! Doors for `tests/compaction_seat_exact_model.rs` (FIX-LIST
//! SELF-WRITER-HOUSE-FALLBACK-SEAT-EXACT-REFUSED): one pass on code mode's
//! house compaction backend, and one on the writer an agent definition's run
//! compacts on, each built as a run gets it. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use std::sync::Arc;

use oneiron::code_run::bind_compaction_caller;
use oneiron::compaction::{CompactionBackend, CompactionRequest};
use oneiron::settings::CallerLocality;
use oneiron::{EdgeActorClass, EntityId, LlmRequest, WriteActor};

use super::{AnsweringRungSlot, CodeModeCompaction, LiveAdmission, LiveCompaction};
use crate::models::{AnsweringRung, RoleCall, RoleRefusal};
use crate::server::SyncServer;

/// What one pass answered.
#[derive(Debug)]
pub struct PassAnswer {
    /// The summary text the pass's model wrote.
    pub summary: String,
    /// For a self-written pass, the model its receipt names as admitted.
    pub admitted_model: Option<String>,
    /// For a self-written pass, how many model calls it files as its steps.
    pub filed_calls: usize,
}

/// The code-mode compaction the host bound at attach, while it is live.
fn live(server: &SyncServer) -> Result<Arc<LiveCompaction>, String> {
    match server.ai.writer_compaction.get() {
        Some(CodeModeCompaction::Live(live)) => Ok(Arc::clone(live)),
        Some(CodeModeCompaction::Off(why)) => {
            Err(format!("code mode's compaction is off: {why:?}"))
        }
        None => Err("no code-mode compaction is bound".to_owned()),
    }
}

/// One pass of `request` on the house route's backend: the one a run
/// whose agent writes no compaction of its own compacts on. A pass blocks
/// on the host's runtime, so call it off that runtime.
///
/// # Errors
///
/// The pass's refusal, in its debug words.
pub fn house_pass(server: &SyncServer, request: &CompactionRequest) -> Result<PassAnswer, String> {
    let live = live(server)?;
    let house = live
        .served
        .first()
        .ok_or("code mode's compaction serves no house seat")?;
    let product = house
        .compact(request, None)
        .map_err(|refusal| format!("{refusal:?}"))?;
    Ok(PassAnswer {
        summary: product.summary_text,
        admitted_model: None,
        filed_calls: 0,
    })
}

/// One pass of `request` on the writer the run of `agent`, an agent
/// definition, compacts on (its memory profile as `run_profile` reads it,
/// its writer as `self_registry` registers it): its flight prepared on
/// this device, then sent as the agent's own. A pass blocks on the host's
/// runtime, so call it off that runtime.
///
/// # Errors
///
/// Why the run writes no compaction of its own, or the flight's or the
/// pass's refusal, in its debug words.
pub fn self_written_pass(
    server: &SyncServer,
    agent: EntityId,
    request: &CompactionRequest,
) -> Result<PassAnswer, String> {
    let live = live(server)?;
    let byline = WriteActor::new(agent, EdgeActorClass::Agent);
    let (profile, definition) = live.run_profile(byline);
    let definition = definition.ok_or("the agent's run does not write its own compaction")?;
    let host = bind_compaction_caller(byline, CallerLocality::OnDevice, None);
    let admission: Arc<dyn LiveAdmission> = Arc::new(NoLiveFork);
    let registry = live
        .self_registry(&profile, definition, host, None, &admission)
        .map_err(|why| format!("{why:?}"))?;
    let writer = registry
        .resolve(&profile)
        .map_err(|error| error.to_string())?;
    writer
        .prepare_flight(false)
        .map_err(|why| format!("{why:?}"))?;
    let answer = writer.compact_as_writer(request, None);
    writer.end_flight();
    let (product, execution) = answer.map_err(|refusal| format!("{refusal:?}"))?;
    Ok(PassAnswer {
        summary: product.summary_text,
        admitted_model: execution
            .as_ref()
            .map(|execution| execution.admitted_model.clone()),
        filed_calls: execution.map_or(0, |execution| execution.calls.len()),
    })
}

/// A run with no live call to fork: a flight on the retained turns, or on
/// `auto` with no capture, never asks it.
struct NoLiveFork;

impl LiveAdmission for NoLiveFork {
    fn admit_live(&self, _: LlmRequest) -> Result<RoleCall, RoleRefusal> {
        Err(RoleRefusal::NoSeat)
    }

    fn hold_answering_rungs(&self, _: &LlmRequest) -> Option<Arc<AnsweringRungSlot>> {
        None
    }

    fn answering_rung(&self, _: &LlmRequest) -> Option<AnsweringRung> {
        None
    }
}
