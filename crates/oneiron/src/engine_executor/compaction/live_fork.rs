//! The live fork's flight transport (FIX 4465 C): the capture a breakpoint
//! sealed rides its flight, the run's driver admits it for the run's own
//! actor, the backend freezes it for the flight's calls, and the flight lets
//! go of it when it ends. Thresholds, the hot window and the single flight
//! are unchanged.

use crate::code_run::{AdmittedLiveFork, LiveCompactionFork};
use crate::compaction::{CompactionBackend, CompactionDriver, SelfCompactionUnavailable};
use crate::{LlmRequest, WriteActor};

/// What one breakpoint captured of the run's `live` request (FIX 4465 C):
/// nothing when the backend does not write from the live context, else the
/// capture or why there is none. Beside it, the input the flight's window
/// may fill: what the live model leaves beside the captured prefix, else
/// what the backend takes. The span is sized on the model the fork is sent
/// on, before any of it is sealed.
pub(in crate::engine_executor) fn capture(
    driver: &CompactionDriver,
    live: &LlmRequest,
) -> (
    Option<Result<LiveCompactionFork, SelfCompactionUnavailable>>,
    Option<u64>,
) {
    let budget = driver.summary_token_budget();
    let captured = driver.backend().capture_live_fork(live, budget);
    let room = match &captured {
        Some(Ok(fork)) => Some(fork.input_room()),
        _ => driver.backend().input_token_limit(budget),
    };
    (captured, room)
}

/// The breakpoint's capture, admitted by the run's driver for `byline`.
pub(super) fn admit(
    driver: &CompactionDriver,
    byline: WriteActor,
    live: Option<Result<LiveCompactionFork, SelfCompactionUnavailable>>,
) -> Option<Result<AdmittedLiveFork, SelfCompactionUnavailable>> {
    live.map(|captured| driver.admit_self_live_binding(byline, captured))
}

/// Prepares one flight: on the live fork its driver admitted, on why the
/// breakpoint bound none, or as every other flight is prepared.
pub(super) fn prepare(
    backend: &dyn CompactionBackend,
    session_bound: bool,
    live: Option<Result<AdmittedLiveFork, SelfCompactionUnavailable>>,
) -> Result<(), SelfCompactionUnavailable> {
    match live {
        None => backend.prepare_flight(session_bound),
        Some(Ok(fork)) => backend.prepare_live_flight(session_bound, fork),
        Some(Err(why)) => Err(why),
    }
}
