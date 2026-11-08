//! The live fork's flight transport (FIX 4465 C): the capture a breakpoint
//! sealed rides its flight, the run's driver admits it for the run's own
//! actor, the backend freezes it for the flight's calls, and the flight lets
//! go of it when it ends. Thresholds, the hot window and the single flight
//! are unchanged.
//!
//! FIX 4933: the capture is the run's latest completed call, as the rung
//! that answered it sent it, never the call the step is about to send. Its
//! flight seals only the steps that call holds; the later steps stay raw
//! for a later breakpoint. No breakpoint waits for an unsent call.

use crate::code_run::{AdmittedLiveFork, LiveCompactionFork};
use crate::compaction::{CompactionBackend, CompactionDriver, SelfCompactionUnavailable};
use crate::engine_executor::ENGINE_EXECUTOR_FALLBACK_NAME;
use crate::{CallClass, EntityId, LlmRequest, WriteActor};

/// What one breakpoint captured of the run's `live` request (FIX 4465 C):
/// nothing when the flight is written from the retained turns (a row on
/// them, or a row on `auto` whose live prefix is cold, FIX 6029), else the
/// capture or why there is none. Beside it, the input the flight's window
/// may fill: what the live model leaves beside the captured prefix (for
/// `auto`, no more than its cheap writer takes), else what the backend
/// takes. The span is sized on the model the flight is sent on, before any
/// of it is sealed. `prefix_sources` is every row `live` was read from,
/// `None` when the run did not witness them all: no fork is captured then
/// (FIX 9463).
pub(in crate::engine_executor) fn capture(
    driver: &CompactionDriver,
    live: &LlmRequest,
    prefix_sources: Option<Vec<EntityId>>,
) -> (
    Option<Result<LiveCompactionFork, SelfCompactionUnavailable>>,
    Option<u64>,
) {
    let budget = driver.summary_token_budget();
    let captured = driver
        .backend()
        .capture_live_fork(live, prefix_sources, budget);
    let room = match &captured {
        Some(Ok(fork)) => Some(fork.input_room()),
        _ => driver.backend().input_token_limit(budget),
    };
    (captured, room)
}

/// How many of the run's steps a breakpoint's live fork holds (FIX 4933):
/// the steps before the one its prefix's call was assembled for, as that
/// call names them. A prefix of another run's call, or one that names no
/// step, holds none. `None` when the flight is not a live fork.
pub(in crate::engine_executor) fn held_steps(
    live: Option<&Result<LiveCompactionFork, SelfCompactionUnavailable>>,
    request: &LlmRequest,
) -> Option<u64> {
    let Some(Ok(fork)) = live else {
        return None;
    };
    Some(match (step_of(fork.request()), step_of(request)) {
        (Some((run, steps)), Some((current, _))) if run == current => steps,
        _ => 0,
    })
}

/// The last step a flight seals through `watermark` when its live fork
/// holds `held` steps (FIX 4933): never one past them, and `None` when the
/// fork holds none.
pub(in crate::engine_executor) fn within_prefix(watermark: u64, held: Option<u64>) -> Option<u64> {
    match held {
        None => Some(watermark),
        Some(steps) => steps.checked_sub(1).map(|last| watermark.min(last)),
    }
}

/// The run and the step count a step's call names in its envelope, as the
/// executor wrote them when it assembled the call.
fn step_of(request: &LlmRequest) -> Option<(&str, u64)> {
    let CallClass::Durable { fallback } = &request.envelope.class else {
        return None;
    };
    if fallback.name != ENGINE_EXECUTOR_FALLBACK_NAME {
        return None;
    }
    let config = fallback.config.as_ref()?;
    Some((
        config.get("run_id")?.as_str()?,
        config.get("step_seq")?.as_u64()?,
    ))
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
