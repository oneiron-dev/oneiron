//! A captured step's replay context as an arm reads it (FIX 6351): read once,
//! in the snapshot the step's start and the record of its end are read in,
//! checked against both, and frozen beside them before either fork runs.
//! Each recorded call the arm matches is answered with the response the
//! live guest read: the hook's view in the outcome's place, or none, and the
//! budget envelope, or none. A response the context does not hold, a
//! context that is missing or incomplete, and a view that contradicts its
//! row are `GuestViewCaptureMissing`: the guest never reads the bare
//! outcome in its place.

use super::{Outcome, PreparedShadowStep, Reason, unavailable};
use crate::code_run::{
    CapturedGuestResponse, CodeRunReplayRecord, ExecutorStepStart, StepReplayCapsule,
    StepReplayContext,
};

/// A captured step's replay context, read and checked once: the context and
/// the BLAKE3 of its body as stored, or why the step has none to read.
pub(crate) enum ArmContext {
    Captured {
        context: StepReplayContext,
        digest: [u8; 32],
    },
    /// No context is read: none was committed, or its body is released,
    /// withheld, marked erased or gone.
    Missing,
}

/// The context `bytes` hold, the body the step's capsule names as stored,
/// checked against the step's capsule, its `start` and its `window`, the
/// row cut to the end its checkpoint records: `Missing` with no body, and
/// `SourceDigestMismatch` for a body that is no context, names another run
/// or step, another start or end, keeps a response at a position twice or
/// past the step's end, or keeps a read of reader state (FIX 6352) for
/// another run or outside the step's window.
pub(super) fn freeze_context(
    bytes: Option<Vec<u8>>,
    capsule: &StepReplayCapsule,
    start: &ExecutorStepStart,
    window: &CodeRunReplayRecord,
) -> Outcome<ArmContext> {
    let Some(bytes) = bytes else {
        return Ok(ArmContext::Missing);
    };
    let mismatch = || unavailable(Reason::SourceDigestMismatch, "replay_context");
    let context = StepReplayContext::decode(&bytes).ok_or_else(mismatch)?;
    let bridge_end = window.bridge_calls.len() as u64;
    if context.run != capsule.run
        || context.step != capsule.step
        || context.bridge_start != start.bridge_start
        || context.bridge_end != bridge_end
        || !context.guest_responses.placed_before(bridge_end)
        || !context
            .reader_reads
            .held_within(capsule.run, start.bridge_start, bridge_end)
    {
        return Err(mismatch());
    }
    Ok(ArmContext::Captured {
        context,
        digest: *blake3::hash(&bytes).as_bytes(),
    })
}

impl PreparedShadowStep {
    /// The BLAKE3 of the step's replay context as stored (FIX 6351), its
    /// read context with it (FIX 6352), when one is read: what a fork's
    /// execution pin binds.
    #[must_use]
    pub fn context_digest(&self) -> Option<[u8; 32]> {
        match &self.context {
            ArmContext::Captured { digest, .. } => Some(*digest),
            ArmContext::Missing => None,
        }
    }

    /// The response the live guest read for the recorded call at `seq`
    /// (FIX 6351): its hook's view or none, and its budget envelope or none,
    /// as the step's replay context kept them. `GuestViewCaptureMissing`
    /// when the context is missing or incomplete, keeps no response there,
    /// or keeps a view where the row says none was served, or none where it
    /// says one was.
    pub(crate) fn guest_response(&self, seq: u64) -> Outcome<&CapturedGuestResponse> {
        let missing = |cause| unavailable(Reason::GuestViewCaptureMissing, cause);
        let ArmContext::Captured { context, .. } = &self.context else {
            return Err(missing("replay_context"));
        };
        let responses = &context.guest_responses;
        let response = responses
            .at(seq)
            .filter(|_| responses.complete)
            .ok_or_else(|| missing("guest_response"))?;
        let served = usize::try_from(seq)
            .ok()
            .and_then(|at| self.window.bridge_calls.get(at))
            .is_some_and(|row| row.hook_view_served);
        if served != response.view.is_some() {
            return Err(missing("hook_view"));
        }
        Ok(response)
    }

    /// Whether each recorded call an arm matched, from the step's start to
    /// `consumed`, has the response its live guest read (FIX 6351): the
    /// check the arm's bridge answers each call by, so an execution that
    /// passed it read every call as the live guest did.
    pub(crate) fn captured_responses(&self, consumed: u64) -> Outcome<()> {
        let (start, _) = self.bridge_window();
        for seq in start..consumed {
            self.guest_response(seq)?;
        }
        Ok(())
    }
}
