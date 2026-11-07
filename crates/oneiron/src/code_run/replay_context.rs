//! A captured step's replay context (FIX 6351): what the live guest read
//! beside the step's bridge rows. A row keeps a call's typed outcome; the
//! guest read that outcome through its response, which may carry a verb
//! hook's view in the outcome's place and the wake pass's budget envelope.
//! The step's host keeps each response as it hands it to the runtime, at
//! the bridge position whose row answers it, and the step's checkpoint
//! commits the context beside the step's capsule and binds its digest
//! (`storage::replay_capsule`). A shadow arm then answers each recorded call
//! with the response the live guest read, never with the bare outcome.
//!
//! A response kept with no view and no envelope is a response that carried
//! neither. A position the context does not hold is not captured: no reader
//! takes it for a bare outcome. A granted `reveal.wait` answer carries a
//! secret's value in its view (OF-560), so no context keeps it: its position
//! stays not captured, and no arm replays the call.
//!
//! The context is a typed body with named members. Beside the responses, it
//! holds what the step's result reads saw of reader state (FIX 6352,
//! `reads`): a reader child's binding, whether its job was live, a parent's
//! settled findings, the fold receipt each whole result's card carried and
//! the verdict the door's row check gave each read of another run's result.

mod reads;

use serde::{Deserialize, Serialize};

pub(crate) use self::reads::{
    CapturedReaderChild, ReaderFindingSelection, ReaderReadCapture, RetainedReadVerdict,
    SelectedFinding,
};
use super::types::SelfCall;
use crate::dreamer_wake::BudgetLegibilityEnvelope;
use crate::task_verb::sdk::AgentVerb;
use crate::{EntityId, Error, Result};

/// One guest response a step's bridge handed out, at the bridge position
/// whose row answers it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct CapturedGuestResponse {
    /// The bridge position of the row that answers it.
    pub(crate) seq: u64,
    /// The verb hook's view the guest read in place of the outcome; `None`
    /// when the guest read the outcome itself.
    pub(crate) view: Option<serde_json::Value>,
    /// The budget envelope the response carried; `None` outside a wake pass.
    pub(crate) budget: Option<BudgetLegibilityEnvelope>,
}

/// The guest responses one step's host handed out, in the order it handed
/// them out.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct GuestResponseCapture {
    pub(crate) responses: Vec<CapturedGuestResponse>,
    /// Whether every response the host handed out is here at its position:
    /// `false` once one had no position to keep it at, or a position was
    /// answered twice.
    pub(crate) complete: bool,
}

impl GuestResponseCapture {
    /// A capture of no response yet.
    pub(crate) const fn new() -> Self {
        Self {
            responses: Vec::new(),
            complete: true,
        }
    }

    /// Keeps the response the guest read for `call`: its `view` and its
    /// `budget`, the same values the runtime was handed, at `seq`, the
    /// position of the row that answers it. A `reveal.wait`'s response is
    /// never kept. A response with no position, or at a position kept
    /// before, leaves the capture incomplete.
    pub(crate) fn keep(
        &mut self,
        call: &SelfCall,
        seq: Option<u64>,
        view: Option<&serde_json::Value>,
        budget: Option<BudgetLegibilityEnvelope>,
    ) {
        if reveals_secret(call) {
            return;
        }
        match seq {
            Some(seq) if self.at(seq).is_none() => self.responses.push(CapturedGuestResponse {
                seq,
                view: view.cloned(),
                budget,
            }),
            _ => self.complete = false,
        }
    }

    /// The response kept at `seq`.
    pub(crate) fn at(&self, seq: u64) -> Option<&CapturedGuestResponse> {
        self.responses.iter().find(|response| response.seq == seq)
    }

    /// Whether each response is at its own position, all before
    /// `bridge_end`: a step's responses answer its own rows, and a settled
    /// call's answer an earlier entry's.
    pub(crate) fn placed_before(&self, bridge_end: u64) -> bool {
        self.responses.iter().enumerate().all(|(index, response)| {
            response.seq < bridge_end
                && self.responses[..index]
                    .iter()
                    .all(|earlier| earlier.seq != response.seq)
        })
    }
}

/// One captured step's replay context: the step it is, where its calls are
/// in its run's bridge log, and what its guest read beside them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct StepReplayContext {
    pub(crate) run: EntityId,
    pub(crate) step: u64,
    /// Where the step's calls are in its run's bridge log: from its start,
    /// to its exclusive end, the end its checkpoint records (FIX 6354).
    pub(crate) bridge_start: u64,
    pub(crate) bridge_end: u64,
    pub(crate) guest_responses: GuestResponseCapture,
    /// What the step's result reads saw of reader state (FIX 6352).
    pub(crate) reader_reads: ReaderReadCapture,
}

impl StepReplayContext {
    /// Its body: canonical JSON.
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|error| Error::InvalidConfig(format!("step replay context: {error}")))
    }

    /// The context a body holds, when it reads as one.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// What one step's host keeps for the step's replay context while the step
/// runs: each guest response it hands out (FIX 6351) and what its result
/// reads see of reader state (FIX 6352).
pub(crate) struct StepContextCapture {
    pub(crate) guest_responses: GuestResponseCapture,
    pub(crate) reader_reads: ReaderReadCapture,
}

impl StepContextCapture {
    /// A capture of nothing yet, for a run that reads under `child`.
    pub(crate) const fn new(child: Option<CapturedReaderChild>) -> Self {
        Self {
            guest_responses: GuestResponseCapture::new(),
            reader_reads: ReaderReadCapture::new(child),
        }
    }
}

/// A step's replay context as its checkpoint commits it: the context, its
/// body as captured, whose digest the checkpoint binds, and the capsule
/// that captured the step, by its attempt and lease generation, when one
/// may have.
pub(crate) struct StepContextCommit {
    pub(crate) capsule: Option<(EntityId, u32)>,
    pub(crate) context: StepReplayContext,
    pub(crate) bytes: Vec<u8>,
}

impl StepContextCommit {
    /// `context`, encoded, for `capsule`.
    pub(crate) fn new(
        capsule: Option<(EntityId, u32)>,
        context: StepReplayContext,
    ) -> Result<Self> {
        let bytes = context.encode()?;
        Ok(Self {
            capsule,
            context,
            bytes,
        })
    }

    /// The BLAKE3 of the context's body as captured: what the step's
    /// checkpoint binds.
    pub(crate) fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.bytes).as_bytes()
    }
}

/// Whether `call` is a `reveal.wait`, whose granted answer carries a
/// secret's value in its view (OF-560): no context keeps that view, and no
/// arm replays the call.
pub(crate) fn reveals_secret(call: &SelfCall) -> bool {
    matches!(call, SelfCall::AgentVerb(verb) if verb.verb == AgentVerb::RevealWait)
}
