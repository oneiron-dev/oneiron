//! A session-bound run's results and wait, outside its entries (FIX 4284):
//! `self.off_record.results.list` and `.results.read` read the named
//! results of a run `self.off_record.execute` entered, and
//! `self.off_record.waits.get` and `.waits.answer` read and answer the wait
//! it parked on. Each reads through the managed session the run's entries
//! bind, as their runner, never through the vault's canonical result
//! readers. An answer delivers its reply once; the runner enters the run
//! again with `self.off_record.execute` to go on (CALLS: FIX 4284 wait
//! continuation). Like every session row, none keeps a call receipt, and a
//! bare embedded handle answers each with [`super::off_record_host_only`].

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::code_run::SelfDurableWaitReason;
use crate::memory::MemoryResult;
use crate::memory::result_doors::ResultCard;
use crate::off_record::{SessionRunCards, SessionRunWait, SessionWaitAnswer};

#[doc(hidden)]
use oneiron_verb_wire::verbs::off_record_runs::decode;
#[doc(hidden)]
pub use oneiron_verb_wire::verbs::off_record_runs::{
    OffRecordResultRead, OffRecordResultReadRequest, OffRecordResultsRequest,
    OffRecordWaitAnswerRequest, OffRecordWaitRequest,
};

/// `self.off_record.results.list`'s answer.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordResultCards {
    pub run_ref: String,
    /// The run's id in the session, 32 hex.
    pub run_id: String,
    /// How many names the run has bound.
    pub count: usize,
    /// The cards of this page's names that hold a result, newest first: a
    /// preview and a shape only of a clean body.
    pub cards: Vec<ResultCard>,
    /// Where the next page starts, when names remain past this one.
    pub next_offset: Option<usize>,
    /// The rows the run's answers were served from stay where this caller
    /// is not, so no card is shown.
    pub withheld: bool,
}

/// `self.off_record.waits.get`'s answer.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordWaitView {
    pub run_ref: String,
    /// The run's id in the session, 32 hex.
    pub run_id: String,
    /// The wait the run is parked on now; `None` when it waits on nothing.
    pub wait: Option<OffRecordRunWait>,
}

/// The wait a session run is parked on.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordRunWait {
    /// 32 hex.
    pub wait_id: String,
    /// How many times the run already resumed from this wait.
    pub generation: u64,
    /// The effect that parked, as a run's program names it.
    pub effect: String,
    /// `human_input`, `destructive_effect`, `outbound_effect` or
    /// `peer_result`.
    pub reason: String,
    /// What the wait asks, when it says.
    pub prompt: Option<String>,
    /// Whether `self.off_record.waits.answer` answers it: a human input or
    /// an effect approval the run raised itself. A peer's result, a
    /// connector call and a code consent are answered by their own settlers.
    pub answerable: bool,
    /// When a reply was delivered to it (Unix ms); the run takes it at its
    /// next entry.
    pub delivered_at_ms: Option<u64>,
}

/// `self.off_record.waits.answer`'s answer.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffRecordWaitAnswered {
    pub run_ref: String,
    /// The run's id in the session, 32 hex.
    pub run_id: String,
    /// 32 hex.
    pub wait_id: String,
    pub generation: u64,
    /// Another reply settled the wait first, before this call or beside
    /// it; that first reply stands and this one was not delivered.
    pub already_answered: bool,
    /// When the reply that stands was delivered (Unix ms). Enter the run
    /// again with `self.off_record.execute` to go on.
    pub delivered_at_ms: u64,
}

impl OffRecordResultCards {
    /// `page` of run `run_ref`'s result cards, each in its typed shape.
    ///
    /// # Errors
    ///
    /// A card the reader made that is not a [`ResultCard`].
    pub fn of(run_ref: String, run_id: EntityId, page: SessionRunCards) -> MemoryResult<Self> {
        Ok(Self {
            run_ref,
            run_id: run_id.to_hex(),
            count: page.count,
            cards: page
                .cards
                .into_iter()
                .map(decode::<ResultCard>)
                .collect::<MemoryResult<_>>()?,
            next_offset: page.next_offset,
            withheld: page.withheld,
        })
    }
}

impl OffRecordRunWait {
    /// The wait a session run is parked on, as the wire reads it.
    #[must_use]
    pub fn of(parked: SessionRunWait) -> Self {
        Self {
            wait_id: parked.key.wait_id.to_hex(),
            generation: parked.key.generation,
            effect: parked.wait.effect.as_str().to_owned(),
            reason: match parked.wait.reason {
                SelfDurableWaitReason::HumanInput => "human_input",
                SelfDurableWaitReason::DestructiveEffect => "destructive_effect",
                SelfDurableWaitReason::OutboundEffect => "outbound_effect",
                SelfDurableWaitReason::PeerResult => "peer_result",
            }
            .to_owned(),
            prompt: parked.wait.prompt,
            answerable: parked.answerable,
            delivered_at_ms: parked.delivered_at_ms,
        }
    }
}

impl OffRecordWaitAnswered {
    /// What an answer to run `run_ref`'s wait did.
    #[must_use]
    pub fn of(run_ref: String, run_id: EntityId, answer: SessionWaitAnswer) -> Self {
        Self {
            run_ref,
            run_id: run_id.to_hex(),
            wait_id: answer.key.wait_id.to_hex(),
            generation: answer.key.generation,
            already_answered: answer.already_answered,
            delivered_at_ms: answer.delivered_at_ms,
        }
    }
}
