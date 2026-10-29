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

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::EntityId;
use crate::code_run::{ResultFacet, SelfDurableWaitReason};
use crate::memory::result_doors::{ResultCard, ResultReadRefusal};
use crate::memory::{MemoryError, MemoryResult};
use crate::off_record::{SessionRunCards, SessionRunWait, SessionWaitAnswer};

/// `self.off_record.results.list`'s input: a page of the named results of
/// the run `run_ref` names in the session, newest name first.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordResultsRequest {
    pub session_ref: String,
    pub run_ref: String,
    /// How many of the newest names to pass over first.
    #[serde(default)]
    pub offset: Option<u32>,
    /// How many names this page reads; every remaining one when absent.
    #[serde(default)]
    pub limit: Option<u32>,
}

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

/// `self.off_record.results.read`'s input: one read of one result of the
/// run `run_ref` names in the session.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordResultReadRequest {
    pub session_ref: String,
    pub run_ref: String,
    /// A name the run bound, a result handle, `occurrence:<hex>`, or a
    /// range of one (`<ref>#<start>-<end>`).
    #[serde(rename = "ref")]
    pub reference: String,
    /// The facet to read; the result's card when absent.
    #[serde(default)]
    pub facet: Option<ResultFacet>,
    /// The facet's input object, as a run's own read takes it: a
    /// selection, a pattern, a path or a page's `next` as its cursor.
    #[serde(default)]
    pub input: Option<serde_json::Value>,
}

/// `self.off_record.results.read`'s answer: the run's own reader's reply.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum OffRecordResultRead {
    /// The result's card (no facet asked).
    Card { card: ResultCard },
    /// One page of the facet asked, as the run's reader answers it; its
    /// `next`, when present, reads on.
    Page {
        facet: ResultFacet,
        page: serde_json::Value,
    },
    /// The reader's refusal: an unknown reference, the run's served rows
    /// withheld from this caller, an invalid range or input.
    Denied { refusal: ResultReadRefusal },
}

/// `self.off_record.waits.get`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordWaitRequest {
    pub session_ref: String,
    pub run_ref: String,
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

/// `self.off_record.waits.answer`'s input: the reply to the wait the run
/// `run_ref` names is parked on now.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffRecordWaitAnswerRequest {
    pub session_ref: String,
    pub run_ref: String,
    /// The reply the parked step's call comes back with.
    pub reply: serde_json::Value,
    /// The wait this answer is for, as `waits.get` read it; when given, an
    /// answer for a wait the run has since left answers nothing.
    #[serde(default)]
    pub wait_id: Option<EntityId>,
    /// The wait's generation, as `waits.get` read it; checked like
    /// `wait_id`.
    #[serde(default)]
    pub generation: Option<u64>,
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

impl OffRecordResultRead {
    /// The run's reader's `reply` to a read of `facet` (its card when
    /// `None`), in its typed shape.
    ///
    /// # Errors
    ///
    /// A reply that is not the reader's own shape.
    pub fn of(reply: Value, facet: Option<ResultFacet>) -> MemoryResult<Self> {
        if reply.get("denied").is_some() {
            return Ok(Self::Denied {
                refusal: decode(reply)?,
            });
        }
        let output = reply.get("output").cloned().unwrap_or(Value::Null);
        Ok(match facet {
            None => Self::Card {
                card: decode(output)?,
            },
            Some(facet) => Self::Page {
                facet,
                page: output,
            },
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

fn decode<T: DeserializeOwned>(value: Value) -> MemoryResult<T> {
    serde_json::from_value(value).map_err(|_| {
        MemoryError::from(crate::Error::InvariantViolation(
            "a session run's result reply has its typed shape",
        ))
    })
}
