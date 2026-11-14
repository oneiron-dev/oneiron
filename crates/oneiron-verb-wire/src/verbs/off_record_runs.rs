//! Moved from `crates/oneiron/src/verbs/off_record_runs.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::result_doors::types::ResultCard;
use crate::memory::result_doors::types::ResultReadRefusal;
use crate::memory::result_facet::ResultFacet;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

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

pub fn decode<T: DeserializeOwned>(value: Value) -> MemoryResult<T> {
    serde_json::from_value(value).map_err(|_| {
        MemoryError::from(oneiron_base::error::Error::InvariantViolation(
            "a session run's result reply has its typed shape",
        ))
    })
}
