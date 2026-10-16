//! OF-221: the conversation that started a dispatch.
//!
//! The host stamps it on a ROOT dispatch at its admission boundary
//! ([`AgentSpawnContext::origin_conversation`](super::AgentSpawnContext));
//! it rides the payload as one more pinned key, and every child takes its
//! parent's stored value, so a spawning agent can neither name nor drop one.
//! A retry reuses its source's payload and so keeps it. Only a job whose
//! payload carries a stamp ever links its notification to a conversation;
//! nothing is inferred from run ids, home conversations or the material a
//! job reads.

use rmpv::Value;

use super::dispatch::AgentDispatcher;
use super::types::{AGENT_DISPATCH_ATTEMPT_TYPE, KEY_ORIGIN_CONVERSATION};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::dreamer_runner::{DreamerAttemptPayload, decode_dreamer_attempt_payload};
use crate::entity_id::EntityId;
use crate::error::Result;

/// The origin conversation an agent-dispatch payload carries; `None` for any
/// other payload and for an unstamped one.
pub(crate) fn dispatch_origin_conversation(payload: &DreamerAttemptPayload) -> Option<EntityId> {
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return None;
    }
    let Value::Map(entries) = &payload.input else {
        return None;
    };
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(KEY_ORIGIN_CONVERSATION))
        .and_then(|(_, value)| value.as_str())
        .and_then(|hex| EntityId::from_hex(hex).ok())
}

/// `input`, an encoded dispatch map, with `origin` stamped on it; unchanged
/// when there is none.
pub(super) fn with_origin_conversation(input: Value, origin: Option<EntityId>) -> Value {
    match (input, origin) {
        (Value::Map(mut entries), Some(origin)) => {
            entries.push((
                Value::from(KEY_ORIGIN_CONVERSATION),
                Value::from(origin.to_hex()),
            ));
            Value::Map(entries)
        }
        (input, _) => input,
    }
}

impl AgentDispatcher<'_> {
    /// The origin a new dispatch stores: the host's stamp for a root, the
    /// parent's stored origin for a child (whatever the child's spawn named).
    pub(super) fn origin_conversation_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        parent: Option<AttemptId>,
        stamped: Option<EntityId>,
    ) -> Result<Option<EntityId>> {
        let Some(parent) = parent else {
            return Ok(stamped);
        };
        Ok(AttemptQueue::new(self.vault)
            .get_in_txn(txn, parent)?
            .and_then(|record| decode_dreamer_attempt_payload(&record.payload).ok())
            .and_then(|payload| dispatch_origin_conversation(&payload)))
    }
}
