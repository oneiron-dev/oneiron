//! Room-bound launches (OF-531). An agent launched to work in a room carries
//! the room in its dispatch input, and every launch transaction (a spawn, and
//! each workflow leaf at its release) re-proves the agent's join there, for
//! exactly that room or thread, against live facts before it reserves or
//! enqueues anything. The receipt it proved is frozen beside the room.
//! Without a room a launch is exactly as before.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::workspace_roster::{JoinReceiptRef, RoomWork};

use super::types::{KEY_JOIN, KEY_ROOM};
use super::{AgentDispatchInput, AgentDispatcher, SpendScopeId};

impl AgentDispatcher<'_> {
    /// `agent`'s join in `room`, re-proved in the launch's transaction. A
    /// room-bound launch is paid work: it spends under `scope`, the scope it
    /// reserves under, whose root carries its payer's consent. A launch with
    /// no such scope is refused, never run on anyone else's funds. The join
    /// is its subject's (OF-529): a PERSON-anchored pen's person, else the
    /// agent itself.
    pub(super) fn require_room_join_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        room: Option<&RoomWork>,
        agent: EntityId,
        scope: Option<&SpendScopeId>,
    ) -> Result<Option<JoinReceiptRef>> {
        let Some(work) = room else {
            return Ok(None);
        };
        let scope =
            scope.ok_or_else(|| invalid("a room-bound launch spends under its payer's scope"))?;
        let subject = crate::workspace_roster::join_subject_for_actor_in_txn(
            self.vault,
            txn,
            agent,
            self.vault.store.clock.now_recorded_at(),
        )?;
        crate::workspace_roster::require_join_for_branch_in_txn(
            self.vault,
            txn,
            work.room,
            work.branch,
            &subject,
            Some(scope),
        )
        .map(Some)
    }
}

/// Encodes the room and its proved join; each is elided when absent.
pub(super) fn encode_room_keys(
    input: &AgentDispatchInput,
    entries: &mut Vec<(Value, Value)>,
) -> Result<()> {
    if let Some(room) = &input.room {
        let json = serde_json::to_string(room).map_err(|_| invalid("room must encode"))?;
        entries.push((Value::from(KEY_ROOM), Value::from(json)));
    }
    if let Some(join) = &input.join {
        entries.push((Value::from(KEY_JOIN), Value::from(join.as_str())));
    }
    Ok(())
}

pub(super) fn decode_room(value: &Value) -> Result<RoomWork> {
    let json = value
        .as_str()
        .ok_or_else(|| invalid("room must be a serialized room"))?;
    serde_json::from_str(json).map_err(|_| invalid("room must decode as a room"))
}

pub(super) fn decode_join(value: &Value) -> Result<JoinReceiptRef> {
    JoinReceiptRef::parse(
        value
            .as_str()
            .ok_or_else(|| invalid("join must be a join receipt ref"))?,
    )
}

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(reason))
}
