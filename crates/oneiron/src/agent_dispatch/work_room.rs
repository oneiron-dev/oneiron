//! The room an agent's run works in (ROOM-SCOPED-PINS P2c): the one room
//! whose shared pins the run's native board and self brief read. Engine
//! ruling THREADTASK-PINS-NATIVE Q1 = A (12 Nov): the room work comes first,
//! then the TASK the run serves; the first one present wins.

use super::AgentDispatchTarget;
use super::codec::record_dispatch_input;
use super::resident::resident_attempt_room_wake_turn;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::error::Result;
use crate::workspace_roster::{task_thread_room_in, turn_room_in};
use crate::{EntityId, Vault};

impl Vault {
    /// The room agent `agent`'s run of dispatch attempt `attempt` works in,
    /// read in one snapshot from the attempt's own engine-minted row. The
    /// sources are taken in this order, and the first one present wins:
    /// 1. the room work its dispatch froze at spawn (`AgentDispatchInput.room`,
    ///    OF-531);
    /// 2. for a resident's room wake, the room of the TURN that woke it,
    ///    named by the attempt's dedupe key and never by its briefing
    ///    (FIX 15647);
    /// 3. the room of the threads its TASK (`task_ref`) is bound into.
    ///
    /// `None` for an attempt that is gone, that is not a dispatch of `agent`,
    /// or that names none of these. `None` also for a TASK bound into threads
    /// of more than one room, or into a thread whose binding turn is gone.
    /// The room only selects which room's pin list the run reads; it grants
    /// nothing. Each pin still needs the agent's standing in that room and a
    /// read of its target through the room's lane.
    ///
    /// # Errors
    ///
    /// A store read failed, the attempt's TASK ref is no entity id, or the
    /// TASK's binding rows disagree with their turns.
    pub fn agent_run_work_room(
        &self,
        attempt: AttemptId,
        agent: EntityId,
    ) -> Result<Option<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let Some(record) = AttemptQueue::new(self).get_in_txn(&txn, attempt)? else {
            return Ok(None);
        };
        let Some(input) = record_dispatch_input(&record) else {
            return Ok(None);
        };
        if input.target != AgentDispatchTarget::Custom(agent) {
            return Ok(None);
        }
        if let Some(work) = input.room {
            return Ok(Some(work.room));
        }
        if let Some(turn) = resident_attempt_room_wake_turn(&record, agent) {
            return turn_room_in(self, &txn, turn);
        }
        let Some(task) = record.task_ref.as_deref() else {
            return Ok(None);
        };
        task_thread_room_in(self, &txn, EntityId::from_hex(task)?)
    }
}
