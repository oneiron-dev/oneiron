//! A settled resident's room wakes (FIX 15647): a room turn that addresses
//! the resident, or whose thread's open TASK it holds, dispatches it once,
//! under its wake mode.
//!
//! The room's witness staged each wake in its own write
//! ([`crate::workspace_roster::ROOM_WAKE_ATTEMPT_KIND`]); the inbox pass reads
//! the staged wakes of its resident, reads each live again
//! ([`crate::Vault::room_wake_turn`]) and settles it once taken. Wake mode
//! decides as for messages: `AllAddressed` wakes on every such turn,
//! `HumanMessages` only on one a PERSON spoke, and `Manual` never. The
//! briefing names the room and the turn by ref and copies none of the turn:
//! the resident reads the room with its own reads, so one admitted from now
//! on reads no earlier history (owner ruling 2026-10-20).

use std::collections::HashSet;

use super::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher,
    AgentSpawnContext, DispatchAgent, ResidentAgentSpec, ResidentWakeMode, resident_run_id,
};
use crate::EntityId;
use crate::attempt_queue::AttemptRecord;
use crate::context_projection::ContextSpec;
use crate::error::Result;
use crate::workspace_roster::RoomWake;

/// The dedupe-key segment that marks a resident's room wake.
const ROOM_WAKE_KEY: &str = "room";

/// A resident's room wake key: its agent and the turn that woke it, once.
fn room_wake_key(agent: EntityId, turn: EntityId) -> String {
    format!(
        "resident:{}:{ROOM_WAKE_KEY}:{}",
        agent.to_hex(),
        turn.to_hex()
    )
}

/// Whether `attempt`, a run of resident `agent`, was dispatched for a room
/// turn: its engine-minted dedupe key says so, never its briefing. A retry
/// keeps its source's key.
#[must_use]
pub fn resident_attempt_wakes_for_room(attempt: &AttemptRecord, agent: EntityId) -> bool {
    let prefix = format!(
        "{AGENT_DISPATCH_ATTEMPT_TYPE}:resident:{}:{ROOM_WAKE_KEY}:",
        agent.to_hex()
    );
    attempt
        .dedupe_key
        .as_deref()
        .is_some_and(|key| key.starts_with(&prefix))
}

/// The briefing a room wake's run reads: the room and the turn, by ref.
fn room_wake_briefing(wake: &RoomWake) -> String {
    format!(
        "a room turn woke you; read the room through your own reads.\nroom: {}\nturn: {}\n",
        wake.room.to_hex(),
        wake.turn.to_hex()
    )
}

impl AgentDispatcher<'_> {
    /// Dispatches resident `spec`'s staged room wakes under its wake mode,
    /// each at most once (`woken` holds the keys its run already took), and
    /// settles each one taken, woken or not. Stops, leaving the rest staged,
    /// once `outcomes` holds `limit` new dispatches.
    pub(super) fn dispatch_resident_room_wakes(
        &self,
        spec: &ResidentAgentSpec,
        woken: &HashSet<String>,
        limit: usize,
        now: u64,
        outcomes: &mut Vec<AgentDispatchOutcome>,
    ) -> Result<()> {
        let agent = spec.agent_def_ref;
        let mut settled = Vec::new();
        for staged in self.vault.staged_room_wakes()? {
            if staged.wake.agent != agent {
                continue;
            }
            let wakes = match spec.wake {
                ResidentWakeMode::Manual => false,
                mode => self
                    .vault
                    .room_wake_turn(&staged.wake)?
                    .is_some_and(|turn| {
                        mode == ResidentWakeMode::AllAddressed || turn.speaker_is_person
                    }),
            };
            let key = room_wake_key(agent, staged.wake.turn);
            if wakes && !woken.contains(&format!("{AGENT_DISPATCH_ATTEMPT_TYPE}:{key}")) {
                if outcomes.len() >= limit.min(64) {
                    break;
                }
                let outcome = self.dispatch_with_context(
                    DispatchAgent {
                        target: AgentDispatchTarget::Custom(agent),
                        parent_attempt: None,
                        dedupe_key: Some(key),
                        run_id: Some(resident_run_id(agent)),
                        now,
                    },
                    AgentSpawnContext {
                        context_spec: Some(ContextSpec {
                            briefing: Some(room_wake_briefing(&staged.wake)),
                            ..ContextSpec::default()
                        }),
                        ..AgentSpawnContext::default()
                    },
                )?;
                if !matches!(outcome, AgentDispatchOutcome::Existing(_)) {
                    outcomes.push(outcome);
                }
            }
            settled.push(staged.attempt);
        }
        self.vault.settle_room_wakes(&settled, now)
    }
}
