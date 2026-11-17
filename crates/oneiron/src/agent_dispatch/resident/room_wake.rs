//! A settled resident's room wakes (FIX 15647): a room turn that addresses
//! the resident, or whose thread's open TASK it holds, dispatches it once,
//! under its wake mode and its wake hold (AGM-4 = C).
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
//!
//! The hold works room by room. The first waking turn of a room opens it at
//! its staging instant, and the turns of that room staged before it ends
//! join one wake, up to [`WAKE_CARRY_LIMIT`]. Until then they stay staged,
//! so a restart keeps the hold. The wake's dedupe key names its first turn,
//! which the run works in (ROOM-SCOPED-PINS P2c), and its dispatch input
//! carries the other turns' keys. A room wake never carries another room's
//! turn or an inbox message: its run works in its one room.
//!
//! A project's home room wakes the project's leader under the project's
//! leader binding (UNBUILT3-22): that binding's wake mode and hold apply to
//! the room, and its wake runs stamped with the project, in the room. A turn
//! the project's goal intake took wakes no resident run: the intake answers
//! it (RULING GOAL-INTAKE-DRAFT-RUN = A). Every other room takes the agent's
//! own binding, and with none it is no resident wake of this pass.

use std::collections::{BTreeMap, HashSet};

use super::project_leader::RoomWakePolicy;
use super::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher,
    AgentSpawnContext, DispatchAgent, ResidentAgentSpec, ResidentInboxDispatch, ResidentWakeMode,
    WAKE_CARRY_LIMIT, resident_run_id,
};
use crate::EntityId;
use crate::attempt_queue::AttemptRecord;
use crate::context_projection::ContextSpec;
use crate::error::Result;
use crate::workspace_roster::StagedRoomWake;

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
    attempt
        .dedupe_key
        .as_deref()
        .is_some_and(|key| key.starts_with(&room_wake_attempt_key_prefix(agent)))
}

/// The room turn whose wake dispatched `attempt`, a run of resident `agent`
/// (ROOM-SCOPED-PINS P2c): read from its engine-minted dedupe key, never its
/// briefing. `None` for any other run. A retry keeps its source's key.
pub(crate) fn resident_attempt_room_wake_turn(
    attempt: &AttemptRecord,
    agent: EntityId,
) -> Option<EntityId> {
    let turn = attempt
        .dedupe_key
        .as_deref()?
        .strip_prefix(&room_wake_attempt_key_prefix(agent))?;
    EntityId::from_hex(turn).ok()
}

/// What every room wake attempt key of resident `agent` starts with; the
/// waking turn follows it.
fn room_wake_attempt_key_prefix(agent: EntityId) -> String {
    format!(
        "{AGENT_DISPATCH_ATTEMPT_TYPE}:resident:{}:{ROOM_WAKE_KEY}:",
        agent.to_hex()
    )
}

/// The briefing a room wake's run reads: the room and each turn it
/// carries, by ref, first turn first.
fn room_wake_briefing(room: EntityId, turns: &[StagedRoomWake]) -> String {
    let mut briefing = if turns.len() > 1 {
        format!(
            "room turns woke you; read the room through your own reads.\nroom: {}\n",
            room.to_hex()
        )
    } else {
        format!(
            "a room turn woke you; read the room through your own reads.\nroom: {}\n",
            room.to_hex()
        )
    };
    for staged in turns {
        briefing.push_str(&format!("turn: {}\n", staged.wake.turn.to_hex()));
    }
    briefing
}

impl AgentDispatcher<'_> {
    /// Dispatches resident `agent`'s staged room wakes, each under the
    /// policy of its room: the leader binding of the project whose home room
    /// it is, else `own`, the agent's own binding. Each turn wakes it at
    /// most once (`woken` holds the keys its run already took), and each
    /// one taken settles, woken or not. A turn that does not wake it settles
    /// at once; a waking turn whose room's hold still runs stays staged, and
    /// `pass` records when that hold falls due. A wake no binding takes is
    /// left staged. Stops, leaving the rest staged, once `pass` holds
    /// `limit` new dispatches.
    pub(super) fn dispatch_resident_room_wakes(
        &self,
        agent: EntityId,
        own: Option<&ResidentAgentSpec>,
        woken: &HashSet<String>,
        limit: usize,
        now: u64,
        pass: &mut ResidentInboxDispatch,
    ) -> Result<()> {
        let mut settled = Vec::new();
        let mut rooms: BTreeMap<EntityId, (RoomWakePolicy, Vec<StagedRoomWake>)> = BTreeMap::new();
        for staged in self.vault.staged_room_wakes()? {
            if staged.wake.agent != agent {
                continue;
            }
            let policy = {
                let txn = self.vault.store.env.read_txn()?;
                self.vault
                    .room_wake_policy_in_txn(&txn, agent, staged.wake.room, own)?
            };
            let Some(policy) = policy else {
                continue;
            };
            let wakes = match policy.wake {
                ResidentWakeMode::Manual => false,
                mode => self
                    .vault
                    .room_wake_turn(&staged.wake)?
                    .is_some_and(|turn| {
                        mode == ResidentWakeMode::AllAddressed || turn.speaker_is_person
                    }),
            };
            let taken_by_intake = match policy.project {
                Some(project) => self.goal_intake_took_turn(project, staged.wake.turn)?,
                None => false,
            };
            let key = room_wake_key(agent, staged.wake.turn);
            if wakes
                && !taken_by_intake
                && !woken.contains(&format!("{AGENT_DISPATCH_ATTEMPT_TYPE}:{key}"))
            {
                rooms
                    .entry(staged.wake.room)
                    .or_insert_with(|| (policy, Vec::new()))
                    .1
                    .push(staged);
            } else {
                settled.push(staged.attempt);
            }
        }
        'rooms: for (room, (policy, mut turns)) in rooms {
            let hold = u64::from(policy.wake_hold_secs);
            turns.sort_by_key(|staged| (staged.staged_at, staged.attempt));
            let mut rest = turns.as_slice();
            while let Some(first) = rest.first() {
                let due = first.staged_at.saturating_add(hold);
                if now < due {
                    pass.hold(due);
                    continue 'rooms;
                }
                if pass.outcomes.len() >= limit.min(64) {
                    break 'rooms;
                }
                let (carried, after) = rest.split_at(rest.len().min(WAKE_CARRY_LIMIT));
                rest = after;
                let context = AgentSpawnContext {
                    context_spec: Some(ContextSpec {
                        briefing: Some(room_wake_briefing(room, carried)),
                        ..ContextSpec::default()
                    }),
                    carried_wake_keys: carried[1..]
                        .iter()
                        .map(|staged| room_wake_key(agent, staged.wake.turn))
                        .collect(),
                    ..AgentSpawnContext::default()
                };
                // A project's room wake runs in the project, from its room.
                let context = match policy.project {
                    Some(project) => context.with_project(project).with_origin_conversation(room),
                    None => context,
                };
                let outcome = self.dispatch_with_context(
                    DispatchAgent {
                        target: AgentDispatchTarget::Custom(agent),
                        parent_attempt: None,
                        dedupe_key: Some(room_wake_key(agent, first.wake.turn)),
                        run_id: Some(resident_run_id(agent)),
                        now,
                    },
                    context,
                )?;
                if !matches!(outcome, AgentDispatchOutcome::Existing(_)) {
                    pass.outcomes.push(outcome);
                }
                settled.extend(carried.iter().map(|staged| staged.attempt));
            }
        }
        self.vault.settle_room_wakes(&settled, now)
    }
}
