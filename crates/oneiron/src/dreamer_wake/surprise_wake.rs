//! The wake at a surprising save (FIX 11317, the Engine's ruling (b)): a
//! re-tag whose surprise reaches the wake policy's floor offers the turn
//! wake, at its save, to every agent a surprise may wake. The window is due on
//! the surprise test alone (FIX 11410): the agent's role admits a surprise
//! wake, so its cadence dial never fires at a save. Each agent first notes a
//! refusal dial its owner moved (OF-533), and the programs the wake owes are
//! admitted after it (DOOR-141), as the host's turn wake does. No wake kind of
//! its own, and the re-dirty carrier still puts the turn in the next window.

use crate::Vault;
use crate::agent_def::decode_agent_definition;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::vault::LiveEntityRow;

use super::policy::AgentWakeSignals;
use super::scheduling::{surprise_floor_in_txn, surprises};

impl Vault {
    /// The turn wake of every agent whose role a surprise alone wakes, for a
    /// save whose re-tag measured `surprise` beside the set it replaced: none
    /// when that is below the wake policy's surprise floor. Each wake is
    /// [`Self::wake_dreamer_on_surprise`] for that agent, in its own commit,
    /// after its refusal dial note; the first one due queues the window and
    /// moves the Micro watermark, so a later one finds the window read. The
    /// programs owed are admitted once all are offered. Returns whether any
    /// wake was queued.
    pub(crate) fn wake_agents_on_surprise(&self, surprise: f32, now: u64) -> Result<bool> {
        let agents = self.surprise_wakeable_agents(surprise)?;
        let mut queued = false;
        for &id in &agents {
            // An agent waking under a dial its owner moved notes the move in
            // its own diary before it acts again (OF-533).
            if let Err(error) = self.note_refusal_dial_change(id) {
                tracing::warn!(
                    kind = ?error.kind(),
                    agent = %id.to_hex(),
                    "refusal dial note not written"
                );
            }
            queued |= self.wake_dreamer_on_surprise(id, now)?;
        }
        if !agents.is_empty() {
            self.admit_owed_turn_programs(now);
        }
        Ok(queued)
    }

    /// DOOR-141, as the host's turn wake runs it: every owed program wake is
    /// admitted, a batch at a time, until none is left. A failure is logged;
    /// the wakes it leaves wait for the next turn or the next boot.
    fn admit_owed_turn_programs(&self, now: u64) {
        loop {
            match self.wake_turn_programs(now) {
                Ok(drain) if drain.more => {}
                Ok(_) => return,
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "turn program wakes not admitted");
                    return;
                }
            }
        }
    }

    /// The live agents whose role triggers admit a surprise wake under the
    /// stored policy row, when `surprise` reaches its floor: the turn wake's
    /// own test on a surprise signal alone, with no cadence ordinal. A
    /// definition that does not decode wakes at no turn either, and is left.
    fn surprise_wakeable_agents(&self, surprise: f32) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        if !surprises(surprise, surprise_floor_in_txn(self, &txn)?) {
            return Ok(Vec::new());
        }
        let policy = super::policy::policy_in_txn(self, &txn)?;
        let signals = AgentWakeSignals {
            surprise: true,
            ..AgentWakeSignals::default()
        };
        let ids = self
            .store
            .port_entity_ids_by_type(&txn, ENTITY_TYPE_AGENT_DEF, None)?
            .collect::<Result<Vec<_>>>()?;
        let mut wakeable = Vec::new();
        for id in ids {
            let LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_AGENT_DEF,
                body,
            } = crate::vault::live_entity_row_in_txn(&self.store, &txn, &id)?
            else {
                continue;
            };
            if decode_agent_definition(&body)
                .is_ok_and(|definition| definition.dream_wake_due(&policy, 0, signals))
            {
                wakeable.push(id);
            }
        }
        Ok(wakeable)
    }
}
