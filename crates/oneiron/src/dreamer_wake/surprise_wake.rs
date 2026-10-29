//! The wake at a surprising save (FIX 11317, the Engine's ruling (b)): a
//! re-tag whose surprise reaches the wake policy's floor offers the turn
//! wake, at its save, to every agent a surprise may wake. The turn wake
//! decides each one as it does at a turn: it reads the window's saved tags
//! against the floor and the agent's role triggers. No wake kind of its own,
//! and the re-dirty carrier still puts the turn in the next window.

use crate::Vault;
use crate::agent_def::decode_agent_definition;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::vault::LiveEntityRow;

use super::policy::AgentWakeSignals;
use super::scheduling::{WakeTurnSubject, surprise_floor_in_txn, surprises};

impl Vault {
    /// The turn wake of every agent whose role a surprise alone wakes, for a
    /// save whose re-tag measured `surprise` beside the set it replaced: none
    /// when that is below the wake policy's surprise floor. Each wake is
    /// [`Self::wake_dreamer_on_turn`] for that agent, in its own commit; the
    /// first one due queues the window and moves the Micro watermark, so a
    /// later one finds the window read. Returns whether any wake was queued.
    pub(crate) fn wake_agents_on_surprise(&self, surprise: f32, now: u64) -> Result<bool> {
        let mut queued = false;
        for id in self.surprise_wakeable_agents(surprise)? {
            let subject = WakeTurnSubject::Agent {
                id,
                signals: AgentWakeSignals::default(),
            };
            queued |= self.wake_dreamer_on_turn(subject, now)?;
        }
        Ok(queued)
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
