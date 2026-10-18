//! The objectives an agent run confesses against (OF-544), kept with its
//! attempt from its first claim.
//!
//! A run whose dispatch carries no objectives takes them from a live read
//! (its TASK brief's done-means, a planned need, a briefing, a definition's
//! `desc`). Read again at each claim, a brief revised while the run waits
//! would change its bound task text, and its re-entry would refuse as config
//! drift. So the pump chooses them once, at the first claim, and every later
//! claim of that attempt reads them back. A run continued from a failed one
//! (FIX 3694) runs the source's task, which carries the source's ask: it
//! confesses against the objectives its predecessor was asked.

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::attempt_queue::AttemptId;
use crate::engine_executor::continuation::run_continuation;
use crate::side_table::{self, Named, SideTable};

use super::AgentDispatcher;

/// The objectives each claimed run was asked. Key: the attempt's 16 bytes.
const RUN_OBJECTIVES: SideTable<[u8; 16], RunObjectives, Named> =
    SideTable::new(&side_table::AGENT_DISPATCH_RUN_OBJECTIVES);

/// One run's confession objectives, as chosen at its first claim. Empty: the
/// run is asked no confession.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunObjectives {
    objectives: Vec<String>,
}

impl AgentDispatcher<'_> {
    /// The objectives `attempt` confesses against: the ones kept at its
    /// first claim; else, for a continued run, the ones its predecessor was
    /// asked; else the ones `choose` reads now. The answer is kept for the
    /// attempt's later claims; a row already kept wins over a new choice.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn claimed_run_objectives(
        &self,
        attempt: AttemptId,
        choose: impl FnOnce() -> Vec<String>,
    ) -> Result<Vec<String>> {
        let key = *attempt.as_bytes();
        let inherited = {
            let txn = self.vault.store.env.read_txn()?;
            if let Some(kept) = RUN_OBJECTIVES.get(&self.vault.store, &txn, &key)? {
                return Ok(kept.objectives);
            }
            drop(txn);
            match run_continuation(self.vault, attempt)? {
                Some(continuation) => {
                    let txn = self.vault.store.env.read_txn()?;
                    RUN_OBJECTIVES.get(
                        &self.vault.store,
                        &txn,
                        continuation.predecessor.as_bytes(),
                    )?
                }
                None => None,
            }
        };
        // The choice reads the vault on its own snapshots: never inside the
        // writer below.
        let chosen = inherited.unwrap_or_else(|| RunObjectives {
            objectives: choose(),
        });
        self.vault.with_write_txn_grouped(|txn| {
            if let Some(kept) = RUN_OBJECTIVES.get(&self.vault.store, txn, &key)? {
                return Ok(kept.objectives);
            }
            RUN_OBJECTIVES.put(&self.vault.store, txn, &key, &chosen)?;
            Ok(chosen.objectives)
        })
    }
}
