//! The condition an automatic re-entry of a parked `execute` run
//! carries to its host (FIX 4606), and what the host answers it.
//!
//! A re-entry is readied for one wait at one replay generation. A caller's
//! own call of the same run can take the run's single flight first,
//! consume the reply and move the record on. The host therefore reads the
//! record again once the single flight and the run permit are the
//! re-entry's own. A record that moved runs no batch for that re-entry.

use oneiron::code_run::{CodeRunReplayGeneration, WaitKey};
use oneiron::engine_executor::{EngineExecutorOutcome, code_run_position};
use oneiron::{EntityId, Vault};

/// What must still exist when the host takes a resumed run's single flight.
/// An automatic re-entry also names its parked wait and replay generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpCodeRunResumeCondition {
    run_id: EntityId,
    parked: Option<(WaitKey, CodeRunReplayGeneration)>,
}

impl McpCodeRunResumeCondition {
    /// The condition of a re-entry readied for `wait` while the run's record
    /// stood at `generation`.
    #[must_use]
    pub(crate) const fn new(wait: WaitKey, generation: CodeRunReplayGeneration) -> Self {
        Self {
            run_id: wait.run,
            parked: Some((wait, generation)),
        }
    }

    /// A caller's own resume can take any current generation, but never
    /// starts a new run when the handle no longer resolves.
    pub(crate) const fn existing(run_id: EntityId) -> Self {
        Self {
            run_id,
            parked: None,
        }
    }

    /// Whether the run's committed record still stands where the re-entry
    /// was readied: at the same replay generation, and parked on the same
    /// wait. A record that is gone or does not read, an erased one
    /// included, does not stand there.
    #[must_use]
    pub fn stands(&self, vault: &Vault) -> bool {
        let Some((wait, generation)) = self.parked else {
            return vault
                .get_code_run_replay_record(&self.run_id)
                .is_ok_and(|record| record.is_some());
        };
        match code_run_position(vault, self.run_id) {
            Ok(Some(position)) => {
                position.generation == generation && position.parked_wait == Some(wait)
            }
            Ok(None) => false,
            Err(error) => {
                tracing::warn!(
                    %error,
                    run = %self.run_id.to_hex(),
                    "a parked MCP code run's record did not read again; its re-entry runs nothing"
                );
                false
            }
        }
    }
}

/// What a host answers one automatic re-entry (FIX 4606).
#[derive(Debug)]
pub enum McpCodeRunResumed {
    /// The run still stood where the re-entry was readied, and ran this
    /// batch.
    Entered(Box<EngineExecutorOutcome>),
    /// The run had left the wait or the generation the re-entry was readied
    /// for, so no batch ran. This is not a run failure: another entry of the
    /// run already took it on.
    Superseded,
}
