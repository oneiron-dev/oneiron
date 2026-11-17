//! Who asked the host to step a run (LEARN-GRANT = A): the verified caller
//! of `vault.coach.training_runs.execute`, carried to each writer an execute
//! starts (the dispatch, a hold, the evaluation claim), so that writer
//! admits the caller again in its own snapshot. The Coach's own steps carry
//! none: the owner's authorization of the run is their standing.

use crate::Vault;
use crate::authority::{NoStanding, PACT_STANDING_LAPSED, principal_standing_or_lapse_in_txn};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::memory::MemoryResult;
use crate::verbs::TRAINING_RUN_EXECUTE_VERB;

/// What a writer answers a caller its snapshot no longer admits.
const EXECUTE_CALLER_REFUSED: &str = "the run's execute caller is neither the vault owner nor an agent a live Grant lists the verb for";

/// The caller an execute admitted: an identity a writer checks, never a
/// standing of its own. A caller the writer does not admit stops that write;
/// the run stays where it stood.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrainingRunCaller {
    actor: EntityId,
    class: EdgeActorClass,
}

impl TrainingRunCaller {
    #[must_use]
    pub const fn new(actor: EntityId, class: EdgeActorClass) -> Self {
        Self { actor, class }
    }

    /// Why `verb` does not admit this caller in `txn`, or `None` when it
    /// does: the vault owner, or an agent one live Grant from a live owner
    /// names and lists `verb` for.
    pub(crate) fn refusal_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        verb: &str,
    ) -> MemoryResult<Option<&'static str>> {
        if crate::memory::actor_is_vault_owner_in_txn(vault, txn, self.actor, self.class)? {
            return Ok(None);
        }
        if self.class != EdgeActorClass::Agent {
            return Ok(Some("the caller is neither the vault owner nor an agent"));
        }
        Ok(
            match principal_standing_or_lapse_in_txn(
                vault,
                txn,
                self.actor,
                EdgeActorClass::Agent,
                verb,
            )? {
                Ok(standing) if standing.grant.is_some() => None,
                Err(NoStanding::PactStandingLapsed) => Some(PACT_STANDING_LAPSED),
                Ok(_) | Err(NoStanding::NotStanding) => {
                    Some("no live Grant from a live owner names this agent and lists the verb")
                }
            },
        )
    }

    /// The writer's own admission of the execute caller in `txn`.
    ///
    /// # Errors
    ///
    /// `AuthorityRefused` for a caller `txn` does not admit, the reading
    /// error itself carried as `InvalidConfig` by its code and text.
    pub(crate) fn admit_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<()> {
        match self.refusal_in_txn(vault, txn, TRAINING_RUN_EXECUTE_VERB) {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Err(Error::Record(RecordError::AuthorityRefused(
                EXECUTE_CALLER_REFUSED,
            ))),
            Err(error) => Err(Error::InvalidConfig(format!(
                "the execute caller's admission did not read: {}: {}",
                error.code, error.message
            ))),
        }
    }
}

/// The writer's admission of `caller`, when an execute started the write.
pub(crate) fn admit_caller_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: Option<&TrainingRunCaller>,
) -> Result<()> {
    caller.map_or(Ok(()), |caller| caller.admit_in_txn(vault, txn))
}
