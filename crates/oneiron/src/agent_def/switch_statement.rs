//! The owner's statement of an agent definition's switches (Fable pass 28 R2d; Engine RULING
//! AGENT-DEF-OWN-LANE-FIX = B, 16 Nov 02:21).
//!
//! Turning a definition back on or moving its models is the owner's alone (`super::widening`).
//! On the commit path the owner's door is the one that may do it. A row another install
//! brings carries no proof of who widened it, so before this module an own machine's row was
//! believed as it came, and a federation peer's refused. Now the owner's door states the
//! switches it writes in a grant act of family `agent_definition` on the authority log, and
//! every install lands a replicated row that widens its stored definition only within the
//! switches the vault's owner last stated. Beyond them, or with no statement standing, the row
//! waits (dependency-pending) for the statement to arrive. The honest re-enable on another
//! device lands once its act has; a forged or replayed row that goes beyond the owner's last
//! statement confers nothing anywhere.
//!
//! A statement is appended when the owner's edit widens the stored definition, when it changes
//! switches the owner stated before (his own turn-off replaces the statement, so a replay of
//! the old "on" row waits), and when no statement covers switches that would widen a definition
//! anywhere (his first edit of a running definition, or his save again after a statement this
//! install could not carry). A turn-off by a writer below the owner takes no act, so a replay
//! of the owner's last stated row after it still lands (FIX row filed with R2d). An owner-grade
//! generic batch states the switches it writes as the owner's door does, in the rollback scope
//! of its puts, and its answer carries the same notice when one lands on this install alone.

use crate::Vault;
use crate::authority::{ActSurface, AgentSwitches, GrantActBy, GrantActChange, GrantFamily};
use crate::entity_id::EntityId;
#[cfg(feature = "sync")]
use crate::error::ArtifactError;
use crate::error::{Error, RecordError, Result, SecretError};

use super::codec::decode_agent_definition;
use super::types::AgentDefinition;
use super::widening::{agent_definition_put_widens_in_txn, agent_switches, switches_widen};

/// The refusal of a replicated row that widens an agent definition beyond the switches its
/// owner last stated: it waits for the owner's statement, a dependency, not a verdict on the
/// row.
#[cfg(feature = "sync")]
const OWNER_STATEMENT_PENDING: &str =
    "an agent definition widening waits for its owner's statement of those switches";

/// Whether `error` is the refusal of a widening row that waits for its owner's statement.
#[cfg(feature = "sync")]
pub(crate) fn owner_statement_pending(error: &Error) -> bool {
    matches!(
        error,
        Error::Artifact(ArtifactError::InvalidAgentDefBody(OWNER_STATEMENT_PENDING))
    )
}

/// Whether the owner's agent definition edit reaches his other installs (Engine RULING
/// R2D-NO-CARRIER-POLICY = B, 16 Nov 06:59): his answer shows [`Self::notice`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentSwitchesReach {
    /// Every install lands the edit: it needed no statement, or its statement is on the
    /// authority log.
    EveryInstall,
    /// The edit widened switches this install could not state on the authority log: it
    /// landed here alone, and the owner's other installs keep the old setting until a later
    /// statement.
    ThisInstallOnly,
}

impl AgentSwitchesReach {
    /// What the owner's answer tells him; `None` when every install lands the edit.
    #[must_use]
    pub fn notice(self) -> Option<&'static str> {
        match self {
            Self::EveryInstall => None,
            Self::ThisInstallOnly => Some(
                "Saved on this device only. Your other devices keep the old setting until this \
                 device has its install key and you save the change again.",
            ),
        }
    }
}

/// The reach each agent definition an owner-grade batch put took, by the id it was written
/// at, recorded in the batch's writer and readable once the batch has committed (R2d review
/// finding 6): the batch's answer carries [`AgentSwitchesReach::notice`] per definition.
#[derive(Debug, Clone, Default)]
pub(crate) struct AgentSwitchesReaches(
    std::sync::Arc<std::sync::Mutex<Vec<(EntityId, AgentSwitchesReach)>>>,
);

impl AgentSwitchesReaches {
    /// Records `reaches`, replacing any earlier record.
    fn replace(&self, reaches: Vec<(EntityId, AgentSwitchesReach)>) -> Result<()> {
        *self
            .0
            .lock()
            .map_err(|_| Error::InvariantViolation("agent switches reaches"))? = reaches;
        Ok(())
    }

    /// The notice for the definition written at `id`: `Some` when a put of it landed on this
    /// install alone.
    pub(crate) fn notice_for(&self, id: &EntityId) -> Option<&'static str> {
        let recorded = self.0.lock().ok()?;
        recorded
            .iter()
            .filter(|(put, _)| put == id)
            .find_map(|(_, reach)| reach.notice())
    }
}

impl Vault {
    /// The switches the vault's owner last stated for agent definition `id`, read in `txn`:
    /// the one counted statement on its line, when the person who made it is a live owner of
    /// the vault now, a shared vault's by a counted Owner giving
    /// ([`crate::policy_model::is_live_vault_owner_in_txn`]). `None` when no statement
    /// stands.
    ///
    /// # Errors
    ///
    /// A store, owner census or authority-fold read failure.
    pub(crate) fn owner_stated_agent_switches_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
    ) -> Result<Option<AgentSwitches>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let Some((giver, switches)) = fold.stated_agent_switches(id) else {
            return Ok(None);
        };
        if !crate::policy_model::is_live_vault_owner_in_txn(self, txn, &giver)? {
            return Ok(None);
        }
        Ok(Some(switches.clone()))
    }

    /// The refusal a replicated put of `body` at agent definition `id` waits on, read in
    /// `txn`: `Some` when the put widens the stored definition and goes beyond the switches
    /// the owner last stated, or no statement stands. `None` for a put that widens nothing,
    /// and for one within the statement.
    ///
    /// # Errors
    ///
    /// A body that does not decode; a store, owner census or authority-fold read failure.
    #[cfg(feature = "sync")]
    pub(crate) fn unstated_agent_widening_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        body: &[u8],
    ) -> Result<Option<Error>> {
        if !agent_definition_put_widens_in_txn(&self.store, txn, id, body)? {
            return Ok(None);
        }
        let updated = agent_switches(&decode_agent_definition(body)?);
        let within = self
            .owner_stated_agent_switches_in_txn(txn, *id)?
            .is_some_and(|stated| !switches_widen(Some(&stated), &updated));
        Ok(
            (!within).then_some(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                OWNER_STATEMENT_PENDING,
            ))),
        )
    }

    /// Whether the owner's put of `body` with `switches` at agent definition `id` needs his
    /// statement, read in `txn`: when a statement stands, whenever the switches differ from it;
    /// when none stands, when the put widens the stored definition or the switches would widen
    /// a definition anywhere. A missing statement is never taken for one that covers the
    /// switches already (R2d review finding 3): a save again of switches stated on this install
    /// alone states them.
    fn switch_statement_needed_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        switches: &AgentSwitches,
        body: &[u8],
    ) -> Result<bool> {
        Ok(match self.owner_stated_agent_switches_in_txn(txn, *id)? {
            Some(stated) => stated != *switches,
            None => {
                switches_widen(None, switches)
                    || agent_definition_put_widens_in_txn(&self.store, txn, id, body)?
            }
        })
    }

    /// The owner `owner`'s statement of `def`'s switches at agent definition `id`, in the
    /// owner's door's transaction `txn`, before it writes `body` (`def` encoded), when it is
    /// needed ([`Self::switch_statement_needed_in_txn`]). Every other edit states nothing.
    ///
    /// The row's authority here is the owner's door, so the act only carries his switches to
    /// his other installs. An act this install cannot carry or count (no live install key,
    /// more heads than one entry names, a line another family took, a known machine whose key
    /// did not load) or cannot form (more models than a statement lists) leaves the edit to
    /// land here alone: the other installs
    /// hold the row waiting until a later statement, and the edit answers
    /// [`AgentSwitchesReach::ThisInstallOnly`] (Engine RULING R2D-NO-CARRIER-POLICY = B,
    /// 16 Nov 06:59).
    ///
    /// # Errors
    ///
    /// A store or authority-fold failure.
    pub(crate) fn state_agent_switches_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        id: &EntityId,
        def: &AgentDefinition,
        body: &[u8],
    ) -> Result<AgentSwitchesReach> {
        let switches = agent_switches(def);
        if !self.switch_statement_needed_in_txn(txn, id, &switches, body)? {
            return Ok(AgentSwitchesReach::EveryInstall);
        }
        // In a savepoint: an act the fold refused after it was put leaves nothing behind.
        let mut savepoint = self.store.env.nested_write_txn(txn)?;
        let appended = self.append_grant_act_in_txn(
            &mut savepoint,
            GrantActBy::Person {
                person: owner,
                surface: ActSurface::ThisInstall,
            },
            *id,
            GrantFamily::AgentDefinition,
            GrantActChange::State { switches },
        );
        match appended {
            Ok(_) => {
                savepoint.commit()?;
                Ok(AgentSwitchesReach::EveryInstall)
            }
            Err(
                Error::Record(
                    RecordError::AuthorityRefused(reason)
                    | RecordError::InvalidAuthorityLogBody(reason),
                )
                | Error::Secret(SecretError::KeystoreUnavailable(reason)),
            ) => {
                savepoint.abort();
                tracing::warn!(
                    agent = %id.to_hex(),
                    reason,
                    "the owner's agent definition edit lands on this install alone; its other \
                     installs hold the widening until a later statement"
                );
                Ok(AgentSwitchesReach::ThisInstallOnly)
            }
            Err(error) => Err(error),
        }
    }

    /// An owner-grade generic batch's statements, in its writer `txn` in the rollback scope of
    /// its puts, before they apply (R2d review findings 1, 2 and 4): the vault's owner states the
    /// switches of each agent definition put of `puts`, as the batch writes it, as the owner's
    /// update door does, so the row reaches his other installs. The owner is `person`, the
    /// human the batch's door bound it to, when that person is a counted owner of the vault now
    /// (R2d review finding 5); else the vault's one recorded owner. A shared vault with several
    /// owners and no counted owner bound to the batch has no one person it speaks for: a put
    /// there that needs a statement lands on this install alone, as one this install cannot
    /// carry does. Each put's reach goes to `reaches`, for the batch's answer.
    ///
    /// # Errors
    ///
    /// A body that does not decode; a store, owner census or authority-fold failure.
    pub(crate) fn state_owner_batch_switches_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        person: Option<EntityId>,
        puts: &[(EntityId, Vec<u8>)],
        reaches: &AgentSwitchesReaches,
    ) -> Result<()> {
        if puts.is_empty() {
            return Ok(());
        }
        let owner = match person {
            Some(person)
                if crate::policy_model::is_live_vault_owner_in_txn(self, txn, &person)? =>
            {
                Some(person)
            }
            _ => crate::policy_model::sole_recorded_owner_in_txn(self, txn)?,
        };
        let mut recorded = Vec::with_capacity(puts.len());
        for (id, body) in puts {
            let def = decode_agent_definition(body)?;
            let reach = match owner {
                Some(owner) => self.state_agent_switches_in_txn(txn, owner, id, &def, body)?,
                None if self.switch_statement_needed_in_txn(
                    txn,
                    id,
                    &agent_switches(&def),
                    body,
                )? =>
                {
                    AgentSwitchesReach::ThisInstallOnly
                }
                None => AgentSwitchesReach::EveryInstall,
            };
            if reach == AgentSwitchesReach::ThisInstallOnly {
                tracing::warn!(
                    agent = %id.to_hex(),
                    "an owner batch's agent definition edit lands on this install alone; its \
                     other installs hold the widening until the owner states it"
                );
            }
            recorded.push((*id, reach));
        }
        reaches.replace(recorded)
    }
}
