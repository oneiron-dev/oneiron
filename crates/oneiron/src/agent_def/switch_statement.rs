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
//! A statement is appended when the owner's edit widens the stored definition, and when it
//! changes switches the owner stated before: his own turn-off replaces the statement, so a
//! replay of the old "on" row waits. A turn-off by a writer below the owner takes no act, so a
//! replay of the owner's last stated row after it still lands (FIX row filed with R2d).

use crate::Vault;
use crate::authority::{ActSurface, AgentSwitches, GrantActBy, GrantActChange, GrantFamily};
use crate::entity_id::EntityId;
#[cfg(feature = "sync")]
use crate::error::ArtifactError;
use crate::error::{Error, RecordError, Result};

#[cfg(feature = "sync")]
use super::codec::decode_agent_definition;
use super::types::AgentDefinition;
#[cfg(feature = "sync")]
use super::widening::switches_widen;
use super::widening::{agent_definition_put_widens_in_txn, agent_switches};

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

impl Vault {
    /// The switches the vault's owner last stated for agent definition `id`, read in `txn`:
    /// the one counted statement on its line, when the person who made it is a live owner of
    /// the vault now. `None` when no statement stands.
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

    /// The owner `owner`'s statement of `def`'s switches at agent definition `id`, in the
    /// owner's door's transaction `txn`, before it writes `body` (`def` encoded): appended when
    /// the put widens the stored definition, or when its switches differ from a statement the
    /// owner made before. Every other edit states nothing.
    ///
    /// The row's authority here is the owner's door, so the act only carries his switches to
    /// his other installs. An act this install cannot carry or count (no live install key,
    /// more heads than one entry names, a line another family took) or cannot form (more
    /// models than a statement lists) leaves the edit to land here alone: the other installs
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
        let stated = self.owner_stated_agent_switches_in_txn(txn, *id)?;
        let widens = agent_definition_put_widens_in_txn(&self.store, txn, id, body)?;
        if !widens && stated.as_ref().is_none_or(|stated| *stated == switches) {
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
            Err(Error::Record(
                RecordError::AuthorityRefused(reason)
                | RecordError::InvalidAuthorityLogBody(reason),
            )) => {
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
}
