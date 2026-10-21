//! FIX 6219 (L02 seam): whether a recorded principal still stands, for work a
//! host does later in that principal's name while no caller is present.
//!
//! The host holds no credential of the principal's (canon grants no such
//! custody): the authority of such work is the principal's own recorded act,
//! and this check, run again in each snapshot the work writes in, that the
//! principal is still live. A person stands while its PERSON row is live and
//! active. An agent stands while its agent row is live (an enabled, active
//! agent definition, or a base agent's MACHINE principal) AND one live Grant
//! the owner gave it names it, confers now and lists the work's verb. Grants
//! are never unioned and no other holder is picked. It mints nothing, and
//! the work still crosses every gate it crosses for a caller.

use crate::Vault;
use crate::claim::ClaimLifecycleStatus;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::ScopeAxis;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MACHINE};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// A recorded principal that stood in one snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrincipalStanding {
    pub(crate) principal: EntityId,
    pub(crate) class: EdgeActorClass,
    /// The one live Grant that lists the work's verb, for an agent; `None`
    /// for a person.
    pub(crate) grant: Option<EntityId>,
}

/// Whether `principal`, of `class`, still stands in `txn` for work under
/// `verb`.
///
/// `Ok(None)`: the principal is dead, retired, erased, switched off or of
/// another class, or, for an agent, no single live Grant names it, confers
/// now (unexpired, given by a live owner) and lists `verb`.
/// # Errors
/// A store, fold or clock failure, or an agent definition that does not
/// decode; never "no principal".
pub(crate) fn principal_standing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    class: EdgeActorClass,
    verb: &str,
) -> Result<Option<PrincipalStanding>> {
    let grant = match class {
        EdgeActorClass::Human => {
            if !crate::consent::person_is_live_in_txn(vault, txn, &principal)? {
                return Ok(None);
            }
            None
        }
        EdgeActorClass::Agent | EdgeActorClass::System => {
            if !live_agent_principal_in_txn(vault, txn, principal, class)? {
                return Ok(None);
            }
            let Some(grant) = agent_grant_listing_in_txn(vault, txn, principal, verb)? else {
                return Ok(None);
            };
            Some(grant)
        }
    };
    Ok(Some(PrincipalStanding {
        principal,
        class,
        grant,
    }))
}

/// Whether `agent` is a live agent principal acting as `class`: an enabled,
/// active agent definition the archive has not taken, acting as an agent, or
/// a base agent's MACHINE principal, which acts as the system class.
fn live_agent_principal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    class: EdgeActorClass,
) -> Result<bool> {
    match (class, live_entity_row_in_txn(&vault.store, txn, &agent)?) {
        (
            EdgeActorClass::Agent,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_AGENT_DEF,
                body,
            },
        ) => {
            if vault.archive_tombstone_in_txn(txn, &agent)?.is_some() {
                return Ok(false);
            }
            let definition = crate::agent_def::decode_agent_definition(&body)?;
            Ok(definition.enabled && definition.lifecycle_status == ClaimLifecycleStatus::Active)
        }
        (
            EdgeActorClass::System,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_MACHINE,
                ..
            },
        ) => crate::dreamer_runner::authority::is_base_agent_actor(&agent),
        _ => Ok(false),
    }
}

/// The first live owner-agent Grant, in id order, that alone names `agent`,
/// confers now, was given by a live owner of this vault and lists `verb` in
/// its explicit verb set.
fn agent_grant_listing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    verb: &str,
) -> Result<Option<EntityId>> {
    let now = vault.instant_in_txn(txn)?.secs();
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    Ok(vault
        .agent_grants_in_txn(txn)?
        .into_iter()
        .find(|standing| standing.stands_for(agent, verb, now, &owners))
        .map(|standing| standing.id))
}

impl crate::federation::AgentGrantStanding {
    /// Whether this Grant alone stands for `agent`'s work under `verb` at
    /// `now`: it names `agent`, confers now, was given by one of `owners`
    /// (this vault's live owners) and lists `verb` in its explicit verb set.
    /// The one rule [`principal_standing_in_txn`] picks its Grant by; an
    /// agent's own read takes every Grant it holds (FIX 7462).
    pub(crate) fn stands_for(
        &self,
        agent: EntityId,
        verb: &str,
        now: u64,
        owners: &[EntityId],
    ) -> bool {
        self.grant.member_ref == agent
            && self.grant.confers_at(now)
            && owners.contains(&self.delegated_by)
            && matches!(
                &self.grant.authority_scope.verbs,
                ScopeAxis::Some(verbs) if verbs.contains(verb)
            )
    }
}
