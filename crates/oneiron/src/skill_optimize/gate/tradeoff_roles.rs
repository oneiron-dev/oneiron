//! Host-resolved role authority for skill-edit A/B requests. The model may
//! request an escalation; it cannot choose a role holder or authenticate a pick.
use std::collections::BTreeSet;
use std::sync::OnceLock;

use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillTradeoffRole {
    pub role: EntityId,
    /// A person or agent, as resolved by the host's authority service.
    pub actor: EntityId,
}

/// An authority receipt reference safe to retain in the verdict ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillTradeoffRoleAuthentication {
    pub actor: EntityId,
    pub receipt: String,
}

/// The host's existing role service. All methods read the committing snapshot.
/// The last role must be the vault owner role, regardless of its holder's species.
pub trait SkillTradeoffRoles: Send + Sync {
    fn owner_role_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<EntityId>;
    fn chain_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        responsible: EntityId,
    ) -> Result<Vec<SkillTradeoffRole>>;
    /// Authenticate a host credential, not an actor id or model-produced claim.
    fn authenticate_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        authentication: &str,
    ) -> Result<SkillTradeoffRoleAuthentication>;
}

static ROLES: OnceLock<&'static dyn SkillTradeoffRoles> = OnceLock::new();

pub fn register_skill_tradeoff_roles(
    roles: &'static dyn SkillTradeoffRoles,
) -> std::result::Result<(), &'static str> {
    ROLES
        .set(roles)
        .map_err(|_| "skill tradeoff roles are already registered")
}

pub(super) fn service() -> Result<&'static dyn SkillTradeoffRoles> {
    ROLES.get().copied().ok_or(super::invalid(
        "no skill tradeoff role resolver is registered",
    ))
}

pub(super) fn chain_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    responsible: EntityId,
) -> Result<Vec<SkillTradeoffRole>> {
    let resolver = service()?;
    let chain = resolver.chain_in_txn(vault, txn, responsible)?;
    let owner = resolver.owner_role_in_txn(vault, txn)?;
    let mut seen = BTreeSet::new();
    if chain.first().is_none_or(|first| first.role != responsible)
        || chain.last().is_none_or(|last| last.role != owner)
        || chain.iter().any(|holder| !seen.insert(holder.role))
    {
        return Err(super::invalid(
            "skill tradeoff role chain must end at the vault owner role",
        ));
    }
    Ok(chain)
}

pub(super) fn current_actor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ask: &super::SkillTradeoffAsk,
) -> Result<EntityId> {
    if chain_in_txn(vault, txn, ask.question.responsible)? != ask.roles {
        return Err(super::invalid(
            "skill tradeoff role holders changed; re-score the proposal",
        ));
    }
    ask.roles
        .get(ask.role_index)
        .map(|role| role.actor)
        .ok_or(super::invalid("invalid skill tradeoff role index"))
}
