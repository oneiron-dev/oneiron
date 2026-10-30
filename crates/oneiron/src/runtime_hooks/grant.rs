//! Every hook has a grant (ARCH-0080 §6). A fact hook has no session, so it
//! reads under its own grant, never the writer's.

use serde::{Deserialize, Serialize};

use crate::claim::ClaimBody;
use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::pack_catalog::{HookActorClass, PackHookBinding};
use crate::{EntityId, Error, Result as VaultResult, Vault};

use super::filter::glob_match;

/// The owner's grant rows, by binding. Absent, a hook reads at its author's
/// ceiling.
const GRANTS: SideTable<EntityId, GrantRow, Named> = SideTable::new(&side_table::HOOKS_GRANT);

/// What a hook may read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookGrant {
    /// The actor whose read key the hook reads under.
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub reader: EntityId,
    pub reader_class: HookActorClass,
    /// Predicate globs the hook may see; empty is every predicate.
    #[serde(default)]
    pub predicates: Vec<String>,
    /// Worlds the hook may see; empty is every world.
    #[serde(default, with = "crate::serialize::entity_ref::sequence")]
    #[schemars(with = "Vec<String>")]
    pub worlds: Vec<EntityId>,
}

impl HookGrant {
    /// The author's ceiling: the owner's own reach for an owner's hook, and
    /// for a hub hook its publisher's, which reads only what its Grant does.
    #[must_use]
    pub fn author_ceiling(binding: &PackHookBinding) -> Self {
        Self {
            reader: binding.author_id(),
            reader_class: binding.author_class(),
            predicates: Vec::new(),
            worlds: Vec::new(),
        }
    }

    /// The grant's digest, lowercase hex: a saved verb input built under it
    /// names it, so a replay knows whether the grant changed since (FIX
    /// 10084).
    pub(super) fn digest(&self) -> String {
        let encoded = serde_json::to_vec(self).unwrap_or_default();
        blake3::hash(&encoded).to_hex().to_string()
    }

    /// Whether the grant shows `claim`, on top of what the reader's key admits.
    pub(super) fn admits(&self, claim: &ClaimBody) -> bool {
        (self.predicates.is_empty()
            || self
                .predicates
                .iter()
                .any(|glob| glob_match(glob, &claim.predicate)))
            && (self.worlds.is_empty()
                || claim
                    .world
                    .is_some_and(|world| self.worlds.contains(&world)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GrantRow {
    grant: HookGrant,
    #[serde(with = "crate::serialize::entity_ref")]
    set_by: EntityId,
    set_at: u64,
}

impl Vault {
    /// The owner sets a hook's grant by hand. It is an ordinary owner grant
    /// and may widen the hook past its author's ceiling.
    pub fn set_hook_grant(
        &self,
        owner: &AuthenticatedOwner,
        binding: EntityId,
        grant: HookGrant,
    ) -> VaultResult<()> {
        self.with_write_txn_grouped(|txn| {
            let set_by = owner.revalidate_in_txn(self, txn)?;
            // The whole grant, any size, is checked before it is installed
            // (FIX 10073): only an empty glob is malformed.
            if grant.predicates.iter().any(String::is_empty) {
                return Err(Error::InvalidConfig(
                    "hook grant has an empty predicate glob".to_owned(),
                ));
            }
            if !self
                .pack_hook_bindings_in_txn(txn)?
                .iter()
                .any(|(id, _)| *id == binding)
            {
                return Err(Error::EntityNotFound);
            }
            let row = GrantRow {
                grant,
                set_by,
                set_at: self.store.clock.now_recorded_at(),
            };
            GRANTS.put(&self.store, txn, &binding, &row)
        })
    }

    /// The grant the owner set on a hook, if any.
    pub fn hook_grant(&self, binding: EntityId) -> VaultResult<Option<HookGrant>> {
        let rtxn = self.store.env.read_txn()?;
        grant_in_txn(self, &rtxn, binding)
    }

    /// The grant a live binding reads under: the owner's assignment, or
    /// its author's ceiling when none was assigned.
    pub fn effective_hook_grant(&self, binding: EntityId) -> VaultResult<HookGrant> {
        let txn = self.store.env.read_txn()?;
        let (_, row) = self
            .pack_hook_bindings_in_txn(&txn)?
            .into_iter()
            .find(|(id, _)| *id == binding)
            .ok_or(Error::EntityNotFound)?;
        effective_grant_in_txn(self, &txn, binding, &row)
    }

    /// Live bindings, enabled or not, with the grants they read under.
    /// Bindings and grants come from the same snapshot.
    pub fn pack_hook_bindings_with_grants(
        &self,
    ) -> VaultResult<Vec<(EntityId, PackHookBinding, HookGrant)>> {
        let txn = self.store.env.read_txn()?;
        self.pack_hook_bindings_in_txn(&txn)?
            .into_iter()
            .map(|(id, binding)| {
                let grant = effective_grant_in_txn(self, &txn, id, &binding)?;
                Ok((id, binding, grant))
            })
            .collect()
    }
}

fn grant_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding: EntityId,
) -> VaultResult<Option<HookGrant>> {
    Ok(GRANTS
        .get(&vault.store, txn, &binding)?
        .map(|row| row.grant))
}

fn effective_grant_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding_id: EntityId,
    binding: &PackHookBinding,
) -> VaultResult<HookGrant> {
    Ok(grant_in_txn(vault, txn, binding_id)?.unwrap_or_else(|| HookGrant::author_ceiling(binding)))
}

/// Carries the owner's grant to `to`, the binding a body-only rebind gives
/// a hook, from the first of `from`, its same-author bindings in the
/// caller's order, that holds one (FIX 10123). The row moves as the owner
/// set it, so the hook reads no wider than before. A grant the owner already
/// set on `to` stays, and nothing is written when none of `from` holds one.
pub(crate) fn carry_hook_grant_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    from: &[EntityId],
    to: EntityId,
) -> VaultResult<()> {
    if GRANTS.get(&vault.store, txn, &to)?.is_some() {
        return Ok(());
    }
    for binding in from {
        if let Some(row) = GRANTS.get(&vault.store, txn, binding)? {
            return GRANTS.put(&vault.store, txn, &to, &row);
        }
    }
    Ok(())
}

/// The grant a run reads under: the owner's, else the author's ceiling.
pub(super) fn effective_grant(
    vault: &Vault,
    binding_id: EntityId,
    binding: &PackHookBinding,
) -> VaultResult<HookGrant> {
    let txn = vault.store.env.read_txn()?;
    effective_grant_in_txn(vault, &txn, binding_id, binding)
}
