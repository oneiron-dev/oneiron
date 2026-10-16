//! Every hook has a grant (ARCH-0080 §6). A fact hook has no session, so it
//! reads under its own grant, never the writer's.

use serde::{Deserialize, Serialize};

use crate::claim::ClaimBody;
use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::pack_catalog::{HookActorClass, PackHookBinding};
use crate::{EntityId, Error, Result, Vault};

use super::filter::glob_match;

/// The owner's grant rows, by binding. Absent, a hook reads at its author's
/// ceiling.
const GRANTS: SideTable<EntityId, GrantRow, Named> = SideTable::new(&side_table::HOOKS_GRANT);
const MAX_GRANT_ENTRIES: usize = 64;

/// What a hook may read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookGrant {
    /// The actor whose read key the hook reads under.
    #[serde(with = "crate::serialize::entity_ref")]
    pub reader: EntityId,
    pub reader_class: HookActorClass,
    /// Predicate globs the hook may see; empty is every predicate.
    #[serde(default)]
    pub predicates: Vec<String>,
    /// Worlds the hook may see; empty is every world.
    #[serde(default, with = "crate::serialize::entity_ref::sequence")]
    pub worlds: Vec<EntityId>,
}

impl HookGrant {
    /// The author's ceiling. Slice 1 bindings are owner-written, so this is
    /// the owner's own reach.
    #[must_use]
    pub fn author_ceiling(binding: &PackHookBinding) -> Self {
        Self {
            reader: binding.owner,
            reader_class: HookActorClass::Human,
            predicates: Vec::new(),
            worlds: Vec::new(),
        }
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
    ) -> Result<()> {
        if grant.predicates.len() > MAX_GRANT_ENTRIES
            || grant.worlds.len() > MAX_GRANT_ENTRIES
            || grant
                .predicates
                .iter()
                .any(|glob| glob.is_empty() || glob.len() > 256)
        {
            return Err(Error::InvalidConfig(
                "hook grant is out of bounds".to_owned(),
            ));
        }
        if !self
            .pack_hook_bindings()?
            .iter()
            .any(|(id, _)| *id == binding)
        {
            return Err(Error::EntityNotFound);
        }
        self.with_write_txn_grouped(|txn| {
            let set_by = owner.revalidate_in_txn(self, txn)?;
            let row = GrantRow {
                grant,
                set_by,
                set_at: self.store.clock.now_recorded_at(),
            };
            GRANTS.put(&self.store, txn, &binding, &row)
        })
    }

    /// The grant the owner set on a hook, if any.
    pub fn hook_grant(&self, binding: EntityId) -> Result<Option<HookGrant>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(GRANTS
            .get(&self.store, &rtxn, &binding)?
            .map(|row| row.grant))
    }
}

/// The grant a run reads under: the owner's, else the author's ceiling.
pub(super) fn effective_grant(
    vault: &Vault,
    binding_id: EntityId,
    binding: &PackHookBinding,
) -> Result<HookGrant> {
    Ok(vault
        .hook_grant(binding_id)?
        .unwrap_or_else(|| HookGrant::author_ceiling(binding)))
}
