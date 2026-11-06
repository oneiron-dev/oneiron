//! The owner's drafter policy (I5-DRAFTER = A, DRAFTER-DATA = A): on by
//! default with an off switch, the worlds whose content never trains a
//! drafter, and the recipe as data.
//!
//! Off stops new work and returns every binding to stock; the versions stay
//! retained. A newly excluded world returns to stock every binding whose
//! version's ancestry trained on it; such a version is not reverted to while
//! the world stays excluded, and its key is kept. Either way the serving
//! host restarts its worker with stock (FIX 14976).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    BINDINGS, BindingMove, DrafterActor, DrafterEventKind, DrafterRecipe, DrafterServing, POLICY,
    ancestry_names_world, invalid, move_binding_in_txn, policy_in_txn, record_event_in_txn,
    versions_by_id,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The owner's drafter policy, at its revision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterPolicy {
    /// Nightly retraining runs and a version may serve. Off: no new work,
    /// and every binding serves stock. On by default (I5-DRAFTER = A).
    pub enabled: bool,
    /// Worlds whose content never trains a drafter, quoted and derived
    /// context included.
    pub excluded_worlds: BTreeSet<EntityId>,
    /// The recipe the nightly retrain runs; `None` until one is chosen.
    pub recipe: Option<DrafterRecipe>,
    /// Bumps on every set: a set names the revision it read.
    pub revision: u64,
    /// Who set it last; `None` for the shipped default.
    pub set_by: Option<DrafterActor>,
    /// The vault's recorded clock at the last set.
    pub set_at: Option<u64>,
}

impl Default for DrafterPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            excluded_worlds: BTreeSet::new(),
            recipe: None,
            revision: 0,
            set_by: None,
            set_at: None,
        }
    }
}

/// The owner's whole policy, set at the revision they read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterPolicySetRequest {
    /// The revision the owner read: a set at any other is refused.
    pub expected_revision: u64,
    pub enabled: bool,
    #[serde(default)]
    pub excluded_worlds: BTreeSet<EntityId>,
    #[serde(default)]
    pub recipe: Option<DrafterRecipe>,
}

/// The owner sets the drafter policy at the revision they read, in one
/// write: off returns every binding to stock, and a newly excluded world
/// returns to stock every binding whose version's ancestry trained on it.
/// Each binding moved gets its own event; a set that moves none records one.
/// After commit the serving host is told, which serves each moved binding.
///
/// # Errors
/// An owner proof that does not revalidate, a revision that moved since it
/// was read, and storage faults.
pub fn set_drafter_policy_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &DrafterPolicySetRequest,
) -> Result<DrafterPolicy> {
    let policy = set_policy_in_txn(vault, owner, input)?;
    vault.notify_drafter_serving();
    Ok(policy)
}

fn set_policy_in_txn(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &DrafterPolicySetRequest,
) -> Result<DrafterPolicy> {
    vault.with_write_txn_grouped(|txn| {
        let store = &vault.store;
        let actor = owner.revalidate_in_txn(vault, txn)?;
        let current = policy_in_txn(store, txn)?;
        if current.revision != input.expected_revision {
            return Err(invalid("the drafter policy moved since it was read"));
        }
        let at = vault.now_recorded_at();
        let by = DrafterActor::Owner(actor);
        let policy = DrafterPolicy {
            enabled: input.enabled,
            excluded_worlds: input.excluded_worlds.clone(),
            recipe: input.recipe.clone(),
            revision: current.revision + 1,
            set_by: Some(by),
            set_at: Some(at),
        };
        POLICY.put(store, txn, &(), &policy)?;
        let kind = DrafterEventKind::Policy {
            revision: policy.revision,
        };
        let versions = versions_by_id(store, txn)?;
        let bindings = BINDINGS.scan(store, txn)?;
        let mut moved = false;
        for (key, binding) in bindings {
            let DrafterServing::Version(serving) = binding.serving else {
                continue;
            };
            let excluded = versions.get(&serving).is_some_and(|version| {
                ancestry_names_world(&versions, version, &policy.excluded_worlds)
            });
            if policy.enabled && !excluded {
                continue;
            }
            let previous = binding.serving;
            move_binding_in_txn(
                store,
                txn,
                &key,
                binding,
                BindingMove {
                    to: DrafterServing::Stock,
                    previous,
                    by,
                    kind: kind.clone(),
                    at,
                },
            )?;
            moved = true;
        }
        if !moved {
            record_event_in_txn(store, txn, by, kind, None, at)?;
        }
        Ok(policy)
    })
}
