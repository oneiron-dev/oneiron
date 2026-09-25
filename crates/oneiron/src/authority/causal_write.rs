//! Causal authorization across actor revoke/regrant windows.
use super::*;
use crate::EntityId;
use std::collections::{BTreeMap, BTreeSet};

/// A write that raced a revocation is held, never retroactively authorized by regrant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CausalWriteDisposition {
    Admitted,
    Unbound,
    Quarantined,
}

impl AuthorityFold {
    /// A missing frontier is not evidence of having observed a regrant.
    /// Before any revoke, the existing local actor-binding rule is unchanged.
    #[must_use]
    pub fn actor_write_disposition(
        &self,
        actor: &EntityId,
        class: &str,
        frontier: Option<AuthorityEntryHash>,
    ) -> CausalWriteDisposition {
        let mut matched = false;
        for (key, binding) in &self.actor_bindings {
            if binding.actor_ref != *actor || binding.actor_class != class {
                continue;
            }
            matched = true;
            if binding.status != ActorBindingStatus::Active {
                continue;
            }
            if !self.revoked_actor_keys.contains(key)
                || frontier.is_some_and(|hash| {
                    self.actor_write_frontiers
                        .get(key)
                        .is_some_and(|frontiers| frontiers.contains(&hash))
                })
            {
                return CausalWriteDisposition::Admitted;
            }
        }
        if matched {
            CausalWriteDisposition::Quarantined
        } else {
            CausalWriteDisposition::Unbound
        }
    }
}

pub(super) fn causal_actor_frontiers(
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    final_state: Option<&FoldState>,
    bindings: &BTreeMap<AuthorityKey, FoldedActorBinding>,
) -> BTreeMap<AuthorityKey, BTreeSet<AuthorityEntryHash>> {
    let Some(final_state) = final_state else {
        return BTreeMap::new();
    };
    let mut out = BTreeMap::new();
    for (key, final_binding) in bindings {
        if final_binding.status != ActorBindingStatus::Active {
            continue;
        }
        let required = final_state
            .actor_revocation_hashes
            .get(key)
            .cloned()
            .unwrap_or_default();
        let frontiers = states
            .iter()
            .filter_map(|(hash, state)| {
                let binding = state.live_actor_binding(key)?;
                (binding.actor_ref == final_binding.actor_ref
                    && binding.actor_class == final_binding.actor_class
                    && required.is_subset(&binding.observed_revocations)
                    && state
                        .roster
                        .get(key)
                        .is_some_and(|device| !device.revoked && device.roles != 0))
                .then_some(*hash)
            })
            .collect();
        out.insert(key.clone(), frontiers);
    }
    out
}

pub(super) fn revocation_affected_writers(
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    final_state: Option<&FoldState>,
) -> BTreeSet<(EntityId, String)> {
    let Some(final_state) = final_state else {
        return BTreeSet::new();
    };
    states
        .values()
        .flat_map(|state| {
            state
                .actor_bindings
                .iter()
                .filter(|(key, _)| final_state.actor_revocation_hashes.contains_key(*key))
                .map(|(_, binding)| (binding.actor_ref, binding.actor_class.clone()))
        })
        .collect()
}
