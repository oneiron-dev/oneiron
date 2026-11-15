//! The owner's drafter policy (I5-DRAFTER = A, DRAFTER-DATA = A): on by
//! default with an off switch, the worlds whose content never trains a
//! drafter, and the recipe as data. It is the catalogue key `drafter.policy`,
//! which the owner sets through `vault.settings.set` (any other caller
//! proposes); its revision is the change that wrote the row in force.
//!
//! Off stops new work and returns every binding to stock; the versions stay
//! retained. A newly excluded world returns to stock every binding whose
//! version's ancestry trained on it; such a version is not reverted to while
//! the world stays excluded, and its key is kept. Either way the serving
//! host restarts its worker with stock (FIX 14976).

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::setting_keys::DRAFTER_POLICY;
use super::{
    BINDINGS, BindingMove, DrafterActor, DrafterEventKind, DrafterRecipe, DrafterServing,
    ancestry_names_world, move_binding_in_txn, versions_by_id,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::setting::{Setter, SettingChange, SettingValue, settings_after_in_txn};
use crate::store::Store;

/// The owner's drafter policy as the key `drafter.policy` holds it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterPolicyValue {
    /// Nightly retraining runs and a version may serve. Off: no new work,
    /// and every binding serves stock. On by default (I5-DRAFTER = A).
    pub enabled: bool,
    /// Worlds whose content never trains a drafter, quoted and derived
    /// context included.
    #[serde(default)]
    pub excluded_worlds: BTreeSet<EntityId>,
    /// The recipe the nightly retrain runs; `None` until one is chosen.
    #[serde(default)]
    pub recipe: Option<DrafterRecipe>,
}

impl Default for DrafterPolicyValue {
    fn default() -> Self {
        Self {
            enabled: true,
            excluded_worlds: BTreeSet::new(),
            recipe: None,
        }
    }
}

impl SettingValue for DrafterPolicyValue {}

/// The owner's drafter policy in force, at its revision.
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
    /// The sequence of the setting change that wrote the row in force; 0
    /// for the shipped default. A night pins it, and a set names the
    /// revision it read (`expected_revision`).
    pub revision: u64,
    /// Who set it last; `None` for the shipped default.
    pub set_by: Option<DrafterActor>,
    /// The vault's recorded clock at the last set.
    pub set_at: Option<u64>,
}

impl Default for DrafterPolicy {
    fn default() -> Self {
        Self::of(DrafterPolicyValue::default(), 0)
    }
}

impl DrafterPolicy {
    /// `value` at `revision`, before the change that wrote it is read.
    fn of(value: DrafterPolicyValue, revision: u64) -> Self {
        let DrafterPolicyValue {
            enabled,
            excluded_worlds,
            recipe,
        } = value;
        Self {
            enabled,
            excluded_worlds,
            recipe,
            revision,
            set_by: None,
            set_at: None,
        }
    }
}

/// The owner's policy in `txn`, read through the key `drafter.policy`: the
/// shipped default, on, when no row is set; who set the row in force and
/// when, from the change its revision names.
///
/// # Errors
/// A row that does not decode (the key names no strictest value), and
/// storage faults.
pub(super) fn policy_in_txn(store: &Store, txn: &RoTxn<'_>) -> Result<DrafterPolicy> {
    let resolved = DRAFTER_POLICY.read_in_dbs_txn(store, txn, &[], None)?;
    let mut policy = DrafterPolicy::of(resolved.value, resolved.revision);
    let Some(after) = resolved.revision.checked_sub(1) else {
        return Ok(policy);
    };
    let (changes, _) = settings_after_in_txn(store, txn, Some(after), 1)?;
    if let Some(change) = changes
        .into_iter()
        .find(|change| change.sequence == resolved.revision)
    {
        policy.set_by = Some(actor_of(change.by, change.setter));
        policy.set_at = Some(change.at);
    }
    Ok(policy)
}

/// Who made a change of the key, as the drafter's events name them.
const fn actor_of(by: Option<EntityId>, setter: Setter) -> DrafterActor {
    match (by, setter) {
        (Some(owner), Setter::Owner) => DrafterActor::Owner(owner),
        (Some(agent), _) => DrafterActor::Agent(agent),
        // The engine's own path names no actor: the drafter's work is the
        // Coach's.
        (None, Setter::Engine { .. }) => DrafterActor::Coach,
        // An erase took the actor out of the change.
        (None, _) => DrafterActor::Erased,
    }
}

/// The `drafter.policy` key's hook, in the write of each applied change:
/// with the policy now in force off, every binding returns to stock; with
/// it on, each binding whose version's ancestry trained on an excluded
/// world does. Each binding moved gets its own event; the change row is the
/// record of the set itself. The key's `after_commit` tells the serving
/// host, which serves each moved binding.
///
/// # Errors
/// Storage faults.
pub(crate) fn drafter_policy_changed_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    change: &SettingChange,
) -> Result<()> {
    let store = &vault.store;
    let policy = policy_in_txn(store, txn)?;
    let by = actor_of(change.by, change.setter);
    let kind = DrafterEventKind::Policy {
        revision: policy.revision,
    };
    let versions = versions_by_id(store, txn)?;
    let bindings = BINDINGS.scan(store, txn)?;
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
                at: change.at,
            },
        )?;
    }
    Ok(())
}
