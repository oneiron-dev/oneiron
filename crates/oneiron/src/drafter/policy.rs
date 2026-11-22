//! The owner's drafter policy (I5-DRAFTER = A, DRAFTER-DATA = A): on by
//! default with an off switch, the worlds whose content never trains a
//! drafter, and the recipe as data.
//!
//! Off stops new work and returns every binding to stock; the versions stay
//! retained. A newly excluded world returns to stock every binding whose
//! version's ancestry trained on it; such a version is not reverted to while
//! the world stays excluded, and its key is kept. Either way the serving
//! host restarts its worker with stock (FIX 14976).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    BINDINGS, BindingMove, DrafterActor, DrafterEventKind, DrafterRecipe, DrafterServing,
    DrafterVersion, POLICY, VERSIONS, binding_retired_by_policy, invalid, move_binding_in_txn,
    policy_in_txn, record_event_in_txn, versions_by_id,
};
use crate::Vault;
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::SideKey;

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
            if !binding_retired_by_policy(&versions, &binding, &policy) {
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

/// Whether `version`'s ancestry chain ends at stock without a missing parent
/// or a cycle: every parent the chain names is still held.
fn binding_ancestry_is_complete(
    versions: &BTreeMap<EntityId, DrafterVersion>,
    version: &DrafterVersion,
) -> bool {
    let mut seen = BTreeSet::from([version.id]);
    let mut next = version.parent;
    while let DrafterServing::Version(parent) = next {
        if !seen.insert(parent) {
            return false;
        }
        let Some(found) = versions.get(&parent) else {
            return false;
        };
        next = found.parent;
    }
    true
}

/// Moves every binding the restored `policy` retires to stock, in `txn`: the
/// same selection the owner setter moves, each with the existing generation
/// bump and one [`DrafterEventKind::ArchiveRestore`] event at one vault-clock
/// time; none when none retires, and the clock is not read then. The permit
/// proves this restore. Callers preflight every affected binding before the
/// first write; this writes.
///
/// # Errors
/// Storage faults.
fn restore_policy_bindings_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    policy: &DrafterPolicy,
) -> Result<()> {
    let _ = permit;
    let store = &vault.store;
    let versions = versions_by_id(store, txn)?;
    let bindings = BINDINGS.scan(store, txn)?;
    let mut affected = Vec::new();
    for (key, binding) in bindings {
        if binding_retired_by_policy(&versions, &binding, policy) {
            affected.push((key, binding));
        }
    }
    if affected.is_empty() {
        return Ok(());
    }
    let at = vault.now_recorded_at();
    let by = DrafterActor::ArchiveRestore;
    let kind = DrafterEventKind::ArchiveRestore {
        policy_revision: policy.revision,
    };
    for (key, binding) in affected {
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
    }
    Ok(())
}

/// Preflights the Stock repair the restored `policy` needs, in `txn`: every
/// binding and version row must decode, and every affected binding must move
/// safely (its key, target, complete ancestry and generation). Returns the
/// held-back reason, or `None` when the repair may run. Storage faults fail;
/// undecodable or unsafe companions hold back.
///
/// # Errors
/// Storage faults.
fn preflight_archived_policy_bindings_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &DrafterPolicy,
) -> Result<Option<RetainedSideHeldBackReason>> {
    let inconsistent = Some(RetainedSideHeldBackReason::InconsistentCompanion);
    let mut versions = BTreeMap::new();
    for row in VERSIONS.iter_raw_from(vault, txn, &[])? {
        let (key_bytes, value_bytes) = row?;
        let (Some(id), Ok(version)) = (
            <EntityId as SideKey>::decode_key(&key_bytes),
            VERSIONS.decode_value(&value_bytes),
        ) else {
            return Ok(inconsistent);
        };
        versions.insert(id, version);
    }
    let mut bindings = Vec::new();
    for row in BINDINGS.iter_raw_from(vault, txn, &[])? {
        let (key_bytes, value_bytes) = row?;
        let (Some(key), Ok(binding)) = (
            <[u8; 32] as SideKey>::decode_key(&key_bytes),
            BINDINGS.decode_value(&value_bytes),
        ) else {
            return Ok(inconsistent);
        };
        bindings.push((key, binding));
    }
    for (binding_key, binding) in &bindings {
        if !binding_retired_by_policy(&versions, binding, policy) {
            continue;
        }
        let expected = match binding.target.key() {
            Ok(expected) => expected,
            Err(_) => return Ok(inconsistent),
        };
        if expected != *binding_key {
            return Ok(inconsistent);
        }
        let DrafterServing::Version(serving) = binding.serving else {
            continue;
        };
        let Some(version) = versions.get(&serving) else {
            return Ok(inconsistent);
        };
        if version.target != binding.target
            || !binding_ancestry_is_complete(&versions, version)
            || binding.generation == u64::MAX
        {
            return Ok(inconsistent);
        }
    }
    Ok(None)
}

/// Lands one archived `DRAFTER_POLICY` envelope in `txn`: canonical decode
/// and the credential predicate, then the absent key installs with its local
/// Stock repair, the identical key is unchanged, and a different key stays
/// live. The owning setter takes any enabled flag, excluded-world set and
/// recipe without bounds or liveness checks, so decode is the whole value
/// check; excluded worlds stay allowed absent and the recipe stays
/// configuration data, never a live reference.
///
/// # Errors
/// Storage faults; validation stays in the returned outcome.
fn land_archived_drafter_policy_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    row: &ArchiveRetainedSideRow,
) -> Result<ArchivedSideRowOutcome> {
    let (key, policy) = match decode_archived_row(&POLICY, row) {
        Ok(decoded) => decoded,
        Err(reason) => return Ok(ArchivedSideRowOutcome::HeldBack(reason)),
    };
    match POLICY.get_bytes(vault, txn, &key)? {
        Some(stored) if stored == row.source_value => Ok(ArchivedSideRowOutcome::Unchanged),
        Some(_) => Ok(ArchivedSideRowOutcome::KeptLive),
        None => {
            if let Some(reason) = preflight_archived_policy_bindings_in_txn(vault, txn, &policy)? {
                return Ok(ArchivedSideRowOutcome::HeldBack(reason));
            }
            restore_policy_bindings_in_txn(vault, txn, permit, &policy)?;
            install_archived_row(&POLICY, vault, txn, permit, &key, row)
        }
    }
}

impl Vault {
    /// Lands the owner's archived `DRAFTER_POLICY` envelopes in input order,
    /// one outcome per row: an absent policy installs with its Stock repair,
    /// an identical policy is unchanged, and a different policy stays live.
    /// Never trains and never starts a job; the caller notifies serving
    /// after commit when any row installed.
    ///
    /// # Errors
    /// Storage faults; validation stays in the returned outcomes.
    pub(crate) fn land_archived_drafter_rows_in_txn(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        permit: &OwnerArchiveRestorePermit,
        rows: &[ArchiveRetainedSideRow],
    ) -> Result<Vec<ArchivedSideRowOutcome>> {
        let mut outcomes = Vec::with_capacity(rows.len());
        for row in rows {
            outcomes.push(land_archived_drafter_policy_row_in_txn(
                vault, txn, permit, row,
            )?);
        }
        Ok(outcomes)
    }
}
