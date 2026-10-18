//! The fold transitions of a machine revision: a roster revision, an owner
//! anchor's mark, and the checks every chain applies to a revision.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::merge::add_removal;
use super::*;

/// One fold transition, signed by an owner roster key, for a machine that is
/// not an actor and whose key is not authority: the explicit bootstrap arm
/// (the host's own node, the fresh self-host first install; C4) and older
/// roster revisions. The owner's answer carried by a linked machine under his
/// act folds through [`super::apply_owner_answer`] instead. Only an
/// owner-held key answers "yours", "work/school" or "rented" here (truthful
/// custody): a cloud or custodial root, which the hosted posture lets
/// consent, can register its own node or demote and remove a machine, but
/// never vouch for a machine as the owner's. Neither can the host's own root
/// on a hosted vault, whatever its role labels say (FIX 2222): an unproved
/// host-root `Owned` answer refuses.
pub(in crate::authority) fn apply_machine_profile(
    state: &mut FoldState,
    signer: &AuthorityKey,
    profile: &MachineProfile,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
    restriction_only: bool,
) -> std::result::Result<(), AuthorityFoldIssue> {
    let Some(device) = state
        .roster
        .get(signer)
        .filter(|device| device.roles & ROLE_OWNER != 0)
    else {
        return Err(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    };
    let signer_class = if folded_device_can_authority_consent(device)
        && !custodial_host_root(state, signer, context)
    {
        SignerClass::OwnerHeld
    } else {
        SignerClass::Custodial
    };
    let admitted = match profile.role {
        MachineRole::Owned(_) => signer_class == SignerClass::OwnerHeld,
        MachineRole::HostedNode | MachineRole::ExecutionNode | MachineRole::Removed => {
            context.device_can_consent(device)
        }
    };
    if !admitted {
        return Err(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    let head = roster_chain(state, profile.machine).map(|chain| &chain.head);
    if refused_revision(state, profile, head) {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let folded = MachineRevision {
        profile: profile.clone(),
        conflicted: false,
        removed: profile.role == MachineRole::Removed || head.is_some_and(|folded| folded.removed),
        stale: false,
        admitter_unsettled: false,
        floor_held: false,
        signer: signer.clone(),
        signer_class,
        entry: hash,
        act: None,
    };
    let revisions = crate::authority::machine_standing::with_revision(
        roster_chain(state, profile.machine),
        &folded,
        signer_class == SignerClass::OwnerHeld,
        restriction_only,
    );
    let chains = state.machines.entry(profile.machine).or_default();
    let prior = chains.remove(&MachineAdmitter::Roster);
    // The owner-held chain keeps only its own removals: a custodian's
    // removal stays in the roster's chain and never reaches it.
    let mut owner_held_removals = prior
        .as_ref()
        .map(|chain| chain.owner_held_removals.clone())
        .unwrap_or_default();
    if signer_class == SignerClass::OwnerHeld && profile.role == MachineRole::Removed {
        add_removal(&mut owner_held_removals, signer, &folded);
    }
    let owner_held = match prior {
        _ if signer_class == SignerClass::OwnerHeld => Some(MachineRevision {
            removed: profile.role == MachineRole::Removed
                || prior
                    .as_ref()
                    .and_then(|chain| chain.owner_held.as_ref())
                    .is_some_and(|held| held.removed),
            ..folded.clone()
        }),
        Some(chain) => chain.owner_held,
        None => None,
    };
    chains.insert(
        MachineAdmitter::Roster,
        MachineChain {
            head: folded,
            owner_held,
            owner_held_removals,
            revisions,
        },
    );
    state
        .machine_keys
        .entry(profile.machine_key)
        .or_default()
        .insert(KeyClaim {
            machine: profile.machine,
            admitter: MachineAdmitter::Roster,
            owner_held: (signer_class == SignerClass::OwnerHeld).then(|| signer.clone()),
            act_carrier: None,
        });
    Ok(())
}

/// One revision in a valid root's anchor chain of a machine (E2(b)): an owned
/// mark or a removal, never a hosted or execution node. It supersedes only
/// that anchor's chain; the roster's chain and every other anchor's stay as
/// they are. No install key and no host cosign vouches here. One past its
/// signer's sequence floor lands restriction only, as a roster revision does.
pub(in crate::authority) fn apply_anchor_profile(
    state: &mut FoldState,
    anchor: [u8; 32],
    profile: &MachineProfile,
    hash: AuthorityEntryHash,
    restriction_only: bool,
) -> std::result::Result<(), AuthorityFoldIssue> {
    if !matches!(profile.role, MachineRole::Owned(_) | MachineRole::Removed) {
        return Err(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    let admitter = MachineAdmitter::Anchor(anchor);
    let chain = state
        .machines
        .get(&profile.machine)
        .and_then(|chains| chains.get(&admitter));
    let head = chain.map(|chain| &chain.head);
    if refused_revision(state, profile, head) {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let folded = MachineRevision {
        profile: profile.clone(),
        conflicted: false,
        removed: profile.role == MachineRole::Removed || head.is_some_and(|folded| folded.removed),
        stale: false,
        admitter_unsettled: false,
        floor_held: false,
        signer: AuthorityKey::Ed25519(anchor),
        signer_class: SignerClass::OwnerHeld,
        entry: hash,
        act: None,
    };
    let revisions =
        crate::authority::machine_standing::with_revision(chain, &folded, true, restriction_only);
    state.machines.entry(profile.machine).or_default().insert(
        admitter,
        MachineChain {
            head: folded,
            owner_held: None,
            owner_held_removals: BTreeMap::new(),
            revisions,
        },
    );
    state
        .machine_keys
        .entry(profile.machine_key)
        .or_default()
        .insert(KeyClaim {
            machine: profile.machine,
            admitter,
            owner_held: None,
            act_carrier: None,
        });
    Ok(())
}

/// A revision no chain takes: a key that is authority, a row that is an
/// actor's, a proof the machine did not sign, or no higher than its chain.
pub(super) fn refused_revision(
    state: &FoldState,
    profile: &MachineProfile,
    head: Option<&MachineRevision>,
) -> bool {
    key_is_authority(state, &profile.machine_key)
        || machine_is_actor(state, profile.machine)
        || !profile.proof_verifies(&state.vault_id)
        || head.is_some_and(|folded| profile.revision <= folded.profile.revision)
}

/// A key in the host's custody on a hosted vault, where the host's root is
/// the provider's key and not the owner's: that root, or any key it admitted
/// directly or through another custodial key. Judged from provenance and the
/// vault's posture, so a key labelled owner-held still counts.
fn custodial_host_root(state: &FoldState, signer: &AuthorityKey, context: FoldContext<'_>) -> bool {
    context.hosted && in_host_custody(state, signer)
}

/// Whether `key`, or any key up its admitters, is marked as the host's.
pub(in crate::authority) fn in_host_custody(state: &FoldState, key: &AuthorityKey) -> bool {
    let mut seen = BTreeSet::new();
    let mut pending = vec![key];
    while let Some(next) = pending.pop() {
        if state.host_custody_keys.contains(next) {
            return true;
        }
        if seen.insert(next) {
            pending.extend(state.key_admitters.get(next).into_iter().flatten());
        }
    }
    false
}

pub(super) fn roster_chain(state: &FoldState, machine: EntityId) -> Option<&MachineChain> {
    state.machines.get(&machine)?.get(&MachineAdmitter::Roster)
}

/// An install key that is also a roster key or an actor's key is no machine's.
pub(in crate::authority) fn key_is_authority(state: &FoldState, machine_key: &[u8; 32]) -> bool {
    let key = AuthorityKey::Ed25519(*machine_key);
    state.roster.contains_key(&key) || state.actor_bindings.contains_key(&key)
}

/// A row any accepted binding ever named, on any branch, is an actor's.
pub(in crate::authority) fn machine_is_actor(state: &FoldState, machine: EntityId) -> bool {
    state.actor_rows.contains(&machine)
}
