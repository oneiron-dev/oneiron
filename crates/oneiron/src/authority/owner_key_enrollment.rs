//! The fold's judge of the owner's enrollment of one of his devices' own
//! owner signing keys (FIX 4920; Engine 10-20 00:5x, rulings B and C).
//!
//! An `OwnerKeyEnroll` entry puts one fresh Ed25519 key on the roster as an
//! owner root of its own (`ROLE_OWNER`, Software tier), revocable like any
//! owner root. Two signatures carry it, the enrollment's one exception to the
//! owner-act contract's carrier-alone rule (CALLS "FIX 4920 enrollment
//! signatures"):
//! - its primary signer is an existing owner root, live and consenting in the
//!   entry's parents: a root change is signed by an existing root (the
//!   predecessor-authorized handoff). An incoming key never authorizes itself:
//!   the shape check refuses the new key as a signer, and this judge reads the
//!   roster before the key enters it;
//! - its one cosign is the install key of the carrier of the owner's act,
//!   judged by the one carrier rule every owner act shares
//!   ([`super::owner_act_signer_admits`]) and by the owner's liveness at the
//!   act's causal point (`owner_live_at`), both as they stand. The carrier is
//!   no roster key, so it never joins the roster's participants.
//!
//! The key's proof of possession, the act's kind, target and zero `seen`, and
//! the device's one shape are the wire shape check's
//! (`OwnerKeyEnroll::validate_entry`), which runs before this judge.
//!
//! Validity here reads the parents' fold state alone, pin-free and
//! install-free: counting changes no entry's validity (`install_fold`), and a
//! roster key is the same on every replica. A sequence floor still refuses
//! the entry as it refuses any roster-signed row (it never lands restriction
//! only). A carrier removed later does not unenrol the key: the owner revokes
//! it with an ordinary `RevokeDevice`, as he revokes any owner root. A resumed
//! fold refolds in full past an enrollment (`fold_resume::admits_past` takes
//! none), and a checkpoint image carries its body.

use super::*;

/// The `OwnerKeyEnroll` judge, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster
/// participant check. On `Ok` the dispatcher applies the op (`upsert_device`
/// with the predecessor as the key's admitter) and advances the predecessor's
/// sequence; the carrier's install key keeps its own sequence.
pub(super) fn judge_owner_key_enroll(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    enroll: &OwnerKeyEnroll,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> std::result::Result<(), AuthorityFoldIssue> {
    // The owner's own say-so alone: the codec and the shape check refuse an
    // agent's act and an answered ask, and the judge holds the same line.
    if enroll.act.by != ActBy::Owner || enroll.act.answer.is_some() {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let Some(new_key) = enroll.public_key() else {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    };
    if !fresh_owner_key(state, &enroll.device.key, new_key) {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    // The predecessor: an owner root on the parents' roster, live and
    // consenting under this fold's consent arm (a managed root as its
    // context allows), past its own last sequence.
    let predecessor = entry.signer_key();
    let Some(root) = state.roster.get(predecessor).filter(|root| !root.revoked) else {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    };
    if root.roles & ROLE_OWNER == 0 || !context.device_can_consent(root) {
        return Err(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    if state
        .seqs
        .get(predecessor)
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    // The carrier: its install key is the one cosign, the one carrier rule
    // admits it in the parents, and the owner is live there.
    let Some(carrier_key) = OwnerKeyEnroll::carrier_key(entry) else {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    };
    let carrier = super::machine_claims::folded_machine_in(state, enroll.carrier);
    if !super::owner_act_signer_admits(carrier.as_ref(), &state.roster, carrier_key) {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    if !super::owner_act::owner_live_at(state, enroll.act.owner) {
        return Err(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    // The machine that holds the key: a live machine of the vault.
    if !super::machine_claims::folded_machine_in(state, enroll.machine)
        .as_ref()
        .is_some_and(machine_is_live)
    {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    Ok(())
}

/// Whether `key` (`bytes` its Ed25519 form) is fresh in `state`: no roster
/// row names it, live or revoked, so a revoked key never comes back; no
/// machine revision named it as an install key, no actor binding names it,
/// and no owner anchor signed with it. An owner key never doubles as a
/// machine, actor or anchor key: the carrier rule and the machine fold read
/// a roster key as no machine's.
fn fresh_owner_key(state: &FoldState, key: &AuthorityKey, bytes: &[u8; 32]) -> bool {
    !state.roster.contains_key(key)
        && !state.actor_bindings.contains_key(key)
        && !state.machine_keys.contains_key(bytes)
        && !state.root_anchors.contains_key(bytes)
}

/// A live machine of the vault, in any role: no chain removed it, and some
/// chain of it is live (the carrier rule's liveness, without its key).
fn machine_is_live(machine: &FoldedMachine) -> bool {
    machine.chains().all(|(_, chain)| !chain.removed)
        && machine.chains().any(|(_, chain)| chain.is_live())
}
