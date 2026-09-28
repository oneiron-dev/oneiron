//! Per-entry state transition and the consent / quorum predicates.
//!
//! Every accepted op lands the moment its ancestry folds. There is no pending
//! state and no seen-time delay: the device-key widen ceremony, with its
//! delayed-broadcast veto, died 2026-08-05 (identity canon, "Device-key widen
//! ceremony (dead 2026-08-05)"; ARCH-0040 ONE-AUTHLOG-F6). Widening is owner
//! action through the host, so an owner-signed enrollment, rotation or floor
//! change is already the whole ceremony.
use std::collections::{BTreeMap, BTreeSet};

use super::*;

#[expect(clippy::large_enum_variant, reason = "transient per-entry fold value")]
pub(in crate::authority) enum EntryFold {
    Ready(FoldState),
    Waiting,
    Invalid(AuthorityFoldIssue),
}

pub(super) fn fold_entry_state(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    context: FoldContext<'_>,
) -> EntryFold {
    if entry.validate_shape().is_err() || verify_entry_signatures(entry).is_err() {
        return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
    }
    // Still decodes and hashes, so signed history stays byte-identical, but
    // the ceremony it vetoed is dead (identity canon, "Device-key widen
    // ceremony (dead 2026-08-05)"): there is never a pending widen to veto.
    if matches!(entry.op, AuthorityOp::VetoPendingWiden { .. }) {
        return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
    }
    // Slips are the client credential in every posture. Retired device-key
    // operations survive only as verified pre-handoff ancestry: a later
    // client enrollment, rotation or floor change gains no authority.
    if entry_is_retired(entry, hash, context) {
        return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
    }

    // A strictly older observed sequence is rollback. Equal-sequence siblings
    // have separate hashes and fold under their own ancestry, not a fork alarm.
    if context
        .sequence_floors
        .and_then(|floors| floors.get(&hash))
        .is_some_and(|floor| entry.seq < *floor)
    {
        return EntryFold::Invalid(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }

    // Wire validation is posture-blind. Cloud owner roles are only lawful
    // under the explicitly selected managed/peer root arm.
    let incoming_device = match &entry.op {
        AuthorityOp::Genesis { device, .. } | AuthorityOp::EnrollDevice { device } => Some(device),
        AuthorityOp::RotateKey { new_device, .. } | AuthorityOp::ReRoot { new_device, .. } => {
            Some(new_device)
        }
        _ => None,
    };
    if let Some(device) = incoming_device
        && device.roles & (ROLE_OWNER | ROLE_ADMIN) != 0
        && !context.device_can_consent(&FoldedDevice {
            key: device.key.clone(),
            tier: device.tier,
            roles: device.roles,
            revoked: false,
        })
    {
        return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
    }
    // `pending_widen_delay_secs` is a legacy signed field: validated on the
    // wire, never read here.
    if let AuthorityOp::Genesis {
        recovery,
        device,
        tier_floor,
        ..
    } = &entry.op
    {
        if *entry.signer_key() != device.key || entry.seq != 0 {
            return EntryFold::Invalid(AuthorityFoldIssue::SignerNotInAncestry(hash));
        }
        let Ok(vault_id) = genesis_vault_id(entry) else {
            return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
        };
        let mut state = FoldState {
            slips: SlipAuthorityState::default(),
            vault_id,
            roster: BTreeMap::new(),
            tier_floor: *tier_floor,
            genesis_recovery_dismissed: recovery.dismissed(),
            recovery_redundancy_established: false,
            tier_floor_events: BTreeMap::from([(hash, (*tier_floor, BTreeSet::new()))]),
            federation_pacts: BTreeMap::new(),
            federation_confirms: BTreeMap::new(),
            critical_write_confirms: BTreeMap::new(),
            consumed_critical_write_confirm_nonces: BTreeSet::new(),
            critical_write_confirm_nonce_provenance: BTreeMap::new(),
            conflicted_critical_write_confirms: BTreeSet::new(),
            federation_grant_bindings: BTreeMap::new(),
            actor_bindings: BTreeMap::new(),
            actor_binding_revocations: BTreeMap::new(),
            actor_revocation_hashes: BTreeMap::new(),
            seqs: BTreeMap::new(),
        };
        if !tier_meets_floor(device.tier, *tier_floor) {
            return EntryFold::Invalid(AuthorityFoldIssue::SignerBelowTierFloor(hash));
        }
        upsert_device(&mut state, device);
        state.seqs.insert(device.key.clone(), 0);
        return EntryFold::Ready(state);
    }

    let mut parent_state: Option<FoldState> = None;
    for parent in &entry.parent_hashes {
        let Some(state) = states.get(parent) else {
            return EntryFold::Waiting;
        };
        if parent_state
            .as_ref()
            .is_some_and(|current| current.vault_id != state.vault_id)
        {
            return EntryFold::Invalid(AuthorityFoldIssue::WrongVault(hash));
        }
        parent_state = Some(match parent_state {
            Some(current) => merge_states(&current, state),
            None => state.clone(),
        });
    }
    let Some(mut state) = parent_state else {
        return EntryFold::Invalid(AuthorityFoldIssue::InvalidAncestry(hash));
    };

    if entry.vault_id != Some(state.vault_id) {
        return EntryFold::Invalid(AuthorityFoldIssue::WrongVault(hash));
    }
    let signer = entry.signer_key().clone();
    if state
        .roster
        .get(&signer)
        .is_some_and(|device| !tier_meets_floor(device.tier, state.tier_floor))
    {
        return EntryFold::Invalid(AuthorityFoldIssue::SignerBelowTierFloor(hash));
    }
    if state
        .roster
        .get(&signer)
        .is_none_or(|device| device.revoked)
    {
        return EntryFold::Invalid(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    let participants = match active_participant_keys(&state, entry) {
        Ok(participants) => participants,
        Err(issue) => return EntryFold::Invalid(issue),
    };
    if matches!(entry.op, AuthorityOp::CriticalWriteConfirm(_))
        && !state.roster.get(&signer).is_some_and(|device| {
            context.device_can_consent(device) && device.roles & ROLE_OWNER != 0
        })
    {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    if !has_authority_consent(&state, &participants, context) {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    if entry_requires_peer_cosign(entry)
        && active_roster_count(&state) >= 2
        && participants.len() < 2
    {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingQuorum(hash));
    }
    if revoke_would_break_quorum(&state, entry, &participants) {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingQuorum(hash));
    }
    if let Some(prior_seq) = state.seqs.get(&signer).copied()
        && entry.seq <= prior_seq
    {
        return EntryFold::Invalid(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    if let AuthorityOp::ReRoot { new_device } = &entry.op {
        let old_root = &state.roster[&signer];
        if old_root.roles & ROLE_OWNER == 0
            || new_device.roles & !(old_root.roles | ROLE_CLOUD) != 0
            || !tier_meets_floor(new_device.tier, state.tier_floor)
        {
            return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
        }
    }
    if op_reuses_existing_device_key(&state, &entry.op) {
        return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
    }
    if let AuthorityOp::FederationConfirm(action) = &entry.op
        && state
            .federation_confirms
            .values()
            .any(|prior| prior.confirm_id == action.confirm_id || prior.nonce == action.nonce)
    {
        return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
    }
    if let AuthorityOp::CriticalWriteConfirm(action) = &entry.op
        && (state
            .critical_write_confirms
            .contains_key(&action.confirm_id)
            || state
                .consumed_critical_write_confirm_nonces
                .contains(&action.nonce))
    {
        return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
    }
    if matches!(
        entry.op,
        AuthorityOp::SlipMint(_) | AuthorityOp::SlipRevoke { .. } | AuthorityOp::SlipConsume { .. }
    ) {
        // A consent cosigner cannot launder an agent primary into a mint issuer.
        if !roster_has_live_owner(&state.roster, &signer) || state.slips.apply(entry, hash).is_err()
        {
            return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
        }
        state.seqs.insert(signer, entry.seq);
        return EntryFold::Ready(state);
    }
    if let AuthorityOp::FederationLifecycle(action) = &entry.op {
        if let Err(reason) = apply_federation_lifecycle(&mut state, action, context) {
            return EntryFold::Invalid(AuthorityFoldIssue::FederationLifecycleRejected {
                entry: hash,
                reason,
            });
        }
        state.seqs.insert(signer, entry.seq);
        return EntryFold::Ready(state);
    }
    if matches!(
        entry.op,
        AuthorityOp::BindActor { .. }
            | AuthorityOp::RebindActor { .. }
            | AuthorityOp::RevokeActor { .. }
    ) {
        if let Err(reason) = apply_actor_binding(&mut state, &entry.op, hash, context.consent_arm) {
            return EntryFold::Invalid(AuthorityFoldIssue::ActorBindingRejected {
                entry: hash,
                reason,
            });
        }
        state.seqs.insert(signer, entry.seq);
        return EntryFold::Ready(state);
    }
    apply_op(&mut state, &entry.op, hash, &signer);
    if !state_has_authority_consent(&state, context) {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    state.seqs.insert(signer, entry.seq);
    EntryFold::Ready(state)
}

/// A device-key op the host-rooted redesign retired (identity canon,
/// op-vocabulary amendment 2026-08-05): client enrollment is pairing-only,
/// `SetTierFloor` and the delayed veto died with the device-key ceremony plane,
/// and `RotateKey` became the re-root. An agent-only enrollment is not one of
/// them: it is the host enrolling an engine MACHINE writer (ARCH-0053 seeds
/// system actors through the authority registry at bootstrap), and an agent
/// key holds no consent, so it widens no authority.
pub(super) fn op_is_retired_device_op(op: &AuthorityOp) -> bool {
    match op {
        AuthorityOp::EnrollDevice { device } => device.roles != ROLE_AGENT,
        AuthorityOp::RotateKey { .. }
        | AuthorityOp::SetTierFloor { .. }
        | AuthorityOp::VetoPendingWiden { .. } => true,
        _ => false,
    }
}

/// Whether the vault door refuses `entry` as a retired device-key op. Only a
/// verified re-root's pre-handoff ancestry may still use one; the legacy
/// reference fold (no handoff set) keeps the historical rule.
pub(super) fn entry_is_retired(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> bool {
    op_is_retired_device_op(&entry.op)
        && context
            .pre_handoff_entries
            .is_some_and(|permitted| !permitted.contains(&hash))
}

pub(super) fn active_participant_keys(
    state: &FoldState,
    entry: &AuthorityLogEntry,
) -> std::result::Result<BTreeSet<AuthorityKey>, AuthorityFoldIssue> {
    let mut participants = BTreeSet::new();
    for signature in std::iter::once(&entry.signer).chain(entry.cosigns.iter()) {
        let key = &signature.public_key;
        if state
            .roster
            .get(key)
            .is_none_or(|device| device.revoked || device.roles == 0)
        {
            return Err(AuthorityFoldIssue::SignerNotInAncestry(
                authority_entry_hash(entry).unwrap_or([0; 32]),
            ));
        }
        participants.insert(key.clone());
    }
    Ok(participants)
}

pub(super) fn has_authority_consent(
    state: &FoldState,
    participants: &BTreeSet<AuthorityKey>,
    context: FoldContext<'_>,
) -> bool {
    participants.iter().any(|key| {
        state
            .roster
            .get(key)
            .is_some_and(|device| context.device_can_consent(device))
    })
}

fn state_has_authority_consent(state: &FoldState, context: FoldContext<'_>) -> bool {
    state
        .roster
        .values()
        .any(|device| context.device_can_consent(device))
}

fn op_reuses_existing_device_key(state: &FoldState, op: &AuthorityOp) -> bool {
    match op {
        AuthorityOp::EnrollDevice { device }
        | AuthorityOp::RotateKey {
            new_device: device, ..
        }
        | AuthorityOp::ReRoot {
            new_device: device, ..
        } => state.roster.contains_key(&device.key),
        AuthorityOp::Genesis { .. }
        | AuthorityOp::RevokeDevice { .. }
        | AuthorityOp::RetiredCeiling { .. }
        | AuthorityOp::SlipMint(_)
        | AuthorityOp::SlipRevoke { .. }
        | AuthorityOp::SlipConsume { .. }
        | AuthorityOp::SetTierFloor { .. }
        | AuthorityOp::FederationConfirm(_)
        | AuthorityOp::CriticalWriteConfirm(_)
        | AuthorityOp::VetoPendingWiden { .. }
        | AuthorityOp::FederationLifecycle(_)
        | AuthorityOp::BindActor { .. }
        | AuthorityOp::RebindActor { .. }
        | AuthorityOp::RevokeActor { .. } => false,
    }
}

fn entry_requires_peer_cosign(entry: &AuthorityLogEntry) -> bool {
    !matches!(
        entry.op,
        AuthorityOp::Genesis { .. }
            | AuthorityOp::SlipMint(_)
            | AuthorityOp::SlipRevoke { .. }
            | AuthorityOp::SlipConsume { .. }
    )
}

fn revoke_would_break_quorum(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    participants: &BTreeSet<AuthorityKey>,
) -> bool {
    let AuthorityOp::RevokeDevice { revoked_key } = &entry.op else {
        return false;
    };
    // Revoking a MACHINE writer's key never weakens the owner quorum.
    if state
        .roster
        .get(revoked_key)
        .is_some_and(|device| !device.revoked && machine_writer_key(state, revoked_key, device))
    {
        return false;
    }
    let active_before = active_roster_count(state);
    let revoked_was_active = state
        .roster
        .get(revoked_key)
        .is_some_and(|device| !device.revoked && device.roles != 0);
    let active_after = active_before.saturating_sub(usize::from(revoked_was_active));
    participants.len() < 2 || active_after < 2
}

fn active_roster_count(state: &FoldState) -> usize {
    state
        .roster
        .iter()
        .filter(|(key, device)| {
            !device.revoked && device.roles != 0 && !machine_writer_key(state, key, device)
        })
        .count()
}

/// A MACHINE writer's key: agent-only and bound to a system actor. It signs
/// only its own claims, and ops land when the owner acts through the host
/// (identity.md, host-rooted authority), so it is neither a quorum peer nor
/// protected by quorum: the host alone enrolls and revokes each writer.
fn machine_writer_key(state: &FoldState, key: &AuthorityKey, device: &FoldedDevice) -> bool {
    device.roles == ROLE_AGENT
        && state
            .actor_bindings
            .get(key)
            .is_some_and(|binding| binding.actor_class == "system")
}
