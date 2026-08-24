//! Per-entry state transition and the consent / quorum / widen-delay predicates.
//!
//! MUST BE READ TOGETHER WITH [`super::fork_resolution`]. The two files are
//! mutually recursive by direct call — [`fold_entry_state`] consults the
//! quarantine and global-fork-resolution helpers there, and
//! [`super::fork_resolution::resolve_equivocation_group`] calls
//! [`fold_entry_state`] back. Any fork, quorum, or equivocation correctness
//! change has to be reasoned about across both files; the file boundary is a
//! readability split, not a decoupling.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

pub(super) fn fold_entry_state(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
    context: FoldContext<'_>,
) -> EntryFold {
    if entry.validate_shape().is_err() || verify_entry_signatures(entry).is_err() {
        return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
    }

    if let AuthorityOp::Genesis {
        device,
        tier_floor,
        pending_widen_delay_secs,
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
            vault_id,
            roster: BTreeMap::new(),
            tier_floor: *tier_floor,
            pending_widen_delay_secs: *pending_widen_delay_secs,
            pending_widens: BTreeMap::new(),
            vetoed_widens: context.vetoed_widens.clone(),
            delayed_rotation_veto_revocations: BTreeMap::new(),
            fork_resolution_revocations: BTreeSet::new(),
            authority_forks: BTreeMap::new(),
            federation_pacts: BTreeMap::new(),
            critical_write_confirms: BTreeMap::new(),
            consumed_critical_write_confirm_nonces: BTreeSet::new(),
            critical_write_confirm_nonce_provenance: BTreeMap::new(),
            conflicted_critical_write_confirms: BTreeSet::new(),
            federation_grant_bindings: BTreeMap::new(),
            actor_bindings: BTreeMap::new(),
            actor_binding_revocations: BTreeMap::new(),
            seqs: BTreeMap::new(),
        };
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
    if entry_waits_on_unresolved_equivocation(entry, hash, context) {
        return EntryFold::Waiting;
    }
    if let AuthorityOp::VetoPendingWiden { pending_widen_hash } = &entry.op {
        if !context.vetoed_widens.contains(pending_widen_hash) {
            let Some(target_state) = states.get(pending_widen_hash) else {
                return EntryFold::Waiting;
            };
            if !target_state.pending_widens.contains_key(pending_widen_hash) {
                return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
            }
        }
        let participants =
            match veto_participant_keys(&state, entry, hash, *pending_widen_hash, context) {
                Ok(participants) => participants,
                Err(issue) => return EntryFold::Invalid(issue),
            };
        if !has_veto_authority_consent(&state, &participants, *pending_widen_hash, context) {
            return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
        }
        if let Some(prior_seq) = state.seqs.get(&signer).copied()
            && entry.seq <= prior_seq
        {
            return EntryFold::Invalid(AuthorityFoldIssue::NonMonotonicSeq(hash));
        }
        state.vetoed_widens.insert(*pending_widen_hash);
        state.pending_widens.remove(pending_widen_hash);
        state.seqs.insert(signer, entry.seq);
        return EntryFold::Ready(state);
    }
    if context.enforce_seen_time_delay
        && !state.pending_widens.is_empty()
        && !op_applies_despite_pending_widen(&entry.op)
    {
        return EntryFold::Waiting;
    }
    if state
        .roster
        .get(&signer)
        .is_none_or(|device| device.revoked)
    {
        return EntryFold::Invalid(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    let participants = match active_participant_keys(&state, entry, hash, context) {
        Ok(participants) => participants,
        Err(issue) => return EntryFold::Invalid(issue),
    };
    if matches!(entry.op, AuthorityOp::CriticalWriteConfirm(_))
        && !state
            .roster
            .get(&signer)
            .is_some_and(folded_signer_can_critical_write_confirm)
    {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    if !has_authority_consent(&state, &participants, context) {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    if entry_requires_peer_cosign(entry)
        && active_roster_count_for_entry(&state, entry, context, hash) >= 2
        && participants.len() < 2
    {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingQuorum(hash));
    }
    if revoke_would_break_quorum(&state, entry, &participants, hash, context) {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingQuorum(hash));
    }
    if let Some(prior_seq) = state.seqs.get(&signer).copied()
        && entry.seq <= prior_seq
    {
        return EntryFold::Invalid(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    if op_reuses_existing_device_key(&state, &entry.op) {
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
        if let Err(reason) = apply_actor_binding(&mut state, &entry.op) {
            return EntryFold::Invalid(AuthorityFoldIssue::ActorBindingRejected {
                entry: hash,
                reason,
            });
        }
        state.seqs.insert(signer, entry.seq);
        return EntryFold::Ready(state);
    }
    if context.vetoed_widens.contains(&hash)
        && op_is_delayable_widen(&state, &entry.op, &participants)
    {
        state.pending_widens.remove(&hash);
        state.seqs.insert(signer, entry.seq);
        return EntryFold::Ready(state);
    }
    if let Some(pending_widen) =
        pending_widen_for_entry(&state, entry, hash, &participants, context)
    {
        let mut eventual_state = state.clone();
        apply_op(&mut eventual_state, &entry.op, hash, true, &signer);
        if !state_has_authority_consent_for_entry(&eventual_state, entry, context, hash) {
            return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
        }
        state.pending_widens.insert(hash, pending_widen);
        state.seqs.insert(signer, entry.seq);
        return EntryFold::Ready(state);
    }
    let applied_delayed_widen =
        context.enforce_seen_time_delay && op_is_delayable_widen(&state, &entry.op, &participants);
    apply_op(&mut state, &entry.op, hash, applied_delayed_widen, &signer);
    match &entry.op {
        AuthorityOp::RevokeDevice { revoked_key } => {
            resolve_global_forks_for_revoke(&mut state, context, revoked_key);
        }
        AuthorityOp::RecoveryReboot { .. } => {
            resolve_global_forks_for_recovery_reboot(&mut state, context);
        }
        AuthorityOp::Genesis { .. }
        | AuthorityOp::EnrollDevice { .. }
        | AuthorityOp::SetCeiling { .. }
        | AuthorityOp::RotateKey { .. }
        | AuthorityOp::SetTierFloor { .. }
        | AuthorityOp::FederationConfirm(_)
        | AuthorityOp::CriticalWriteConfirm(_)
        | AuthorityOp::VetoPendingWiden { .. }
        | AuthorityOp::FederationLifecycle(_)
        | AuthorityOp::BindActor { .. }
        | AuthorityOp::RebindActor { .. }
        | AuthorityOp::RevokeActor { .. } => {}
    }
    if !state_has_authority_consent_for_entry(&state, entry, context, hash) {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    state.seqs.insert(signer, entry.seq);
    EntryFold::Ready(state)
}

fn veto_participant_keys(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    pending_widen_hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> std::result::Result<BTreeSet<AuthorityKey>, AuthorityFoldIssue> {
    let mut participants = BTreeSet::new();
    for signature in std::iter::once(&entry.signer).chain(entry.cosigns.iter()) {
        let key = &signature.public_key;
        let active_member = state
            .roster
            .get(key)
            .is_some_and(|device| !device.revoked && device.roles != 0);
        if key_is_quarantined_for_entry(
            state,
            context,
            key,
            hash,
            Some((entry.signer_key(), entry.seq)),
        ) || (!active_member
            && !delayed_rotation_veto_allowed(state, key, pending_widen_hash, context))
        {
            return Err(AuthorityFoldIssue::SignerNotInAncestry(
                authority_entry_hash(entry).unwrap_or([0; 32]),
            ));
        }
        participants.insert(key.clone());
    }
    Ok(participants)
}

pub(super) fn active_participant_keys(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> std::result::Result<BTreeSet<AuthorityKey>, AuthorityFoldIssue> {
    let mut participants = BTreeSet::new();
    for signature in std::iter::once(&entry.signer).chain(entry.cosigns.iter()) {
        let key = &signature.public_key;
        if state
            .roster
            .get(key)
            .is_none_or(|device| device.revoked || device.roles == 0)
            || key_is_quarantined_for_entry(
                state,
                context,
                key,
                hash,
                Some((entry.signer_key(), entry.seq)),
            )
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

fn has_veto_authority_consent(
    state: &FoldState,
    participants: &BTreeSet<AuthorityKey>,
    pending_widen_hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> bool {
    participants.iter().any(|key| {
        state
            .roster
            .get(key)
            .is_some_and(folded_device_can_owner_veto)
            || delayed_rotation_veto_allowed(state, key, pending_widen_hash, context)
    })
}

fn delayed_rotation_veto_allowed(
    state: &FoldState,
    key: &AuthorityKey,
    pending_widen_hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> bool {
    let Some(revocations) = state.delayed_rotation_veto_revocations.get(key) else {
        return false;
    };
    let Some(entry_ancestors) = context.entry_ancestors else {
        return false;
    };
    let Some(target_ancestors) = entry_ancestors.get(&pending_widen_hash) else {
        return false;
    };

    revocations
        .iter()
        .all(|revocation| !target_ancestors.contains(revocation))
}

fn state_has_authority_consent_for_entry(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    context: FoldContext<'_>,
    hash: AuthorityEntryHash,
) -> bool {
    state.roster.iter().any(|(key, device)| {
        context.device_can_consent(device)
            && !key_is_quarantined_for_entry(
                state,
                context,
                key,
                hash,
                Some((entry.signer_key(), entry.seq)),
            )
    })
}

fn pending_widen_for_entry(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    participants: &BTreeSet<AuthorityKey>,
    context: FoldContext<'_>,
) -> Option<AuthorityPendingWiden> {
    if !context.enforce_seen_time_delay || !op_is_delayable_widen(state, &entry.op, participants) {
        return None;
    }

    let first_seen_at_secs = context.first_seen_at_secs.get(&hash).copied();
    let eligible_at_secs =
        first_seen_at_secs.and_then(|seen_at| seen_at.checked_add(state.pending_widen_delay_secs));
    if let (Some(now_secs), Some(eligible_at_secs)) = (context.now_secs, eligible_at_secs)
        && now_secs >= eligible_at_secs
    {
        return None;
    }

    Some(AuthorityPendingWiden {
        entry_hash: hash,
        first_seen_at_secs,
        eligible_at_secs,
        delay_secs: state.pending_widen_delay_secs,
    })
}

fn op_has_instant_widen_authority(
    state: &FoldState,
    op: &AuthorityOp,
    participants: &BTreeSet<AuthorityKey>,
) -> bool {
    if matches!(op, AuthorityOp::RecoveryReboot { .. }) {
        return true;
    }
    participants.iter().any(|key| {
        state.roster.get(key).is_some_and(|device| {
            folded_device_can_authority_consent(device) && device.tier == AuthorityTier::Hardware
        })
    })
}

fn op_is_delayable_widen(
    state: &FoldState,
    op: &AuthorityOp,
    participants: &BTreeSet<AuthorityKey>,
) -> bool {
    op_can_be_pending_widen(state, op) && !op_has_instant_widen_authority(state, op, participants)
}

/// Whether `op` still folds while an UNRELATED widen is pending.
///
/// A pending widen freezes the log: every later entry waits, because the widen
/// may yet be vetoed and folding on a roster that might change would decide the
/// entry against the wrong state. That is the right default for anything that
/// GRANTS — the grant can afford to wait out the veto window, and waiting is the
/// conservative direction.
///
/// It is the wrong default for `RevokeActor`. A revocation is the operator's
/// emergency brake: it WITHDRAWS consent, and withdrawal of consent is
/// unconditional — no roster the pending widen could produce makes a revoked
/// actor's authority legitimate again. Deferring it hands the widen's clock (up
/// to `MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS`) to the revocation, so an owner who
/// files a revocation because a key is compromised watches that key keep every
/// owner verb until an unrelated enrollment matures. Worse, the attacker chooses
/// the delay: filing any delayable widen of their own extends their own
/// authority.
///
/// The asymmetry is deliberate and narrow. `BindActor`/`RebindActor` GRANT
/// identity, so they keep the deferral; only the withdrawal skips it. Skipping
/// is safe because a revocation cannot widen anything: it only raises a
/// per-key watermark that kills bindings at or below it, so folding it early
/// can strictly REMOVE authority from the derived roster, never add it — and
/// the pending widen still matures on its own clock, unaffected.
///
/// SEAM — this exemption has a SECOND half, [`revocation_bypass_states`]. The
/// check here runs after parents are resolved, so on its own it does nothing
/// for a revocation whose PARENT is the frozen entry: an unresolved parent
/// returns `Waiting` before this line is reached, and a compromised key can
/// manufacture exactly that parent. The ancestry bypass closes that path by
/// letting a stalled revocation — and only a revocation — resolve against its
/// nearest ready ancestor. Same ruling, same blast radius (removal-only,
/// monotone watermark); read the two together before changing either.
pub(super) fn op_applies_despite_pending_widen(op: &AuthorityOp) -> bool {
    match op {
        AuthorityOp::RevokeActor { .. } => true,
        AuthorityOp::Genesis { .. }
        | AuthorityOp::EnrollDevice { .. }
        | AuthorityOp::RevokeDevice { .. }
        | AuthorityOp::SetCeiling { .. }
        | AuthorityOp::RotateKey { .. }
        | AuthorityOp::SetTierFloor { .. }
        | AuthorityOp::RecoveryReboot { .. }
        | AuthorityOp::FederationConfirm(_)
        | AuthorityOp::CriticalWriteConfirm(_)
        | AuthorityOp::VetoPendingWiden { .. }
        | AuthorityOp::FederationLifecycle(_)
        | AuthorityOp::BindActor { .. }
        | AuthorityOp::RebindActor { .. } => false,
    }
}

fn op_can_be_pending_widen(state: &FoldState, op: &AuthorityOp) -> bool {
    match op {
        AuthorityOp::EnrollDevice { device } => state
            .roster
            .get(&device.key)
            .is_none_or(|folded| folded.revoked),
        AuthorityOp::RotateKey { .. } => true,
        AuthorityOp::SetTierFloor { tier_floor } => *tier_floor < state.tier_floor,
        AuthorityOp::RecoveryReboot { .. } => true,
        AuthorityOp::Genesis { .. }
        | AuthorityOp::RevokeDevice { .. }
        | AuthorityOp::SetCeiling { .. }
        | AuthorityOp::FederationConfirm(_) | AuthorityOp::CriticalWriteConfirm(_)
        | AuthorityOp::VetoPendingWiden { .. }
        | AuthorityOp::FederationLifecycle(_)
        // Bind ops are instant, never delayed-vetoable widens: the widen
        // ceremony already ran when the KEY was enrolled, and a human-class
        // bind additionally demands an owner-capable signer AND an
        // owner-capable bound key, so no authority widens at bind time.
        | AuthorityOp::BindActor { .. }
        | AuthorityOp::RebindActor { .. }
        | AuthorityOp::RevokeActor { .. } => false,
    }
}

fn op_reuses_existing_device_key(state: &FoldState, op: &AuthorityOp) -> bool {
    match op {
        AuthorityOp::EnrollDevice { device }
        | AuthorityOp::RotateKey {
            new_device: device, ..
        }
        | AuthorityOp::RecoveryReboot {
            new_device: device, ..
        } => state.roster.contains_key(&device.key),
        AuthorityOp::Genesis { .. }
        | AuthorityOp::RevokeDevice { .. }
        | AuthorityOp::SetCeiling { .. }
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
        AuthorityOp::Genesis { .. } | AuthorityOp::VetoPendingWiden { .. }
    )
}

fn revoke_would_break_quorum(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    participants: &BTreeSet<AuthorityKey>,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> bool {
    let AuthorityOp::RevokeDevice { revoked_key } = &entry.op else {
        return false;
    };
    let active_before = active_roster_count_for_entry(state, entry, context, hash);
    let revoked_was_active = state.roster.get(revoked_key).is_some_and(|device| {
        !device.revoked
            && device.roles != 0
            && !key_is_quarantined_for_entry(
                state,
                context,
                revoked_key,
                hash,
                Some((entry.signer_key(), entry.seq)),
            )
    });
    let active_after = active_before.saturating_sub(usize::from(revoked_was_active));
    participants.len() < 2 || active_after < 2
}

fn active_roster_count_for_entry(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    context: FoldContext<'_>,
    hash: AuthorityEntryHash,
) -> usize {
    state
        .roster
        .iter()
        .filter(|(key, device)| {
            !device.revoked
                && device.roles != 0
                && !key_is_quarantined_for_entry(
                    state,
                    context,
                    key,
                    hash,
                    Some((entry.signer_key(), entry.seq)),
                )
        })
        .count()
}
