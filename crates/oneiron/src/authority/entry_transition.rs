//! Per-entry state transition and the consent / quorum / widen-delay predicates.
//!
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

    // Managed clients pair for logged capability slips. A legacy device-key
    // enrollment/rotation or tier-floor change cannot grant managed authority,
    // regardless of attestation, signer quorum, or elapsed local time.
    if context.hosted_root
        && matches!(
            entry.op,
            AuthorityOp::EnrollDevice { .. }
                | AuthorityOp::RotateKey { .. }
                | AuthorityOp::SetTierFloor { .. }
                | AuthorityOp::VetoPendingWiden { .. }
        )
    {
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
    if let AuthorityOp::Genesis {
        recovery,
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
            slips: SlipAuthorityState::default(),
            vault_id,
            roster: BTreeMap::new(),
            tier_floor: *tier_floor,
            genesis_recovery_dismissed: recovery.dismissed(),
            recovery_redundancy_established: false,
            tier_floor_events: BTreeMap::from([(hash, (*tier_floor, BTreeSet::new()))]),
            pending_widen_delay_secs: *pending_widen_delay_secs,
            pending_widens: BTreeMap::new(),
            vetoed_widens: context.vetoed_widens.clone(),
            delayed_rotation_veto_revocations: BTreeMap::new(),
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
    if let AuthorityOp::VetoPendingWiden { pending_widen_hash } = &entry.op {
        if !context.vetoed_widens.contains(pending_widen_hash) {
            let Some(target_state) = states.get(pending_widen_hash) else {
                return EntryFold::Waiting;
            };
            if !target_state.pending_widens.contains_key(pending_widen_hash) {
                return EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(hash));
            }
        }
        let participants = match veto_participant_keys(&state, entry, *pending_widen_hash, context)
        {
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
    if context.vetoed_widens.contains(&hash) && op_is_delayable_widen(&state, &entry.op) {
        state.pending_widens.remove(&hash);
        state.seqs.insert(signer, entry.seq);
        return EntryFold::Ready(state);
    }
    if let Some(pending_widen) = pending_widen_for_entry(&state, entry, hash, context) {
        let mut eventual_state = state.clone();
        apply_op(&mut eventual_state, &entry.op, hash, true, &signer);
        if !state_has_authority_consent(&eventual_state, context) {
            return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
        }
        // Record eligibility before a later veto (or fixed-point pass) can
        // remove this pending row from the final fold. Cache expiry must still
        // revisit whether that veto is valid at the target's deadline.
        if let (Some(observer), Some(deadline)) =
            (context.deadline_observer, pending_widen.eligible_at_secs)
        {
            observer.set(Some(
                observer.get().map_or(deadline, |old| old.min(deadline)),
            ));
        }
        state.pending_widens.insert(hash, pending_widen);
        state.seqs.insert(signer, entry.seq);
        return EntryFold::Ready(state);
    }
    let applied_delayed_widen =
        context.enforce_seen_time_delay && op_is_delayable_widen(&state, &entry.op);
    apply_op(&mut state, &entry.op, hash, applied_delayed_widen, &signer);
    if !state_has_authority_consent(&state, context) {
        return EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(hash));
    }
    state.seqs.insert(signer, entry.seq);
    EntryFold::Ready(state)
}

fn veto_participant_keys(
    state: &FoldState,
    entry: &AuthorityLogEntry,
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
        if !active_member && !delayed_rotation_veto_allowed(state, key, pending_widen_hash, context)
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

fn has_veto_authority_consent(
    state: &FoldState,
    participants: &BTreeSet<AuthorityKey>,
    pending_widen_hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> bool {
    participants.iter().any(|key| {
        state.roster.get(key).is_some_and(|device| {
            context.device_can_consent(device) && device.roles & ROLE_OWNER != 0
        }) || delayed_rotation_veto_allowed(state, key, pending_widen_hash, context)
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

fn state_has_authority_consent(state: &FoldState, context: FoldContext<'_>) -> bool {
    state
        .roster
        .values()
        .any(|device| context.device_can_consent(device))
}

fn pending_widen_for_entry(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> Option<AuthorityPendingWiden> {
    if !context.enforce_seen_time_delay || !op_is_delayable_widen(state, &entry.op) {
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

fn op_is_delayable_widen(state: &FoldState, op: &AuthorityOp) -> bool {
    // A device's assurance tier is not a widen credential. In particular,
    // Hardware must not bypass the local pending window for legacy device ops.
    op_can_be_pending_widen(state, op)
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
        AuthorityOp::RevokeActor { .. }
        | AuthorityOp::SlipRevoke { .. }
        | AuthorityOp::SlipConsume { .. } => true,
        AuthorityOp::Genesis { .. }
        | AuthorityOp::EnrollDevice { .. }
        | AuthorityOp::RevokeDevice { .. }
        | AuthorityOp::RetiredCeiling { .. }
        | AuthorityOp::SlipMint(_)
        | AuthorityOp::RotateKey { .. }
        | AuthorityOp::SetTierFloor { .. }
        | AuthorityOp::ReRoot { .. }
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
        AuthorityOp::ReRoot { .. } => false,
        AuthorityOp::Genesis { .. }
        | AuthorityOp::RevokeDevice { .. }
        | AuthorityOp::RetiredCeiling { .. }
        | AuthorityOp::SlipMint(_) | AuthorityOp::SlipRevoke {..} | AuthorityOp::SlipConsume {..}
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
            | AuthorityOp::VetoPendingWiden { .. }
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
        .values()
        .filter(|device| !device.revoked && device.roles != 0)
        .count()
}
