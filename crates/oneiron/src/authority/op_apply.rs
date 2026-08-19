//! Applies one [`super::AuthorityOp`] to a [`super::fold_state::FoldState`].
//!
//! Roster, tier-floor, actor-binding, federation-lifecycle, and pact-merge
//! mutations. Treated as a black box by [`super::entry_transition`].

use std::collections::BTreeSet;

use crate::federation::{
    FederationDirectionScope, FederationPactScope, encode_federation_pact_scope,
};

use super::*;

pub(super) fn apply_op(
    state: &mut FoldState,
    op: &AuthorityOp,
    entry_hash: AuthorityEntryHash,
    applied_delayed_widen: bool,
    signer: &AuthorityKey,
) {
    match op {
        AuthorityOp::Genesis { .. } => {}
        AuthorityOp::EnrollDevice { device } => upsert_device(state, device),
        AuthorityOp::RevokeDevice { revoked_key } => {
            state
                .fork_resolution_revocations
                .insert(revoked_key.clone());
            revoke_key(state, revoked_key);
            for fork in state.authority_forks.values_mut() {
                if fork.signer == *revoked_key && fork.status == AuthorityForkStatus::Quarantined {
                    fork.status = AuthorityForkStatus::Resolved;
                }
            }
        }
        AuthorityOp::SetCeiling { .. } | AuthorityOp::FederationConfirm(_) => {}
        AuthorityOp::CriticalWriteConfirm(action) => {
            state
                .consumed_critical_write_confirm_nonces
                .insert(action.nonce);
            state
                .critical_write_confirm_nonce_provenance
                .entry(action.nonce)
                .or_default()
                .insert(action.confirm_id);
            state
                .critical_write_confirms
                .entry(action.confirm_id)
                .or_insert_with(|| CriticalWriteConfirmState {
                    action: action.clone(),
                    signer: signer.clone(),
                    authority_entry_hash: entry_hash,
                });
        }
        AuthorityOp::RotateKey {
            old_key,
            new_device,
        } => {
            // Vetoes signed during a delayed rotation can be parented after the
            // pending rotation entry; keep the old key as veto-only authority
            // once that delayed rotation lands and revokes it.
            if applied_delayed_widen
                && state
                    .roster
                    .get(old_key)
                    .is_some_and(folded_device_can_owner_veto)
            {
                state
                    .delayed_rotation_veto_revocations
                    .entry(old_key.clone())
                    .or_default()
                    .insert(entry_hash);
            }
            revoke_key(state, old_key);
            upsert_device(state, new_device);
        }
        AuthorityOp::SetTierFloor { tier_floor } => {
            state.tier_floor = most_restrictive_tier_floor(state.tier_floor, *tier_floor);
        }
        AuthorityOp::RecoveryReboot {
            new_device,
            tier_floor,
            ..
        } => {
            let revoked_keys: BTreeSet<_> = state.roster.keys().cloned().collect();
            state
                .fork_resolution_revocations
                .extend(revoked_keys.iter().cloned());
            for device in state.roster.values_mut() {
                device.revoked = true;
            }
            state.tier_floor = most_restrictive_tier_floor(state.tier_floor, *tier_floor);
            upsert_device(state, new_device);
            for fork in state.authority_forks.values_mut() {
                if fork.status == AuthorityForkStatus::Quarantined
                    && revoked_keys.contains(&fork.signer)
                {
                    fork.status = AuthorityForkStatus::Resolved;
                }
            }
        }
        AuthorityOp::VetoPendingWiden { .. } => {}
        // The VetoPendingWiden precedent: `apply_op` returns `()` and cannot
        // emit rejections; all lifecycle validation and state transitions
        // live in `fold_entry_state`'s lifecycle arm.
        AuthorityOp::FederationLifecycle(_) => {}
        // Same precedent: the binding arm in `fold_entry_state` returns before
        // reaching here, so these are unreachable for Ready entries.
        AuthorityOp::BindActor { .. }
        | AuthorityOp::RebindActor { .. }
        | AuthorityOp::RevokeActor { .. } => {}
    }
}

/// The actor-binding transition table (ONE-1604-D2).
///
/// Evaluated against the MERGED ancestry state — the fold is the ordering, so
/// these rows never consult wall-clock or arrival sequence. Bind/Rebind are
/// ancestry-validated; Revoke is deliberately asymmetric and never rejected
/// for absence, because a revocation that fails to apply is the only
/// unrecoverable outcome here.
pub(super) fn apply_actor_binding(
    state: &mut FoldState,
    op: &AuthorityOp,
) -> std::result::Result<(), ActorBindingRejection> {
    let (authority_key, actor_ref, actor_class, epoch, is_rebind) = match op {
        AuthorityOp::RevokeActor {
            authority_key,
            epoch,
        } => {
            let watermark = state
                .actor_binding_revocations
                .entry(authority_key.clone())
                .or_insert(0);
            *watermark = (*watermark).max(*epoch);
            return Ok(());
        }
        AuthorityOp::BindActor {
            authority_key,
            actor_ref,
            actor_class,
            epoch,
        } => (authority_key, actor_ref, actor_class, *epoch, false),
        AuthorityOp::RebindActor {
            authority_key,
            actor_ref,
            actor_class,
            epoch,
        } => (authority_key, actor_ref, actor_class, *epoch, true),
        _ => return Ok(()),
    };

    // The linkage teeth: a binding may only attach to a key the roster still
    // vouches for. Without this, any signed entry could mint identity for a
    // key that was never enrolled.
    let Some(device) = state.roster.get(authority_key).filter(|d| !d.revoked) else {
        return Err(ActorBindingRejection::KeyNotInRoster);
    };
    // Closes the bind-an-agent-key-as-human hole: human class is the owner
    // class, so the bound key must itself be able to give owner consent.
    // Agent/system bindings may target ROLE_AGENT keys (the 1634 seam).
    if actor_class == "human" && !folded_device_can_authority_consent(device) {
        return Err(ActorBindingRejection::OwnerCapabilityRequired);
    }

    let live = state.live_actor_binding(authority_key);
    match (is_rebind, live) {
        (false, Some(_)) => return Err(ActorBindingRejection::BindingExists),
        (true, None) => return Err(ActorBindingRejection::BindingMissing),
        (true, Some(existing)) if epoch <= existing.epoch => {
            return Err(ActorBindingRejection::EpochNotAdvanced);
        }
        _ => {}
    }
    // A fresh bind must clear BOTH the revocation watermark and any dead
    // binding still parked on this key, so a revoked epoch can never be
    // resurrected by replaying the original bind.
    let floor = state
        .actor_binding_revocations
        .get(authority_key)
        .copied()
        .unwrap_or(0)
        .max(
            state
                .actor_bindings
                .get(authority_key)
                .map_or(0, |binding| binding.epoch),
        );
    if epoch <= floor {
        return Err(ActorBindingRejection::EpochNotAdvanced);
    }
    state.actor_bindings.insert(
        authority_key.clone(),
        ActorBindingState {
            actor_ref: *actor_ref,
            actor_class: actor_class.clone(),
            epoch,
            conflicted: false,
        },
    );
    Ok(())
}

/// Local-outbound half of a pact scope pair.
///
/// `lo_to_hi` when the local vault id is the byte-wise smaller of the pair,
/// else `hi_to_lo`. Inverting this is a SILENT reciprocal overshare — every
/// arm resolves its outbound half through this one helper.
pub(super) fn local_outbound_scope(
    local_vault_id: &AuthorityVaultId,
    peer_vault_id: &AuthorityVaultId,
    scope: &FederationPactScope,
) -> FederationDirectionScope {
    if local_vault_id <= peer_vault_id {
        scope.lo_to_hi.clone()
    } else {
        scope.hi_to_lo.clone()
    }
}

fn verify_pact_scope_digest(
    scope: &FederationPactScope,
    pact_nonce: &[u8; 16],
    claimed_digest: &[u8; 32],
) -> std::result::Result<(), FederationLifecycleRejection> {
    let canonical_scope = encode_federation_pact_scope(scope)
        .map_err(|_| FederationLifecycleRejection::ScopeInvalid)?;
    if federation_scope_digest(pact_nonce, &canonical_scope) == *claimed_digest {
        Ok(())
    } else {
        Err(FederationLifecycleRejection::ScopeDigestMismatch)
    }
}

/// Verifies the embedded peer gesture against the side-symmetric transcript.
///
/// `pinned_peer_key` is `None` only for Connect (TOFU — the trust event is
/// approving the connection); every later gesture must verify under the pinned
/// peer owner key OR a key the peer's own admitted authority log currently
/// makes a consent root (FED-03: the peer rotates its owner devices without
/// re-pinning, and the roster that says so is refolded locally from relayed
/// bytes, never asserted by the relay). A signer present in the LOCAL roster is
/// always rejected: a local device must never impersonate the peer.
fn verify_lifecycle_gesture(
    state: &FoldState,
    action: &FederationLifecycleAction,
    scope_digest: &[u8; 32],
    pinned_peer_key: Option<&AuthorityKey>,
    context: FoldContext<'_>,
) -> std::result::Result<AuthorityKey, FederationLifecycleRejection> {
    let Some(gesture) = &action.gesture else {
        return Err(FederationLifecycleRejection::GestureMissing);
    };
    if state.roster.contains_key(&gesture.signer) {
        return Err(FederationLifecycleRejection::GestureInvalid);
    }
    if pinned_peer_key.is_some_and(|pinned| *pinned != gesture.signer)
        && !peer_roster_authorizes_gesture(context, &action.peer_vault_id, &gesture.signer)
    {
        return Err(FederationLifecycleRejection::GestureInvalid);
    }
    let transcript = federation_pact_transcript(
        action.kind,
        &action.pact_id,
        &state.vault_id,
        &action.peer_vault_id,
        action.pact_epoch,
        scope_digest,
        action.successor_vault_id.as_ref(),
        &action.pact_nonce,
    )
    .map_err(|_| FederationLifecycleRejection::GestureInvalid)?;
    let signature = AuthoritySignature {
        suite: gesture.signer.suite(),
        public_key: gesture.signer.clone(),
        signature: gesture.signature.clone(),
    };
    if verify_authority_signature(&signature, &transcript) {
        Ok(gesture.signer.clone())
    } else {
        Err(FederationLifecycleRejection::GestureInvalid)
    }
}

/// True when `signer` is a consent root of the ADMITTED authority log of the
/// peer vault this action names.
///
/// The map is empty unless the caller admitted that peer's log locally, so a
/// vault with no admitted peer rows keeps pinned-key-only FED-01 behaviour.
fn peer_roster_authorizes_gesture(
    context: FoldContext<'_>,
    peer_vault_id: &AuthorityVaultId,
    signer: &AuthorityKey,
) -> bool {
    context
        .peer_consent_roots
        .get(peer_vault_id)
        .is_some_and(|roots| roots.contains(signer))
}

/// Full D5 transition table, evaluated against the merged ancestry state.
pub(super) fn apply_federation_lifecycle(
    state: &mut FoldState,
    action: &FederationLifecycleAction,
    context: FoldContext<'_>,
) -> std::result::Result<(), FederationLifecycleRejection> {
    let local_vault_id = state.vault_id;
    let Some(pact) = state.federation_pacts.get(&action.pact_id).cloned() else {
        if action.kind != FederationLifecycleKind::Connect {
            return Err(FederationLifecycleRejection::UnknownPact);
        }
        // Re-connection is a NEW pact_id AND a new grant: a grant_ref that
        // has EVER appeared in a pact binding (the registry is a superset of
        // the live pact states' grant_refs — every binding enters through a
        // Connect) is never re-covered by a fresh pact, including bindings
        // discarded by a divergent-binding merge.
        if state
            .federation_grant_bindings
            .contains_key(&action.grant_ref)
        {
            return Err(FederationLifecycleRejection::GrantAlreadyBound);
        }
        if action.pact_epoch != 1 {
            return Err(FederationLifecycleRejection::EpochMismatch);
        }
        let scope = action
            .pact_scope
            .as_ref()
            .ok_or(FederationLifecycleRejection::ScopeInvalid)?;
        let claimed_digest = action
            .scope_digest
            .ok_or(FederationLifecycleRejection::ScopeDigestMismatch)?;
        verify_pact_scope_digest(scope, &action.pact_nonce, &claimed_digest)?;
        let peer_owner_key =
            verify_lifecycle_gesture(state, action, &claimed_digest, None, context)?;
        let effective_scope = local_outbound_scope(&local_vault_id, &action.peer_vault_id, scope);
        state
            .federation_grant_bindings
            .entry(action.grant_ref)
            .or_default()
            .insert(action.pact_id);
        state.federation_pacts.insert(
            action.pact_id,
            FederationPactState {
                status: FederationPactStatus::Active,
                grant_ref: action.grant_ref,
                peer_vault_id: action.peer_vault_id,
                peer_owner_key,
                pact_epoch: action.pact_epoch,
                scope_digest: claimed_digest,
                pact_scope: scope.clone(),
                effective_scope,
                successor_vault_id: None,
                terminal_epoch: None,
            },
        );
        return Ok(());
    };

    if pact.status.is_terminal() {
        return Err(FederationLifecycleRejection::TerminalPact);
    }
    if action.kind == FederationLifecycleKind::Connect {
        return Err(FederationLifecycleRejection::DuplicateConnect);
    }
    if action.peer_vault_id != pact.peer_vault_id {
        return Err(FederationLifecycleRejection::PeerVaultMismatch);
    }
    if action.grant_ref != pact.grant_ref {
        return Err(FederationLifecycleRejection::GrantAlreadyBound);
    }

    let mut pact = pact;
    match action.kind {
        FederationLifecycleKind::Connect => {
            return Err(FederationLifecycleRejection::DuplicateConnect);
        }
        FederationLifecycleKind::Rescope if action.effective_scope.is_some() => {
            // Narrow form: unilateral effective-scope overlay under the
            // dual-signed ceiling; epoch unchanged.
            if pact.status == FederationPactStatus::Suspended {
                return Err(FederationLifecycleRejection::SuspendedPact);
            }
            if action.pact_epoch != pact.pact_epoch {
                return Err(FederationLifecycleRejection::EpochMismatch);
            }
            let effective = action
                .effective_scope
                .as_ref()
                .ok_or(FederationLifecycleRejection::ScopeInvalid)?;
            let ceiling =
                local_outbound_scope(&local_vault_id, &pact.peer_vault_id, &pact.pact_scope);
            if !effective.is_narrowing_of(&ceiling) {
                return Err(FederationLifecycleRejection::WidenWithoutGesture);
            }
            pact.effective_scope = effective.clone();
        }
        FederationLifecycleKind::Rescope => {
            // Repact form: dual-signed epoch bump; heals a suspended pact.
            if action.pact_epoch.checked_sub(1) != Some(pact.pact_epoch) {
                return Err(FederationLifecycleRejection::EpochMismatch);
            }
            let scope = action
                .pact_scope
                .as_ref()
                .ok_or(FederationLifecycleRejection::ScopeInvalid)?;
            let claimed_digest = action
                .scope_digest
                .ok_or(FederationLifecycleRejection::ScopeDigestMismatch)?;
            verify_pact_scope_digest(scope, &action.pact_nonce, &claimed_digest)?;
            verify_lifecycle_gesture(
                state,
                action,
                &claimed_digest,
                Some(&pact.peer_owner_key),
                context,
            )?;
            pact.status = FederationPactStatus::Active;
            pact.pact_epoch = action.pact_epoch;
            pact.scope_digest = claimed_digest;
            pact.pact_scope = scope.clone();
            pact.effective_scope =
                local_outbound_scope(&local_vault_id, &pact.peer_vault_id, scope);
        }
        FederationLifecycleKind::Promote => {
            if pact.status == FederationPactStatus::Suspended {
                return Err(FederationLifecycleRejection::SuspendedPact);
            }
            if action.pact_epoch.checked_sub(1) != Some(pact.pact_epoch) {
                return Err(FederationLifecycleRejection::EpochMismatch);
            }
            // Promote carries no scope bytes: its digest must EQUAL the
            // stored one (byte equality, no recompute).
            let claimed_digest = action
                .scope_digest
                .ok_or(FederationLifecycleRejection::ScopeDigestMismatch)?;
            if claimed_digest != pact.scope_digest {
                return Err(FederationLifecycleRejection::ScopeDigestMismatch);
            }
            verify_lifecycle_gesture(
                state,
                action,
                &claimed_digest,
                Some(&pact.peer_owner_key),
                context,
            )?;
            pact.status = FederationPactStatus::Promoted;
            pact.pact_epoch = action.pact_epoch;
            pact.successor_vault_id = action.successor_vault_id;
            pact.terminal_epoch = Some(action.pact_epoch);
        }
        FederationLifecycleKind::Disconnect => {
            if action.pact_epoch != pact.pact_epoch {
                return Err(FederationLifecycleRejection::EpochMismatch);
            }
            pact.status = FederationPactStatus::Disconnected;
            pact.terminal_epoch = Some(pact.pact_epoch);
        }
        FederationLifecycleKind::Dissolve => {
            if action.pact_epoch != pact.pact_epoch {
                return Err(FederationLifecycleRejection::EpochMismatch);
            }
            pact.status = FederationPactStatus::Dissolved;
            pact.terminal_epoch = Some(pact.pact_epoch);
        }
    }
    state.federation_pacts.insert(action.pact_id, pact);
    Ok(())
}

/// Deterministic, commutative pick between two equally ranked pact states:
/// the lexicographic-min (scope_digest, grant_ref) side. The pair is always
/// discriminating for divergent states, since divergence implies at least one
/// of the two fields differs.
fn pact_merge_tiebreak_side<'a>(
    left: &'a FederationPactState,
    right: &'a FederationPactState,
) -> &'a FederationPactState {
    if (left.scope_digest, left.grant_ref) <= (right.scope_digest, right.grant_ref) {
        left
    } else {
        right
    }
}

/// Commutative, associative, idempotent per-pact merge join.
///
/// Terminal-wins regardless of epoch (revocations-win); two terminals resolve
/// by fixed precedence Dissolved > Disconnected > Promoted; non-terminals
/// resolve by max epoch. Equal-epoch non-terminals fold as a COMPETITOR SET
/// keyed by (scope_digest, grant_ref): equal keys combine (effective scopes
/// intersect, min peer key, Suspended if either side is); divergent keys
/// suspend fail-closed and carry the lexicographic-min key's fields. Because
/// every pairwise step re-takes the min — a Suspended side is never absorbed
/// verbatim past an Active competitor — any merge tree folds a 3+-way
/// divergence to the GLOBAL lex-min, so the heal target (the grant_ref an
/// epoch+1 repact must name) is independent of merge topology and hash
/// order. Every binding discarded by a pick stays denied through
/// `FoldState::federation_grant_bindings` (union-merged), so no grant that
/// ever appeared in a pact binding regains `Unpacted` legacy-allow.
pub(super) fn merge_pact_states(
    left: &FederationPactState,
    right: &FederationPactState,
) -> FederationPactState {
    let left_terminal = left.status.is_terminal();
    let right_terminal = right.status.is_terminal();
    if left_terminal != right_terminal {
        return if left_terminal {
            left.clone()
        } else {
            right.clone()
        };
    }
    if left_terminal && right_terminal {
        if left.status != right.status {
            return if left.status > right.status {
                left.clone()
            } else {
                right.clone()
            };
        }
        if left.pact_epoch != right.pact_epoch {
            return if left.pact_epoch > right.pact_epoch {
                left.clone()
            } else {
                right.clone()
            };
        }
        return pact_merge_tiebreak_side(left, right).clone();
    }
    if left.pact_epoch != right.pact_epoch {
        return if left.pact_epoch > right.pact_epoch {
            left.clone()
        } else {
            right.clone()
        };
    }
    // Both non-terminal at the same consent epoch: fold the competitor set.
    if (left.scope_digest, left.grant_ref) == (right.scope_digest, right.grant_ref) {
        let mut merged = left.clone();
        // Concurrent unilateral narrows are both honored.
        merged.effective_scope = left.effective_scope.intersect(&right.effective_scope);
        // Concurrent duplicate Connects can pin different verified peer
        // roster keys; the pick is determinism-only.
        merged.peer_owner_key = left
            .peer_owner_key
            .clone()
            .min(right.peer_owner_key.clone());
        // Same discipline for the peer vault id (duplicate Connects can be
        // dual-signed with different peers), and — reachable only through a
        // digest collision — for divergent scope bytes via their canonical
        // encoding, so this arm stays commutative, associative, and
        // idempotent on every field it carries.
        merged.peer_vault_id = left.peer_vault_id.min(right.peer_vault_id);
        if left.pact_scope != right.pact_scope {
            let left_scope_bytes =
                encode_federation_pact_scope(&left.pact_scope).unwrap_or_default();
            let right_scope_bytes =
                encode_federation_pact_scope(&right.pact_scope).unwrap_or_default();
            if right_scope_bytes < left_scope_bytes {
                merged.pact_scope = right.pact_scope.clone();
            }
        }
        // A suspension carried by either side persists under an agreeing
        // competitor: the conflict that caused it is still unhealed.
        merged.status = left.status.max(right.status);
        return merged;
    }
    // Divergent concurrent re-pacts (digest) or concurrent Connects binding
    // one pact id to two different grants (grant_ref): both are
    // equivocation-shaped conflicts on the consent axis. Fail closed at the
    // shared epoch and carry the min-key side, RE-TAKING the min even when
    // one side is already Suspended; heals via a fresh dual-signed Rescope
    // at epoch+1 naming the surviving binding. The losing grant_ref stays
    // denied via the grant-binding registry.
    let mut merged = pact_merge_tiebreak_side(left, right).clone();
    merged.status = FederationPactStatus::Suspended;
    merged.successor_vault_id = None;
    merged.terminal_epoch = None;
    merged
}

pub(super) fn upsert_device(state: &mut FoldState, device: &DeviceAuthority) {
    let folded = FoldedDevice {
        key: device.key.clone(),
        tier: device.tier,
        roles: device.roles,
        revoked: false,
    };
    match state.roster.get_mut(&device.key) {
        Some(existing) => {
            if !existing.revoked {
                existing.roles &= folded.roles;
                existing.tier = most_restrictive_device_tier(existing.tier, folded.tier);
            }
        }
        None => {
            state.roster.insert(device.key.clone(), folded);
        }
    }
}

fn revoke_key(state: &mut FoldState, key: &AuthorityKey) {
    state
        .roster
        .entry(key.clone())
        .and_modify(|device| device.revoked = true)
        .or_insert(FoldedDevice {
            key: key.clone(),
            tier: AuthorityTier::Software,
            roles: 0,
            revoked: true,
        });
}
