//! Host-authorized issuance of one immutable machine-claim transition.
//!
//! The typed caller must authorize the *verb* and authenticate its actor before
//! entering this staging door. In particular an actor id/class is attribution,
//! not a substitute for a capability, owner approval, or a Gate decision.
//! This door independently requires a live local host issuer and a complete,
//! trusted predecessor closure; it never appends to AUTHORITY_LOG.

use std::collections::BTreeSet;

use rand_core::RngCore;
use rmpv::Value;

use super::{
    ClaimTransitionKind, SignedClaimTransitionEvent, TransitionDelta,
    encode_machine_claim_transition_event, fold_machine_claim_transitions,
    machine_claim_transition_event_hash, machine_claim_transition_event_id,
    machine_claim_transition_transcript,
};
use crate::authority::{AuthorityKey, ROLE_OWNER};
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::history_projection::{
    machine_history_rows, pin_key, project_machine_claim, resolved_machine_history,
    trusted_machine_handoff,
};
use crate::claim::history_store::{
    MachineHistoryKind, machine_history_claim, machine_history_scope_bytes,
    machine_history_shape_matches,
};
use crate::claim::{
    ClaimBirth, ClaimBody, ClaimHistoryHandoff, ClaimHistoryHandoffPin, ClaimSubject,
    ClaimTransition, HandoffStanding, HandoffVerification, verify_claim_history_handoff,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::{ClaimError, Error, Result};
use crate::store::Store;
use crate::{EntityId, TimeRange, VaultConfig};

fn incomplete() -> Error {
    Error::Claim(ClaimError::MachineClaimHistoryIncomplete)
}

fn invalid() -> Error {
    Error::Claim(ClaimError::InvalidMachineClaimProof)
}

fn refused() -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority {
        reason: "a live local host history issuer is required",
    })
}

fn content_id(hash: [u8; 32]) -> Result<EntityId> {
    EntityId::from_bytes(hash[..16].try_into().map_err(|_| invalid())?).map_err(|_| invalid())
}

/// Stage one event and its complete, chained handoff in the caller's writer.
///
/// The caller has already authenticated `actor`/`actor_class`, authorized this
/// particular kind at its typed verb, and enforced its Gate policy. This
/// function cannot derive a verb grant from an arbitrary entity id. The
/// resulting body is a projection only: the signed birth remains unchanged.
/// The caller must abort the whole transaction on any staging error.
#[expect(
    clippy::too_many_arguments,
    reason = "the typed caller supplies its one transaction, actor decision and materialization context"
)]
pub(crate) fn stage_machine_claim_transition(
    store: &Store,
    config: &VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    txn: &mut heed::RwTxn<'_>,
    target: EntityId,
    kind: ClaimTransitionKind,
    delta: TransitionDelta,
    actor: EntityId,
    actor_class: EdgeActorClass,
    occurred: TimeRange,
    learned_at: u64,
    text_index_trusted: bool,
) -> Result<ClaimBody> {
    // Keep the issuer guard until both controls and the new pin have been
    // staged. Rechecking within this same LMDB snapshot closes host-roster
    // changes; no peer packet or caller-provided key selects the signer.
    let guard = store
        .machine_history_issuer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let issuer = guard.as_ref().ok_or_else(refused)?;
    let signer = issuer.public_key();
    let (vault_id, authority_head) = crate::authority::machine_history_host_context(
        store,
        config.privacy.posture,
        txn,
        &signer,
    )?;
    let fold = crate::authority::authority_fold_readonly_for_store_in_txn(
        store,
        config.privacy.posture,
        txn,
    )?;
    if fold.vault_root_is_conflicted()
        || fold.vault_id != Some(vault_id)
        || !fold.valid_entries.contains(&authority_head)
        || !fold
            .roster
            .get(&signer)
            .is_some_and(|root| !root.revoked && root.roles & ROLE_OWNER != 0)
    {
        return Err(refused());
    }

    let rows = machine_history_rows(store, txn, target)?;
    rows.birth.verify().map_err(|_| invalid())?;
    if rows.birth.vault_id != vault_id || rows.birth.target != target {
        return Err(invalid());
    }
    let original = crate::claim::decode_claim_body(&rows.birth.initial_body, true)?;
    let prior = trusted_machine_handoff(store, txn, target)?;
    let prior_hash = prior.content_hash().map_err(|_| invalid())?;
    let prior_id = content_id(prior_hash)?;
    let prior_raw = store
        .entities
        .get(txn, prior_id.as_bytes())?
        .ok_or_else(incomplete)?;
    if EntityMetadataHeader::parse(&prior_raw)
        .is_none_or(|header| header.entity_type != crate::registry::ENTITY_TYPE_CLAIM)
    {
        return Err(invalid());
    }
    let prior_row =
        crate::claim::decode_claim_body(&prior_raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    if !machine_history_shape_matches(&prior_row, MachineHistoryKind::Handoff, target, &original)
        || prior_row.value != Value::Binary(prior.encode().map_err(|_| invalid())?)
        || prior.vault_id != vault_id
        || prior.genesis_hash != vault_id
        || prior.scope != machine_history_scope_bytes(&original)?
        || prior.births
            != vec![ClaimBirth {
                id: target,
                digest: rows.birth.digest,
            }]
        || !fold.valid_entries.contains(&prior.authority_head)
    {
        return Err(invalid());
    }
    // A trusted pin is local host custody, not merely a packet copied from
    // the peer. Verify its signature and DAG, then independently compare every
    // referenced transition hash and parent to verified resident controls.
    let prior_pin = ClaimHistoryHandoffPin {
        vault_id: &vault_id,
        genesis_hash: &vault_id,
        expected_signer: &prior.signer,
        scope: &prior.scope,
        previous_handoff_hash: prior.previous_handoff_hash,
        challenge: &prior.challenge,
    };
    if !matches!(
        verify_claim_history_handoff(&prior, &prior_pin, |_| HandoffStanding::OwnerAndComplete),
        HandoffVerification::Verified(_)
    ) {
        return Err(invalid());
    }
    if prior.transitions.len() != rows.events.len() {
        return Err(incomplete());
    }
    let mut seen = BTreeSet::new();
    for event in &rows.events {
        let hash = machine_claim_transition_event_hash(event).map_err(|_| invalid())?;
        let mut predecessors = if event.predecessors.is_empty() {
            vec![rows.birth.digest]
        } else {
            event.predecessors.clone()
        };
        predecessors.sort_unstable();
        if !prior
            .transitions
            .iter()
            .any(|row| row.hash == hash && row.predecessors == predecessors)
            || !seen.insert(hash)
        {
            return Err(incomplete());
        }
    }
    // Also require the prior closure's pure fold to prove its claimed tips
    // and event signatures/authority before extending it.
    let before = resolved_machine_history(store, txn, &fold, target)?;
    let prior_tips: Vec<_> = if before.frontier.is_empty() {
        vec![rows.birth.digest]
    } else {
        before.frontier.clone()
    };
    if prior.heads != prior_tips {
        return Err(incomplete());
    }
    let target_raw = store
        .entities
        .get(txn, target.as_bytes())?
        .ok_or_else(incomplete)?;
    if EntityMetadataHeader::parse(&target_raw)
        .is_none_or(|header| header.entity_type != crate::registry::ENTITY_TYPE_CLAIM)
        || crate::claim::decode_claim_body(&target_raw[ENTITY_METADATA_HEADER_LEN..], true)?
            != project_machine_claim(&before)
    {
        return Err(invalid());
    }

    let host_public_key = match &signer {
        AuthorityKey::Ed25519(key) => *key,
        AuthorityKey::P256(_) => return Err(refused()),
    };
    let mut event = SignedClaimTransitionEvent {
        vault_id,
        target,
        birth_digest: rows.birth.digest,
        // Empty means a direct child of birth in the signed event codec.
        predecessors: before.frontier,
        authority_head,
        actor,
        actor_class,
        host_public_key,
        kind,
        delta,
        signature: [0; 64],
    };
    event.signature = issuer.sign_claim_handoff(&machine_claim_transition_transcript(&event)?);
    let event_bytes = encode_machine_claim_transition_event(&event)?;
    let event_hash = machine_claim_transition_event_hash(&event)?;
    let event_id = machine_claim_transition_event_id(&event)?;
    let mut events = rows.events;
    events.push(event.clone());
    let initial_weight = matches!(original.subject, ClaimSubject::Entity(_))
        .then_some(EdgeKind::ClaimOf.default_weight().unwrap_or(1.0));
    let result = fold_machine_claim_transitions(
        &original,
        &vault_id,
        target,
        &rows.birth.digest,
        initial_weight,
        &events,
        &[event_hash],
        |candidate| {
            if candidate == &event {
                return true;
            }
            machine_claim_transition_event_hash(candidate).is_ok_and(|hash| seen.contains(&hash))
        },
    )
    .map_err(|_| invalid())?;
    let projected = project_machine_claim(&result);

    let mut handoff = ClaimHistoryHandoff {
        vault_id,
        genesis_hash: vault_id,
        scope: prior.scope.clone(),
        births: prior.births.clone(),
        transitions: prior.transitions.clone(),
        heads: vec![event_hash],
        authority_head,
        previous_handoff_hash: Some(prior_hash),
        nonce: [0; 32],
        challenge: [0; 32],
        signer: issuer.public_key(),
        signature: [0; 64],
    };
    handoff.transitions.push(ClaimTransition {
        hash: event_hash,
        predecessors: prior_tips,
    });
    handoff.transitions.sort_unstable_by_key(|row| row.hash);
    rand_core::OsRng.fill_bytes(&mut handoff.nonce);
    rand_core::OsRng.fill_bytes(&mut handoff.challenge);
    handoff.signature = issuer.sign_claim_handoff(&handoff.transcript().map_err(|_| invalid())?);
    let handoff_bytes = handoff.encode().map_err(|_| invalid())?;
    let handoff_hash = handoff.content_hash().map_err(|_| invalid())?;
    let handoff_id = content_id(handoff_hash)?;
    let next_pin = ClaimHistoryHandoffPin {
        vault_id: &vault_id,
        genesis_hash: &vault_id,
        expected_signer: &signer,
        scope: &handoff.scope,
        previous_handoff_hash: Some(prior_hash),
        challenge: &handoff.challenge,
    };
    if !matches!(
        verify_claim_history_handoff(&handoff, &next_pin, |_| HandoffStanding::OwnerAndComplete),
        HandoffVerification::Verified(_)
    ) {
        return Err(invalid());
    }
    // All authorization, closure, fold and size checks precede the first
    // mutation. Apply both scoped, reserved CLAIM controls in this writer.
    let mut ops = Vec::new();
    for (id, control) in [
        (
            event_id,
            machine_history_claim(
                MachineHistoryKind::Transition,
                target,
                &original,
                event_bytes,
            ),
        ),
        (
            handoff_id,
            machine_history_claim(
                MachineHistoryKind::Handoff,
                target,
                &original,
                handoff_bytes.clone(),
            ),
        ),
    ] {
        ops.push(BatchOp::Put {
            id,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            data: crate::claim::encode_claim_body(&control)?,
            allow_maintenance: false,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        });
        ops.push(BatchOp::Edge {
            src: id,
            kind: EdgeKind::FacetOf,
            tgt: original.scope_facet,
            weight: 1.0,
            vad: crate::affect::Vad::NEUTRAL,
        });
    }
    crate::batch::apply_ops_with_gate_mode(
        store,
        config,
        analyzer,
        txn,
        ops,
        text_index_trusted,
        crate::batch::ApplyOpsGateMode::new(false, false),
    )?;
    store
        .vault_meta
        .put(txn, &pin_key(target), &handoff_bytes)?;
    Ok(projected)
}
