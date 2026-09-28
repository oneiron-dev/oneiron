use ed25519_dalek::{Signer, SigningKey};
use rmpv::Value;

use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;

use super::*;

fn id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).unwrap()
}

fn birth() -> ClaimBody {
    ClaimBody::new(
        "core.example",
        ClaimSubject::Entity(id(8)),
        Value::from("immutable"),
        0.9,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
}

fn signed(
    kind: ClaimTransitionKind,
    delta: TransitionDelta,
    parents: Vec<TransitionEventHash>,
) -> SignedClaimTransitionEvent {
    let key = SigningKey::from_bytes(&[11; 32]);
    let mut event = SignedClaimTransitionEvent {
        vault_id: [9; 32],
        target: id(7),
        birth_digest: [10; 32],
        predecessors: parents,
        authority_head: [12; 32],
        actor: id(6),
        actor_class: EdgeActorClass::System,
        host_public_key: key.verifying_key().to_bytes(),
        kind,
        delta,
        signature: [0; 64],
    };
    event.signature = key
        .sign(&machine_claim_transition_transcript(&event).unwrap())
        .to_bytes();
    event
}

fn hash(event: &SignedClaimTransitionEvent) -> TransitionEventHash {
    machine_claim_transition_event_hash(event).unwrap()
}

fn folded(
    events: &[SignedClaimTransitionEvent],
    tips: &[TransitionEventHash],
) -> Result<ClaimTransitionProjection, TransitionFoldError> {
    fold_machine_claim_transitions(
        &birth(),
        &[9; 32],
        id(7),
        &[10; 32],
        Some(0.8),
        events,
        tips,
        |event| {
            event.authority_head == [12; 32]
                && event.host_public_key
                    == SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes()
                && event.actor == id(6)
        },
    )
}

#[test]
fn canonical_wire_signature_full_hash_and_id() {
    let event = signed(ClaimTransitionKind::Approve, TransitionDelta::None, vec![]);
    let wire = encode_machine_claim_transition_event(&event).unwrap();
    assert_eq!(decode_machine_claim_transition_event(&wire).unwrap(), event);
    verify_machine_claim_transition_event(&event).unwrap();
    assert_eq!(
        machine_claim_transition_event_id(&event)
            .unwrap()
            .as_bytes(),
        &hash(&event)[..16]
    );
    let mut appended = wire;
    appended.push(0);
    assert!(decode_machine_claim_transition_event(&appended).is_err());
    let mut tampered = event.clone();
    tampered.authority_head = [13; 32];
    assert!(verify_machine_claim_transition_event(&tampered).is_err());
    assert_ne!(hash(&event), hash(&tampered));
}

#[test]
fn sorted_unique_parent_hashes_and_delta_shapes_are_mandatory() {
    let a = signed(
        ClaimTransitionKind::Weaken,
        TransitionDelta::Confidence(0.7),
        vec![],
    );
    let b = signed(
        ClaimTransitionKind::Decay,
        TransitionDelta::ClaimOfWeight(0.4),
        vec![],
    );
    let mut hashes = vec![hash(&a), hash(&b)];
    hashes.sort();
    let event = signed(
        ClaimTransitionKind::Stale,
        TransitionDelta::None,
        hashes.clone(),
    );
    assert!(encode_machine_claim_transition_event(&event).is_ok());
    hashes.reverse();
    let mut unordered = event.clone();
    unordered.predecessors = hashes;
    assert!(encode_machine_claim_transition_event(&unordered).is_err());
    let mut wrong_delta = event.clone();
    wrong_delta.kind = ClaimTransitionKind::Approve;
    wrong_delta.delta = TransitionDelta::Confidence(0.2);
    assert!(encode_machine_claim_transition_event(&wrong_delta).is_err());
    let mut not_finite = event;
    not_finite.kind = ClaimTransitionKind::Weaken;
    not_finite.delta = TransitionDelta::Confidence(f32::NAN);
    assert!(encode_machine_claim_transition_event(&not_finite).is_err());
}

#[test]
fn order_independent_restrictive_fork_and_birth_immutability() {
    let b = birth();
    let decay = signed(
        ClaimTransitionKind::Decay,
        TransitionDelta::ClaimOfWeight(0.4),
        vec![],
    );
    let weaken_a = signed(
        ClaimTransitionKind::Weaken,
        TransitionDelta::Confidence(0.7),
        vec![hash(&decay)],
    );
    let weaken_b = signed(
        ClaimTransitionKind::Weaken,
        TransitionDelta::Confidence(0.6),
        vec![hash(&decay)],
    );
    let mut tips = vec![hash(&weaken_a), hash(&weaken_b)];
    tips.sort();
    let first = folded(&[weaken_a.clone(), decay.clone(), weaken_b.clone()], &tips).unwrap();
    let second = folded(&[weaken_b, weaken_a, decay], &tips).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.birth, b);
    assert_eq!(first.confidence, 0.6);
    assert_eq!(first.claim_of_weight, Some(0.4));
    assert_eq!(
        first.demotion_rung,
        Some(crate::claim::ClaimDemotionRung::Weakened)
    );
    assert_eq!(first.birth.valid_to, None);
    assert_eq!(first.birth.confidence, 0.9);
}
#[test]
fn missing_history_and_tip_pin_refused() {
    let parent = signed(ClaimTransitionKind::Approve, TransitionDelta::None, vec![]);
    let child = signed(
        ClaimTransitionKind::Retract,
        TransitionDelta::ValidTo(100),
        vec![hash(&parent)],
    );
    assert_eq!(
        folded(std::slice::from_ref(&child), &[hash(&child)]).unwrap_err(),
        TransitionFoldError::MissingHistory
    );
    assert_eq!(
        folded(std::slice::from_ref(&parent), &[]).unwrap_err(),
        TransitionFoldError::FrontierMismatch
    );
    assert_eq!(
        folded(&[parent, child.clone()], &[hash(&child)])
            .unwrap()
            .approval,
        ClaimApprovalStatus::Approved
    );
    assert_eq!(
        folded(&[child.clone(), child.clone()], &[hash(&child)]).unwrap_err(),
        TransitionFoldError::InvalidEvent
    );
}

#[test]
fn incompatible_approval_fork_and_rollback_refused() {
    let approve = signed(ClaimTransitionKind::Approve, TransitionDelta::None, vec![]);
    let reject = signed(ClaimTransitionKind::Reject, TransitionDelta::None, vec![]);
    let mut tips = vec![hash(&approve), hash(&reject)];
    tips.sort();
    assert_eq!(
        folded(&[reject, approve], &tips).unwrap_err(),
        TransitionFoldError::IncompatibleFork
    );
    let decay = signed(
        ClaimTransitionKind::Decay,
        TransitionDelta::ClaimOfWeight(0.4),
        vec![],
    );
    let first = signed(
        ClaimTransitionKind::Weaken,
        TransitionDelta::Confidence(0.5),
        vec![hash(&decay)],
    );
    let second = signed(
        ClaimTransitionKind::Weaken,
        TransitionDelta::Confidence(0.6),
        vec![hash(&first)],
    );
    assert_eq!(
        folded(&[first, second.clone(), decay], &[hash(&second)]).unwrap_err(),
        TransitionFoldError::Rollback
    );
    let denied = signed(ClaimTransitionKind::Reject, TransitionDelta::None, vec![]);
    let next = signed(
        ClaimTransitionKind::Approve,
        TransitionDelta::None,
        vec![hash(&denied)],
    );
    assert_eq!(
        folded(&[next.clone(), denied], &[hash(&next)]).unwrap_err(),
        TransitionFoldError::Rollback
    );
}

#[test]
fn callback_checks_historical_authority_not_clock_or_signature_only() {
    let event = signed(ClaimTransitionKind::Approve, TransitionDelta::None, vec![]);
    let result = fold_machine_claim_transitions(
        &birth(),
        &[9; 32],
        id(7),
        &[10; 32],
        Some(0.8),
        std::slice::from_ref(&event),
        &[hash(&event)],
        |_| false,
    );
    assert_eq!(result.unwrap_err(), TransitionFoldError::Unauthorized);
}

#[test]
fn malformed_wire_and_opaque_scope_are_not_normalized() {
    let decay = signed(
        ClaimTransitionKind::Decay,
        TransitionDelta::ClaimOfWeight(0.4),
        vec![],
    );
    let weaken = signed(
        ClaimTransitionKind::Weaken,
        TransitionDelta::Confidence(0.5),
        vec![hash(&decay)],
    );
    let event = signed(
        ClaimTransitionKind::Stale,
        TransitionDelta::ScopeBand(3),
        vec![hash(&weaken)],
    );
    let wire = encode_machine_claim_transition_event(&event).unwrap();
    let mut noncanonical = wire;
    assert_eq!(noncanonical[0], 0x9c);
    assert_eq!(noncanonical[1], 1);
    noncanonical.splice(1..2, [0xcc, 1]);
    assert!(decode_machine_claim_transition_event(&noncanonical).is_err());
    let result = folded(
        &[event.clone(), weaken.clone(), decay.clone()],
        &[hash(&event)],
    )
    .unwrap();
    assert_eq!(result.scope_band_floor, Some(3));
    assert!(result.stale);
    assert_eq!(result.birth.scope, birth().scope);
    let lower_band = signed(
        ClaimTransitionKind::Stale,
        TransitionDelta::ScopeBand(1),
        vec![hash(&weaken)],
    );
    assert_eq!(
        folded(&[lower_band.clone(), decay, weaken], &[hash(&lower_band)]).unwrap_err(),
        TransitionFoldError::Rollback
    );
}

#[test]
fn terminal_validity_and_approval_causality() {
    // A Proposed birth may be superseded; ARCH-0040 gates the closure on the
    // superseding write's approval, not on the target's.
    let close = signed(
        ClaimTransitionKind::SupersedeClose,
        TransitionDelta::ValidTo(100),
        vec![],
    );
    let result = folded(std::slice::from_ref(&close), &[hash(&close)]).unwrap();
    assert_eq!(result.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(result.approval, ClaimApprovalStatus::Proposed);
    let approval = signed(ClaimTransitionKind::Approve, TransitionDelta::None, vec![]);
    let close = signed(
        ClaimTransitionKind::SupersedeClose,
        TransitionDelta::ValidTo(100),
        vec![hash(&approval)],
    );
    let result = folded(&[close.clone(), approval.clone()], &[hash(&close)]).unwrap();
    assert_eq!(result.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(result.valid_to, Some(100));
    assert_eq!(result.birth.valid_to, None);
    let retr = signed(
        ClaimTransitionKind::Retract,
        TransitionDelta::ValidTo(101),
        vec![hash(&close)],
    );
    assert_eq!(
        folded(&[close, retr.clone(), approval], &[hash(&retr)]).unwrap_err(),
        TransitionFoldError::Rollback
    );
}

#[test]
fn decay_requires_verified_birth_edge_weight() {
    let decay = signed(
        ClaimTransitionKind::Decay,
        TransitionDelta::ClaimOfWeight(0.7),
        vec![],
    );
    let missing = fold_machine_claim_transitions(
        &birth(),
        &[9; 32],
        id(7),
        &[10; 32],
        None,
        std::slice::from_ref(&decay),
        &[hash(&decay)],
        |_| true,
    );
    assert_eq!(missing.unwrap_err(), TransitionFoldError::Rollback);
    let raised = fold_machine_claim_transitions(
        &birth(),
        &[9; 32],
        id(7),
        &[10; 32],
        Some(0.5),
        std::slice::from_ref(&decay),
        &[hash(&decay)],
        |_| true,
    );
    assert_eq!(raised.unwrap_err(), TransitionFoldError::Rollback);
}
