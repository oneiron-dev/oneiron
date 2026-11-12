//! Doors to the signed claim-transition fold (FIX 22387). A chain of decays
//! over one fixed birth is signed and folded as the fold's own unit tests
//! fold one, so an integration test can set the fold's decay rule beside the
//! live demotion door's.

use ed25519_dalek::{Signer, SigningKey};
use rmpv::Value;

use crate::claim::transition::{
    ClaimTransitionKind, SignedClaimTransitionEvent, TransitionDelta,
    fold_machine_claim_transitions, machine_claim_transition_event_hash,
    machine_claim_transition_transcript,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimDemotionRung, ClaimLifecycleStatus, ClaimSubject,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;

/// What a folded decay chain leaves on the claim.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FoldedDecay {
    /// The effective ClaimOf weight.
    pub claim_of_weight: Option<f32>,
    /// The demotion rung.
    pub demotion_rung: Option<ClaimDemotionRung>,
}

/// Signs one `Decay` event per weight of `weights`, each parented on the
/// one before, over a claim born at ClaimOf weight `birth_weight`, and folds
/// the chain at its last event with every event authorized.
///
/// # Errors
///
/// The fold's refusal by its variant name (`Rollback`, ...), or the text of
/// an event that did not encode.
pub fn fold_decay_chain(birth_weight: f32, weights: &[f32]) -> Result<FoldedDecay, String> {
    let key = SigningKey::from_bytes(&[11; 32]);
    let target = fixture_id(7)?;
    let birth = ClaimBody::new(
        "core.example",
        ClaimSubject::Entity(fixture_id(8)?),
        Value::from("decay chain"),
        0.9,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .map_err(|error| error.to_string())?;
    let mut events = Vec::new();
    let mut tip = None;
    for weight in weights {
        let mut event = SignedClaimTransitionEvent {
            vault_id: [9; 32],
            target,
            birth_digest: [10; 32],
            predecessors: tip.into_iter().collect(),
            authority_head: [12; 32],
            actor: fixture_id(6)?,
            actor_class: EdgeActorClass::System,
            host_public_key: key.verifying_key().to_bytes(),
            kind: ClaimTransitionKind::Decay,
            delta: TransitionDelta::ClaimOfWeight(*weight),
            signature: [0; 64],
        };
        let transcript =
            machine_claim_transition_transcript(&event).map_err(|error| error.to_string())?;
        event.signature = key.sign(&transcript).to_bytes();
        tip = Some(machine_claim_transition_event_hash(&event).map_err(|error| error.to_string())?);
        events.push(event);
    }
    let frontier: Vec<[u8; 32]> = tip.into_iter().collect();
    fold_machine_claim_transitions(
        &birth,
        &[9; 32],
        target,
        &[10; 32],
        Some(birth_weight),
        &events,
        &frontier,
        |_| true,
    )
    .map(|projection| FoldedDecay {
        claim_of_weight: projection.claim_of_weight,
        demotion_rung: projection.demotion_rung,
    })
    .map_err(|error| format!("{error:?}"))
}

/// `[seed; 16]`, the fold unit tests' fixture ids.
fn fixture_id(seed: u8) -> Result<EntityId, String> {
    EntityId::from_bytes([seed; 16]).map_err(|error| error.to_string())
}
