//! Canonical bounded MessagePack and Ed25519 proof for claim transition events.

use std::io::Cursor;

use ed25519_dalek::{Signature, VerifyingKey};
use rmpv::Value;

use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

const DOMAIN: &[u8] = b"oneiron/machine-claim-transition/v1";
const MAX_WIRE_BYTES: usize = 8192;
const MAX_PARENTS: usize = 64;
const VERSION: u64 = 1;

pub(crate) type TransitionEventHash = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ClaimTransitionKind {
    Approve = 0,
    Reject = 1,
    Retract = 2,
    SupersedeClose = 3,
    Decay = 4,
    Weaken = 5,
    Stale = 6,
}

impl ClaimTransitionKind {
    fn from_wire(raw: u64) -> Result<Self> {
        Ok(match raw {
            0 => Self::Approve,
            1 => Self::Reject,
            2 => Self::Retract,
            3 => Self::SupersedeClose,
            4 => Self::Decay,
            5 => Self::Weaken,
            6 => Self::Stale,
            _ => return Err(invalid()),
        })
    }
}

/// A small, closed transition payload. Scope demotion is an effective visibility
/// floor, not an edit to the immutable birth body's provenance/scope map.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum TransitionDelta {
    None,
    ValidTo(u64),
    ClaimOfWeight(f32),
    Confidence(f32),
    ScopeBand(u8),
}

/// Signed event binds one exact birth and one historical authority state.
/// An empty predecessor set means a direct child of birth. No clock field exists.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SignedClaimTransitionEvent {
    pub vault_id: [u8; 32],
    pub target: EntityId,
    pub birth_digest: [u8; 32],
    pub predecessors: Vec<TransitionEventHash>,
    pub authority_head: [u8; 32],
    pub actor: EntityId,
    pub actor_class: EdgeActorClass,
    pub host_public_key: [u8; 32],
    pub kind: ClaimTransitionKind,
    pub delta: TransitionDelta,
    pub signature: [u8; 64],
}

fn invalid() -> Error {
    Error::InvalidClaimBody("invalid machine claim transition event")
}

fn bin(bytes: &[u8]) -> Value {
    Value::Binary(bytes.to_vec())
}

fn sized<const N: usize>(value: &Value) -> Result<[u8; N]> {
    let Value::Binary(raw) = value else {
        return Err(invalid());
    };
    raw.as_slice().try_into().map_err(|_| invalid())
}

fn integer(value: &Value) -> Result<u64> {
    value.as_u64().ok_or_else(invalid)
}

fn validate(event: &SignedClaimTransitionEvent) -> Result<()> {
    if event.predecessors.len() > MAX_PARENTS
        || event.predecessors.windows(2).any(|pair| pair[0] >= pair[1])
        || event.predecessors.contains(&[0; 32])
        || event.vault_id == [0; 32]
        || event.birth_digest == [0; 32]
        || event.authority_head == [0; 32]
        || VerifyingKey::from_bytes(&event.host_public_key).is_err()
    {
        return Err(invalid());
    }
    match (event.kind, event.delta) {
        (ClaimTransitionKind::Approve | ClaimTransitionKind::Reject, TransitionDelta::None) => {}
        (
            ClaimTransitionKind::Retract | ClaimTransitionKind::SupersedeClose,
            TransitionDelta::ValidTo(_),
        ) => {}
        (ClaimTransitionKind::Decay, TransitionDelta::ClaimOfWeight(weight))
            if weight.is_finite() && (0.0..=1.0).contains(&weight) => {}
        (ClaimTransitionKind::Weaken, TransitionDelta::Confidence(confidence))
            if confidence.is_finite() && (0.0..=1.0).contains(&confidence) => {}
        (ClaimTransitionKind::Stale, TransitionDelta::None)
        | (ClaimTransitionKind::Stale, TransitionDelta::ScopeBand(0..=3)) => {}
        _ => return Err(invalid()),
    }
    Ok(())
}

fn unsigned_value(event: &SignedClaimTransitionEvent) -> Value {
    let delta = match event.delta {
        TransitionDelta::None => Value::Nil,
        TransitionDelta::ValidTo(end) => Value::from(end),
        TransitionDelta::ClaimOfWeight(weight) => Value::F32(weight),
        TransitionDelta::Confidence(confidence) => Value::F32(confidence),
        TransitionDelta::ScopeBand(band) => Value::from(band),
    };
    Value::Array(vec![
        Value::from(VERSION),
        bin(&event.vault_id),
        bin(event.target.as_bytes()),
        bin(&event.birth_digest),
        Value::Array(event.predecessors.iter().map(|hash| bin(hash)).collect()),
        bin(&event.authority_head),
        bin(event.actor.as_bytes()),
        Value::from(event.actor_class as u8),
        bin(&event.host_public_key),
        Value::from(event.kind as u8),
        delta,
    ])
}

fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|_| invalid())?;
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

/// The bytes signed by the host: fixed domain followed by exact canonical
/// unsigned MessagePack. The host owns signing; no private key enters this module.
pub(crate) fn machine_claim_transition_transcript(
    event: &SignedClaimTransitionEvent,
) -> Result<Vec<u8>> {
    validate(event)?;
    let wire = encode_value(&unsigned_value(event))?;
    let mut result = Vec::with_capacity(DOMAIN.len() + wire.len());
    result.extend_from_slice(DOMAIN);
    result.extend_from_slice(&wire);
    Ok(result)
}

/// Encodes the entire signed event, including its signature.
pub(crate) fn encode_machine_claim_transition_event(
    event: &SignedClaimTransitionEvent,
) -> Result<Vec<u8>> {
    validate(event)?;
    let Value::Array(mut values) = unsigned_value(event) else {
        unreachable!();
    };
    values.push(bin(&event.signature));
    encode_value(&Value::Array(values))
}

/// Decodes only exact canonical MessagePack; trailing bytes, alternate integer
/// widths, aliases, duplicate or unsorted parent hashes all fail closed.
pub(crate) fn decode_machine_claim_transition_event(
    bytes: &[u8],
) -> Result<SignedClaimTransitionEvent> {
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(invalid());
    }
    let mut cursor = Cursor::new(bytes);
    let Value::Array(fields) = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid())? else {
        return Err(invalid());
    };
    if fields.len() != 12
        || cursor.position() != bytes.len() as u64
        || integer(&fields[0])? != VERSION
    {
        return Err(invalid());
    }
    let Value::Array(parents) = &fields[4] else {
        return Err(invalid());
    };
    if parents.len() > MAX_PARENTS {
        return Err(invalid());
    }
    let predecessors = parents
        .iter()
        .map(sized::<32>)
        .collect::<Result<Vec<_>>>()?;
    let actor_class =
        EdgeActorClass::try_from_u8(u8::try_from(integer(&fields[7])?).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
    let kind = ClaimTransitionKind::from_wire(integer(&fields[9])?)?;
    let delta = match kind {
        ClaimTransitionKind::Retract | ClaimTransitionKind::SupersedeClose => {
            TransitionDelta::ValidTo(integer(&fields[10])?)
        }
        ClaimTransitionKind::Decay => {
            let Value::F32(weight) = fields[10] else {
                return Err(invalid());
            };
            TransitionDelta::ClaimOfWeight(weight)
        }
        ClaimTransitionKind::Weaken => {
            let Value::F32(confidence) = fields[10] else {
                return Err(invalid());
            };
            TransitionDelta::Confidence(confidence)
        }
        ClaimTransitionKind::Stale if !matches!(fields[10], Value::Nil) => {
            TransitionDelta::ScopeBand(u8::try_from(integer(&fields[10])?).map_err(|_| invalid())?)
        }
        _ if matches!(fields[10], Value::Nil) => TransitionDelta::None,
        _ => return Err(invalid()),
    };
    let event = SignedClaimTransitionEvent {
        vault_id: sized(&fields[1])?,
        target: EntityId::from_bytes(sized(&fields[2])?).map_err(|_| invalid())?,
        birth_digest: sized(&fields[3])?,
        predecessors,
        authority_head: sized(&fields[5])?,
        actor: EntityId::from_bytes(sized(&fields[6])?).map_err(|_| invalid())?,
        actor_class,
        host_public_key: sized(&fields[8])?,
        kind,
        delta,
        signature: sized(&fields[11])?,
    };
    if encode_machine_claim_transition_event(&event)?.as_slice() != bytes {
        return Err(invalid());
    }
    Ok(event)
}

/// Verifies the host signature, independently of its historical authorization.
pub(crate) fn verify_machine_claim_transition_event(
    event: &SignedClaimTransitionEvent,
) -> Result<()> {
    let transcript = machine_claim_transition_transcript(event)?;
    let key = VerifyingKey::from_bytes(&event.host_public_key).map_err(|_| invalid())?;
    key.verify_strict(&transcript, &Signature::from_bytes(&event.signature))
        .map_err(|_| invalid())
}

/// Full BLAKE3 hash over the signed canonical event, not the unsigned payload.
pub(crate) fn machine_claim_transition_event_hash(
    event: &SignedClaimTransitionEvent,
) -> Result<TransitionEventHash> {
    Ok(*blake3::hash(&encode_machine_claim_transition_event(event)?).as_bytes())
}

/// Content-addressed ID from the first 16 bytes of the full signed hash.
pub(crate) fn machine_claim_transition_event_id(
    event: &SignedClaimTransitionEvent,
) -> Result<EntityId> {
    let hash = machine_claim_transition_event_hash(event)?;
    EntityId::from_bytes(hash[..16].try_into().map_err(|_| invalid())?).map_err(|_| invalid())
}
