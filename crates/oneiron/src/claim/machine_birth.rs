//! Immutable signed birth of a MACHINE-authored CLAIM.
//!
//! A birth is an assertion about the original canonical CLAIM bytes, not a
//! snapshot of mutable approval/lifecycle state. The carrier CLAIM uses the
//! same scope as the signed body; storage/replay policy lives at its doors.

use std::io::Cursor;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rmpv::Value;

use super::{ClaimApprovalStatus, ClaimLifecycleStatus, decode_claim_body, encode_claim_body};
use crate::EntityId;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};

/// Upper bound for the complete birth wire value (including its initial CLAIM).
pub(crate) const MAX_MACHINE_CLAIM_BIRTH_BYTES: usize = 1024 * 1024;
const KEYS: [&str; 7] = [
    "version",
    "vault_id",
    "target",
    "initial_body",
    "machine_public_key",
    "machine_signature",
    "digest",
];

fn invalid() -> Error {
    Error::InvalidClaimBody("invalid signed machine claim birth")
}

/// Full content-addressed birth, including the exact canonical original body.
///
/// The digest covers the domain and the canonical signed map WITHOUT the
/// digest field. It therefore binds all fields, including the signature. The
/// first sixteen digest bytes identify its immutable carrier event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignedClaimBirth {
    pub(crate) vault_id: [u8; 32],
    pub(crate) target: EntityId,
    pub(crate) initial_body: Vec<u8>,
    pub(crate) machine_public_key: [u8; 32],
    pub(crate) machine_signature: [u8; 64],
    pub(crate) digest: [u8; 32],
}

impl SignedClaimBirth {
    /// Construct only from an already-signed canonical initial CLAIM body.
    pub(crate) fn new(
        vault_id: [u8; 32],
        target: EntityId,
        initial_body: Vec<u8>,
        machine_public_key: [u8; 32],
        machine_signature: [u8; 64],
    ) -> Result<Self> {
        let mut birth = Self {
            vault_id,
            target,
            initial_body,
            machine_public_key,
            machine_signature,
            digest: [0; 32],
        };
        birth.digest = birth.compute_digest()?;
        birth.verify()?;
        Ok(birth)
    }

    /// Fail closed on a changed body, signer, signature, actor evidence, or digest.
    pub(crate) fn verify(&self) -> Result<()> {
        if self.vault_id == [0; 32] || self.initial_body.len() > MAX_MACHINE_CLAIM_BIRTH_BYTES {
            return Err(invalid());
        }
        let body = decode_claim_body(&self.initial_body, true).map_err(|_| invalid())?;
        let canonical = encode_claim_body(&body).map_err(|_| invalid())?;
        if canonical != self.initial_body {
            return Err(invalid());
        }
        // Opaque CLAIM values may contain maps too. No duplicate-key
        // interpretation is safe inside a signed birth, even in evidence.
        reject_ambiguous_maps(&body.value)?;
        if let Some(value) = &body.evidence {
            reject_ambiguous_maps(value)?;
        }
        if let Some(value) = &body.scope {
            reject_ambiguous_maps(value)?;
        }
        if body.lifecycle != ClaimLifecycleStatus::Active
            || body.stale
            || body.approval == ClaimApprovalStatus::Rejected
        {
            return Err(invalid());
        }
        let Some(Value::Map(entries)) = body.evidence.as_ref() else {
            return Err(invalid());
        };
        let evidence = |name| {
            entries
                .iter()
                .find(|(key, _)| key.as_str() == Some(name))
                .map(|(_, value)| value)
        };
        if evidence("actor_class").and_then(Value::as_u64) != Some(EdgeActorClass::System as u64) {
            return Err(invalid());
        }
        let Some(Value::Binary(actor_bytes)) = evidence("actor_entity_ref") else {
            return Err(invalid());
        };
        let actor: [u8; 16] = actor_bytes.as_slice().try_into().map_err(|_| invalid())?;
        EntityId::from_bytes(actor).map_err(|_| invalid())?;
        let Some(Value::Array(proof)) = evidence("machine_signature") else {
            return Err(invalid());
        };
        let [Value::Binary(key), Value::Binary(signature)] = proof.as_slice() else {
            return Err(invalid());
        };
        if key.as_slice() != &self.machine_public_key[..]
            || signature.as_slice() != &self.machine_signature[..]
        {
            return Err(invalid());
        }
        let transcript =
            crate::authority::machine_claim_transcript(&self.vault_id, &self.target, &body)
                .map_err(|_| invalid())?;
        VerifyingKey::from_bytes(&self.machine_public_key)
            .map_err(|_| invalid())?
            .verify(&transcript, &Signature::from_bytes(&self.machine_signature))
            .map_err(|_| invalid())?;
        if self.compute_digest()? != self.digest {
            return Err(invalid());
        }
        encode_map(self, true)?;
        Ok(())
    }

    /// Encode with pinned map order, integer spelling, and raw binary fields.
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.verify()?;
        encode_map(self, true)
    }

    /// Decode exactly one canonical birth; reject duplicate/unknown map keys.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_MACHINE_CLAIM_BIRTH_BYTES {
            return Err(invalid());
        }
        let mut cursor = Cursor::new(bytes);
        let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid())?;
        if cursor.position() != bytes.len() as u64 {
            return Err(invalid());
        }
        let Value::Map(fields) = value else {
            return Err(invalid());
        };
        if fields.len() != KEYS.len() {
            return Err(invalid());
        }
        let mut values = fields
            .into_iter()
            .zip(KEYS)
            .map(|((key, value), expected)| {
                if key.as_str() == Some(expected) {
                    Ok(value)
                } else {
                    Err(invalid())
                }
            });
        if values.next().ok_or_else(invalid)??.as_u64() != Some(1) {
            return Err(invalid());
        }
        let vault_id = binary::<32>(&values.next().ok_or_else(invalid)??)?;
        let target = EntityId::from_bytes(binary::<16>(&values.next().ok_or_else(invalid)??)?)
            .map_err(|_| invalid())?;
        let initial_body = binary_vec(values.next().ok_or_else(invalid)??)?;
        let machine_public_key = binary::<32>(&values.next().ok_or_else(invalid)??)?;
        let machine_signature = binary::<64>(&values.next().ok_or_else(invalid)??)?;
        let digest = binary::<32>(&values.next().ok_or_else(invalid)??)?;
        let birth = Self {
            vault_id,
            target,
            initial_body,
            machine_public_key,
            machine_signature,
            digest,
        };
        birth.verify()?;
        if birth.encode()? != bytes {
            return Err(invalid());
        }
        Ok(birth)
    }

    /// Content-addressed event ID; a reserved EntityId byte pattern fails closed.
    pub(crate) fn event_id(&self) -> Result<EntityId> {
        self.verify()?;
        let prefix: [u8; 16] = self.digest[..16].try_into().map_err(|_| invalid())?;
        EntityId::from_bytes(prefix).map_err(|_| invalid())
    }

    fn compute_digest(&self) -> Result<[u8; 32]> {
        let encoded = encode_map(self, false)?;
        Ok(*blake3::hash(&encoded).as_bytes())
    }
}

fn reject_ambiguous_maps(value: &Value) -> Result<()> {
    let mut pending = vec![(value, 0usize)];
    while let Some((value, depth)) = pending.pop() {
        if depth > 64 {
            return Err(invalid());
        }
        match value {
            Value::Map(fields) => {
                for (index, (key, nested)) in fields.iter().enumerate() {
                    let Some(key) = key.as_str() else {
                        return Err(invalid());
                    };
                    if fields[..index]
                        .iter()
                        .any(|(previous, _)| previous.as_str() == Some(key))
                    {
                        return Err(invalid());
                    }
                    pending.push((nested, depth + 1));
                }
            }
            Value::Array(items) => {
                for item in items {
                    pending.push((item, depth + 1));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn binary_vec(value: Value) -> Result<Vec<u8>> {
    match value {
        Value::Binary(bytes) => Ok(bytes),
        _ => Err(invalid()),
    }
}

fn binary<const N: usize>(value: &Value) -> Result<[u8; N]> {
    let Value::Binary(bytes) = value else {
        return Err(invalid());
    };
    bytes.as_slice().try_into().map_err(|_| invalid())
}

fn encode_map(birth: &SignedClaimBirth, with_digest: bool) -> Result<Vec<u8>> {
    let mut fields = vec![
        (Value::from(KEYS[0]), Value::from(1)),
        (Value::from(KEYS[1]), Value::Binary(birth.vault_id.to_vec())),
        (
            Value::from(KEYS[2]),
            Value::Binary(birth.target.as_bytes().to_vec()),
        ),
        (
            Value::from(KEYS[3]),
            Value::Binary(birth.initial_body.clone()),
        ),
        (
            Value::from(KEYS[4]),
            Value::Binary(birth.machine_public_key.to_vec()),
        ),
        (
            Value::from(KEYS[5]),
            Value::Binary(birth.machine_signature.to_vec()),
        ),
    ];
    if with_digest {
        fields.push((Value::from(KEYS[6]), Value::Binary(birth.digest.to_vec())));
    }
    let mut out = Vec::with_capacity(birth.initial_body.len() + 256);
    rmpv::encode::write_value(&mut out, &Value::Map(fields)).map_err(|_| invalid())?;
    if out.len() > MAX_MACHINE_CLAIM_BIRTH_BYTES {
        return Err(invalid());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use rmpv::Value;

    use super::*;
    use crate::claim::{ClaimBody, ClaimSubject};

    fn signed_birth() -> SignedClaimBirth {
        let machine = EntityId::from_bytes([0x31; 16]).unwrap();
        let target = EntityId::from_bytes([0x32; 16]).unwrap();
        let signer = SigningKey::from_bytes(&[0x33; 32]);
        let key = signer.verifying_key().to_bytes();
        let mut body = ClaimBody::new(
            "profile.preference",
            ClaimSubject::Entity(EntityId::from_bytes([0x34; 16]).unwrap()),
            Value::from("quiet"),
            0.9,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        )
        .unwrap();
        body.evidence = Some(Value::Map(vec![
            (
                Value::from("actor_class"),
                Value::from(EdgeActorClass::System as u8),
            ),
            (
                Value::from("actor_entity_ref"),
                Value::Binary(machine.as_bytes().to_vec()),
            ),
            (
                Value::from("machine_signature"),
                Value::Array(vec![
                    Value::Binary(key.to_vec()),
                    Value::Binary(vec![0; 64]),
                ]),
            ),
        ]));
        let vault_id = [0x35; 32];
        let transcript =
            crate::authority::machine_claim_transcript(&vault_id, &target, &body).unwrap();
        let signature = signer.sign(&transcript).to_bytes();
        let Some(Value::Map(evidence)) = &mut body.evidence else {
            unreachable!()
        };
        evidence[2].1 = Value::Array(vec![
            Value::Binary(key.to_vec()),
            Value::Binary(signature.to_vec()),
        ]);
        SignedClaimBirth::new(
            vault_id,
            target,
            encode_claim_body(&body).unwrap(),
            key,
            signature,
        )
        .unwrap()
    }

    #[test]
    fn signature_and_digest_bind_all_identity_and_body_fields() {
        let original = signed_birth();
        let mut birth = original.clone();
        birth.vault_id = [0x36; 32];
        birth.digest = birth.compute_digest().unwrap();
        assert!(birth.verify().is_err());
        let mut birth = original.clone();
        birth.target = EntityId::from_bytes([0x37; 16]).unwrap();
        birth.digest = birth.compute_digest().unwrap();
        assert!(birth.verify().is_err());
        let mut birth = original.clone();
        birth.initial_body[3] ^= 1;
        birth.digest = birth.compute_digest().unwrap();
        assert!(birth.verify().is_err());
        let mut birth = original.clone();
        birth.machine_signature[0] ^= 1;
        birth.digest = birth.compute_digest().unwrap();
        assert!(birth.verify().is_err());
        let mut birth = original;
        birth.digest[31] ^= 1;
        assert!(birth.verify().is_err());
    }

    #[test]
    fn malformed_and_noncanonical_birth_wire_is_rejected() {
        let birth = signed_birth();
        let raw = birth.encode().unwrap();
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(SignedClaimBirth::decode(&trailing).is_err());
        let mut value = rmpv::decode::read_value(&mut raw.as_slice()).unwrap();
        let Value::Map(fields) = &mut value else {
            unreachable!()
        };
        let duplicate_key = fields[0].clone();
        fields.insert(1, duplicate_key);
        let mut duplicate = Vec::new();
        rmpv::encode::write_value(&mut duplicate, &value).unwrap();
        assert!(SignedClaimBirth::decode(&duplicate).is_err());
        assert!(SignedClaimBirth::decode(&vec![0; MAX_MACHINE_CLAIM_BIRTH_BYTES + 1]).is_err());
    }

    #[test]
    fn initial_state_and_ambiguous_actor_evidence_are_rejected() {
        let original = signed_birth();
        for changed in [
            (
                ClaimApprovalStatus::Rejected,
                ClaimLifecycleStatus::Active,
                false,
            ),
            (
                ClaimApprovalStatus::Proposed,
                ClaimLifecycleStatus::Retracted,
                false,
            ),
            (
                ClaimApprovalStatus::Proposed,
                ClaimLifecycleStatus::Active,
                true,
            ),
        ] {
            let mut birth = original.clone();
            let mut body = decode_claim_body(&birth.initial_body, true).unwrap();
            body.approval = changed.0;
            body.lifecycle = changed.1;
            body.stale = changed.2;
            birth.initial_body = encode_claim_body(&body).unwrap();
            birth.digest = birth.compute_digest().unwrap();
            assert!(birth.verify().is_err());
        }
        let mut birth = original;
        let mut body = decode_claim_body(&birth.initial_body, true).unwrap();
        let Some(Value::Map(evidence)) = &mut body.evidence else {
            unreachable!()
        };
        let duplicate_actor = evidence[0].clone();
        evidence.push(duplicate_actor);
        birth.initial_body = encode_claim_body(&body).unwrap();
        birth.digest = birth.compute_digest().unwrap();
        assert!(birth.verify().is_err());
    }
}
