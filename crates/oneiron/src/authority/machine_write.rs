//! MACHINE software-key enrollment and origin signatures for claim writes.
//!
//! The signature is over the exact canonical stored claim (less its signature),
//! its entity id and the genesis-bound vault id. The log fold, not a transport
//! credential or a row in MACHINE, grants the signer authority.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rmpv::Value;

use crate::batch::EntityMetadataHeader;
use crate::claim::ClaimBody;
use crate::edge::EdgeActorClass;
use crate::error::{ClaimError, Error, Result};
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::store::Store;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::{MachineWriteSignature, WriteEnvelope};
use crate::{EntityId, HostingPrivacyPosture, TimeRange, Vault};

use super::slip_vault::require_host;
use super::{
    ActorBindingStatus, AuthorityAttestation, AuthorityKey, AuthorityOp, AuthoritySignature,
    AuthoritySignatureSuite, AuthorityTier, DeviceAuthority, HostSlipIssuer, ROLE_AGENT,
    authority_entry_hash, authority_transcript, invalid_authority,
};

const DOMAIN: &[u8] = b"oneiron/machine-claim/v1";
const SIGNATURE_KEY: &str = "machine_signature";

fn denied() -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority {
        reason: "machine write requires a signed enrolled software identity",
    })
}

/// Bind an existing MACHINE row to a fresh per-vault Ed25519 authority key.
/// The retained host root signs both enrollment and actor binding in one transaction.
/// This door never creates, holds or exports the machine's private key.
impl Vault {
    pub fn enroll_machine_identity(
        &self,
        issuer: &HostSlipIssuer,
        machine: EntityId,
        public_key: [u8; 32],
        transport_key_binding: [u8; 32],
        sign_binding: impl FnOnce(&[u8]) -> Result<[u8; 64]>,
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        let raw = self
            .store
            .entities
            .get(&txn, machine.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != ENTITY_TYPE_MACHINE)
        {
            return Err(denied());
        }
        VerifyingKey::from_bytes(&public_key).map_err(|_| denied())?;
        if transport_key_binding == public_key {
            return Err(denied());
        }
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        require_host(&fold, issuer)?;
        let key = AuthorityKey::Ed25519(public_key);
        if fold.roster.contains_key(&key) || fold.actor_bindings.contains_key(&key) {
            return Err(denied());
        }
        let seq = fold
            .append_sequences
            .get(&issuer.public_key())
            .ok_or_else(invalid_authority)?
            .checked_add(1)
            .ok_or_else(invalid_authority)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let now = self.instant_in_txn(&txn)?.secs();
        let enroll = issuer.sign_entry(
            Some(vault_id),
            seq,
            fold.append_heads.iter().copied().collect(),
            AuthorityOp::EnrollDevice {
                device: DeviceAuthority {
                    key: key.clone(),
                    transport_key_binding,
                    attestation: AuthorityAttestation {
                        kind: "SoftwareArgon2id".into(),
                        evidence: Vec::new(),
                    },
                    tier: AuthorityTier::Software,
                    roles: ROLE_AGENT,
                },
            },
            now,
        )?;
        let enroll_hash = authority_entry_hash(&enroll)?;
        let mut bind = issuer.sign_entry(
            Some(vault_id),
            seq.checked_add(1).ok_or_else(invalid_authority)?,
            vec![enroll_hash],
            AuthorityOp::BindActor {
                authority_key: key.clone(),
                actor_ref: machine,
                actor_class: "system".into(),
                epoch: 1,
            },
            now,
        )?;
        bind.cosigns.push(AuthoritySignature {
            suite: AuthoritySignatureSuite::Ed25519,
            public_key: key,
            signature: vec![0; 64],
        });
        let transcript = authority_transcript(&bind)?;
        bind.cosigns[0].signature = sign_binding(&transcript)?.to_vec();
        issuer.resign_entry(&mut bind)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(&mut txn, &[(enroll, at, now), (bind, at, now)])?;
        // Software enrollment may remain pending under the vault's existing
        // observed-time delay; the write door refuses it until the fold activates.
        txn.commit()?;
        Ok(())
    }

    /// Bytes to sign for a machine `ClaimCandidate` before attaching its proof.
    /// Set the candidate's facet explicitly when the vault default can change
    /// between this call and commit; the write door always signs stored bytes.
    pub fn machine_claim_transcript(
        &self,
        id: &EntityId,
        candidate: &ClaimCandidate,
        envelope: &WriteEnvelope,
    ) -> Result<Vec<u8>> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(denied)?;
        let facet = crate::claim::default_facet_in(&self.store, &txn)?;
        let body = candidate.clone().into_claim_body(envelope, facet);
        machine_claim_transcript(&vault_id, id, &body)
    }
}

/// Canonical body binding includes all envelope metadata, source and payload.
/// The signature value itself is excluded to avoid a circular transcript.
pub fn machine_claim_transcript(
    vault_id: &[u8; 32],
    id: &EntityId,
    body: &ClaimBody,
) -> Result<Vec<u8>> {
    let mut unsigned = body.clone();
    if let Some(Value::Map(entries)) = &mut unsigned.evidence {
        entries.retain(|(key, _)| key.as_str() != Some(SIGNATURE_KEY));
    }
    let bytes = crate::claim::encode_claim_body(&unsigned)?;
    let mut transcript = Vec::with_capacity(DOMAIN.len() + 32 + 16 + 32);
    transcript.extend_from_slice(DOMAIN);
    transcript.extend_from_slice(vault_id);
    transcript.extend_from_slice(id.as_bytes());
    transcript.extend_from_slice(blake3::hash(&bytes).as_bytes());
    Ok(transcript)
}

fn evidence_field<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<Option<&'a Value>> {
    let mut values = entries.iter().filter(|(key, _)| key.as_str() == Some(name));
    let first = values.next().map(|(_, value)| value);
    if values.next().is_some() {
        return Err(denied());
    }
    Ok(first)
}

fn proof(body: &ClaimBody) -> Result<Option<(EntityId, u64, Option<MachineWriteSignature>)>> {
    let Some(Value::Map(entries)) = body.evidence.as_ref() else {
        return Ok(None);
    };
    let class = evidence_field(entries, "actor_class")?.and_then(Value::as_u64);
    let signature = evidence_field(entries, SIGNATURE_KEY)?;
    let actor = evidence_field(entries, "actor_entity_ref")?.and_then(|value| match value {
        Value::Binary(bytes) => EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok(),
        _ => None,
    });
    if class.is_none() && signature.is_none() && actor.is_none() {
        return Ok(None);
    }
    let actor = actor.ok_or_else(denied)?;
    let class = class.ok_or_else(denied)?;
    let Some(value) = signature else {
        return Ok(Some((actor, class, None)));
    };
    let Value::Array(parts) = value else {
        return Err(denied());
    };
    let [Value::Binary(key), Value::Binary(sig)] = parts.as_slice() else {
        return Err(denied());
    };
    let public_key: [u8; 32] = key.as_slice().try_into().map_err(|_| denied())?;
    let signature: [u8; 64] = sig.as_slice().try_into().map_err(|_| denied())?;
    Ok(Some((
        actor,
        class,
        Some(MachineWriteSignature {
            public_key,
            signature,
        }),
    )))
}

/// Whether any asserted author resolves to a stored MACHINE row. Scan all
/// occurrences before strict parsing so duplicate actor fields cannot hide it.
fn names_machine(store: &Store, txn: &heed::RoTxn<'_>, entries: &[(Value, Value)]) -> Result<bool> {
    for (_, value) in entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some("actor_entity_ref"))
    {
        if let Value::Binary(bytes) = value
            && let Ok(raw_id) = bytes.as_slice().try_into()
            && let Ok(actor_id) = EntityId::from_bytes(raw_id)
            && let Some(raw) = store.entities.get(txn, actor_id.as_bytes())?
            && EntityMetadataHeader::parse(&raw)
                .is_some_and(|header| header.entity_type == ENTITY_TYPE_MACHINE)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Read-time machine identity is derived from the CURRENT entity kind and
/// folded authority, not from a peer-supplied class or cached roster. A claim
/// that arrived before its MACHINE row cannot become visible unsigned later.
pub(crate) fn machine_claim_read_admitted(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &super::AuthorityFold,
    body: &ClaimBody,
) -> Result<bool> {
    let Some(Value::Map(entries)) = body.evidence.as_ref() else {
        return Ok(true);
    };
    let carries_proof = entries
        .iter()
        .any(|(key, _)| key.as_str() == Some(SIGNATURE_KEY));
    let machine_ref = names_machine(store, txn, entries)?;
    if !carries_proof {
        if fold.vault_id.is_none() && !fold.vault_root_is_conflicted() {
            return Ok(true);
        }
        if machine_ref {
            return Ok(false);
        }
        // A SYSTEM author whose entity has not arrived is not proof of being
        // a different kind: deny until the row resolves, then classify it.
        let claimed_system = entries.iter().any(|(key, value)| {
            key.as_str() == Some("actor_class")
                && value.as_u64() == Some(EdgeActorClass::System as u64)
        });
        if claimed_system
            && entries.iter().any(|(key, value)| {
                key.as_str() == Some("actor_entity_ref") && matches!(value, Value::Binary(_))
            })
        {
            let resolved = entries
                .iter()
                .filter(|(key, _)| key.as_str() == Some("actor_entity_ref"))
                .filter_map(|(_, value)| match value {
                    Value::Binary(bytes) => {
                        EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok()
                    }
                    _ => None,
                });
            for actor in resolved {
                if store.entities.get(txn, actor.as_bytes())?.is_none() {
                    return Ok(false);
                }
            }
        }
        return Ok(true);
    }
    let Some((actor, class, Some(proof))) = proof(body).ok().flatten() else {
        return Ok(false);
    };
    if class != EdgeActorClass::System as u64 || !machine_ref {
        return Ok(false);
    }
    let key = AuthorityKey::Ed25519(proof.public_key);
    Ok(fold.actor_bindings.get(&key).is_some_and(|binding| {
        binding.status == ActorBindingStatus::Active
            && binding.actor_ref == actor
            && binding.actor_class == "system"
    }) && fold.roster.get(&key).is_some_and(|device| {
        !device.revoked && device.tier == AuthorityTier::Software && device.roles & ROLE_AGENT != 0
    }))
}

/// Replay checks origin only, while the local writer must also have an active
/// key/actor tuple in the transaction's folded roster. No unknown-signer
/// rejection occurs on replay: an enrollment can arrive after its signed claim.
pub(crate) fn verify_machine_claim_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    posture: HostingPrivacyPosture,
    id: &EntityId,
    body: &ClaimBody,
    replicated: bool,
) -> Result<()> {
    let Some(Value::Map(entries)) = body.evidence.as_ref() else {
        return Ok(());
    };
    let carries_proof = entries
        .iter()
        .any(|(key, _)| key.as_str() == Some(SIGNATURE_KEY));
    // Existing system-labeled engine writes are not MACHINE identities.
    let machine_ref = names_machine(store, txn, entries)?;
    if !machine_ref && !carries_proof {
        return Ok(());
    }
    let (actor, class, proof) = proof(body)?.ok_or_else(denied)?;
    let actor_type = store
        .entities
        .get(txn, actor.as_bytes())?
        .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|header| header.entity_type));
    if class != EdgeActorClass::System as u64
        || !replicated && actor_type != Some(ENTITY_TYPE_MACHINE)
        || actor_type.is_some_and(|kind| kind != ENTITY_TYPE_MACHINE)
    {
        return Err(denied());
    }
    let fold = super::authority_fold_readonly_for_store_in_txn(store, posture, txn)?;
    if fold.vault_root_is_conflicted() {
        return Err(denied());
    }
    let Some(vault_id) = fold.vault_id else {
        // Pre-bootstrap vaults retain their existing unsigned local authoring.
        // Once rooted, no MACHINE claim may use that transitional path.
        return if replicated { Err(denied()) } else { Ok(()) };
    };
    let proof = proof.ok_or_else(denied)?;
    let transcript = machine_claim_transcript(&vault_id, id, body)?;
    let key = VerifyingKey::from_bytes(&proof.public_key).map_err(|_| denied())?;
    key.verify(&transcript, &Signature::from_bytes(&proof.signature))
        .map_err(|_| denied())?;
    if !replicated {
        let authority_key = AuthorityKey::Ed25519(proof.public_key);
        if !fold
            .actor_bindings
            .get(&authority_key)
            .is_some_and(|binding| {
                binding.status == ActorBindingStatus::Active
                    && binding.actor_ref == actor
                    && binding.actor_class == "system"
            })
            || !fold.roster.get(&authority_key).is_some_and(|device| {
                !device.revoked
                    && device.tier == AuthorityTier::Software
                    && device.roles & ROLE_AGENT != 0
            })
        {
            return Err(denied());
        }
    }
    Ok(())
}
