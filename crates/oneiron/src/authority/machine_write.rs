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
use crate::ports::EntityStoreRead;
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

mod successor;

const DOMAIN: &[u8] = b"oneiron/machine-claim/v1";
const SIGNATURE_KEY: &str = "machine_signature";

fn denied() -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority {
        reason: "machine write requires a signed enrolled software identity",
    })
}

fn invalid_origin(replicated: bool) -> Error {
    if replicated {
        Error::Claim(ClaimError::InvalidMachineClaimProof)
    } else {
        denied()
    }
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
        // A host-landed enrollment takes effect at once: the device-key widen
        // delay is dead (identity.md, "Device-key widen ceremony").
        txn.commit()?;
        self.retain_machine_history_issuer(issuer)?;
        Ok(())
    }

    /// Retain a verified host root for this vault handle's scoped history
    /// issuance. A reopen requires the host to supply it again; relay cannot.
    pub fn retain_machine_history_issuer(&self, issuer: &HostSlipIssuer) -> Result<()> {
        if self.privacy_posture() == crate::HostingPrivacyPosture::Relay {
            return Err(denied());
        }
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        super::slip_vault::require_host(&fold, issuer)?;
        *self
            .store
            .machine_history_issuer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(HostSlipIssuer::from_secret(issuer.secret())?);
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
        self.machine_claim_transcript_in_txn(&txn, id, candidate, envelope)
    }

    fn machine_claim_transcript_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        candidate: &ClaimCandidate,
        envelope: &WriteEnvelope,
    ) -> Result<Vec<u8>> {
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        let vault_id = fold.vault_id.ok_or_else(denied)?;
        let facet =
            crate::batch::claim_candidate_apply::claim_candidate_birth_facet(&self.store, txn, id)?;
        let body = candidate.clone().into_claim_body(envelope, facet)?;
        machine_claim_transcript(&vault_id, id, &body)
    }

    /// Install a host-owned software signing callback for one MACHINE in this
    /// vault handle. Enrollment remains a separate, host-rooted authority-log
    /// action; retaining a callback cannot grant the actor standing. A reopen
    /// requires the host to provide the callback again.
    pub fn retain_machine_write_signer(
        &self,
        machine: EntityId,
        public_key: [u8; 32],
        sign: impl Fn(&[u8]) -> Result<[u8; 64]> + Send + Sync + 'static,
    ) -> Result<()> {
        VerifyingKey::from_bytes(&public_key).map_err(|_| denied())?;
        let txn = self.store.env.read_txn()?;
        let raw = self
            .store
            .entities
            .get(&txn, machine.as_bytes())?
            .ok_or_else(denied)?;
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != ENTITY_TYPE_MACHINE)
            || self
                .authority_fold_readonly_in_txn(&txn)?
                .vault_id
                .is_none()
        {
            return Err(denied());
        }
        drop(txn);
        self.store
            .machine_write_signers
            .lock()
            .map_err(|_| Error::InvariantViolation("machine signer lock poisoned"))?
            .insert(machine, (public_key, std::sync::Arc::new(sign)));
        Ok(())
    }

    /// The calendar importer holds no actor key: it uses only the explicitly
    /// retained host callback. Commit still re-verifies the exact stored body,
    /// so a facet change between this transcript and admission fails closed.
    pub(crate) fn sign_registered_machine_claim(
        &self,
        id: &EntityId,
        candidate: &ClaimCandidate,
        envelope: &mut WriteEnvelope,
    ) -> Result<()> {
        if envelope.actor().actor_class() != EdgeActorClass::System {
            return Err(denied());
        }
        let signer = self
            .retained_machine_signer(envelope.actor().entity_ref())?
            .ok_or_else(denied)?;
        let txn = self.store.env.read_txn()?;
        self.attach_machine_signature(&txn, id, candidate, envelope, signer)
    }

    /// An engine writer signs its own MACHINE candidate inside the caller's
    /// transaction with the signer the host retained for the envelope's
    /// actor. Without one the envelope stays unsigned and the write door
    /// decides: a MACHINE author is refused, any other author is unaffected.
    pub(crate) fn sign_retained_machine_claim_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        candidate: &ClaimCandidate,
        envelope: &mut WriteEnvelope,
    ) -> Result<()> {
        if envelope.machine_signature().is_some()
            || envelope.actor().actor_class() != EdgeActorClass::System
        {
            return Ok(());
        }
        match self.retained_machine_signer(envelope.actor().entity_ref())? {
            Some(signer) => self.attach_machine_signature(txn, id, candidate, envelope, signer),
            None => Ok(()),
        }
    }

    fn retained_machine_signer(
        &self,
        machine: EntityId,
    ) -> Result<Option<([u8; 32], crate::store::MachineWriteSigner)>> {
        Ok(self
            .store
            .machine_write_signers
            .lock()
            .map_err(|_| Error::InvariantViolation("machine signer lock poisoned"))?
            .get(&machine)
            .cloned())
    }

    fn attach_machine_signature(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        candidate: &ClaimCandidate,
        envelope: &mut WriteEnvelope,
        (public_key, sign): ([u8; 32], crate::store::MachineWriteSigner),
    ) -> Result<()> {
        let transcript = self.machine_claim_transcript_in_txn(txn, id, candidate, envelope)?;
        *envelope = envelope
            .clone()
            .with_machine_signature(MachineWriteSignature {
                public_key,
                signature: sign(&transcript)?,
            });
        Ok(())
    }
}

/// A claim's evidence without the MACHINE signature that binds it.
pub(crate) fn evidence_without_machine_signature(body: &ClaimBody) -> Option<Value> {
    let mut evidence = body.evidence.clone();
    if let Some(Value::Map(entries)) = &mut evidence {
        entries.retain(|(key, _)| key.as_str() != Some(SIGNATURE_KEY));
    }
    evidence
}

/// Canonical body binding includes all envelope metadata, source and payload.
/// The signature value itself is excluded to avoid a circular transcript.
pub fn machine_claim_transcript(
    vault_id: &[u8; 32],
    id: &EntityId,
    body: &ClaimBody,
) -> Result<Vec<u8>> {
    let mut unsigned = body.clone();
    unsigned.evidence = evidence_without_machine_signature(body);
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

pub(crate) fn machine_claim_needs_history(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
) -> Result<bool> {
    if crate::claim::history_store::machine_history_kind(&body.predicate).is_some() {
        return Ok(false);
    }
    let Some(Value::Map(entries)) = &body.evidence else {
        return Ok(false);
    };
    if entries
        .iter()
        .any(|(key, _)| key.as_str() == Some(SIGNATURE_KEY))
    {
        return Ok(true);
    }
    names_machine(store, txn, entries)
}

/// Read-time machine identity is derived from the CURRENT entity kind and
/// folded authority, not from a peer-supplied class or cached roster. A claim
/// that arrived before its MACHINE row cannot become visible unsigned later.
pub(crate) fn machine_claim_read_admitted(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &super::AuthorityFold,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<bool> {
    if let Some(kind) = crate::claim::history_store::machine_history_kind(&body.predicate) {
        let crate::claim::ClaimSubject::Entity(target) = body.subject else {
            return Ok(false);
        };
        // Selector/guest export operates on RAW CRDT bytes. A control row
        // travels only if these exact bytes match a locally verified row and
        // its id belongs to the authenticated target closure.
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            return Ok(false);
        };
        if raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
            != Some(crate::claim::encode_claim_body(body)?.as_slice())
        {
            return Ok(false);
        }
        let Ok(rows) = crate::claim::history_projection::machine_history_rows(store, txn, target)
        else {
            return Ok(false);
        };
        let Ok(packet) =
            crate::claim::history_projection::trusted_machine_handoff(store, txn, target)
        else {
            return Ok(false);
        };
        if packet.births.len() != 1
            || packet.births[0].digest != rows.birth.digest
            || fold.vault_id != Some(rows.birth.vault_id)
            || crate::claim::history_projection::resolved_machine_history(store, txn, fold, target)
                .is_err()
        {
            return Ok(false);
        }
        return Ok(match kind {
            crate::claim::history_store::MachineHistoryKind::Birth => {
                rows.birth.event_id().is_ok_and(|birth_id| birth_id == *id)
            }
            crate::claim::history_store::MachineHistoryKind::Transition => {
                packet.transitions.iter().any(|listed| {
                    rows.events.iter().any(|event| {
                        crate::claim::transition::machine_claim_transition_event_hash(event)
                            .is_ok_and(|hash| hash == listed.hash)
                            && crate::claim::transition::machine_claim_transition_event_id(event)
                                .is_ok_and(|event_id| event_id == *id)
                    })
                })
            }
            crate::claim::history_store::MachineHistoryKind::Handoff => {
                crate::claim::history_projection::verified_handoff_chain(store, txn, &packet, fold)
                    .is_ok_and(|chain| {
                        chain.iter().any(|packet| {
                            packet.content_hash().ok().and_then(|hash| {
                                EntityId::from_bytes(hash[..16].try_into().ok()?).ok()
                            }) == Some(*id)
                        })
                    })
            }
        });
    }
    // An id that already has machine history stays machine-owned even if an
    // attacker replaces its LWW row with ordinary/no actor evidence.
    if !crate::claim::history_store::machine_history_ids_for_target(store, txn, *id)?.is_empty()
        || store
            .vault_meta
            .get(txn, &crate::claim::history_projection::pin_key(*id))?
            .is_some()
    {
        match crate::claim::history_projection::resolved_machine_history(store, txn, fold, *id) {
            Ok(projection)
                if crate::claim::history_projection::project_machine_claim(&projection)
                    == *body => {}
            // A superseded history's same-id successor is an ordinary claim.
            Ok(projection)
                if projection.admits_successor_by(crate::memory::claim_author(body))
                    && !machine_claim_needs_history(store, txn, body)? => {}
            Ok(_)
            | Err(Error::Claim(ClaimError::MachineClaimHistoryIncomplete))
            | Err(Error::Claim(ClaimError::InvalidMachineClaimProof)) => return Ok(false),
            Err(other) => return Err(other),
        }
    }
    let Some(Value::Map(entries)) = body.evidence.as_ref() else {
        return Ok(true);
    };
    let carries_proof = entries
        .iter()
        .any(|(key, _)| key.as_str() == Some(SIGNATURE_KEY));
    let machine_ref = names_machine(store, txn, entries)?;
    if !carries_proof {
        if machine_ref {
            return Ok(false);
        }
        // Unknown peer actor kind never makes an unsigned SYSTEM claim visible.
        for (_, value) in entries
            .iter()
            .filter(|(key, _)| key.as_str() == Some("actor_entity_ref"))
        {
            if let Value::Binary(bytes) = value
                && let Ok(raw_id) = bytes.as_slice().try_into()
                && let Ok(actor) = EntityId::from_bytes(raw_id)
                && store.entities.get(txn, actor.as_bytes())?.is_none()
                && entries.iter().any(|(key, value)| {
                    key.as_str() == Some("actor_class")
                        && value.as_u64() == Some(EdgeActorClass::System as u64)
                })
            {
                return Ok(false);
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
    let Some(vault_id) = fold.vault_id else {
        return Ok(false);
    };
    let key = VerifyingKey::from_bytes(&proof.public_key);
    let Ok(key_bytes) = key else { return Ok(false) };
    // The immutable signed origin is verified against the exact stored birth
    // bytes. Current approval/lifecycle comes from the signed operation fold.
    let Ok(projection) =
        crate::claim::history_projection::resolved_machine_history(store, txn, fold, *id)
    else {
        return Ok(false);
    };
    let original = &projection.birth;
    let Ok(transcript) = machine_claim_transcript(&vault_id, id, original) else {
        return Ok(false);
    };
    if key_bytes
        .verify(&transcript, &Signature::from_bytes(&proof.signature))
        .is_err()
        || crate::claim::history_projection::project_machine_claim(&projection) != *body
    {
        return Ok(false);
    }
    let authority_key = AuthorityKey::Ed25519(proof.public_key);
    Ok(fold
        .actor_bindings
        .get(&authority_key)
        .is_some_and(|binding| {
            binding.status == ActorBindingStatus::Active
                && binding.actor_ref == actor
                && binding.actor_class == "system"
        })
        && fold.roster.get(&authority_key).is_some_and(|device| {
            !device.revoked
                && device.tier == AuthorityTier::Software
                && device.roles & ROLE_AGENT != 0
        }))
}

/// Exact signed-log causal descent; an advisory timestamp or a claimed head
/// cannot backdate an event past re-root/revocation. Both hashes must fold
/// valid in the same vault snapshot. No process-local watermark is trusted.
pub(crate) fn machine_history_authority_descends(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    old: &[u8; 32],
    successor: &[u8; 32],
) -> Result<bool> {
    let mut by_hash = std::collections::BTreeMap::new();
    for id in
        store.port_entity_ids_by_type(txn, crate::registry::ENTITY_TYPE_AUTHORITY_LOG, None)?
    {
        let id = id?;
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            return Err(Error::CorruptedIndex("authority history row"));
        };
        let body = raw
            .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("authority history header"))?;
        let entry = super::decode_authority_log_entry_body(body)?;
        let hash = super::authority_entry_hash(&entry)?;
        if super::authority_log_entity_id_from_hash(&hash)? != id {
            return Err(Error::CorruptedIndex("authority history key"));
        }
        by_hash.insert(hash, entry);
    }
    if !by_hash.contains_key(old) || !by_hash.contains_key(successor) {
        return Ok(false);
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut stack = by_hash[successor].parent_hashes.clone();
    while let Some(hash) = stack.pop() {
        if hash == *old {
            return Ok(true);
        }
        if seen.insert(hash) {
            let Some(entry) = by_hash.get(&hash) else {
                return Ok(false);
            };
            stack.extend(entry.parent_hashes.iter().copied());
        }
    }
    Ok(false)
}

/// One current, fold-verified authority head for scoped history signatures.
/// Fail closed if the root is absent, conflicted or its signer is revoked.
pub(crate) fn machine_history_host_context(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    signer: &AuthorityKey,
) -> Result<([u8; 32], [u8; 32])> {
    let fold = super::authority_view_readonly_for_store_in_txn(store, posture, txn)?;
    let vault_id = fold.vault_id.ok_or_else(denied)?;
    if fold.vault_root_is_conflicted()
        || !fold
            .roster
            .get(signer)
            .is_some_and(|root| !root.revoked && root.roles & super::ROLE_OWNER != 0)
    {
        return Err(denied());
    }
    // A successor root has no authored sequence yet: its trust event is the
    // predecessor-signed ReRoot, not an arbitrary lexicographically maximal
    // concurrent head. Pin that exact causal ancestor for history handoff.
    let mut re_roots = Vec::new();
    let mut authored_heads = Vec::new();
    for id in
        store.port_entity_ids_by_type(txn, crate::registry::ENTITY_TYPE_AUTHORITY_LOG, None)?
    {
        let id = id?;
        let raw = store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("authority head row"))?;
        let entry = super::decode_authority_log_entry_body(
            raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                .ok_or(Error::CorruptedIndex("authority head header"))?,
        )?;
        let hash = super::authority_entry_hash(&entry)?;
        if !fold.valid_entries.contains(&hash) {
            continue;
        }
        if matches!(&entry.op, AuthorityOp::ReRoot { new_device } if new_device.key == *signer) {
            re_roots.push(hash);
        }
        if fold.append_heads.contains(&hash) && entry.signer_key() == signer {
            authored_heads.push(hash);
        }
    }
    let head = match re_roots.as_slice() {
        [head] => *head,
        [] => match authored_heads.as_slice() {
            [head] => *head,
            _ => return Err(denied()),
        },
        _ => return Err(denied()),
    };
    Ok((vault_id, head))
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
    writer_envelope: Option<&WriteEnvelope>,
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
    let (actor, class, proof) = proof(body)
        .map_err(|err| match err {
            Error::Claim(ClaimError::ActorLacksClaimAuthority { .. }) => invalid_origin(replicated),
            other => other,
        })?
        .ok_or_else(|| invalid_origin(replicated))?;
    let actor_type = store
        .entities
        .get(txn, actor.as_bytes())?
        .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|header| header.entity_type));
    if class != EdgeActorClass::System as u64
        || !replicated && actor_type != Some(ENTITY_TYPE_MACHINE)
        || actor_type.is_some_and(|kind| kind != ENTITY_TYPE_MACHINE)
    {
        return Err(invalid_origin(replicated));
    }
    let fold = super::authority_fold_readonly_for_store_in_txn(store, posture, txn)?;
    if fold.vault_root_is_conflicted() {
        return Err(denied());
    }
    let proof = proof.ok_or_else(|| invalid_origin(replicated))?;
    let key =
        VerifyingKey::from_bytes(&proof.public_key).map_err(|_| invalid_origin(replicated))?;
    if let Some(vault_id) = fold.vault_id {
        match crate::claim::history_projection::resolved_machine_history(store, txn, &fold, *id) {
            Ok(projection) => {
                if crate::claim::history_projection::project_machine_claim(&projection) != *body
                    || projection.birth.evidence.as_ref().is_none_or(|value| {
                        !matches!(value, Value::Map(entries) if entries.iter().any(|(key, _)|
                            key.as_str() == Some(SIGNATURE_KEY)))
                    })
                {
                    return Err(invalid_origin(replicated));
                }
            }
            Err(Error::Claim(ClaimError::MachineClaimHistoryIncomplete)) => {
                if !replicated
                    && !writer_envelope.is_some_and(|envelope| {
                        envelope.actor().entity_ref() == actor
                            && envelope.actor().actor_class() == EdgeActorClass::System
                            && envelope.machine_signature() == Some(proof)
                    })
                {
                    return Err(denied());
                }
                // A first birth may reach replay before its scoped controls.
                // Origin-verifiable rows are provisional; malformed proofs
                // quarantine without requiring enrollment arrival order.
                let transcript = machine_claim_transcript(&vault_id, id, body)?;
                key.verify(&transcript, &Signature::from_bytes(&proof.signature))
                    .map_err(|_| invalid_origin(replicated))?;
            }
            Err(Error::Claim(ClaimError::InvalidMachineClaimProof)) => {
                return Err(invalid_origin(replicated));
            }
            Err(other) => return Err(other),
        }
    } else if !replicated {
        return Err(denied());
    }
    // A relay may see the signed row before genesis/birth. Store its canonical
    // bytes provisionally; read/export withhold until verified history arrives.
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
