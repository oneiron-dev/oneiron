//! Doors to an owner's hold store for `tests/legal_hold_clone.rs`: a
//! hold's directory, and each of its sealed captures opened and checked.

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use oneiron_crypto::legal_clone::{
    CaptureBinding, ContentBinding, ContentSource, SourceComponent, live_session_ref_digest,
    open_content, open_descriptor,
};
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridSecretKey, Kek, OpenKey, OpenPolicy, Purpose, SuiteId, WrapType,
};
use oneiron_keystore::{KeystoreSlot, SlotKind};
use oneiron_vault_contract::host_legal::{
    CaptureDescriptor, CaptureSource, FrameHeader, FrameKind,
};

use crate::Vault;
use crate::deletion::LegalHoldProduction;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};

/// One opened component of a hold's sealed captures.
pub struct OpenedHoldComponent {
    /// The capture that holds it.
    pub capture: [u8; 16],
    /// The stored record or gate decision it copies.
    pub source: [u8; 16],
    /// The component's family label.
    pub family: String,
    /// The exact stored key, as sealed.
    pub key: Vec<u8>,
    /// The exact stored bytes, as sealed.
    pub value: Vec<u8>,
}

/// The hold's directory in the install's hold store.
pub fn hold_dir(vault: &Vault, hold_id: EntityId) -> Result<PathBuf> {
    let Some(root) = vault.config.legal_hold_store.clone() else {
        return Err(Error::InvalidConfig("no legal hold store is set".into()));
    };
    Ok(root
        .join(bytes_to_hex_lower(vault.vault_id().as_bytes()))
        .join(hold_id.to_hex()))
}

/// Opens every sealed capture of `hold_id`: `hold.key` under this install's
/// hold-store key, then each `.clone` file's frames, each component's
/// descriptor and content, checked against the Ready digest's recomputed
/// transcript. Components in stream order, captures in file order.
pub fn open_clone(vault: &Vault, hold_id: EntityId) -> Result<Vec<OpenedHoldComponent>> {
    let secret = hold_secret(vault, &hold_id)?;
    let dir = hold_dir(vault, hold_id)?;
    let mut files: Vec<(String, String)> = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(".clone") {
            let stem = stem.to_owned();
            files.push((name, stem));
        }
    }
    files.sort();
    let mut components = Vec::new();
    for (name, stem) in &files {
        let capture = EntityId::from_hex(stem).map_err(|_| invalid("legal hold capture name"))?;
        let bytes = fs::read(dir.join(name))?;
        open_capture(vault, &hold_id, &secret, &bytes, &capture, &mut components)?;
    }
    Ok(components)
}

/// Opens a production to `recipient`: its sealed hold key under the
/// recipient's secret key, the hold's pair rebuilt from the seed, then each
/// produced capture in order. Mirrors the production seal in the hold store,
/// which no test door reaches: the values below must stay identical to it.
/// A key that does not open is an error.
///
/// # Errors
/// The sealed key does not open under `recipient`, the seed rebuilds no key
/// pair, or a produced capture does not parse.
pub fn open_production(
    vault: &Vault,
    production: &LegalHoldProduction,
    recipient: &HybridSecretKey,
) -> Result<Vec<OpenedHoldComponent>> {
    let vault_id = *vault.vault_id().as_bytes();
    // The production binding: the vault id (32), the hold id (16), then the
    // production id (16), as the hold store seals it.
    let mut binding = [0u8; 64];
    binding[..32].copy_from_slice(&vault_id);
    binding[32..48].copy_from_slice(production.hold_id.as_bytes());
    binding[48..].copy_from_slice(production.production_id.as_bytes());
    let policy = OpenPolicy {
        purpose: Purpose::LegalClone,
        vault_id: &vault_id,
        // `PRODUCTION_RECIPIENT`, mirrored (see above).
        recipient: b"oneiron/legal-hold-store/production/v1",
        key_id: &binding,
        wraps: &[WrapType::HybridCapsule],
        aead_suites: &[SuiteId::XCHACHA20POLY1305_V1],
        kem_suites: &[SuiteId::KEM_X25519_MLKEM1024_V1],
        // `PRODUCTION_KEY_EPOCH`, mirrored (see above).
        min_epoch: 1,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let failed = || invalid("legal hold production does not open");
    let envelope = Envelope::parse(&production.sealed_hold_key).map_err(|_| failed())?;
    let seed = envelope
        .open_with_aad(OpenKey::Hybrid(recipient), &policy, &binding)
        .map_err(|_| failed())?;
    let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| failed())?;
    // `HOLD_SECRET_LABEL`, mirrored (see above).
    let secret = HybridSecretKey::from_seed(&seed, b"oneiron/legal-hold-store/hold-secret/v1")
        .map_err(|_| failed())?;
    let mut components = Vec::new();
    for capture in &production.captures {
        open_capture(
            vault,
            &production.hold_id,
            &secret,
            &capture.frames,
            &capture.capture,
            &mut components,
        )?;
    }
    Ok(components)
}

/// The hold's secret: `hold.key` opened under this install's hold-store key.
/// Mirrors the seal in the hold store, which no test door reaches: the two
/// must stay identical.
fn hold_secret(vault: &Vault, hold_id: &EntityId) -> Result<HybridSecretKey> {
    let keystore = vault.device_keystore()?;
    let slot = KeystoreSlot {
        vault_id: *vault.vault_id().as_bytes(),
        install: [0; 16],
        kind: SlotKind::LegalHoldStore,
    };
    let store_key = keystore
        .get(&slot)
        .map_err(crate::world_keys::keystore_error)?
        .ok_or_else(|| invalid("legal hold store key is missing"))?;
    let vault_id = *vault.vault_id().as_bytes();
    let mut binding = [0u8; 48];
    binding[..32].copy_from_slice(&vault_id);
    binding[32..].copy_from_slice(hold_id.as_bytes());
    let kek = Kek::from_bytes_ref(&store_key);
    let policy = OpenPolicy {
        purpose: Purpose::SecretFile,
        vault_id: &vault_id,
        recipient: b"oneiron/legal-hold-store/hold-key/v1",
        key_id: &binding,
        wraps: &[WrapType::SymmetricKek],
        aead_suites: &[SuiteId::XCHACHA20POLY1305_V1],
        kem_suites: &[],
        min_epoch: 1,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let failed = || invalid("legal hold key does not open");
    let bytes = fs::read(hold_dir(vault, *hold_id)?.join("hold.key"))?;
    let envelope = Envelope::parse(&bytes).map_err(|_| failed())?;
    let seed = envelope
        .open_with_aad(OpenKey::SymmetricKek(&kek), &policy, &binding)
        .map_err(|_| failed())?;
    let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| failed())?;
    let secret = HybridSecretKey::from_seed(&seed, b"oneiron/legal-hold-store/hold-secret/v1")
        .map_err(|_| failed())?;
    Ok(secret)
}

/// One member's descriptor with the content chunks opened so far.
struct OpenMember {
    descriptor: CaptureDescriptor,
    component: SourceComponent,
    source: ContentSource,
    parts: Vec<Vec<u8>>,
}

/// Opens one `.clone` file into `out`: its frames parsed, each component's
/// descriptor and content opened under `secret`, its Ready digest checked
/// against the recomputed transcript.
fn open_capture(
    vault: &Vault,
    hold_id: &EntityId,
    secret: &HybridSecretKey,
    bytes: &[u8],
    capture: &EntityId,
    out: &mut Vec<OpenedHoldComponent>,
) -> Result<()> {
    let mut frames: Vec<(FrameHeader, Vec<u8>)> = Vec::new();
    let mut cursor = io::Cursor::new(bytes);
    while cursor.position() < bytes.len() as u64 {
        let header = FrameHeader::read_from(&mut cursor)?;
        if header.len > bytes.len() as u64 - cursor.position() {
            return Err(invalid("legal hold frame truncated"));
        }
        let len = usize::try_from(header.len).map_err(|_| invalid("legal hold frame length"))?;
        let mut payload = vec![0; len];
        cursor.read_exact(&mut payload)?;
        frames.push((header, payload));
    }
    let [head, tail @ ..] = frames.as_slice() else {
        return Err(invalid("legal hold capture is empty"));
    };
    let (accepted, request_digest) = head;
    if accepted.kind != FrameKind::Accepted || request_digest.len() != 32 {
        return Err(invalid("legal hold capture has no request digest"));
    }
    let request_digest: [u8; 32] = request_digest
        .as_slice()
        .try_into()
        .map_err(|_| invalid("legal hold capture has no request digest"))?;
    let Some((ready, digest)) = tail.last() else {
        return Err(invalid("legal hold capture has no Ready digest"));
    };
    if ready.kind != FrameKind::Ready || digest.len() != 32 {
        return Err(invalid("legal hold capture has no Ready digest"));
    }
    let digest: [u8; 32] = digest
        .as_slice()
        .try_into()
        .map_err(|_| invalid("legal hold capture has no Ready digest"))?;
    // The transcript covers every frame but the Ready one.
    let mut transcript = blake3::Hasher::new();
    for (header, payload) in &frames[..frames.len() - 1] {
        transcript.update(&header.bytes());
        transcript.update(payload);
    }
    if *transcript.finalize().as_bytes() != digest {
        return Err(invalid("legal hold transcript digest"));
    }
    let binding = CaptureBinding {
        order: *hold_id.as_bytes(),
        source_vault: *vault.vault_id().as_bytes(),
        generation: 0,
        capture: *capture.as_bytes(),
        request_digest,
    };
    // Every frame between the Accepted and the Ready one ends in the one
    // summary; before it, each component's descriptor then its chunks.
    let body = &frames[1..frames.len() - 1];
    let Some((summary, _)) = body.last() else {
        return Err(invalid("legal hold capture has no summary"));
    };
    if summary.kind != FrameKind::Summary || summary.member != 0 || summary.part != 0 {
        return Err(invalid("legal hold summary order"));
    }
    let mut member = 0_u64;
    let mut current: Option<OpenMember> = None;
    for (header, payload) in &body[..body.len() - 1] {
        match header.kind {
            FrameKind::Descriptor => {
                if current.is_some() || header.member != member || header.part != 0 {
                    return Err(invalid("legal hold descriptor order"));
                }
                let opened = open_descriptor(secret, &binding, member, payload)
                    .map_err(|_| invalid("legal hold descriptor does not open"))?;
                let descriptor: CaptureDescriptor = serde_json::from_slice(&opened)
                    .map_err(|_| invalid("legal hold descriptor does not decode"))?;
                let component = SourceComponent::from_wire(descriptor.component)
                    .map_err(|_| invalid("legal hold component tag"))?;
                let source = match &descriptor.source {
                    CaptureSource::Message(id) => ContentSource::Message(*id),
                    CaptureSource::GateDecision(id) => ContentSource::GateDecision(*id),
                    CaptureSource::LiveSession(target) => ContentSource::LiveSession {
                        session_ref_digest: live_session_ref_digest(&target.session_ref),
                        instance: target.instance,
                    },
                };
                current = Some(OpenMember {
                    descriptor,
                    component,
                    source,
                    parts: Vec::new(),
                });
            }
            FrameKind::Content => {
                let done = {
                    let Some(open) = current.as_mut() else {
                        return Err(invalid("legal hold content without descriptor"));
                    };
                    if header.member != member || header.part != open.parts.len() as u64 {
                        return Err(invalid("legal hold content order"));
                    }
                    let content = ContentBinding {
                        capture: binding,
                        member_ordinal: member,
                        component: open.component,
                        source: open.source,
                        source_key_digest: open.descriptor.source_key_digest,
                        revision: open.descriptor.revision,
                        plaintext_fingerprint: open.descriptor.plaintext_fingerprint,
                        chunk_index: header.part,
                        chunk_count: open.descriptor.chunk_count,
                    };
                    let plain = open_content(secret, &content, payload)
                        .map_err(|_| invalid("legal hold content does not open"))?;
                    open.parts.push(plain.to_vec());
                    header.part + 1 == open.descriptor.chunk_count
                };
                if done {
                    let open = current
                        .take()
                        .ok_or_else(|| invalid("legal hold content order"))?;
                    let mut value = Vec::new();
                    for part in &open.parts {
                        value.extend_from_slice(part);
                    }
                    if value.len() as u64 != open.descriptor.plaintext_len
                        || *blake3::hash(&value).as_bytes() != open.descriptor.plaintext_fingerprint
                    {
                        return Err(invalid("legal hold component digest"));
                    }
                    let source = match open.descriptor.source {
                        CaptureSource::Message(id) | CaptureSource::GateDecision(id) => id,
                        CaptureSource::LiveSession(_) => {
                            return Err(invalid("legal hold live source"));
                        }
                    };
                    out.push(OpenedHoldComponent {
                        capture: *capture.as_bytes(),
                        source,
                        family: component_family(open.component).to_owned(),
                        key: open.descriptor.source_key,
                        value,
                    });
                    member += 1;
                }
            }
            _ => return Err(invalid("legal hold frame kind")),
        }
    }
    if current.is_some() {
        return Err(invalid("legal hold trailing descriptor"));
    }
    Ok(())
}

/// The family label an opened component reports: the native label of its
/// row kind, since the sealed descriptor carries no family string.
fn component_family(component: SourceComponent) -> &'static str {
    match component {
        SourceComponent::StoredLedger => "gate_decision:v0:",
        SourceComponent::OpenedMessagePack => "gate_decision:opened_messagepack",
        SourceComponent::RetentionContext => "gate_decision:retention_context:v1:",
        SourceComponent::BundleRefs => "gate_decision_claim_refs:v0:",
        SourceComponent::PendingScrub => "gate_decision:pending_scrub:v1:",
        // Live captures never land in a hold store, but the match is total.
        SourceComponent::LiveSessionBody => "live_session:body",
        SourceComponent::LiveSessionMetadata => "live_session:metadata",
        SourceComponent::MessageRow => "entities",
        SourceComponent::MessageDocument => "document",
        SourceComponent::MessageEdge => "edges_out",
        SourceComponent::MessageResultBody => "code_run:raw_output",
        SourceComponent::MessageRevision => "revision",
    }
}

/// A refusal naming the corrupt hold-store read.
fn invalid(what: &'static str) -> Error {
    io::Error::new(io::ErrorKind::InvalidData, what).into()
}
