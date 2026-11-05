//! Native source half of an order-scoped legal clone. The HOST owns independent
//! key custody, persistence, legal access audit and destruction. No clone is a
//! Vault, and no ordinary owner/member/agent surface routes to this channel.

mod auth;

pub use auth::{HostLegalChannel, HostLegalConnection};

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use getrandom::SysRng;
use oneiron_crypto::legal_clone::{self, CaptureBinding, ContentBinding, SourceComponent};
use oneiron_crypto::{Envelope, HybridPublicKey, MAX_PLAINTEXT_LEN};
use oneiron_vault_contract::host_legal::{
    CaptureAck, CaptureDescriptor, CaptureRequest, CaptureSummary, FrameHeader, FrameKind,
    SourceHello,
};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::store::GateCloneComponent;
use crate::{EntityId, Vault};

impl HostLegalConnection {
    /// Run on the managed blocking executor. Teardown sets `cancelled`, shuts
    /// down the accepted stream and joins this worker BEFORE closing the Vault.
    /// HOST has durably admitted/audited the exact order before invoking it.
    /// Success means the SAME HOST durably acknowledged this exact stream;
    /// it is not permission to remove unrelated live retention or backups.
    pub fn run(mut self, vault: &Vault, cancelled: &AtomicBool) -> Result<()> {
        self.stream.set_nonblocking(false)?;
        SourceHello {
            source_vault: *vault.vault_id().as_bytes(),
        }
        .write_to(&mut self.stream)?;
        self.stream.flush()?;
        let request = CaptureRequest::read_from(&mut self.stream)?;
        EntityId::from_bytes(request.order)?;
        EntityId::from_bytes(request.capture)?;
        if request.source_vault != *vault.vault_id().as_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "legal capture source identity",
            )
            .into());
        }
        let public = HybridPublicKey::from_bytes(&request.recipient)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "legal capture recipient"))?;
        let check = || check(vault, &request, cancelled);
        check()?;
        // This is the actual order term, not an invented service timeout.
        // Managed shutdown separately interrupts ALL accepted streams.
        let remaining = request
            .ends_at
            .saturating_sub(vault.store.clock.now_recorded_at());
        if remaining == 0 {
            check()?;
        }
        let deadline = Some(Duration::from_secs(remaining));
        self.stream.set_read_timeout(deadline)?;
        self.stream.set_write_timeout(deadline)?;
        let binding = CaptureBinding {
            order: request.order,
            source_vault: *vault.vault_id().as_bytes(),
            generation: request.generation,
            capture: request.capture,
        };
        let request_digest = request.digest()?;
        let mut transcript = blake3::Hasher::new();
        frame(
            &mut self.stream,
            &mut transcript,
            FrameKind::Accepted,
            0,
            0,
            &request_digest,
        )?;
        // Custody BEFORE source snapshot/writer. Keep exact bytes pinned and
        // linearize with destructive source writers until durable HOST ack.
        let _custody = vault.store.gate_custody_read_guard()?;
        let txn = vault.store.env.write_txn()?;
        let mut components = 0_u64;
        let mut plaintext_bytes = 0_u64;
        let mut descriptors = blake3::Hasher::new();
        let mut stored_revision = [0; 32];
        let decisions = vault
            .store
            .for_each_claim_free_gate_clone_component_in_txn(
                &txn,
                check,
                |decision, component, key, value| {
                    check()?;
                    let fingerprint = *blake3::hash(value).as_bytes();
                    let revision = match component {
                        GateCloneComponent::StoredPrimary => {
                            stored_revision = fingerprint;
                            fingerprint
                        }
                        GateCloneComponent::OpenedPrimary => stored_revision,
                        _ => fingerprint,
                    };
                    let source_key_digest = source_key_digest(component.label(), key);
                    let chunk_count = value.len().div_ceil(MAX_PLAINTEXT_LEN).max(1) as u64;
                    let descriptor = CaptureDescriptor {
                        component: component_code(component),
                        decision: decision.as_bytes(),
                        source_key: key.to_vec(),
                        source_key_digest,
                        revision,
                        plaintext_fingerprint: fingerprint,
                        plaintext_len: value.len() as u64,
                        chunk_count,
                    };
                    let encoded =
                        Zeroizing::new(serde_json::to_vec(&descriptor).map_err(io::Error::other)?);
                    descriptors.update(&encoded);
                    let sealed = legal_clone::seal_descriptor(
                        &public,
                        &binding,
                        components,
                        &encoded,
                        &mut SysRng,
                    )
                    .map_err(crypto_error)?;
                    envelope(
                        &mut self.stream,
                        &mut transcript,
                        FrameKind::Descriptor,
                        components,
                        0,
                        sealed,
                    )?;
                    for chunk_index in 0..chunk_count {
                        check()?;
                        let start = chunk_index as usize * MAX_PLAINTEXT_LEN;
                        let end = start.saturating_add(MAX_PLAINTEXT_LEN).min(value.len());
                        let content = ContentBinding {
                            capture: binding,
                            member_ordinal: components,
                            component: source_component(component),
                            decision: decision.as_bytes(),
                            source_key_digest,
                            revision,
                            plaintext_fingerprint: fingerprint,
                            chunk_index,
                            chunk_count,
                        };
                        let sealed = legal_clone::seal_content(
                            &public,
                            &content,
                            &value[start..end],
                            &mut SysRng,
                        )
                        .map_err(crypto_error)?;
                        envelope(
                            &mut self.stream,
                            &mut transcript,
                            FrameKind::Content,
                            components,
                            chunk_index,
                            sealed,
                        )?;
                    }
                    plaintext_bytes = plaintext_bytes
                        .checked_add(value.len() as u64)
                        .ok_or(Error::ArithmeticOverflow("legal clone byte count"))?;
                    components = components
                        .checked_add(1)
                        .ok_or(Error::ArithmeticOverflow("legal clone component count"))?;
                    Ok(())
                },
            )?;
        check()?;
        let summary = CaptureSummary {
            order: binding.order,
            capture: binding.capture,
            source_vault: binding.source_vault,
            generation: binding.generation,
            ends_at: request.ends_at,
            decisions,
            components,
            plaintext_bytes,
            descriptors_hash: *descriptors.finalize().as_bytes(),
        };
        let encoded = Zeroizing::new(serde_json::to_vec(&summary).map_err(io::Error::other)?);
        let sealed = legal_clone::seal_summary(&public, &binding, &encoded, &mut SysRng)
            .map_err(crypto_error)?;
        envelope(
            &mut self.stream,
            &mut transcript,
            FrameKind::Summary,
            0,
            0,
            sealed,
        )?;
        let digest = *transcript.finalize().as_bytes();
        // Ready is excluded from its own transcript, avoiding circular binding.
        self.stream.write_all(
            &FrameHeader {
                kind: FrameKind::Ready,
                member: components,
                part: 0,
                len: digest.len() as u64,
            }
            .bytes(),
        )?;
        self.stream.write_all(&digest)?;
        self.stream.flush()?;
        let ack = CaptureAck::read_from(&mut self.stream)?;
        check()?;
        if ack.request != request_digest || ack.transcript != digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "legal capture acknowledgment binding",
            )
            .into());
        }
        // Read-only writer abort: no hold metadata, source bytes or user state
        // changed. Clone publication is the independently committed HOST store.
        drop(txn);
        Ok(())
    }
}

fn check(vault: &Vault, request: &CaptureRequest, cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Acquire) {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "legal capture stopped").into());
    }
    if vault.store.clock.now_recorded_at() >= request.ends_at {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "legal order term ended").into());
    }
    Ok(())
}

fn source_key_digest(family: &str, key: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.legal-clone.source-key.v1");
    hash.update(&(family.len() as u64).to_be_bytes());
    hash.update(family.as_bytes());
    hash.update(&(key.len() as u64).to_be_bytes());
    hash.update(key);
    *hash.finalize().as_bytes()
}

fn component_code(component: GateCloneComponent) -> u8 {
    match component {
        GateCloneComponent::StoredPrimary => 1,
        GateCloneComponent::OpenedPrimary => 2,
        GateCloneComponent::RetentionScope => 3,
        GateCloneComponent::ClaimRefs => 4,
        GateCloneComponent::PendingScrub => 5,
    }
}

fn source_component(component: GateCloneComponent) -> SourceComponent {
    match component {
        GateCloneComponent::StoredPrimary => SourceComponent::StoredLedger,
        GateCloneComponent::OpenedPrimary => SourceComponent::OpenedMessagePack,
        GateCloneComponent::RetentionScope => SourceComponent::RetentionContext,
        GateCloneComponent::ClaimRefs => SourceComponent::BundleRefs,
        GateCloneComponent::PendingScrub => SourceComponent::PendingScrub,
    }
}

fn envelope(
    out: &mut impl Write,
    transcript: &mut blake3::Hasher,
    kind: FrameKind,
    member: u64,
    part: u64,
    sealed: Envelope,
) -> Result<()> {
    frame(out, transcript, kind, member, part, &sealed.to_bytes())
}

fn frame(
    out: &mut impl Write,
    transcript: &mut blake3::Hasher,
    kind: FrameKind,
    member: u64,
    part: u64,
    payload: &[u8],
) -> Result<()> {
    let header = FrameHeader {
        kind,
        member,
        part,
        len: payload.len() as u64,
    }
    .bytes();
    out.write_all(&header)?;
    out.write_all(payload)?;
    transcript.update(&header);
    transcript.update(payload);
    Ok(())
}

fn crypto_error(_error: oneiron_crypto::Error) -> io::Error {
    io::Error::other("legal clone encryption")
}
