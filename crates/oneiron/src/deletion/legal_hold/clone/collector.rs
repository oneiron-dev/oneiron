//! Streaming ciphertext and exact completion shared by native source families.

use std::io::{self, Read, Write};

use getrandom::SysRng;
use oneiron_crypto::legal_clone::{
    self, CaptureBinding, ContentBinding, ContentSource, SourceComponent,
};
use oneiron_crypto::{Envelope, HybridPublicKey, MAX_PLAINTEXT_LEN};
use oneiron_vault_contract::host_legal::{
    CaptureAck, CaptureDescriptor, CaptureExtent, CaptureRequest, CaptureSource, CaptureSummary,
    FrameHeader, FrameKind,
};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub(super) struct Collector<'stream> {
    stream: &'stream mut std::os::unix::net::UnixStream,
    public: &'stream HybridPublicKey,
    request: &'stream CaptureRequest,
    binding: CaptureBinding,
    request_digest: [u8; 32],
    transcript: blake3::Hasher,
    descriptors: blake3::Hasher,
    components: u64,
    plaintext_bytes: u64,
}

impl<'stream> Collector<'stream> {
    /// The caller already holds its actual source pin. Registration is not
    /// sufficient to emit Accepted.
    pub(super) fn pinned(
        stream: &'stream mut std::os::unix::net::UnixStream,
        public: &'stream HybridPublicKey,
        request: &'stream CaptureRequest,
    ) -> Result<Self> {
        let request_digest = request.digest()?;
        let mut collector = Self {
            stream,
            public,
            request,
            binding: CaptureBinding {
                order: request.order,
                source_vault: request.source_vault,
                generation: request.generation,
                capture: request.capture,
                request_digest,
            },
            request_digest,
            transcript: blake3::Hasher::new(),
            descriptors: blake3::Hasher::new(),
            components: 0,
            plaintext_bytes: 0,
        };
        collector.frame(FrameKind::Accepted, 0, 0, &request_digest)?;
        Ok(collector)
    }

    pub(super) fn component(
        &mut self,
        component: SourceComponent,
        source: CaptureSource,
        family: &str,
        key: &[u8],
        revision: [u8; 32],
        plaintext_len: u64,
        fingerprint: [u8; 32],
        input: &mut dyn Read,
        check: impl Fn() -> Result<()>,
    ) -> Result<()> {
        check()?;
        let source_key_digest = source_key_digest(family, key);
        let chunk_count = plaintext_len.div_ceil(MAX_PLAINTEXT_LEN as u64).max(1);
        let content_source = match &source {
            CaptureSource::GateDecision(decision) => ContentSource::GateDecision(*decision),
            CaptureSource::LiveSession(target) => ContentSource::LiveSession {
                session_ref_digest: legal_clone::live_session_ref_digest(&target.session_ref),
                instance: target.instance,
            },
        };
        let descriptor = CaptureDescriptor {
            component: component as u8,
            source,
            source_key: key.to_vec(),
            source_key_digest,
            revision,
            plaintext_fingerprint: fingerprint,
            plaintext_len,
            chunk_count,
        };
        let encoded = Zeroizing::new(serde_json::to_vec(&descriptor).map_err(io::Error::other)?);
        self.descriptors.update(&encoded);
        let sealed = legal_clone::seal_descriptor(
            self.public,
            &self.binding,
            self.components,
            &encoded,
            &mut SysRng,
        )
        .map_err(crypto_error)?;
        self.envelope(FrameKind::Descriptor, self.components, 0, sealed)?;
        let mut actual = blake3::Hasher::new();
        let mut remaining = plaintext_len;
        for chunk_index in 0..chunk_count {
            check()?;
            let len = remaining.min(MAX_PLAINTEXT_LEN as u64) as usize;
            let mut bytes = Zeroizing::new(vec![0; len]);
            input.read_exact(&mut bytes)?;
            actual.update(&bytes);
            let binding = ContentBinding {
                capture: self.binding,
                member_ordinal: self.components,
                component,
                source: content_source,
                source_key_digest,
                revision,
                plaintext_fingerprint: fingerprint,
                chunk_index,
                chunk_count,
            };
            let sealed = legal_clone::seal_content(self.public, &binding, &bytes, &mut SysRng)
                .map_err(crypto_error)?;
            self.envelope(FrameKind::Content, self.components, chunk_index, sealed)?;
            remaining -= len as u64;
        }
        let mut extra = [0];
        if input.read(&mut extra)? != 0 || actual.finalize().as_bytes() != &fingerprint {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "legal source content changed").into(),
            );
        }
        check()?;
        self.plaintext_bytes = self
            .plaintext_bytes
            .checked_add(plaintext_len)
            .ok_or(Error::ArithmeticOverflow("legal clone byte count"))?;
        self.components = self
            .components
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("legal clone component count"))?;
        Ok(())
    }

    /// This acknowledges the exact declared source extent, not an inferred
    /// whole order. The source owner must not wipe an uncaptured extent.
    pub(super) fn finish(
        mut self,
        decisions: u64,
        live_sessions: u64,
        live_bodies: u64,
        extent: CaptureExtent,
        check: impl Fn() -> Result<()>,
    ) -> Result<()> {
        check()?;
        let summary = CaptureSummary {
            order: self.binding.order,
            capture: self.binding.capture,
            source_vault: self.binding.source_vault,
            generation: self.binding.generation,
            ends_at: self.request.ends_at,
            decisions,
            live_sessions,
            live_bodies,
            extent,
            components: self.components,
            plaintext_bytes: self.plaintext_bytes,
            descriptors_hash: *self.descriptors.finalize().as_bytes(),
        };
        let encoded = Zeroizing::new(serde_json::to_vec(&summary).map_err(io::Error::other)?);
        let sealed = legal_clone::seal_summary(self.public, &self.binding, &encoded, &mut SysRng)
            .map_err(crypto_error)?;
        self.envelope(FrameKind::Summary, 0, 0, sealed)?;
        let digest = *self.transcript.finalize().as_bytes();
        self.stream.write_all(
            &FrameHeader {
                kind: FrameKind::Ready,
                member: self.components,
                part: 0,
                len: digest.len() as u64,
            }
            .bytes(),
        )?;
        self.stream.write_all(&digest)?;
        self.stream.flush()?;
        let ack = CaptureAck::read_from(self.stream)?;
        check()?;
        if ack.request != self.request_digest || ack.transcript != digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "legal capture acknowledgment binding",
            )
            .into());
        }
        Ok(())
    }

    fn envelope(
        &mut self,
        kind: FrameKind,
        member: u64,
        part: u64,
        sealed: Envelope,
    ) -> Result<()> {
        self.frame(kind, member, part, &sealed.to_bytes())
    }

    fn frame(&mut self, kind: FrameKind, member: u64, part: u64, payload: &[u8]) -> Result<()> {
        let header = FrameHeader {
            kind,
            member,
            part,
            len: payload.len() as u64,
        }
        .bytes();
        self.stream.write_all(&header)?;
        self.stream.write_all(payload)?;
        self.transcript.update(&header);
        self.transcript.update(payload);
        Ok(())
    }
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

fn crypto_error(_error: oneiron_crypto::Error) -> io::Error {
    io::Error::other("legal clone encryption")
}
