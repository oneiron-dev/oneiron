//! Streaming ciphertext and exact completion shared by native source families.

use std::io::{self, Read, Write};

use getrandom::SysRng;
use oneiron_crypto::HybridPublicKey;
use oneiron_crypto::legal_clone::{self, CaptureBinding, SourceComponent};
use oneiron_vault_contract::host_legal::{
    CaptureAck, CaptureExtent, CaptureRequest, CaptureSource, CaptureSummary, FrameHeader,
    FrameKind,
};
use zeroize::Zeroizing;

use crate::deletion::legal_hold::prospective::{crypto_error, seal_frames};
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

/// What a completion summary counts beyond the stream's own components.
#[derive(Default)]
pub(super) struct SummaryCounts {
    pub(super) decisions: u64,
    pub(super) live_sessions: u64,
    pub(super) live_bodies: u64,
    pub(super) messages: u64,
    pub(super) batch_first_ordinal: u64,
    pub(super) batch_entries: u64,
    pub(super) missed_messages: Vec<[u8; 16]>,
    pub(super) absent_result_bodies: Vec<[u8; 16]>,
    pub(super) final_next_ordinal: Option<u64>,
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

    #[allow(clippy::too_many_arguments)]
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
        let (public, binding, member) = (self.public, self.binding, self.components);
        let (stream, transcript) = (&mut *self.stream, &mut self.transcript);
        let encoded = seal_frames(
            public,
            &binding,
            member,
            component,
            source,
            family,
            key,
            revision,
            plaintext_len,
            fingerprint,
            input,
            &check,
            &mut |kind, member, part, payload| {
                write_frame(stream, transcript, kind, member, part, payload)
            },
        )?;
        self.descriptors.update(&encoded);
        self.count(plaintext_len)
    }

    /// One component a prospective order's outbox already holds as its exact
    /// frames, sealed when its message landed. Its descriptor digest stands
    /// in the batch's descriptor hash.
    pub(super) fn stored_component(
        &mut self,
        frames: &[u8],
        descriptor_digest: &[u8; 32],
        plaintext_len: u64,
        check: impl Fn() -> Result<()>,
    ) -> Result<()> {
        check()?;
        self.stream.write_all(frames)?;
        self.transcript.update(frames);
        self.descriptors.update(descriptor_digest);
        self.count(plaintext_len)
    }

    fn count(&mut self, plaintext_len: u64) -> Result<()> {
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
        self,
        decisions: u64,
        live_sessions: u64,
        live_bodies: u64,
        messages: u64,
        extent: CaptureExtent,
        check: impl Fn() -> Result<()>,
    ) -> Result<()> {
        self.finish_counted(
            SummaryCounts {
                decisions,
                live_sessions,
                live_bodies,
                messages,
                ..SummaryCounts::default()
            },
            extent,
            check,
        )
    }

    /// The summary, Ready and the exact acknowledgement for `counts`. A
    /// prospective batch names its exact ordinal range, so its
    /// acknowledgement covers that batch alone.
    pub(super) fn finish_counted(
        mut self,
        counts: SummaryCounts,
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
            decisions: counts.decisions,
            live_sessions: counts.live_sessions,
            live_bodies: counts.live_bodies,
            messages: counts.messages,
            batch_first_ordinal: counts.batch_first_ordinal,
            batch_entries: counts.batch_entries,
            missed_messages: counts.missed_messages,
            absent_result_bodies: counts.absent_result_bodies,
            final_next_ordinal: counts.final_next_ordinal,
            extent,
            components: self.components,
            plaintext_bytes: self.plaintext_bytes,
            descriptors_hash: *self.descriptors.finalize().as_bytes(),
        };
        let encoded = Zeroizing::new(serde_json::to_vec(&summary).map_err(io::Error::other)?);
        let sealed = legal_clone::seal_summary(self.public, &self.binding, &encoded, &mut SysRng)
            .map_err(crypto_error)?;
        self.frame(FrameKind::Summary, 0, 0, &sealed.to_bytes())?;
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

    fn frame(&mut self, kind: FrameKind, member: u64, part: u64, payload: &[u8]) -> Result<()> {
        write_frame(
            &mut *self.stream,
            &mut self.transcript,
            kind,
            member,
            part,
            payload,
        )
    }
}

fn write_frame(
    stream: &mut std::os::unix::net::UnixStream,
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
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    transcript.update(&header);
    transcript.update(payload);
    Ok(())
}
