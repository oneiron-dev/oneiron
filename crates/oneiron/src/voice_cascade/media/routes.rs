//! Voice media routes and banked voice bindings.
//! Entry: MediaVoiceRoute.
//! Definitions: types stay in the parent; this module owns the listed impls.

use super::{
    AiOperation, BTreeMap, BankBound, BankVoiceBinding, EngineLimit, MediaPart, MediaRequest,
    MediaVoice, MediaVoiceRoute, ModelLocality, Result, Vault, VoiceLane, invalid,
};

impl MediaVoiceRoute {
    /// The media call the lane makes.
    #[must_use]
    pub fn operation(&self) -> AiOperation {
        match self.lane {
            VoiceLane::AsrLive | VoiceLane::AsrBatch => AiOperation::Transcribe,
            VoiceLane::TtsLive | VoiceLane::TtsBatch => AiOperation::Speech,
        }
    }

    pub(in crate::voice_cascade) fn request(
        &self,
        part: MediaPart,
        voice: Option<MediaVoice>,
    ) -> MediaRequest {
        let operation = self.operation();
        let mut params = BTreeMap::new();
        if operation == AiOperation::Speech {
            // WAV says its own rate and channels; the cascade plays PCM16.
            params.insert("response_format".to_owned(), "wav".into());
        }
        MediaRequest {
            model: self.model.clone(),
            envelope: self.envelope.clone(),
            operation,
            parts: vec![part],
            references: Vec::new(),
            params,
            voice,
        }
    }
}

impl BankVoiceBinding {
    /// Binds `voice_id`'s current clone on `target`, a target at
    /// `locality`. An unprovisioned, evicted, stale or withdrawn clone
    /// refuses, as does a voice whose render consent does not reach it.
    pub fn bind(
        vault: &Vault,
        voice_id: &str,
        target: &str,
        include_generated: bool,
        locality: ModelLocality,
    ) -> Result<Self> {
        let (record, grant) = vault
            .voice_target_clone(voice_id, target, include_generated, locality)?
            .ok_or_else(|| invalid("voice target not provisioned, evicted or stale"))?;
        Ok(Self {
            voice_id: record.voice_id,
            target: record.target,
            include_generated,
            bound: BankBound::Clone {
                vendor_voice_id: record.vendor_voice_id,
                revision: record.revision,
                grant,
            },
        })
    }

    /// Binds `voice_id`'s source clip for a reference target: `register`'s,
    /// or the identity's first. The clip is the person's raw voice, so a
    /// third-party route refuses, as does an identity with no source refs
    /// or no render consent reaching `locality`, or a clip that is not a
    /// WAV with its transcript. A long clip binds whole, asking past its
    /// `[limits]` row.
    pub fn bind_reference(
        vault: &Vault,
        voice_id: &str,
        target: &str,
        register: Option<&str>,
        locality: ModelLocality,
    ) -> Result<Self> {
        if locality == ModelLocality::ThirdParty {
            return Err(invalid("a voice reference never goes to a third party"));
        }
        let (clip, fence) = vault.fenced_voice_reference(voice_id, target, register, locality)?;
        if clip.media_type != "audio/wav"
            || clip.audio.len() < 12
            || !clip.audio.starts_with(b"RIFF")
            || &clip.audio[8..12] != b"WAVE"
            || clip.transcript.trim().is_empty()
        {
            return Err(invalid("a voice reference is a WAV with its transcript"));
        }
        vault.measure_limit(
            EngineLimit::VoiceReferenceBytes,
            u64::try_from(clip.audio.len()).unwrap_or(u64::MAX),
        );
        Ok(Self {
            voice_id: voice_id.to_owned(),
            target: target.to_owned(),
            include_generated: false,
            bound: BankBound::Reference { clip, fence },
        })
    }

    /// Whether what this binding names is still the bank's current one,
    /// under the same render consent. A bank that cannot be read, or a
    /// withdrawal waiting to commit, is not current.
    #[must_use]
    pub fn is_current(&self, vault: &Vault) -> bool {
        match &self.bound {
            BankBound::Clone {
                revision, grant, ..
            } => matches!(
                vault.voice_target_clone(
                    &self.voice_id,
                    &self.target,
                    self.include_generated,
                    grant.locality,
                ),
                Ok(Some((record, current))) if record.revision == *revision && current == *grant
            ),
            BankBound::Reference { fence, .. } => vault
                .voice_ref_fence_current_now(&self.voice_id, &self.target, fence)
                .unwrap_or(false),
        }
    }

    /// The voice the call's wire carries: the target's id for the clone,
    /// or the fenced clip itself.
    #[must_use]
    pub fn voice(&self) -> MediaVoice {
        match &self.bound {
            BankBound::Clone {
                vendor_voice_id, ..
            } => MediaVoice::Clone {
                id: vendor_voice_id.clone(),
            },
            BankBound::Reference { clip, fence } => MediaVoice::Reference {
                voice_id: self.voice_id.clone(),
                owner: fence.owner.to_hex(),
                register: clip.register.clone(),
                revision: fence
                    .incarnation
                    .iter()
                    .flatten()
                    .chain(&fence.ref_digest)
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
                media_type: clip.media_type.clone(),
                audio: clip.audio.clone(),
                transcript: clip.transcript.clone(),
            },
        }
    }
}

impl MediaVoiceRoute {
    /// The admission request of one bounded live stream on a transcription
    /// route: the route's call with no audio yet, naming the PCM16LE the
    /// stream carries. Its audio is admitted as it goes, on the stream's
    /// lease ([`LeasedAsrStream`](super::LeasedAsrStream)).
    pub fn stream_request(&self, sample_rate: u32, channels: u16) -> Result<MediaRequest> {
        if self.operation() != AiOperation::Transcribe {
            return Err(invalid("a live stream hears on a transcription route"));
        }
        if !(8_000..=192_000).contains(&sample_rate) || !(1..=2).contains(&channels) {
            return Err(invalid("unsupported PCM rate or channels"));
        }
        let mut request = self.request(
            MediaPart::Audio {
                media_type: "audio/pcm".into(),
                bytes: Vec::new(),
            },
            None,
        );
        request
            .params
            .insert("audio_format".to_owned(), "pcm_s16le".into());
        request
            .params
            .insert("sample_rate".to_owned(), sample_rate.into());
        request
            .params
            .insert("num_channels".to_owned(), channels.into());
        Ok(request)
    }
}
