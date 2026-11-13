//! Media a typed decision reads by reference (owner point 3). `state.media` lists each
//! medium as an immutable ref: what the bytes are of, the full hash of the exact bytes,
//! their type and size (pixels and frame, or duration and time window). The bytes ride
//! beside the 65,536-byte state, never in it. A ref is a locator, not a grant: the host
//! resolves it through the asker's own lane before a call. A medium no rung reads is
//! never captioned in its place; its entry says it was not served, and why.

use super::{
    DecisionAudio, DecisionDial, DecisionImage, DecisionLadder, DecisionQuestion, DecisionRung,
    EvidenceVersion, audio_format,
};
use crate::ingest::meeting_audio::{SourceSpan, SpeakerTrack, SpeechSpan};
use crate::llm::image::ImageBytes;
use crate::memory::PixelRegion;
use crate::{FatalLlmError, LlmResult};
use serde::{Deserialize, Serialize};

/// The state field a call's media entries fill.
pub const MEDIA_FIELD: &str = "media";

#[doc(hidden)]
pub(super) use oneiron_verb_wire::llm::decision::media_ref::dimensions;
#[doc(hidden)]
pub use oneiron_verb_wire::llm::decision::media_ref::{
    AudioRef, DecisionMedia, DecisionMediaRef, ImageRef, MediaServed,
};

/// One medium the host resolved through the asker's lane, with its bytes.
#[derive(Debug, Clone, PartialEq)]
pub enum ResolvedMedia {
    Image {
        name: String,
        reference: ImageRef,
        image: ImageBytes,
    },
    Audio {
        name: String,
        reference: AudioRef,
        bytes: Vec<u8>,
    },
}

/// A call's media as asked: the entries for `state.media`, the images and audio clips
/// that ride beside the state, and the dial, its first rung moved up to the first that
/// reads them.
#[derive(Debug, Clone)]
pub struct MediaCall {
    pub entries: Vec<DecisionMedia>,
    pub images: Vec<DecisionImage>,
    pub audio: Vec<DecisionAudio>,
    pub dial: DecisionDial,
}

impl MediaCall {
    /// `state` with this call's entries in its media field.
    pub fn state(&self, mut state: serde_json::Value) -> LlmResult<serde_json::Value> {
        let entries =
            serde_json::to_value(&self.entries).map_err(|_| FatalLlmError::InvalidRequest)?;
        let object = state.as_object_mut().ok_or(FatalLlmError::InvalidRequest)?;
        object.insert(MEDIA_FIELD.to_owned(), entries);
        Ok(state)
    }

    /// The media of one call under `dial`. Each image and clip is checked against its ref.
    /// A WAV or MP3 clip rides as named audio beside the images; a clip of another type is
    /// listed as not served. The dial starts at the first rung `first_taking` finds, from
    /// the dial's first to its ceiling, that reads every medium; when none reads both
    /// images and audio, the images ride alone if a rung reads them, else the audio alone,
    /// and what no rung reads is listed as not served. The call stands on the rest of its
    /// state.
    pub fn of(
        dial: DecisionDial,
        media: Vec<ResolvedMedia>,
        first_taking: impl Fn(&[DecisionImage], &[DecisionAudio]) -> Option<DecisionRung>,
    ) -> LlmResult<Self> {
        let (mut entries, mut images, mut audio) = Self::checked(media)?;
        DecisionAudio::validate_all(&audio)?;
        if audio
            .iter()
            .any(|clip| images.iter().any(|image| image.name == clip.name))
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let mut dial = dial;
        if !images.is_empty() || !audio.is_empty() {
            if let Some(first) = first_taking(&images, &audio) {
                dial.first = first;
            } else {
                let images_alone = if images.is_empty() {
                    None
                } else {
                    first_taking(&images, &[])
                };
                if let Some(first) = images_alone {
                    unserve_audio(&mut entries, &mut audio);
                    dial.first = first;
                } else {
                    unserve_images(&mut entries, &mut images);
                    let audio_alone = if audio.is_empty() {
                        None
                    } else {
                        first_taking(&[], &audio)
                    };
                    match audio_alone {
                        Some(first) => dial.first = first,
                        None => unserve_audio(&mut entries, &mut audio),
                    }
                }
            }
        }
        Ok(Self {
            entries,
            images,
            audio,
            dial,
        })
    }

    /// Each medium checked against its ref: its entry, and the images and the clips of a
    /// type a rung takes, all as served.
    fn checked(
        media: Vec<ResolvedMedia>,
    ) -> LlmResult<(Vec<DecisionMedia>, Vec<DecisionImage>, Vec<DecisionAudio>)> {
        let mut entries = Vec::with_capacity(media.len());
        let mut images = Vec::new();
        let mut audio = Vec::new();
        for medium in media {
            match medium {
                ResolvedMedia::Image {
                    name,
                    reference,
                    image,
                } => {
                    reference.check(&image)?;
                    images.push(DecisionImage {
                        name: name.clone(),
                        evidence: reference.evidence.clone(),
                        image,
                        frame: reference.frame,
                    });
                    entries.push(DecisionMedia {
                        name,
                        reference: DecisionMediaRef::Image(reference),
                        served: MediaServed::Full,
                    });
                }
                ResolvedMedia::Audio {
                    name,
                    reference,
                    bytes,
                } => {
                    reference.validate()?;
                    if bytes.is_empty()
                        || *blake3::hash(&bytes).as_bytes() != reference.evidence.body_hash
                    {
                        return Err(FatalLlmError::InvalidRequest.into());
                    }
                    let served = if audio_format(&reference.media_type).is_some() {
                        audio.push(DecisionAudio {
                            name: name.clone(),
                            evidence: reference.evidence.clone(),
                            media_type: reference.media_type.clone(),
                            bytes,
                        });
                        MediaServed::Full
                    } else {
                        MediaServed::AudioUnsupported
                    };
                    entries.push(DecisionMedia {
                        name,
                        reference: DecisionMediaRef::Audio(reference),
                        served,
                    });
                }
            }
        }
        DecisionImage::validate_all(&images)?;
        Ok((entries, images, audio))
    }
}

/// Lists every served image as having no reader, and drops them from the call.
fn unserve_images(entries: &mut [DecisionMedia], images: &mut Vec<DecisionImage>) {
    images.clear();
    for entry in entries {
        if matches!(entry.reference, DecisionMediaRef::Image(_)) {
            entry.served = MediaServed::NoImageReader;
        }
    }
}

/// Lists every served clip as having no reader, and drops them from the call.
fn unserve_audio(entries: &mut [DecisionMedia], audio: &mut Vec<DecisionAudio>) {
    audio.clear();
    for entry in entries {
        if matches!(entry.reference, DecisionMediaRef::Audio(_))
            && entry.served == MediaServed::Full
        {
            entry.served = MediaServed::NoAudioReader;
        }
    }
}

impl DecisionLadder<'_> {
    /// The media of one call of `question` under `dial` ([`MediaCall::of`]): its
    /// images and audio ride from the first rung of this ladder, from the dial's first to
    /// its ceiling, whose provider takes `question` over them.
    pub fn media_call(
        &self,
        question: &DecisionQuestion,
        dial: DecisionDial,
        media: Vec<ResolvedMedia>,
    ) -> LlmResult<MediaCall> {
        MediaCall::of(dial, media, |images, audio| {
            self.first_taking_media(question, dial, images, audio)
        })
    }
}
