//! Heard-playback accounting (FIX 4899, ARCH-0061 #heard-playback): what
//! the person actually heard of a reply, kept apart from the text the brain
//! generated.
//!
//! Entry: [`HeardLedger`], which a host keeps for each generation it speaks.
//! Each sentence the TTS seam takes is one submission, numbered from 0 in
//! the order the seam took it, as the media adapter numbers it. As each
//! submission's audio is queued to the client, the ledger records where it
//! falls in the generation's played stream: every sample of the
//! generation's audio, in the order it was queued, each frame at its own
//! rate. When the generation stops or drains, the client's played sample
//! count, or the server's queued count when the client reports none, makes
//! the [`HeardPlayback`]. Session, generation and submission name each
//! utterance.
//!
//! A part-played submission's heard text comes only through a validated
//! [`SpeechAlignment`] its TTS adapter supplied. Without one its text is
//! unknown: it is never cut by a guessed ratio of samples.

use serde::{Deserialize, Serialize};

use super::GenerationEpoch;

#[doc(hidden)]
pub use oneiron_records::voice_cascade::heard::{
    HeardBasis, HeardCoverage, HeardPlayback, HeardUtterance,
};

/// Where a submission's text falls in its audio, as a TTS adapter may
/// report it: `(char_end, sample_end)` pairs, each saying the text's first
/// `char_end` characters were spoken by sample `sample_end`. Both rise
/// through the list (`char_end` strictly), within the text's characters and
/// the audio's samples. No adapter on main supplies one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeechAlignment {
    pub points: Vec<(usize, u64)>,
}

impl SpeechAlignment {
    /// Whether the alignment holds for `text` spoken in `samples` samples.
    fn fits(&self, text: &str, samples: u64) -> bool {
        let characters = text.chars().count();
        let mut last: Option<(usize, u64)> = None;
        !self.points.is_empty()
            && self.points.iter().all(|&(char_end, sample_end)| {
                let rises = last.is_none_or(|(char_before, sample_before)| {
                    char_end > char_before && sample_end >= sample_before
                });
                last = Some((char_end, sample_end));
                rises && (1..=characters).contains(&char_end) && sample_end <= samples
            })
    }

    /// The text spoken by `played` samples: up to the last point at or
    /// before it, empty before the first.
    fn heard(&self, text: &str, played: u64) -> String {
        let spoken = self
            .points
            .iter()
            .take_while(|&&(_, sample_end)| sample_end <= played)
            .last()
            .map_or(0, |&(char_end, _)| char_end);
        text.chars().take(spoken).collect()
    }
}

/// One submission in the ledger.
#[derive(Debug, Clone)]
struct Submission {
    text: String,
    /// Where its audio starts in the generation's played stream, its rate,
    /// its length and its validated alignment, once its audio was queued.
    audio: Option<QueuedAudio>,
}

#[derive(Debug, Clone)]
struct QueuedAudio {
    first_sample: u64,
    sample_rate: u32,
    samples: u64,
    alignment: Option<SpeechAlignment>,
}

/// What one generation queued to the client, submission by submission. The
/// host keeps it while the generation speaks and turns it into the
/// generation's [`HeardPlayback`] when the generation stops or drains.
#[derive(Debug, Clone)]
pub struct HeardLedger {
    session_ref: String,
    generation: GenerationEpoch,
    submissions: Vec<Submission>,
    /// Samples queued to the client so far.
    queued: u64,
}

impl HeardLedger {
    #[must_use]
    pub fn new(session_ref: impl Into<String>, generation: GenerationEpoch) -> Self {
        Self {
            session_ref: session_ref.into(),
            generation,
            submissions: Vec::new(),
            queued: 0,
        }
    }

    #[must_use]
    pub fn generation(&self) -> GenerationEpoch {
        self.generation
    }

    /// A sentence the TTS seam took: the generation's next submission.
    pub fn sentence(&mut self, text: String) {
        self.submissions.push(Submission { text, audio: None });
    }

    /// `submission`'s audio, queued to the client after all audio queued
    /// before it. An alignment that does not fit the text and the audio is
    /// dropped. A submission the ledger does not hold, or whose audio it
    /// already has, changes nothing.
    pub fn queued(
        &mut self,
        submission: u64,
        sample_rate: u32,
        samples: u64,
        alignment: Option<SpeechAlignment>,
    ) {
        let Some(entry) = usize::try_from(submission)
            .ok()
            .and_then(|at| self.submissions.get_mut(at))
            .filter(|entry| entry.audio.is_none())
        else {
            tracing::debug!(submission, "voice heard: audio for no waiting submission");
            return;
        };
        let alignment = alignment.filter(|alignment| {
            let fits = alignment.fits(&entry.text, samples);
            if !fits {
                tracing::warn!(submission, "voice heard: a speech alignment did not fit");
            }
            fits
        });
        entry.audio = Some(QueuedAudio {
            first_sample: self.queued,
            sample_rate,
            samples,
            alignment,
        });
        self.queued = self.queued.saturating_add(samples);
    }

    /// The generation's record. `played` is the client's count of samples
    /// it played; a count past what was queued counts as what was queued.
    /// Without one, the record counts what was queued, an upper bound.
    #[must_use]
    pub fn playback(self, played: Option<u64>) -> HeardPlayback {
        let (played, basis) = match played {
            Some(played) => (played.min(self.queued), HeardBasis::ClientReport),
            None => (self.queued, HeardBasis::SentUpperBound),
        };
        let utterances = (0_u64..)
            .zip(self.submissions)
            .map(|(submission, Submission { text, audio })| {
                let Some(audio) = audio else {
                    return HeardUtterance {
                        submission,
                        text,
                        sample_rate: 0,
                        samples: 0,
                        played_samples: 0,
                        coverage: HeardCoverage::Unplayed,
                        heard_text: None,
                    };
                };
                let played_samples = played.saturating_sub(audio.first_sample).min(audio.samples);
                let (coverage, heard_text) = if played_samples == 0 {
                    (HeardCoverage::Unplayed, None)
                } else if played_samples == audio.samples {
                    (HeardCoverage::Full, Some(text.clone()))
                } else {
                    let heard = audio
                        .alignment
                        .as_ref()
                        .map(|alignment| alignment.heard(&text, played_samples));
                    (HeardCoverage::Partial, heard)
                };
                HeardUtterance {
                    submission,
                    text,
                    sample_rate: audio.sample_rate,
                    samples: audio.samples,
                    played_samples,
                    coverage,
                    heard_text,
                }
            })
            .collect();
        HeardPlayback {
            session_ref: self.session_ref,
            generation: self.generation.value(),
            utterances,
            basis,
        }
    }
}
