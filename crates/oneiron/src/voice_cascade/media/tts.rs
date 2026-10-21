//! Voice media TTS adapter.
//! Entry: MediaTtsAdapter.
//! Definitions: types stay in the parent; this module owns the listed impls.

use super::{
    AiOperation, Arc, BankVoiceBinding, GenerationEpoch, MediaPart, MediaTtsAdapter, MediaVoice,
    MediaVoiceRoute, Phase, Result, TtsCommand, TtsSeamClient, Vault, VoiceMediaQueue,
    VoiceMediaWork, VoiceRender, invalid,
};

impl<Q: VoiceMediaQueue> MediaTtsAdapter<Q> {
    pub fn new(
        vault: Arc<Vault>,
        route: MediaVoiceRoute,
        render: VoiceRender,
        queue: Q,
    ) -> Result<Self> {
        if route.operation() != AiOperation::Speech {
            return Err(invalid("a TTS adapter speaks on a speech route"));
        }
        if let VoiceRender::Stock(name) = &render
            && name.trim().is_empty()
        {
            return Err(invalid("a stock voice has a name"));
        }
        Ok(Self {
            vault,
            route,
            render,
            queue,
            binding: None,
            generation: None,
            phase: Phase::Fresh,
            buffer: String::new(),
            next_submission: 0,
        })
    }

    /// The banked clone this generation renders as, once started.
    #[must_use]
    pub fn binding(&self) -> Option<&BankVoiceBinding> {
        self.binding.as_ref()
    }

    /// Closes output for good; the queued and in-flight speech is dropped
    /// when the cancel goes. A failed cancel stays retryable.
    fn revoke(&mut self, generation: GenerationEpoch) {
        self.phase = Phase::CancelPending;
        self.buffer.clear();
        if self
            .queue
            .try_submit(VoiceMediaWork::Cancel { generation })
            .is_ok()
        {
            self.phase = Phase::Cancelled;
        }
    }

    fn flush(&mut self, generation: GenerationEpoch) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        if let Some(binding) = &self.binding
            && !binding.is_current(&self.vault)
        {
            self.revoke(generation);
            return Err(invalid("voice withdrawn, evicted or stale"));
        }
        let next = self
            .next_submission
            .checked_add(1)
            .ok_or_else(|| invalid("submission exhausted"))?;
        let voice = match &self.render {
            VoiceRender::Stock(name) => Some(MediaVoice::Stock { name: name.clone() }),
            VoiceRender::Bank { .. } => self.binding.as_ref().map(BankVoiceBinding::voice),
        };
        let request = self.route.request(
            MediaPart::Text {
                text: self.buffer.clone(),
            },
            voice,
        );
        // A queue refusal admits nothing and keeps the sentence for retry.
        self.queue.try_submit(VoiceMediaWork::Speech {
            generation,
            submission: self.next_submission,
            request,
            voice: self.binding.clone(),
        })?;
        self.next_submission = next;
        self.buffer.clear();
        Ok(())
    }
}

impl<Q: VoiceMediaQueue> TtsSeamClient for MediaTtsAdapter<Q> {
    fn submit(&mut self, command: TtsCommand) -> Result<()> {
        let generation = match &command {
            TtsCommand::Start { generation }
            | TtsCommand::Text { generation, .. }
            | TtsCommand::Flush { generation }
            | TtsCommand::End { generation }
            | TtsCommand::Cancel { generation } => *generation,
        };
        if matches!(command, TtsCommand::Start { .. }) {
            if self.phase != Phase::Fresh {
                return Err(invalid("adapter is single-generation"));
            }
            // A banked voice binds before any word: no clone, no speech.
            self.binding = match &self.render {
                VoiceRender::Stock(_) => None,
                VoiceRender::Bank {
                    voice_id, register, ..
                } if self.route.reference_target => Some(BankVoiceBinding::bind_reference(
                    &self.vault,
                    voice_id,
                    &self.route.target,
                    register.as_deref(),
                    self.route.locality,
                )?),
                VoiceRender::Bank {
                    voice_id,
                    include_generated,
                    ..
                } => Some(BankVoiceBinding::bind(
                    &self.vault,
                    voice_id,
                    &self.route.target,
                    *include_generated,
                    self.route.locality,
                )?),
            };
            self.generation = Some(generation);
            self.phase = Phase::Open;
            return Ok(());
        }
        if matches!(command, TtsCommand::Cancel { .. }) {
            if self.phase == Phase::Fresh {
                self.generation = Some(generation);
            }
            if self.generation != Some(generation) {
                return Err(invalid("unmatched generation"));
            }
            if self.phase != Phase::Cancelled {
                self.phase = Phase::CancelPending; // fail closed even if dispatch fails
                self.buffer.clear();
                self.queue
                    .try_submit(VoiceMediaWork::Cancel { generation })?;
                self.phase = Phase::Cancelled;
            }
            return Ok(());
        }
        if self.generation != Some(generation) {
            return Err(invalid("unmatched generation"));
        }
        if self.phase == Phase::Ended
            && matches!(command, TtsCommand::End { .. } | TtsCommand::Flush { .. })
        {
            return Ok(());
        }
        if self.phase != Phase::Open {
            return Err(invalid("input closed"));
        }
        match command {
            TtsCommand::Text { text, .. } => {
                // A long sentence is split into calls at flush, never refused.
                if text.is_empty() {
                    return Err(invalid("empty text"));
                }
                self.buffer.push_str(&text);
            }
            TtsCommand::Flush { .. } => self.flush(generation)?,
            TtsCommand::End { .. } => {
                self.flush(generation)?;
                self.phase = Phase::Ended;
            }
            TtsCommand::Start { .. } | TtsCommand::Cancel { .. } => {
                unreachable!("Start and Cancel handled above")
            }
        }
        Ok(())
    }
}
