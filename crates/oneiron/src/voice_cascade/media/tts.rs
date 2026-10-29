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
        fallbacks: Vec<MediaVoiceRoute>,
        render: VoiceRender,
        queue: Q,
    ) -> Result<Self> {
        if route.operation() != AiOperation::Speech
            || fallbacks
                .iter()
                .any(|route| route.operation() != AiOperation::Speech)
        {
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
            fallbacks,
            render,
            queue,
            binding: None,
            bound: Vec::new(),
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
        // The first bound target whose voice is still current speaks; the
        // rest ride along for the worker to try when a provider is down.
        let (route, voice, binding, fallbacks) = match &self.render {
            VoiceRender::Stock(name) => (
                &self.route,
                Some(MediaVoice::Stock { name: name.clone() }),
                None,
                Vec::new(),
            ),
            VoiceRender::Bank { .. } => {
                let Some(chosen) = self
                    .bound
                    .iter()
                    .position(|(_, binding)| binding.is_current(&self.vault))
                else {
                    self.revoke(generation);
                    return Err(invalid("voice withdrawn, evicted or stale"));
                };
                let (route, binding) = &self.bound[chosen];
                let mut rest = self.bound.clone();
                rest.remove(chosen);
                (route, Some(binding.voice()), Some(binding.clone()), rest)
            }
        };
        let next = self
            .next_submission
            .checked_add(1)
            .ok_or_else(|| invalid("submission exhausted"))?;
        let request = route.request(
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
            voice: binding,
            fallbacks,
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
            // Every target that holds it binds, the lane's route first; a
            // fallback that does not bind is simply not a candidate, and
            // none binding refuses with the lane route's own refusal.
            if matches!(self.render, VoiceRender::Bank { .. }) {
                let mut refusal = None;
                for route in std::iter::once(&self.route).chain(&self.fallbacks) {
                    match bind_on(&self.vault, &self.render, route) {
                        Ok(binding) => self.bound.push((route.clone(), binding)),
                        Err(error) => {
                            refusal.get_or_insert(error);
                        }
                    }
                }
                match self.bound.first() {
                    Some((_, binding)) => self.binding = Some(binding.clone()),
                    None => return Err(refusal.expect("the lane route is always tried")),
                }
            }
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

/// Binds the banked `render` voice on `route`'s target: from its source
/// clip on a target that renders from refs, as its recorded clone on one
/// that keeps clones.
fn bind_on(
    vault: &Vault,
    render: &VoiceRender,
    route: &MediaVoiceRoute,
) -> Result<BankVoiceBinding> {
    match render {
        VoiceRender::Bank {
            voice_id, register, ..
        } if route.reference_target => BankVoiceBinding::bind_reference(
            vault,
            voice_id,
            &route.target,
            register.as_deref(),
            route.locality,
        ),
        VoiceRender::Bank {
            voice_id,
            include_generated,
            ..
        } => BankVoiceBinding::bind(
            vault,
            voice_id,
            &route.target,
            *include_generated,
            route.locality,
        ),
        VoiceRender::Stock(_) => Err(invalid("a stock voice binds nothing")),
    }
}
