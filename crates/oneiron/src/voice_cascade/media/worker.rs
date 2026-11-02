//! Voice media queue and its worker.
//! Entry: VoiceMediaSender.
//! Definitions: types stay in the parent; this module owns the listed impls.

use super::{
    AiMediaDoor, BankVoiceBinding, GenerationEpoch, Instant, LlmResult, MediaFuture, MediaPart,
    MediaRequest, MediaVoiceRoute, Ordering, PcmFrame, Poll, Result, Vault, VoiceMediaOutput,
    VoiceMediaQueue, VoiceMediaSender, VoiceMediaWork, VoiceMediaWorker, asr_error, heard, invalid,
    speech_pieces, spoken_frame,
};

impl VoiceMediaSender {
    /// Whether the queue holds less than its pace now. A producer may wait
    /// for room; the queue takes work either way.
    #[must_use]
    pub fn has_room(&self) -> bool {
        self.queued.load(Ordering::Acquire) < self.capacity
    }
}

impl VoiceMediaQueue for VoiceMediaSender {
    fn try_submit(&mut self, work: VoiceMediaWork) -> Result<()> {
        if let VoiceMediaWork::Cancel { generation } = work {
            return self
                .stop
                .send(generation)
                .map_err(|_| invalid("media worker stopped"));
        }
        self.queued.fetch_add(1, Ordering::AcqRel);
        self.work.send(work).map_err(|_| {
            self.queued.fetch_sub(1, Ordering::AcqRel);
            invalid("media worker stopped")
        })
    }
}

impl VoiceMediaWorker {
    /// Runs every queued call until all senders are dropped. A cancel drops
    /// its generation's queued speech and the call in flight (which still
    /// pays for what it sent). A banked voice withdrawn before a call goes,
    /// or before its audio comes back, is not spoken.
    pub async fn run(
        mut self,
        door: &dyn AiMediaDoor,
        vault: &Vault,
        mut deliver: impl FnMut(VoiceMediaOutput),
    ) {
        loop {
            self.drain();
            for generation in self.retired.drain(..) {
                deliver(VoiceMediaOutput::Cancelled { generation });
            }
            let work = match self.pending.pop_front() {
                Some(work) => work,
                None => match self.next().await {
                    Some(work) => {
                        self.take(work);
                        continue;
                    }
                    None => return,
                },
            };
            match work {
                VoiceMediaWork::Cancel { .. } => {}
                VoiceMediaWork::Speech {
                    generation,
                    submission,
                    request,
                    voice,
                    fallbacks,
                } => {
                    let Some(spoken) = self
                        .speak(door, vault, generation, request, voice.as_ref(), &fallbacks)
                        .await
                    else {
                        continue;
                    };
                    deliver(match spoken {
                        Ok(frame) => VoiceMediaOutput::Pcm { submission, frame },
                        Err(error) => VoiceMediaOutput::SpeechFailed {
                            generation,
                            submission,
                            error,
                        },
                    });
                }
                VoiceMediaWork::Transcribe {
                    submission,
                    request,
                } => {
                    let started = Instant::now();
                    let Some(answer) = self.call(door.call(request), None).await else {
                        continue;
                    };
                    let latency = started.elapsed().as_secs_f64() * 1_000.0;
                    let event = match answer {
                        Ok(response) => heard(&response, latency),
                        Err(error) => asr_error(error.to_string()),
                    };
                    deliver(VoiceMediaOutput::Heard { submission, event });
                }
            }
        }
    }

    /// Speaks one queued sentence: one call per piece within
    /// [`MAX_SENTENCE_BYTES`](super::MAX_SENTENCE_BYTES), in order, their audio joined into one frame.
    /// A banked voice withdrawn before a piece goes, or before its audio
    /// comes back, ends the sentence unspoken. A piece whose rung's
    /// provider is down is spoken by the next bound target holding the
    /// voice instead (FIX 3195), and the target that answered is tried
    /// first for the next piece. `None` when the generation was cancelled
    /// first.
    async fn speak(
        &mut self,
        door: &dyn AiMediaDoor,
        vault: &Vault,
        generation: GenerationEpoch,
        request: MediaRequest,
        voice: Option<&BankVoiceBinding>,
        fallbacks: &[(MediaVoiceRoute, BankVoiceBinding)],
    ) -> Option<std::result::Result<PcmFrame, String>> {
        // Candidate 0 is the piece as submitted, in its own voice;
        // candidate k past it is `fallbacks[k - 1]`, the piece rebuilt on
        // that target in its binding's voice.
        let candidates = fallbacks.len() + 1;
        let mut start = 0;
        let mut spoken: Option<PcmFrame> = None;
        for piece in speech_pieces(request) {
            let mut first_error: Option<String> = None;
            let mut called = false;
            let mut answered = false;
            for step in 0..candidates {
                let index = (start + step) % candidates;
                let (call, binding) = if index == 0 {
                    (piece.clone(), voice)
                } else {
                    let (route, binding) = &fallbacks[index - 1];
                    // Only a lone text part can be rebuilt on another
                    // target; anything else a fallback cannot speak.
                    let [MediaPart::Text { text }] = piece.parts.as_slice() else {
                        continue;
                    };
                    (
                        route.request(
                            MediaPart::Text { text: text.clone() },
                            Some(binding.voice()),
                        ),
                        Some(binding),
                    )
                };
                if binding.is_some_and(|binding| !binding.is_current(vault)) {
                    continue;
                }
                called = true;
                let response = match self.call(door.call(call), Some(generation)).await? {
                    Ok(response) => response,
                    Err(error) if error.is_provider_unavailable() => {
                        first_error.get_or_insert_with(|| error.to_string());
                        continue;
                    }
                    Err(error) => return Some(Err(error.to_string())),
                };
                if binding.is_some_and(|binding| !binding.is_current(vault)) {
                    return Some(Err("voice withdrawn, evicted or stale".into()));
                }
                let frame = match spoken_frame(generation, &response) {
                    Ok(frame) => frame,
                    Err(error) => return Some(Err(error.to_string())),
                };
                spoken = Some(match spoken.take() {
                    None => frame,
                    Some(mut joined) if joined.sample_rate == frame.sample_rate => {
                        joined.samples.extend(frame.samples);
                        joined
                    }
                    Some(_) => {
                        return Some(Err("speech pieces came back at different rates".into()));
                    }
                });
                start = index;
                answered = true;
                break;
            }
            if !answered {
                return Some(Err(match first_error {
                    // Every target that was called says its provider is
                    // down: the first call's error is the sentence's.
                    Some(error) if called => error,
                    _ => "voice withdrawn, evicted or stale".into(),
                }));
            }
        }
        Some(spoken.ok_or_else(|| "speech has no words to say".to_owned()))
    }

    /// Takes what is already queued, stops first, without waiting.
    fn drain(&mut self) {
        while let Ok(generation) = self.stops.try_recv() {
            self.take(VoiceMediaWork::Cancel { generation });
        }
        while let Ok(work) = self.work.try_recv() {
            self.queued.fetch_sub(1, Ordering::AcqRel);
            self.take(work);
        }
    }

    /// Waits for the next item, a stop before queued work; `None` once every
    /// sender is gone.
    async fn next(&mut self) -> Option<VoiceMediaWork> {
        std::future::poll_fn(|cx| {
            if let Poll::Ready(Some(generation)) = self.stops.poll_recv(cx) {
                return Poll::Ready(Some(VoiceMediaWork::Cancel { generation }));
            }
            let polled = self.work.poll_recv(cx);
            if let Poll::Ready(Some(_)) = &polled {
                self.queued.fetch_sub(1, Ordering::AcqRel);
            }
            polled
        })
        .await
    }

    /// A cancel drops the generation's queued speech at once; anything else
    /// waits its turn.
    fn take(&mut self, work: VoiceMediaWork) {
        if let VoiceMediaWork::Cancel { generation } = work {
            if self.cancelled.insert(generation) {
                self.retired.push(generation);
            }
            self.pending.retain(|queued| {
                !matches!(queued, VoiceMediaWork::Speech { generation: of, .. } if *of == generation)
            });
            return;
        }
        if let VoiceMediaWork::Speech { generation, .. } = &work
            && self.cancelled.contains(generation)
        {
            return;
        }
        self.pending.push_back(work);
    }

    /// Runs one call while taking what arrives meanwhile; `None` when
    /// `generation` was cancelled before it answered.
    async fn call<T>(
        &mut self,
        mut call: MediaFuture<'_, T>,
        generation: Option<GenerationEpoch>,
    ) -> Option<LlmResult<T>> {
        let mut open = true;
        std::future::poll_fn(|cx| {
            while let Poll::Ready(Some(generation)) = self.stops.poll_recv(cx) {
                self.take(VoiceMediaWork::Cancel { generation });
            }
            while open {
                match self.work.poll_recv(cx) {
                    Poll::Ready(Some(work)) => {
                        self.queued.fetch_sub(1, Ordering::AcqRel);
                        self.take(work);
                    }
                    Poll::Ready(None) => open = false,
                    Poll::Pending => break,
                }
            }
            if generation.is_some_and(|generation| self.cancelled.contains(&generation)) {
                return Poll::Ready(None);
            }
            call.as_mut().poll(cx).map(Some)
        })
        .await
    }
}
