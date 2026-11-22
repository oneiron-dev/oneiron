//! Queue admission, generation checks and PCM handling for `Adapter`.
//! Submission splitting, boundary release and response validation live here.

use super::*;

impl<Q: TransportQueue> Adapter<Q> {
    pub(super) fn new(provider: Provider, config: ProviderConfig, queue: Q) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            queue,
            metadata: ProviderMetadata {
                provider,
                model: provider.model(),
                pins: config.pins,
                sample_rate: config.sample_rate,
                streaming: config.streaming,
            },
            voice: config.voice,
            generation: None,
            phase: Phase::Fresh,
            sequence: 0,
            chunk_index: 0,
            text_bytes: 0,
            buffer: String::new(),
            dirty: false,
            pending: VecDeque::new(),
            held: VecDeque::new(),
            end_owed: false,
            pending_text: None,
        })
    }

    fn buffered(&self) -> bool {
        self.metadata.streaming == StreamingCapability::RequestBuffered
    }

    fn matched(&self, generation: GenerationEpoch) -> Result<()> {
        if self.generation != Some(generation) {
            return Err(invalid("unmatched generation"));
        }
        Ok(())
    }

    pub(super) fn send(
        &mut self,
        generation: GenerationEpoch,
        operation: ProviderOperation,
    ) -> Result<()> {
        let next = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("sequence exhausted"))?;
        self.queue.try_submit(ProviderWork {
            provider: self.metadata.provider,
            generation,
            sequence: self.sequence,
            operation,
        })?;
        self.sequence = next;
        Ok(())
    }

    pub(super) fn submit(&mut self, command: TtsCommand) -> Result<()> {
        let generation = match &command {
            TtsCommand::Start { generation }
            | TtsCommand::Text { generation, .. }
            | TtsCommand::Flush { generation }
            | TtsCommand::End { generation }
            | TtsCommand::Cancel { generation } => *generation,
        };
        if matches!(&command, TtsCommand::Start { .. }) {
            if self.phase != Phase::Fresh {
                return Err(invalid(
                    "adapter is single-generation; Start already consumed",
                ));
            }
            self.send(
                generation,
                ProviderOperation::Start {
                    metadata: self.metadata.clone(),
                    voice: Box::new(self.voice.clone()),
                },
            )?;
            self.generation = Some(generation);
            self.phase = Phase::Open;
            return Ok(());
        }
        if matches!(&command, TtsCommand::Cancel { .. }) {
            if self.phase == Phase::Fresh {
                self.generation = Some(generation);
            }
            self.matched(generation)?;
            if self.phase != Phase::Cancelled {
                // Fail closed BEFORE admission. Failure permits only a Cancel retry.
                self.phase = Phase::CancelPending;
                self.buffer.clear();
                self.pending.clear();
                self.held.clear();
                self.end_owed = false;
                self.pending_text = None;
                self.dirty = false;
                self.send(generation, ProviderOperation::Cancel)?;
                self.phase = Phase::Cancelled;
            }
            return Ok(());
        }
        self.matched(generation)?;
        if matches!(&command, TtsCommand::Flush { .. } | TtsCommand::End { .. }) {
            match self.phase {
                Phase::Done => return Ok(()),
                // Closed input forbids new text, never the release of held
                // text or an owed End: a retry sends them (FIX 10212).
                Phase::Ended => return self.release(generation),
                _ => {}
            }
        }
        if self.phase != Phase::Open {
            return Err(invalid("input is not open"));
        }
        match command {
            TtsCommand::Text { text, .. } => {
                if text.is_empty() {
                    return Err(invalid("empty text"));
                }
                if self.buffered() {
                    self.text_bytes = self.text_bytes.saturating_add(text.len());
                    self.buffer.push_str(&text);
                    self.dirty = true;
                } else {
                    self.submit_text(generation, text)?;
                }
            }
            TtsCommand::Flush { .. } => self.boundary(generation, false)?,
            TtsCommand::End { .. } => self.boundary(generation, true)?,
            _ => unreachable!("Start and Cancel handled above"),
        }
        Ok(())
    }

    fn boundary(&mut self, generation: GenerationEpoch, end: bool) -> Result<()> {
        // An idle Flush is a no-op only with nothing held, owed or unsent
        // (FIX 10212).
        if !end
            && !self.dirty
            && self.held.is_empty()
            && !self.end_owed
            && self.pending_text.is_none()
        {
            return Ok(());
        }
        if !self.buffered() {
            self.resume_text(generation)?;
            let operation = if end {
                ProviderOperation::End {
                    buffered_text: None,
                }
            } else {
                ProviderOperation::Flush {
                    buffered_text: None,
                }
            };
            self.send(generation, operation)?;
            self.dirty = false;
            if end {
                self.phase = Phase::Ended;
            }
            return Ok(());
        }
        if !self.buffer.is_empty() {
            let pieces = speakable_pieces(&self.buffer, MAX_TEXT_BYTES);
            self.held.extend(pieces.into_iter().map(str::to_owned));
            self.buffer.clear();
        }
        self.dirty = false;
        if end {
            self.end_owed = true;
            self.phase = Phase::Ended;
        }
        self.release(generation)
    }

    /// Sends held pieces, each a buffered response, while fewer than
    /// `MAX_PENDING_RESPONSES` await their audio; the rest wait for it to
    /// drain. End goes with the last piece, or alone once none is held. A
    /// refused send keeps its piece held for the next boundary or response.
    fn release(&mut self, generation: GenerationEpoch) -> Result<()> {
        while self.pending.len() < MAX_PENDING_RESPONSES
            && let Some(text) = self.held.front()
        {
            let buffered_text = Some(text.clone());
            let ends = self.end_owed && self.held.len() == 1;
            let operation = if ends {
                ProviderOperation::End { buffered_text }
            } else {
                ProviderOperation::Flush { buffered_text }
            };
            let sequence = self.sequence;
            self.send(generation, operation)?;
            self.held.pop_front();
            self.pending.push_back(sequence);
            if ends {
                self.end_owed = false;
            }
        }
        if self.end_owed && self.held.is_empty() {
            self.send(
                generation,
                ProviderOperation::End {
                    buffered_text: None,
                },
            )?;
            self.end_owed = false;
        }
        Ok(())
    }

    pub(super) fn handle_pcm(&mut self, audio: ProviderAudio<'_>) -> Result<NormalizedPcm> {
        self.matched(audio.generation)?;
        if !matches!(self.phase, Phase::Open | Phase::Ended) || self.text_bytes == 0 {
            return Err(invalid("output is not open"));
        }
        if audio.chunk_index != self.chunk_index {
            return Err(invalid("duplicate or out-of-order PCM"));
        }
        match (&self.metadata.streaming, audio.delivery) {
            (
                StreamingCapability::RequestBuffered,
                AudioDelivery::BufferedResponse { submission },
            ) if self.pending.front() == Some(&submission) => {}
            (StreamingCapability::Incremental { .. }, AudioDelivery::IncrementalChunk) => {}
            _ => {
                return Err(invalid(
                    "unmatched response or unnegotiated streaming claim",
                ));
            }
        }
        if audio.sample_rate != self.metadata.sample_rate
            || audio.channels != 1
            || audio.encoding != AudioEncoding::Pcm16Le
            || audio.bytes.is_empty()
            || !audio.bytes.len().is_multiple_of(2)
        {
            return Err(invalid("expected mono PCM16LE at the configured rate"));
        }
        let next = self
            .chunk_index
            .checked_add(1)
            .ok_or_else(|| invalid("PCM sequence exhausted"))?;
        let samples = audio
            .bytes
            .chunks_exact(2)
            .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        self.chunk_index = next;
        if self.buffered() {
            self.pending.pop_front();
            // A held piece takes the room this one left. A refused send
            // stays held; the queue reports its own failure on the next try.
            let _ = self.release(audio.generation);
        }
        Ok(NormalizedPcm {
            frame: PcmFrame {
                generation: audio.generation,
                sample_rate: audio.sample_rate,
                samples,
            },
            origin: ProviderOrigin {
                metadata: self.metadata.clone(),
                delivery: audio.delivery,
                chunk_index: audio.chunk_index,
            },
        })
    }

    pub(super) fn handle_done(&mut self, generation: GenerationEpoch) -> Result<()> {
        self.matched(generation)?;
        if self.phase == Phase::Done {
            return Ok(());
        }
        if self.phase != Phase::Ended
            || !self.pending.is_empty()
            || !self.held.is_empty()
            || self.end_owed
        {
            return Err(invalid(
                "done before End/responses, or after cancellation/failure",
            ));
        }
        self.phase = Phase::Done;
        Ok(())
    }

    pub(super) fn handle_error(
        &mut self,
        generation: GenerationEpoch,
        failure: ProviderFailure,
    ) -> Result<ProviderFailure> {
        self.matched(generation)?;
        if !matches!(self.phase, Phase::Open | Phase::Ended) {
            return Err(invalid("error for inactive request"));
        }
        self.phase = Phase::Failed;
        self.buffer.clear();
        self.pending.clear();
        self.held.clear();
        self.end_owed = false;
        self.pending_text = None;
        self.dirty = false;
        Ok(failure)
    }
}
