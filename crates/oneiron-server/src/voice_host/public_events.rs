//! Public event correlation and dequeue fencing, independent of transport.
use super::speech::{PlayoutGate, TurnSources, notice_rows};
use super::{PlayoutFrame, VoiceHost};
use oneiron::EntityId;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::task_verb::sdk::*;
use oneiron::voice_cascade::GenerationEpoch;
use std::collections::{BTreeMap, VecDeque};

pub(super) struct Epoch {
    pub(super) token: GenerationEpoch,
    pub(super) utterance_id: String,
    pub(super) end: Option<u64>,
    pub(super) stop: Option<u64>,
    pub(super) ack: bool,
    pub(super) media_cancelled: bool,
    pub(super) finished: bool,
}

pub(super) struct Journal {
    pub(super) session_ref: String,
    pub(super) cursor: u64,
    pub(super) ended: bool,
    pub(super) epochs: BTreeMap<u64, Epoch>,
    pub(super) context_sources: Vec<String>,
    events: VecDeque<(LiveVoiceEvent, Option<PlayoutGate>)>,
    floor: u64,
    /// The rows each generation was made from, by generation, as its brain
    /// handed them over before speech consumed its first event (FIX 4778).
    sources: BTreeMap<u64, TurnSources>,
}

/// A page of events beside the rows they were made from.
pub(crate) type ListedPage = (LiveVoiceEvents, Vec<EntityId>);

impl Journal {
    pub(super) fn new(session_ref: String) -> Self {
        Self {
            session_ref,
            cursor: 0,
            ended: false,
            epochs: BTreeMap::new(),
            context_sources: Vec::new(),
            events: VecDeque::new(),
            floor: 0,
            sources: BTreeMap::new(),
        }
    }

    /// Keeps the rows `generation` was made from for the events it serves.
    pub(super) fn record_sources(&mut self, generation: GenerationEpoch, sources: TurnSources) {
        self.sources.insert(generation.value(), sources);
    }

    /// The rows one served event was made from (FIX 4778). Its audio, and
    /// each safeguard verdict and notice on what it said, come from its
    /// generation's model input (a notice also from the policy row it
    /// names); its memories receipt counts the rows the read found. Every
    /// other event is control only: the cursor, epoch, playout, tool
    /// source label, error and end events list none. A generation's brain
    /// hands its rows over with its first event, before anything it says
    /// is spoken or judged, so a generation with none kept served nothing
    /// made from its input: its events list none (FIX 6080).
    fn event_rows(&self, event: &LiveVoiceEvent) -> Vec<EntityId> {
        let sources = event
            .generation
            .and_then(|generation| self.sources.get(&generation));
        match &event.event {
            LiveVoiceEventKind::Pcm { .. } | LiveVoiceEventKind::Safeguard { .. } => sources
                .map(|sources| sources.said.clone())
                .unwrap_or_default(),
            LiveVoiceEventKind::Notice { notice } => {
                let mut rows = sources
                    .map(|sources| sources.said.clone())
                    .unwrap_or_default();
                rows.extend(notice_rows(notice));
                rows
            }
            LiveVoiceEventKind::Memories { .. } => sources
                .map(|sources| sources.found.clone())
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    pub(super) fn processed(&self) -> LiveVoiceProcessed {
        LiveVoiceProcessed {
            session_ref: self.session_ref.clone(),
            cursor: self.cursor,
            ended: self.ended,
        }
    }

    pub(super) fn push(
        &mut self,
        generation: Option<GenerationEpoch>,
        event: LiveVoiceEventKind,
    ) -> u64 {
        self.cursor += 1;
        let utterance_id =
            generation.and_then(|g| self.epochs.get(&g.value()).map(|e| e.utterance_id.clone()));
        self.events.push_back((
            LiveVoiceEvent {
                sequence: self.cursor,
                utterance_id,
                generation: generation.map(GenerationEpoch::value),
                event,
            },
            None,
        ));
        self.cursor
    }

    pub(super) fn start(&mut self, token: GenerationEpoch, utterance_id: String) {
        self.epochs.insert(
            token.value(),
            Epoch {
                token,
                utterance_id,
                end: None,
                stop: None,
                ack: false,
                media_cancelled: false,
                finished: false,
            },
        );
        self.push(
            Some(token),
            LiveVoiceEventKind::GenerationStarted {
                run: format!("voice:{}:{}", self.session_ref, token.value()),
                context_sources: self.context_sources.clone(),
            },
        );
    }

    pub(super) fn pcm(&mut self, frame: PlayoutFrame) {
        if !frame.is_current() {
            return;
        }
        // Keep the gate with each stored packet. Polling can never resurrect
        // PCM queued before a stop, even if its cursor predates the flush.
        let generation = frame.generation();
        let Some((pcm, gate)) = frame.public_parts() else {
            return;
        };
        for data in super::wire::pcm_chunks(pcm) {
            self.push(
                Some(generation),
                LiveVoiceEventKind::Pcm {
                    sample_rate: pcm.sample_rate,
                    pcm_base64: data,
                },
            );
            if let Some((_, guard)) = self.events.back_mut() {
                *guard = Some(gate.clone());
            }
        }
    }

    pub(super) fn end_playout(&mut self, token: GenerationEpoch) {
        let seq = self.push(Some(token), LiveVoiceEventKind::PlayoutEnd);
        if let Some(epoch) = self.epochs.get_mut(&token.value()) {
            epoch.end = Some(seq);
        }
    }

    pub(super) fn stopped(&mut self, token: GenerationEpoch, reason: LiveVoiceStopReason) {
        if self
            .epochs
            .get(&token.value())
            .is_some_and(|epoch| epoch.stop.is_some())
        {
            return;
        }
        let seq = self.push(Some(token), LiveVoiceEventKind::PlayoutStop { reason });
        if let Some(epoch) = self.epochs.get_mut(&token.value()) {
            epoch.stop = Some(seq);
            epoch.ack = false;
        }
    }

    pub(super) fn ack(&mut self, input: &LiveVoiceAckRequest) -> MemoryResult<GenerationEpoch> {
        let epoch = self
            .epochs
            .get_mut(&input.generation)
            .ok_or_else(|| MemoryError::bad_request("unknown generation"))?;
        let expected = match input.kind {
            LiveVoiceAckKind::Drained if epoch.stop.is_none() => epoch.end,
            LiveVoiceAckKind::Stopped => epoch.stop,
            _ => None,
        };
        if expected != Some(input.event_sequence) {
            return Err(MemoryError::bad_request(
                "ACK must name this epoch's emitted playout boundary",
            ));
        }
        epoch.ack = true;
        Ok(epoch.token)
    }

    pub(super) fn finished(&mut self, host: &VoiceHost) {
        let tokens: Vec<_> = self
            .epochs
            .values()
            .filter(|epoch| !epoch.finished)
            .map(|epoch| epoch.token)
            .collect();
        for token in tokens {
            let finished = host
                .lock()
                .is_ok_and(|state| state.core.brain_context(token).is_none());
            if finished {
                if let Some(epoch) = self.epochs.get_mut(&token.value()) {
                    epoch.finished = true;
                }
                self.push(Some(token), LiveVoiceEventKind::Finished);
            }
        }
    }

    /// The page, beside the rows its served events were made from: their
    /// union (FIX 4778). An event the page skips as a stale epoch's lists
    /// nothing.
    pub(super) fn page(&mut self, input: LiveVoiceEventsRequest) -> MemoryResult<ListedPage> {
        if input.after < self.floor || input.after > self.cursor || input.limit == Some(0) {
            return Err(MemoryError::bad_request(
                "invalid or released voice event cursor",
            ));
        }
        // `after` acknowledges consumption and releases earlier packet storage.
        self.floor = input.after;
        while self
            .events
            .front()
            .is_some_and(|(event, _)| event.sequence <= input.after)
        {
            self.events.pop_front();
        }
        let limit = input.limit.unwrap_or(64);
        let mut events = Vec::new();
        let mut rows = Vec::new();
        let mut cursor = input.after;
        for (event, guard) in &self.events {
            cursor = event.sequence;
            if guard.as_ref().is_none_or(PlayoutGate::is_current) {
                rows.extend(self.event_rows(event));
                events.push(event.clone());
            }
            if events.len() >= limit {
                break;
            }
        }
        let page = LiveVoiceEvents {
            session_ref: self.session_ref.clone(),
            cursor,
            ended: self.ended,
            events,
        };
        Ok((page, rows))
    }
}
