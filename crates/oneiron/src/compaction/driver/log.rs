//! The driver's entries for a host that numbers its own log: an executor
//! run, whose watermark is its own step (agent-runtime-v1 §d7).

use super::*;

impl CompactionDriver {
    /// A host that numbers its own log supplies the snapshot point itself:
    /// an executor run's watermark is its own step, never the Dreamer's
    /// position, which no executor step moves.
    pub fn observe_positioned(
        &mut self,
        used_tokens: u64,
        watermark: CompactionWatermark,
    ) -> CompactionDirective {
        if used_tokens < self.compact_at() {
            return CompactionDirective::Quiet;
        }
        self.begin_positioned(watermark)
    }

    /// `self.compact`: the agent's own breakpoint. The same transition a
    /// crossing makes, at any size: one flight, a watermark that advances.
    pub fn begin_positioned(&mut self, watermark: CompactionWatermark) -> CompactionDirective {
        match self.state {
            CompactionState::Idle => {
                if watermark.turn.is_none()
                    || self
                        .completed_watermark
                        .is_some_and(|completed| !watermark.is_after(completed))
                {
                    return CompactionDirective::Quiet;
                }
                self.state = CompactionState::Compacting {
                    watermark,
                    request: None,
                };
                CompactionDirective::Begin { watermark }
            }
            _ => CompactionDirective::Quiet,
        }
    }

    /// [`Self::request_for`] for a host-numbered log (an executor run): the
    /// window stops at the recorded watermark's turn, `pins` occur verbatim
    /// in it, `sources` is the whole `DerivedFrom` set, refused above
    /// [`crate::compaction::EPOCH_SUMMARY_MAX_SOURCES`] rather than cut,
    /// `prior` is the host's last epoch and the last turn it covers, and
    /// `calls` is how many of the host's calls `sources` were read from.
    /// The host mints `request_id` from the store it reads: base, or its
    /// room's view.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn request_for_log(
        &mut self,
        request_id: EntityId,
        session_ref: &EntityId,
        window: Vec<CompactionWindowMessage>,
        pins: Vec<String>,
        sources: Vec<EntityId>,
        prior: Option<crate::compaction::PriorEpoch>,
        calls: u64,
        note: Option<String>,
    ) -> Result<CompactionRequest> {
        let CompactionState::Compacting { watermark, .. } = &self.state else {
            return Err(Error::InvariantViolation(
                "request_for is legal only while compacting",
            ));
        };
        let stop = watermark.turn.ok_or(Error::InvariantViolation(
            "a log request needs a positioned watermark",
        ))?;
        if window.last().is_some_and(|message| message.turn > stop) {
            return Err(Error::InvariantViolation(
                "compaction window runs past the watermark",
            ));
        }
        if pins.iter().any(|pin| {
            pin.trim().is_empty()
                || !window
                    .iter()
                    .any(|message| message.content.contains(pin.as_str()))
        }) {
            return Err(Error::InvariantViolation(
                "a verbatim pin does not occur in the window",
            ));
        }
        if sources.len() > crate::compaction::EPOCH_SUMMARY_MAX_SOURCES {
            return Err(Error::InvariantViolation(
                "compaction window names more sources than one summary may derive from",
            ));
        }
        // A window the host cut short of the watermark (a backend that takes
        // less) completes only through its last step, so the same position
        // crosses again for the rest.
        if let Some(last) = window.last().map(|message| message.turn)
            && last < stop
            && let CompactionState::Compacting { watermark, .. } = &mut self.state
        {
            watermark.turn = Some(last);
        }
        let mut seen = std::collections::BTreeSet::new();
        let sources = sources.into_iter().filter(|id| seen.insert(*id)).collect();
        self.seal_request_as(
            request_id,
            session_ref,
            window,
            pins,
            sources,
            prior,
            note,
            WindowLog::Host { prior, calls },
        )
    }

    /// The request for one fold of a host-numbered log (ARCH-0067 §2.2): an
    /// arbitrary span `window` covers, not the next epoch. It leaves the
    /// driver's state alone, since a fold mints no epoch and moves no
    /// watermark; the pass runs on the same backend and clears the same gate.
    /// `sources` is every record whose words could reach the span, sealed
    /// with it: what the landed summary derives from (Docs Q24). Unlike an
    /// epoch's, it is not capped, since a fold's sources are only ever its
    /// own dependency rows.
    #[expect(
        clippy::too_many_arguments,
        reason = "the sealed span, its pins and sources, the agent's note and the call count"
    )]
    pub(crate) fn fold_request(
        &self,
        request_id: EntityId,
        session_ref: &EntityId,
        window: Vec<CompactionWindowMessage>,
        pins: Vec<String>,
        sources: Vec<EntityId>,
        note: Option<String>,
        calls: u64,
    ) -> Result<CompactionRequest> {
        let (turn_start, last) = validate_window_span(&window)?;
        if pins.iter().any(|pin| {
            pin.trim().is_empty()
                || !window
                    .iter()
                    .any(|message| message.content.contains(pin.as_str()))
        }) {
            return Err(Error::InvariantViolation(
                "a verbatim pin does not occur in the window",
            ));
        }
        Ok(CompactionRequest {
            request_id,
            session_ref: *session_ref,
            summary_token_budget: self.summary_token_budget(),
            window,
            turn_start,
            watermark: CompactionWatermark {
                learned_at: 0,
                turn_id: None,
                turn: Some(last),
            },
            pins,
            sources: {
                let mut seen = std::collections::BTreeSet::new();
                sources.into_iter().filter(|id| seen.insert(*id)).collect()
            },
            note,
            log: WindowLog::Host { prior: None, calls },
        })
    }
}
