//! Exact, single-use handoff across host async enrichment. No provider work here.

use super::*;
use crate::voice_cascade::PartialEnrichment;

/// Opaque session-minted input for one enrichment attempt. Not cloneable or
/// deserializable. Dropping it performs no retrieval and consumes no revision.
/// Hosts must cancel it on task cancellation; a later prepare supersedes it.
#[derive(Debug, PartialEq)]
pub struct PreparedAsr {
    session: uuid::Uuid,
    serial: u64,
    epoch: u64,
    generation: Option<GenerationEpoch>,
    handle: UtteranceHandle,
    revision: u64,
    event: AsrEvent,
    externally_tainted: bool,
}

impl PreparedAsr {
    /// Exact bytes to send to the host's extraction backend. Never normalize.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.event.text
    }

    fn snapshot(&self) -> Self {
        Self {
            session: self.session,
            serial: self.serial,
            epoch: self.epoch,
            generation: self.generation,
            handle: self.handle.clone(),
            revision: self.revision,
            event: self.event.clone(),
            externally_tainted: self.externally_tainted,
        }
    }
}

impl VoiceCascadeSession {
    /// Validate and reserve an exact observation without enrichment, retrieval,
    /// identity resolution or revision consumption. Only partial/final use this
    /// seam. A newer revision supersedes pending work BEFORE its provider awaits.
    /// Same-revision retries must carry identical event bytes and host taint.
    pub fn prepare_asr(
        &mut self,
        handle: &UtteranceHandle,
        revision: u64,
        event: AsrEvent,
        externally_tainted: bool,
    ) -> Result<Option<PreparedAsr>> {
        if self.ended || !self.retrieval.is_open(handle) {
            return Ok(None);
        }
        if event.text.len() > 8 * 1024
            || event.tokens.len() > 256
            || event
                .tokens
                .iter()
                .fold(0usize, |size, token| size.saturating_add(token.text.len()))
                > 8 * 1024
            || event.error.as_ref().is_some_and(|error| error.len() > 1024)
        {
            return Err(invalid("ASR preparation exceeds limits"));
        }
        event.validate()?;
        if !matches!(event.kind, AsrEventKind::Partial | AsrEventKind::Final) {
            return Err(invalid("only partial/final ASR may be prepared"));
        }
        self.retrieval.check_revision(handle, revision)?;
        self.check_prepared_revision(handle, revision, &event, externally_tainted)?;
        if event.kind == AsrEventKind::Final {
            if self.generation.is_some() {
                return Err(invalid(
                    "finish or interrupt the previous generation before final",
                ));
            }
            self.epoch
                .checked_add(1)
                .ok_or_else(|| invalid("generation epoch exhausted"))?;
        }
        let serial = self
            .preparation_serial
            .checked_add(1)
            .ok_or_else(|| invalid("ASR preparation serial exhausted"))?;
        let prepared = PreparedAsr {
            session: self.id,
            serial,
            epoch: self.epoch,
            generation: self
                .generation
                .as_ref()
                .map(|active| active.request.generation),
            handle: handle.clone(),
            revision,
            event,
            externally_tainted,
        };
        self.preparation_serial = serial;
        self.prepared_asr = Some(prepared.snapshot());
        self.preparation_active = true;
        Ok(Some(prepared))
    }

    pub(super) fn check_prepared_revision(
        &self,
        handle: &UtteranceHandle,
        revision: u64,
        event: &AsrEvent,
        externally_tainted: bool,
    ) -> Result<()> {
        if let Some(prior) = &self.prepared_asr
            && prior.handle == *handle
            && (revision < prior.revision
                || (revision == prior.revision
                    && (event != &prior.event || externally_tainted != prior.externally_tainted)))
        {
            return Err(invalid("ASR preparation revision or exact input mismatch"));
        }
        Ok(())
    }

    /// Tests exact session/utterance/revision/event/generation/attempt binding.
    /// This check has no vault effects. Apply repeats it while holding &mut self.
    #[must_use]
    pub fn accepts_prepared_asr(&self, prepared: &PreparedAsr) -> bool {
        !self.ended
            && self.preparation_active
            && prepared.session == self.id
            && prepared.epoch == self.epoch
            && prepared.generation
                == self
                    .generation
                    .as_ref()
                    .map(|active| active.request.generation)
            && self.prepared_asr.as_ref() == Some(prepared)
            && self
                .retrieval
                .check_revision(&prepared.handle, prepared.revision)
                .is_ok()
    }

    /// Invalidate this attempt only. An old task cannot cancel its successor.
    pub fn cancel_prepared_asr(&mut self, prepared: &PreparedAsr) -> bool {
        if self.preparation_active && self.prepared_asr.as_ref() == Some(prepared) {
            // Keep the bounded observation as the revision/exact-input fence.
            // Cancellation releases an attempt, not permission to change its input
            // or resurrect an older revision after a newer attempt was cancelled.
            self.preparation_active = false;
            true
        } else {
            false
        }
    }

    /// Consumes the ticket and supplied result once. Stale/cancelled results are
    /// ignored BEFORE identity resolution, retrieval, telemetry or brain effects.
    /// This method is synchronous; no provider is called by its private enricher.
    pub fn apply_prepared_asr(
        &mut self,
        prepared: PreparedAsr,
        enrichment: PartialEnrichment,
    ) -> Result<AsrUpdate> {
        if !self.accepts_prepared_asr(&prepared) {
            return Ok(AsrUpdate::Ignored);
        }
        self.preparation_active = false;
        let mut enricher = ExactEnricher {
            text: prepared.event.text.clone(),
            value: Some(enrichment),
        };
        self.handle_asr(
            &prepared.handle,
            prepared.revision,
            prepared.event,
            prepared.externally_tainted,
            &mut enricher,
        )
    }
}

struct ExactEnricher {
    text: String,
    value: Option<PartialEnrichment>,
}

impl PartialEnricher for ExactEnricher {
    fn enrich_speculative_partial(&mut self, text: &str) -> Result<PartialEnrichment> {
        if text != self.text {
            return Err(invalid("prepared enrichment text mismatch"));
        }
        self.value
            .take()
            .ok_or_else(|| invalid("prepared enrichment already consumed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_enricher_mismatch_does_not_consume_and_success_consumes_once() {
        let mut enricher = ExactEnricher {
            text: " exact bytes ".to_owned(),
            value: Some(PartialEnrichment::default()),
        };
        assert!(enricher.enrich_speculative_partial("exact bytes").is_err());
        assert_eq!(
            enricher
                .enrich_speculative_partial(" exact bytes ")
                .unwrap(),
            PartialEnrichment::default()
        );
        assert!(
            enricher
                .enrich_speculative_partial(" exact bytes ")
                .is_err()
        );
    }
}
