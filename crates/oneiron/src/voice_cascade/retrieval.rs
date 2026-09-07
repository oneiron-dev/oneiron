//! One live utterance per connection; actual retrieval semantics stay in OF-108.

use std::sync::Arc;

use crate::Vault;
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::speculative::{
    SpeculativeFinal, SpeculativeFireDecision, SpeculativePartial, SpeculativeSession,
    SpeculativeSessionConfig,
};
use crate::store::RetrievalRunId;

use super::{PartialEnricher, PartialEnrichment, RetrievalContext};

/// Minted by this bridge. The serial prevents a reused human-readable id from
/// admitting late observations from a closed utterance. Never deserialize it
/// from an untrusted client; the local bridge owns the handle mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtteranceHandle {
    bridge: uuid::Uuid,
    serial: u64,
    utterance_id: String,
}

impl UtteranceHandle {
    #[must_use]
    pub fn utterance_id(&self) -> &str {
        &self.utterance_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialRetrieval {
    /// The real engine decision, not a second cap/meaning implementation.
    pub decision: SpeculativeFireDecision,
    /// Only a fire returns context. Skips do not re-export a cached warm pack.
    pub context: Option<RetrievalContext>,
}

struct OpenUtterance {
    handle: UtteranceHandle,
    last_revision: Option<u64>,
    session: SpeculativeSession,
}

pub struct SpeculativeRetrievalBridge {
    vault: Arc<Vault>,
    id: uuid::Uuid,
    serial: u64,
    open: Option<OpenUtterance>,
}

impl SpeculativeRetrievalBridge {
    #[must_use]
    pub fn new(vault: Arc<Vault>) -> Self {
        Self {
            vault,
            id: uuid::Uuid::new_v4(),
            serial: 0,
            open: None,
        }
    }

    pub fn open_utterance(
        &mut self,
        utterance_id: impl Into<String>,
        config: SpeculativeSessionConfig,
    ) -> Result<UtteranceHandle> {
        let utterance_id = utterance_id.into();
        if utterance_id.trim().is_empty() || self.open.is_some() {
            return Err(invalid(
                "utterance id must be nonempty and no utterance may be open",
            ));
        }
        self.serial = self
            .serial
            .checked_add(1)
            .ok_or_else(|| invalid("utterance serial exhausted"))?;
        let handle = UtteranceHandle {
            bridge: self.id,
            serial: self.serial,
            utterance_id,
        };
        self.open = Some(OpenUtterance {
            handle: handle.clone(),
            last_revision: None,
            session: SpeculativeSession::new(Arc::clone(&self.vault), config),
        });
        Ok(handle)
    }

    pub fn observe_partial(
        &mut self,
        handle: &UtteranceHandle,
        revision: u64,
        text: &str,
        enricher: &mut impl PartialEnricher,
    ) -> Result<PartialRetrieval> {
        self.check_revision(handle, revision)?;
        let enriched = enrich(text, enricher)?;
        let open = self
            .open
            .as_mut()
            .ok_or_else(|| invalid("no open utterance"))?;
        let decision = open.session.observe_partial(as_partial(text, &enriched))?;
        let context = match &decision {
            SpeculativeFireDecision::Fired { run_id } => {
                Some(project(open.session.warm_candidates(), *run_id, false))
            }
            _ => None,
        };
        // Retrieval/enrichment errors leave the revision retryable, just as an
        // OF-108 fire error leaves its budget and signature unchanged.
        open.last_revision = Some(revision);
        Ok(PartialRetrieval { decision, context })
    }

    /// Finalization consumes the real engine handle even if retrieval fails.
    /// Enricher and revision errors occur BEFORE consumption and may be retried.
    pub fn finalize(
        &mut self,
        handle: &UtteranceHandle,
        revision: u64,
        text: &str,
        enricher: &mut impl PartialEnricher,
    ) -> Result<RetrievalContext> {
        self.check_revision(handle, revision)?;
        let enriched = enrich(text, enricher)?;
        let open = self
            .open
            .take()
            .ok_or_else(|| invalid("no open utterance"))?;
        match open.session.finalize(as_partial(text, &enriched))? {
            SpeculativeFinal::Promoted { scores, run_id } => Ok(project(&scores, run_id, true)),
            SpeculativeFinal::Finalized { scores, run_id, .. } => {
                Ok(project(&scores, run_id, false))
            }
        }
    }

    /// Closing a stale handle cannot close a newer utterance with the same id.
    pub fn close_utterance(&mut self, handle: &UtteranceHandle) -> bool {
        if self.is_open(handle) {
            self.open = None;
            true
        } else {
            false
        }
    }

    /// Disconnect cleanup. No tombstones, text, vectors or warm packs survive.
    pub fn close(&mut self) {
        self.open = None;
    }

    #[must_use]
    pub fn is_open(&self, handle: &UtteranceHandle) -> bool {
        self.open
            .as_ref()
            .is_some_and(|open| open.handle == *handle)
    }

    pub fn fires_used(&self, handle: &UtteranceHandle) -> Result<u8> {
        self.check_handle(handle)?;
        Ok(self
            .open
            .as_ref()
            .ok_or_else(|| invalid("no open utterance"))?
            .session
            .fires_used())
    }

    fn check_handle(&self, handle: &UtteranceHandle) -> Result<()> {
        if self.is_open(handle) {
            Ok(())
        } else {
            Err(invalid("stale utterance handle"))
        }
    }

    fn check_revision(&self, handle: &UtteranceHandle, revision: u64) -> Result<()> {
        self.check_handle(handle)?;
        if self
            .open
            .as_ref()
            .and_then(|open| open.last_revision)
            .is_some_and(|last| revision <= last)
        {
            return Err(invalid("ASR revision must advance"));
        }
        Ok(())
    }
}

fn enrich(text: &str, enricher: &mut impl PartialEnricher) -> Result<PartialEnrichment> {
    let mut enrichment = enricher.enrich_speculative_partial(text)?;
    for list in [&mut enrichment.entity_labels, &mut enrichment.salient_terms] {
        *list = list
            .iter()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        list.sort();
        list.dedup();
    }
    Ok(enrichment)
}

fn as_partial<'a>(text: &'a str, enriched: &'a PartialEnrichment) -> SpeculativePartial<'a> {
    SpeculativePartial {
        text,
        entity_labels: &enriched.entity_labels,
        salient_terms: &enriched.salient_terms,
        query_vector: enriched.query_vector.as_deref(),
    }
}

fn project(
    scores: &[ScoredEntity],
    run_id: Option<RetrievalRunId>,
    promoted: bool,
) -> RetrievalContext {
    RetrievalContext {
        result_refs: scores.iter().map(|score| score.id.to_hex()).collect(),
        promoted,
        run_id: run_id.map(RetrievalRunId::to_hex),
    }
}

pub(super) fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
