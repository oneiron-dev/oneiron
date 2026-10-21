//! The extraction step's citation check (FIX 7274): a TURN byte range that
//! verification would refuse the whole partition over (past its source's
//! text, or splitting its UTF-8) refuses the reply at the checked step
//! instead, so the reply is never memoized and is asked again after its
//! retry delay.

use super::{build_resolved, check_extraction_reply, extraction_reply, parse_candidate};
use crate::LlmResponse;
use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::evidence::EvidenceLocator;
use crate::dreamer_consolidation::partition::ConsolidationPartitionKey;
use crate::dreamer_consolidation::resources::{BranchResources, OwnedPins};
use crate::llm::{FinishReason, Scope};

/// What one partition's extraction replies are checked against: its
/// branch's pins and cited texts, owned, and what a candidate builds with.
pub(in crate::dreamer_consolidation) struct CitationCheck {
    pins: OwnedPins,
    partition: ConsolidationPartitionKey,
    attempt_id: AttemptId,
    now_ms: u64,
}

impl CitationCheck {
    pub(in crate::dreamer_consolidation) fn new(
        resources: &BranchResources<'_>,
        partition: ConsolidationPartitionKey,
        attempt_id: AttemptId,
        now_ms: u64,
    ) -> Self {
        Self {
            pins: resources.owned_pins(),
            partition,
            attempt_id,
            now_ms,
        }
    }

    /// [`check_extraction_reply`], then the one citation fault verification
    /// fails the whole partition on, for the reply a child reading under
    /// `scope` gets. Only a candidate that surely reaches verification is
    /// checked: one decode takes, that no correction is asked about (so
    /// none waits, or binds it to a head), and that builds uncorrected. Any
    /// other stays decode's to skip, never a refusal; a fallback's reply
    /// stands or falls by the live failure rules, never by this check.
    pub(in crate::dreamer_consolidation) fn check(
        &self,
        response: &LlmResponse,
        scope: &Scope,
    ) -> Result<(), String> {
        check_extraction_reply(response)?;
        if matches!(
            &response.finish_reason,
            FinishReason::Other { name } if name.starts_with("fallback:")
        ) {
            return Ok(());
        }
        let Ok(reply) = extraction_reply(response) else {
            return Ok(());
        };
        let pins = self.pins.pins();
        for (index, item) in reply.candidates.iter().enumerate() {
            let Ok(parsed) = parse_candidate(item, pins, scope) else {
                continue;
            };
            if pins.correctable(parsed.subject, scope).next().is_some() {
                continue;
            }
            let locators = parsed.locators.clone();
            let built = build_resolved(
                parsed,
                None,
                &[],
                &self.partition,
                self.attempt_id,
                self.now_ms,
            );
            if built.is_err() {
                continue;
            }
            if let Some(reason) = locators
                .into_iter()
                .find_map(|locator| self.range_fault(locator))
            {
                return Err(format!(
                    "extraction candidate {index} cites outside its source: {reason}"
                ));
            }
        }
        Ok(())
    }

    /// Why verification refuses `locator`'s TURN byte range, by the function
    /// it uses over the text it reads; `None` for a claim citation, or for
    /// a TURN with no text verification would cite.
    fn range_fault(&self, locator: EvidenceLocator) -> Option<&'static str> {
        let entry = locator.reference();
        if entry.claim_id.is_some() || entry.byte_range.is_none() {
            return None;
        }
        let text = self.pins.cited_text(&entry.source_id)?;
        match crate::dreamer_consolidation::turn_text::cited_evidence_bytes(entry, &[], Some(text))
        {
            Ok(_) => None,
            Err(crate::Error::InvalidClaimBody(reason)) => Some(reason),
            Err(_) => Some("evidence range refused"),
        }
    }
}
