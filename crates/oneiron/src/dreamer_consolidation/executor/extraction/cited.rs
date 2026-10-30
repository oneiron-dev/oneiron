//! The extraction step's citation check (FIX 7274): a citation that
//! verification would refuse the whole partition over refuses the reply at
//! the checked step instead, so the reply is never memoized and is asked
//! again after its retry delay. A quote that binds nothing (FIX 7506: one
//! its source holds nowhere or more than once, or a label its call did not
//! show) takes the same refusal, as an out-of-source byte range did.

use super::wire::{CallPins, ReplyContext, read_candidate};
use super::{check_extraction_reply, extraction_reply, resolve_proposal};
use crate::LlmResponse;
use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::branch::BranchAxes;
use crate::dreamer_consolidation::call_labels::CallLabelMap;
use crate::dreamer_consolidation::evidence::EvidenceLocator;
use crate::dreamer_consolidation::extracted_people::{MintNamespace, bind_people};
use crate::dreamer_consolidation::resources::{BranchResources, OwnedPins};
use crate::llm::{FinishReason, Scope};

/// What one partition's extraction replies are checked against: its
/// branch's pins and cited texts, owned, what a candidate builds with, and
/// the namespace its declared people bind under.
pub(in crate::dreamer_consolidation) struct CitationCheck {
    pins: OwnedPins,
    partition: BranchAxes,
    attempt_id: AttemptId,
    now_ms: u64,
    namespace: MintNamespace,
}

impl CitationCheck {
    pub(in crate::dreamer_consolidation) fn new(
        resources: &BranchResources<'_>,
        partition: BranchAxes,
        attempt_id: AttemptId,
        now_ms: u64,
        namespace: MintNamespace,
    ) -> Self {
        Self {
            pins: resources.owned_pins(),
            partition,
            attempt_id,
            now_ms,
            namespace,
        }
    }

    /// [`check_extraction_reply`], then the citation faults verification
    /// fails the whole partition on, for the reply a child reading under
    /// `scope` with `labels` gets. Only a candidate that surely reaches
    /// verification is checked: one decode takes but for its evidence, that
    /// no correction is asked about (so none waits, or binds it to a head),
    /// and that builds uncorrected. Any other stays decode's to skip, never
    /// a refusal; a fallback's reply stands or falls by the live failure
    /// rules, never by this check.
    pub(in crate::dreamer_consolidation) fn check(
        &self,
        response: &LlmResponse,
        scope: &Scope,
        labels: &CallLabelMap,
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
        let call = CallPins {
            labels,
            pins: self.pins.pins(),
        };
        let people = bind_people(&reply.persons, &call, &self.namespace);
        let ctx = ReplyContext {
            call,
            people: &people,
        };
        for (index, item) in reply.candidates.iter().enumerate() {
            // The candidate's subject, value and admitted sources, apart
            // from whether each of its quotes bound.
            // A fallback returned above: this reply is a model's.
            let Ok((parsed, unbound)) = read_candidate(item, ctx, scope, false) else {
                continue;
            };
            if call
                .pins
                .correctable(parsed.subject, scope)
                .next()
                .is_some()
            {
                continue;
            }
            let Ok((_, locators)) = resolve_proposal(
                parsed,
                None,
                &[],
                &self.partition,
                self.attempt_id,
                self.now_ms,
            ) else {
                continue;
            };
            if let Some(reason) = unbound.or_else(|| {
                locators
                    .into_iter()
                    .find_map(|locator| self.range_fault(locator))
            }) {
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
