//! The Big rung's model as the host's notes model (FIX 3040, 654): one
//! tool-less text call on the rung's seat, routed, admitted and metered as the
//! rung's own calls are, within the time its caller gives. It writes the note
//! beside an answer already decided, and a call that fails or runs out of time
//! writes none.
use std::collections::BTreeMap;
use std::time::Duration;

use oneiron::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, EntityId, LlmMessageRole, LlmRequest,
    ModelTierRef, ResponseFormat, TierPrecedence,
};

use super::{Answerer, BigModel, PURPOSE, message};
use crate::models::CallDeadline;

/// The purpose a note call stamps.
const NOTE_PURPOSE: &str = "decision.note";

impl BigModel {
    /// The text the rung's model writes under `system` over `data`, within
    /// `budget`. Its input is `data`, read from `sources` (`None` is
    /// unknown). `None` when no route serves the call, it fails or its time
    /// runs out, or the reply is empty.
    pub(crate) fn note(
        &self,
        system: &str,
        data: String,
        sources: Option<Vec<EntityId>>,
        budget: Duration,
    ) -> Option<String> {
        if budget.is_zero() {
            return None;
        }
        let route = self.resolve_decision_route().ok()?;
        let purpose = CallPurpose::Other {
            name: NOTE_PURPOSE.to_owned(),
        };
        let request = LlmRequest {
            model: route.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(&purpose, ModelTierRef(PURPOSE.to_owned())),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Text,
                locality: route.locality,
            },
            messages: vec![
                message(LlmMessageRole::System, system.to_owned()),
                message(LlmMessageRole::User, data),
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
            host_segments: None,
        };
        let (ladder, request) = self.admit_decision_route(request).ok()?;
        let run = self
            .models
            .funded_run(
                format!("{NOTE_PURPOSE}:{}", EntityId::now().to_hex()),
                crate::decision_verdict::rung_meter(&self.meter),
                crate::decision_verdict::rung_payer(),
            )
            .sourced(sources);
        let deadline = CallDeadline::caller_in(budget);
        let response = self
            .runtime
            .block_on(async {
                match &self.answerer {
                    Answerer::Seat(_) => ladder
                        .generate_served_by(&run, request, None, &|| true, deadline)
                        .await
                        .map(|(response, _)| response),
                    Answerer::Model(_) => ladder
                        .generate_exact_by(&run, request, None, &|| true, deadline)
                        .await,
                }
            })
            .ok()?;
        let text: String = response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        let text = text.trim();
        (!text.is_empty()).then(|| text.to_owned())
    }
}
