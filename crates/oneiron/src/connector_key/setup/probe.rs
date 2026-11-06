//! A built-in channel's isolated probe (FIX 710), as a host's
//! [`QualificationConnector`](super::QualificationConnector) answers it: one
//! read-only identity tool per connection, with no arguments, whose answer
//! is the account the provider names for the stored credential.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::PackConnectionEvidence;
use crate::connector_key::qualification::{
    ProbeDisposition, ProbeReply, ProbeRequest, ProbeTool, ProbeTraceEvent, ProbeTraceKind,
};

/// The result type every built-in probe answers.
const BUILTIN_PROBE_RESULT_TYPE: &str = "oneiron.builtin.identity";

impl PackConnectionEvidence {
    /// The one tool a built-in channel's probe lists for `check`: the
    /// connection's read-only identity call.
    #[must_use]
    pub fn probe_tool(check: &str) -> ProbeTool {
        ProbeTool {
            name: check.to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false,
            }),
            trigger: None,
            result_types: BTreeSet::from([BUILTIN_PROBE_RESULT_TYPE.to_owned()]),
            writes: false,
        }
    }

    /// The account this read named, its stable id and the scopes the
    /// provider reported: a probe's answer and the channel's state alike.
    /// The reply digest stays out; a provider may vary its bytes for the
    /// same account.
    #[must_use]
    pub fn probe_identity(&self) -> Value {
        json!({
            "account": self.account,
            "provider_account": self.provider_account,
            "scopes": self.scopes,
        })
    }

    /// [`Self::probe_identity`] as the state bytes a probe compares.
    #[must_use]
    pub fn probe_state(&self) -> Vec<u8> {
        self.probe_identity().to_string().into_bytes()
    }

    /// The probe's answer to `request`: the identity, with no write.
    #[must_use]
    pub fn probe_reply(&self, request: &ProbeRequest) -> ProbeReply {
        probe_reply(request, ProbeDisposition::Answer, self.probe_identity())
    }

    /// The probe's reply when the provider refused `request`, and why.
    #[must_use]
    pub fn probe_refusal(request: &ProbeRequest, reason: &str) -> ProbeReply {
        probe_reply(
            request,
            ProbeDisposition::Refused,
            json!({ "reason": reason }),
        )
    }
}

fn probe_reply(request: &ProbeRequest, disposition: ProbeDisposition, result: Value) -> ProbeReply {
    let trace = [ProbeTraceKind::Start, ProbeTraceKind::End]
        .into_iter()
        .zip(0..)
        .map(|(kind, sequence)| ProbeTraceEvent {
            sequence,
            request_id: request.id.clone(),
            kind,
            reference: None,
        })
        .collect();
    ProbeReply {
        request_body: json!({
            "id": request.id,
            "name": request.name,
            "arguments": request.arguments,
        }),
        request_headers: BTreeMap::new(),
        disposition,
        result_type: BUILTIN_PROBE_RESULT_TYPE.to_owned(),
        result,
        writes: Vec::new(),
        answer_claim_refs: Vec::new(),
        retrieval_refs: Vec::new(),
        trace,
        tokens: 0,
        budget_units: 0,
    }
}
