//! Request-owned Human notifications, decoded without recording or settling an ask.

use serde::{Deserialize, Serialize};

use super::{MAX_DECODED_PAYLOAD_BYTES, TransportError};
use crate::llm::decision::{AskConsent, HumanDecisionRequest};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum PrivateHumanKind {
    #[serde(rename = "private.human.ask")]
    Ask,
}

/// An in-memory notification for the host application. Receiving it neither records
/// an ASK nor answers it, and accepting the event does not mean it was rendered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateHumanAsk {
    kind: PrivateHumanKind,
    no_record: bool,
    #[serde(flatten)]
    pub request: HumanDecisionRequest,
    pub state: Option<serde_json::Value>,
    pub consent: Option<AskConsent>,
}

impl PrivateHumanAsk {
    /// Keeps the request and optional state/consent in the private notification lane.
    pub fn new(
        request: HumanDecisionRequest,
        state: Option<serde_json::Value>,
        consent: Option<AskConsent>,
    ) -> Self {
        Self {
            kind: PrivateHumanKind::Ask,
            no_record: true,
            request,
            state,
            consent,
        }
    }
}

/// Decodes the payload after [`super::TAG_PRIVATE_HUMAN`], under the native decoded
/// payload bound. It writes no sync state and produces no protocol response.
pub fn decode_private_human_ask(payload: &[u8]) -> Result<PrivateHumanAsk, TransportError> {
    if payload.len() > MAX_DECODED_PAYLOAD_BYTES {
        return Err(TransportError::FrameTooLarge {
            size: payload.len(),
            max: MAX_DECODED_PAYLOAD_BYTES,
        });
    }
    let ask: PrivateHumanAsk = serde_json::from_slice(payload)
        .map_err(|_| TransportError::InvalidPayload("invalid private Human ask"))?;
    if !ask.no_record {
        return Err(TransportError::InvalidPayload(
            "private Human ask is recordable",
        ));
    }
    Ok(ask)
}
