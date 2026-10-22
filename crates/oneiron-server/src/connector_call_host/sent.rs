//! What one send of the call host came to, before the ledger scrubs its
//! raw fields.

use super::*;

/// What one send came to, before the ledger scrubs its raw fields.
pub(super) struct Sent {
    pub(super) outcome: OutboundSendOutcome,
    pub(super) reply: Option<UntrustedToolResult>,
    /// The questions the connector answered with, in place of a reply.
    pub(super) awaiting: Option<ConnectorAwaitingInput>,
    pub(super) body: Option<Vec<u8>>,
    pub(super) error: Option<String>,
    /// The resume state of the round the connector asked, if it asked one
    /// (FIX 9157).
    pub(super) resume: Option<RoundResume>,
}

impl Sent {
    /// Certain non-delivery: the `tools/call` request never left.
    pub(super) fn not_sent(kind: OutboundFailureKind, code: Option<u16>) -> Self {
        Self {
            outcome: OutboundSendOutcome::Failed(OutboundSendFailure { kind, code }),
            reply: None,
            awaiting: None,
            body: None,
            error: None,
            resume: None,
        }
    }

    /// The request went and no readable answer came back.
    pub(super) fn ambiguous(error: &str) -> Self {
        Self {
            outcome: OutboundSendOutcome::Ambiguous,
            reply: None,
            awaiting: None,
            body: None,
            error: Some(error.to_owned()),
            resume: None,
        }
    }

    /// The connector answered the call.
    pub(super) fn acked(reply: Option<UntrustedToolResult>, body: Vec<u8>) -> Self {
        Self {
            outcome: OutboundSendOutcome::Acked,
            reply,
            awaiting: None,
            body: Some(body),
            error: None,
            resume: None,
        }
    }
}
