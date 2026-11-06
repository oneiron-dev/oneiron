//! What one send of the call host came to, before the ledger scrubs its
//! raw fields.

use oneiron::outbound_intent_ledger::ProviderWaitKind;

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
    /// The remote task the connector took the call as (FIX 7960).
    pub(super) remote_task: Option<RemoteTaskHandle>,
    /// The hold the call's issuer binding, read again at the door, met
    /// (FIX 9303): nothing was presented or sent.
    pub(super) held: Option<&'static str>,
    /// The wait the connector asked for when it refused the call for rate
    /// (FIX 11025).
    pub(super) provider_wait: Option<ProviderWait>,
}

impl Sent {
    /// Certain non-delivery: the `tools/call` request never left.
    pub(super) fn not_sent(kind: OutboundFailureKind, code: Option<u16>) -> Self {
        Self {
            outcome: OutboundSendOutcome::Failed(OutboundSendFailure {
                kind,
                code,
                secret: None,
            }),
            reply: None,
            awaiting: None,
            body: None,
            error: None,
            resume: None,
            remote_task: None,
            held: None,
            provider_wait: None,
        }
    }

    /// Certain non-delivery the credential door refused with the typed
    /// secret refusal `secret` (FIX 11565): rejected, never a transport
    /// failure, and the caller reads which refusal it was.
    pub(super) fn refused(secret: oneiron::outbound_intent_ledger::SecretSendRefusal) -> Self {
        Self {
            outcome: OutboundSendOutcome::Failed(OutboundSendFailure {
                kind: OutboundFailureKind::Rejected,
                code: None,
                secret: Some(secret),
            }),
            reply: None,
            awaiting: None,
            body: None,
            error: None,
            resume: None,
            remote_task: None,
            held: None,
            provider_wait: None,
        }
    }

    /// Certain non-delivery of a send whose row an issuer change the owner
    /// has not accepted holds (FIX 9303): the door read the call's durable
    /// binding again and presented nothing, so the request never left.
    pub(super) fn held(reason: &'static str) -> Self {
        Self {
            held: Some(reason),
            ..Self::not_sent(OutboundFailureKind::TransportNotStarted, None)
        }
    }

    /// Certain non-delivery the connector refused at its door with HTTP
    /// `status`, before any tool ran (FIX 11025): a 429 keeps the
    /// provider's wait, read from its `Retry-After`, so the send stays
    /// queued until then; any other refusal is rejected with its code.
    pub(super) fn refused_status(status: reqwest::StatusCode, headers: &HeaderMap) -> Self {
        let mut sent = Self::not_sent(OutboundFailureKind::Rejected, Some(status.as_u16()));
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            sent.provider_wait = Some(ProviderWait {
                kind: ProviderWaitKind::RateLimit,
                retry_after_secs: retry_after_secs(headers),
            });
        }
        sent
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
            remote_task: None,
            held: None,
            provider_wait: None,
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
            remote_task: None,
            held: None,
            provider_wait: None,
        }
    }

    /// The connector took the call as the remote task `handle` (FIX 7960):
    /// its outcome is still out, and the call is never sent again.
    pub(super) fn deferred(handle: RemoteTaskHandle, body: Vec<u8>) -> Self {
        Self {
            outcome: OutboundSendOutcome::Deferred,
            reply: None,
            awaiting: None,
            body: Some(body),
            error: None,
            resume: None,
            remote_task: Some(handle),
            held: None,
            provider_wait: None,
        }
    }
}

/// The seconds a `Retry-After` header asks for: delta-seconds, or an HTTP
/// date less now (zero once it is past); `None` when it is absent or does
/// not read.
fn retry_after_secs(headers: &HeaderMap) -> Option<u64> {
    let value = headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(seconds);
    }
    let at = httpdate::parse_http_date(value).ok()?;
    Some(
        at.duration_since(std::time::SystemTime::now())
            .map_or(0, |wait| wait.as_secs()),
    )
}
