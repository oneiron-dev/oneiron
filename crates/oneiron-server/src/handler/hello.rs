//! First-frame protocol-version negotiation gate.

use axum::extract::ws::Message as WsMessage;
use futures_util::{SinkExt, Stream};

use super::transport::GuardedTransport;
use crate::protocol::{self, close_codes};

/// How long the server waits for the client's protocol-version hello.
const HELLO_TIMEOUT_SECS: u64 = 10;

/// Outcome of the protocol-version hello phase.
pub(super) enum HelloOutcome {
    /// First frame was a valid hello with a supported version.
    Valid(u8),
    /// Hello missing/malformed/mismatched/timed out — close with
    /// `close_codes::VERSION_MISMATCH` and this reason.
    Reject(&'static str),
    /// Client went away before sending a hello — nothing to close.
    Disconnected,
}

/// Waits for the client's protocol-version hello as the FIRST frame.
///
/// Skips ping/pong keepalives; any other frame must be the hello.
pub(super) async fn await_protocol_hello<S, E>(transport: &mut GuardedTransport<S>) -> HelloOutcome
where
    S: SinkExt<WsMessage> + Stream<Item = Result<WsMessage, E>> + Unpin,
{
    let deadline = tokio::time::Duration::from_secs(HELLO_TIMEOUT_SECS);
    let outcome = tokio::time::timeout(deadline, async {
        loop {
            match transport.read_next().await {
                Some(Ok(WsMessage::Binary(data))) => {
                    return match validate_protocol_hello(&data) {
                        Ok(version) => HelloOutcome::Valid(version),
                        Err(_) => HelloOutcome::Reject("protocol version mismatch"),
                    };
                }
                Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => continue,
                Some(Ok(WsMessage::Text(_))) => {
                    return HelloOutcome::Reject("expected binary protocol hello");
                }
                Some(Ok(WsMessage::Close(_))) | Some(Err(_)) | None => {
                    return HelloOutcome::Disconnected;
                }
            }
        }
    })
    .await;

    outcome.unwrap_or(HelloOutcome::Reject("protocol hello timeout"))
}

/// Validates a hello frame against the server's supported wire protocols.
///
/// Returns the negotiated version on success. Unsupported versions return the
/// close code to send (always `close_codes::VERSION_MISMATCH`) so callers
/// cannot accidentally downgrade the failure to a softer close.
pub(super) fn validate_protocol_hello(frame: &[u8]) -> Result<u8, u16> {
    match protocol::decode_protocol_hello(frame) {
        Ok(version)
            if version == protocol::PROTOCOL_VERSION
                || version == protocol::LEGACY_SELECTOR_PROTOCOL_VERSION
                || version == protocol::LEGACY_FULL_WINDOW_PROTOCOL_VERSION =>
        {
            Ok(version)
        }
        _ => Err(close_codes::VERSION_MISMATCH),
    }
}
