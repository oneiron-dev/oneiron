//! First-frame protocol-version negotiation gate.

use axum::extract::ws::Message as WsMessage;
use futures_util::{SinkExt, Stream};

use super::protocol_close::{CodecReadError, ProtocolRefusal};
use super::transport::GuardedTransport;
use crate::protocol::{self, close_codes};

/// How long the server waits for the client's protocol-version hello.
const HELLO_TIMEOUT_SECS: u64 = 10;

/// Outcome of the protocol-version hello phase.
pub(super) enum HelloOutcome {
    /// First frame was a valid hello with a supported version.
    Valid(u8),
    /// Hello missing/malformed/mismatched/timed out — close with
    /// `close_codes::VERSION_MISMATCH` and its reason — or a first frame the
    /// transport or the WebSocket codec refused (FIX 5549), closed with that
    /// refusal's own code. Either is the connection's refused call,
    /// receipted before the close (FIX 3303).
    Reject(ProtocolRefusal),
    /// Client went away before sending a hello — nothing to close.
    Disconnected,
}

/// A hello the server rejects, closed with `close_codes::VERSION_MISMATCH`.
const fn mismatch(reason: &'static str) -> HelloOutcome {
    HelloOutcome::Reject(ProtocolRefusal::new(close_codes::VERSION_MISMATCH, reason))
}

/// Waits for the client's protocol-version hello as the FIRST frame.
///
/// Skips ping/pong keepalives; any other frame must be the hello.
pub(super) async fn await_protocol_hello<S, E>(transport: &mut GuardedTransport<S>) -> HelloOutcome
where
    S: SinkExt<WsMessage> + Stream<Item = Result<WsMessage, E>> + Unpin,
    E: CodecReadError,
{
    let deadline = tokio::time::Duration::from_secs(HELLO_TIMEOUT_SECS);
    let outcome = tokio::time::timeout(deadline, async {
        loop {
            match transport.read_next().await {
                Some(Ok(WsMessage::Binary(data))) => {
                    return match validate_protocol_hello(&data) {
                        Ok(version) => {
                            // A valid hello's codec list always decodes.
                            if let Ok(codecs) = protocol::decode_protocol_hello_codecs(&data) {
                                transport.set_peer_codecs(codecs);
                            }
                            HelloOutcome::Valid(version)
                        }
                        Err(_) => mismatch("protocol version mismatch"),
                    };
                }
                Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => continue,
                Some(Ok(WsMessage::Text(_))) => {
                    return mismatch("expected binary protocol hello");
                }
                Some(Ok(WsMessage::Close(_))) => return HelloOutcome::Disconnected,
                // A first frame the WebSocket codec refused is a refusal, not
                // a disconnect (FIX 5549); any other read error is the peer's
                // link ending.
                Some(Err(error)) => {
                    return error
                        .codec_refusal()
                        .map_or(HelloOutcome::Disconnected, HelloOutcome::Reject);
                }
                // A frame the transport refused is the server's rejection,
                // carried up to the carrier, not a peer that went away.
                None => {
                    return transport
                        .refusal()
                        .map_or(HelloOutcome::Disconnected, HelloOutcome::Reject);
                }
            }
        }
    })
    .await;

    outcome.unwrap_or(mismatch("protocol hello timeout"))
}

/// Validates a hello frame against the server's supported wire protocols.
///
/// Returns the negotiated version on success. Unsupported versions return the
/// close code to send (always `close_codes::VERSION_MISMATCH`) so callers
/// cannot accidentally downgrade the failure to a softer close.
pub(super) fn validate_protocol_hello(frame: &[u8]) -> Result<u8, u16> {
    match protocol::decode_protocol_hello(frame) {
        Ok(version)
            if protocol::is_residence_version(version)
                || protocol::is_owner_window_version(version)
                || version == protocol::PROTOCOL_VERSION
                || version == protocol::APP_TIER_PROTOCOL_VERSION_VERSION
                || version == protocol::LEGACY_SELECTOR_PROTOCOL_VERSION
                || version == protocol::LEGACY_FULL_WINDOW_PROTOCOL_VERSION =>
        {
            Ok(version)
        }
        _ => Err(close_codes::VERSION_MISMATCH),
    }
}
