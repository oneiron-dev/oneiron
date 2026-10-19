//! A socket the server closes on a protocol rejection (FIX 3303, OF-538):
//! a hello it refused, a frame it would not serve, a codec frame the
//! transport would not unwrap. Each is one refused call of the connection,
//! receipted once before its close, naming no person or credential and
//! capturing nothing the peer sent
//! ([`crate::api::call_receipt::record_socket_close`]). The close code is
//! the one it always was. A peer that went away, a revoked credential and
//! the engine's stop are no refused call, and write none. On a managed
//! vault a held MCP socket's receipt is admitted under the reap freeze, and
//! a socket refused while the vault is frozen closes the same way with no
//! receipt (FIX 5128).

use axum::extract::ws::{CloseFrame, Message as WsMessage, Utf8Bytes};

use super::hello::HelloOutcome;
use super::socket_stop::StoppingTransport;
use crate::managed::ManagedCarrierContext;
use crate::protocol::close_codes;
use crate::server::SyncServer;

/// The verb a refusal at the protocol hello states: no frame was served.
const HELLO_VERB: &str = "ws.hello";

/// The verb a refusal of a frame after the hello states.
const FRAME_VERB: &str = "ws.frame";

/// One protocol refusal: the code the socket closes with and the reason its
/// close frame states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ProtocolRefusal {
    close_code: u16,
    reason: &'static str,
}

impl ProtocolRefusal {
    pub(super) const fn new(close_code: u16, reason: &'static str) -> Self {
        Self { close_code, reason }
    }

    /// The refusal's closed name: the code its receipt states.
    const fn code(self) -> &'static str {
        match self.close_code {
            close_codes::VERSION_MISMATCH => "version_mismatch",
            close_codes::CLOSE_RPC_VERSION_MISMATCH => "rpc_version_mismatch",
            close_codes::DECODE_ERROR => "decode_error",
            close_codes::UNKNOWN_TAG => "unknown_tag",
            close_codes::FRAME_TOO_LARGE => "frame_too_large",
            _ => "protocol_refused",
        }
    }

    /// The close frame that ends the socket.
    fn close_frame(self) -> WsMessage {
        WsMessage::Close(Some(CloseFrame {
            code: self.close_code,
            reason: Utf8Bytes::from_static(self.reason),
        }))
    }

    /// Writes the connection's receipt of this refusal at `verb`, then
    /// closes the socket with it. The receipt is best effort: a row that
    /// cannot be written is logged and the close goes ahead. A managed
    /// socket's receipt is written under its reap `admission`, and while the
    /// vault is frozen none is.
    async fn close(
        self,
        server: &SyncServer,
        verb: &str,
        transport: &mut StoppingTransport,
        admission: Option<&ManagedCarrierContext>,
    ) {
        let record = || {
            crate::api::call_receipt::record_socket_close(server, verb, self.code(), self.reason)
        };
        match admission {
            None => {
                let _ = record();
            }
            Some(admission) => {
                let _ = admission.admit_receipt(record);
            }
        }
        transport
            .send_unguarded_close_frame(self.close_frame())
            .await;
    }
}

/// A carrier's protocol hello: the version the client negotiated, or `None`
/// once the socket is done with. A rejected hello, or a first frame the
/// transport refused, is receipted and closed here; a client that went away
/// first, or the engine's stop, closes nothing.
pub(super) async fn hello(
    transport: &mut StoppingTransport,
    server: &SyncServer,
    conn_id: u32,
    admission: Option<&ManagedCarrierContext>,
) -> Option<u8> {
    match transport.hello().await {
        HelloOutcome::Valid(version) => Some(version),
        HelloOutcome::Reject(refusal) => {
            tracing::warn!(
                conn_id,
                reason = refusal.reason,
                "protocol hello rejected — closing"
            );
            refusal
                .close(server, HELLO_VERB, transport, admission)
                .await;
            None
        }
        HelloOutcome::Disconnected => {
            tracing::info!(conn_id, "client disconnected before protocol hello");
            None
        }
    }
}

/// Refuses a client whose protocol hello was valid but older than this
/// carrier serves: receipted, then closed with `close_code`.
pub(super) async fn refuse_hello_version(
    transport: &mut StoppingTransport,
    server: &SyncServer,
    close_code: u16,
    reason: &'static str,
    admission: Option<&ManagedCarrierContext>,
) {
    ProtocolRefusal::new(close_code, reason)
        .close(server, HELLO_VERB, transport, admission)
        .await;
}

/// Refuses a frame read after the hello (an oversized one, an unknown tag,
/// an envelope that does not decode): receipted, then closed with
/// `close_code`.
pub(super) async fn refuse_frame(
    transport: &mut StoppingTransport,
    server: &SyncServer,
    close_code: u16,
    reason: &'static str,
    admission: Option<&ManagedCarrierContext>,
) {
    ProtocolRefusal::new(close_code, reason)
        .close(server, FRAME_VERB, transport, admission)
        .await;
}

/// After a read that ended the socket: when the transport ended it by
/// refusing a frame (one that would not unwrap within the cap), receipts that
/// refusal and closes with it. A read that ended any other way closes
/// nothing here.
pub(super) async fn close_read_refusal(
    server: &SyncServer,
    transport: &mut StoppingTransport,
    admission: Option<&ManagedCarrierContext>,
) {
    if let Some(refusal) = transport.refusal() {
        refusal
            .close(server, FRAME_VERB, transport, admission)
            .await;
    }
}
