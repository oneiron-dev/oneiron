//! The close a dispatched frame's handler error ends its connection with,
//! apart from the loop so each file stays under the size bar.

use axum::extract::ws::{CloseFrame, Message as WsMessage, Utf8Bytes};

use super::super::protocol_close::internal_fault_close;
use super::super::socket_stop::StoppingTransport;
use crate::protocol::{ProtocolError, close_codes};
use crate::server::SyncServer;

/// Closes the connection `e` ended: the error a frame's handler returned on
/// it. The loop breaks once this returns.
pub(super) async fn close_on(
    transport: &mut StoppingTransport,
    server: &SyncServer,
    conn_id: u32,
    e: &ProtocolError,
) {
    match e {
        // FIX 5550: an app-tier frame on a protocol older
        // than its tier is a refused call: receipted, then
        // the 4007 close it always sent.
        ProtocolError::RpcVersionMismatch => {
            super::super::protocol_close::refuse_frame(
                transport,
                server,
                close_codes::CLOSE_RPC_VERSION_MISMATCH,
                "app-tier admission refused",
                None,
            )
            .await;
        }
        ProtocolError::RpcNoPrincipal => {
            transport
                .send_unguarded_close_frame(WsMessage::Close(Some(CloseFrame {
                    code: close_codes::CLOSE_RPC_NO_PRINCIPAL,
                    reason: Utf8Bytes::from_static("app-tier admission refused"),
                })))
                .await;
        }
        // FIX 5310: each refusal below is its connection's
        // receipt, then the close it always sent, or, where
        // it sent none, its protocol close code.
        ProtocolError::ReplacementUnsupported => {
            super::super::protocol_close::refuse_frame(
                transport,
                server,
                close_codes::VERSION_MISMATCH,
                "window behind its history-free floor: upgrade this device to hello v13+ (v14 for residence)",
                None,
            )
            .await;
        }
        ProtocolError::WaitedOut => {
            tracing::warn!(
                conn_id,
                reason = "waited_out",
                "document waited for its turn past its deadline — closing"
            );
            super::super::protocol_close::refuse_frame(
                transport,
                server,
                close_codes::TRY_AGAIN_LATER,
                "waited for its turn past its deadline: nothing was applied",
                None,
            )
            .await;
        }
        ProtocolError::InvalidPayload(msg) => {
            tracing::warn!(conn_id, error = %msg, "invalid payload — closing");
            super::super::protocol_close::refuse_frame(
                transport,
                server,
                close_codes::DECODE_ERROR,
                "invalid payload",
                None,
            )
            .await;
        }
        ProtocolError::UnknownTag(tag) => {
            tracing::warn!(conn_id, tag, "unknown tag — closing");
            super::super::protocol_close::refuse_frame(
                transport,
                server,
                close_codes::UNKNOWN_TAG,
                "unknown tag",
                None,
            )
            .await;
        }
        ProtocolError::VvDecode(_) => {
            // Fail-closed: a malformed VV is a protocol
            // violation, never answered with a full export.
            tracing::warn!(
                conn_id,
                reason = "version_vector_decode_failed",
                "version vector decode failure — closing"
            );
            // FIX 5550: receipted, then closed as a decode
            // error.
            super::super::protocol_close::refuse_frame(
                transport,
                server,
                close_codes::DECODE_ERROR,
                "version vector does not decode",
                None,
            )
            .await;
        }
        ProtocolError::FrameTooLarge { size, max } => {
            tracing::warn!(conn_id, size, max, "frame too large — closing");
            super::super::protocol_close::refuse_frame(
                transport,
                server,
                close_codes::FRAME_TOO_LARGE,
                "frame too large",
                None,
            )
            .await;
        }
        ProtocolError::LoroImport(_) => {
            tracing::warn!(
                conn_id,
                reason = "loro_import_failed",
                "loro import error — closing"
            );
            // FIX 5550: receipted, then closed as a decode
            // error (CALLS "rootparity sync import close").
            super::super::protocol_close::refuse_frame(
                transport,
                server,
                close_codes::DECODE_ERROR,
                "update does not import",
                None,
            )
            .await;
        }
        // FIX 5570: the server's own export fault is no
        // refused frame: no receipt, closed 1011.
        ProtocolError::ExportFailed(_) => {
            tracing::error!(
                conn_id,
                reason = "server_export_failed",
                "server export failure — closing"
            );
            internal_fault_close(transport, close_codes::EXPORT_FAULT_REASON).await;
        }
        // FIX 5850: nor is its own fault reading the state a
        // window update's admission judges it by.
        ProtocolError::AdmissionReadFailed(_) => {
            tracing::error!(
                conn_id,
                reason = "admission_read_failed",
                "server admission read failure — closing"
            );
            internal_fault_close(transport, close_codes::ADMISSION_FAULT_REASON).await;
        }
        ProtocolError::Persistence(_) => {
            // Fail-closed: the server could not durably
            // persist sync state — do not keep relaying on a
            // connection whose updates would vanish on
            // restart.
            tracing::error!(
                conn_id,
                reason = "sync_persistence_failed",
                "sync persistence failure — closing"
            );
        }
    }
}
