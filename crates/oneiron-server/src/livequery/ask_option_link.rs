//! Bearer option-link dispatch off the socket loop. The machine proof is
//! transport provenance, never authority to answer for the token's recipient.

use std::sync::Arc;

use oneiron::authority::PeerMachine;
use oneiron::sync::ask_option_link::AskOptionLinkRequest;
use tokio::sync::mpsc::UnboundedSender;

use super::{AppError, RpcCall, RpcReply, RpcRequest};
use crate::protocol::ProtocolError;
use crate::server::SyncServer;

pub(crate) struct AskOptionLinkCall {
    peer: PeerMachine,
    request: RpcRequest,
    conn: u32,
}

impl AskOptionLinkCall {
    pub(crate) fn new(peer: PeerMachine, request: RpcRequest, conn: u32) -> Self {
        Self {
            peer,
            request,
            conn,
        }
    }

    pub(crate) async fn answer(
        self,
        server: Arc<SyncServer>,
        direct: UnboundedSender<Vec<u8>>,
    ) -> Result<(), ProtocolError> {
        let Self {
            peer,
            request,
            conn,
        } = self;
        let worker = Arc::clone(&server);
        // The socket's existing verb-call owner joins this task on close,
        // including the actual blocking call and its original task-work wait.
        let reply = tokio::task::spawn_blocking(move || {
            let call = RpcCall::of(&request);
            let request_id = request.request_id;
            let result = (|| {
                if !matches!(
                    worker.vault().peer_machine_stands(peer),
                    PeerMachine::Proven { .. }
                ) {
                    return Err(AppError::unauthorized());
                }
                let request: AskOptionLinkRequest = serde_json::from_value(request.params)
                    .map_err(|_| AppError::invalid_params())?;
                // A delivered RPC carries the exact original MemoryResult,
                // including every typed domain refusal, without projecting it
                // into the transport's code-only rpc.err.
                let value =
                    serde_json::to_value(request.execute(worker.vault())).map_err(|_| {
                        AppError::internal_server_error("option link reply encoding failed")
                    })?;
                Ok((value, Some(Vec::new())))
            })();
            RpcReply::answer_unbound(&worker, call, request_id, result)
        })
        .await
        .map_err(|_| ProtocolError::InvalidPayload("option link worker ended"))??;
        for frame in reply.queued_for_machine(conn, true) {
            direct
                .send(frame)
                .map_err(|_| ProtocolError::InvalidPayload("reply channel closed"))?;
        }
        Ok(())
    }
}
