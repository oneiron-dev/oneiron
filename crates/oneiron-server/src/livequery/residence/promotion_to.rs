//! Promotion's optional native copies travel beside its recorded RPC value.

use super::{AppError, CoreAuth, CoreScope, index, operation_budgets};
use crate::handler::{DirectSender, PromotionFrame};
use crate::livequery::{RpcCall, RpcReply, RpcRequest};
use crate::protocol::ProtocolError;
use crate::server::SyncServer;
use oneiron::authority::PeerMachine;

pub(crate) fn send(
    server: &SyncServer,
    auth: &CoreAuth,
    peer: PeerMachine,
    request: RpcRequest,
    conn: u32,
    direct: &DirectSender,
) -> Result<(), ProtocolError> {
    let call = RpcCall::of(&request);
    let prepared = (|| {
        auth.require(CoreScope::Read)?;
        if !auth.credential_is_live(server.vault.as_ref()) {
            return Err(AppError::unauthorized());
        }
        operation_budgets(server)?;
        index::promote_prepared(server, auth, peer, request.params)
    })();
    let (answer, mut copies) = match prepared {
        Ok((answer, copies)) => (Ok(answer), copies),
        Err(error) => (Err(error), None),
    };
    let reply = RpcReply::answer_attributed(server, auth, None, call, request.request_id, answer)?;
    let mut frames = reply.queued_frames(conn).peekable();
    while let Some(frame) = frames.next() {
        let promotion = if frames.peek().is_none() {
            copies.take().and_then(|copies| {
                let required = super::super::routing::addressed(&frame, conn)?.frame;
                let extended =
                    super::super::wire::promotion_copy_frame(required, copies.as_bytes())?;
                Some(PromotionFrame::new(required.to_vec(), extended, copies))
            })
        } else {
            None
        };
        direct
            .send_with_promotion(frame, promotion)
            .map_err(|_| ProtocolError::InvalidPayload("reply channel closed"))?;
    }
    Ok(())
}
