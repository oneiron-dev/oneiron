//! Ordinary-only prepared reply: the same measured value plus its recorded stamp
//! and rows, framed on demand instead of buffered.

use super::{AppError, CallStamp, RpcReply, routing, rpc_error, wire};
use crate::protocol::ProtocolError;

/// An ordinary call's prepared success-or-refusal plus its recorded stamp,
/// before any frame exists. Framing borrows the prepared value, so the same
/// bytes can be framed again unchanged.
pub(super) struct PreparedRpcReply {
    pub(super) request_id: u64,
    pub(super) packed: Result<(wire::PreparedResult, Option<Vec<oneiron::EntityId>>), AppError>,
    pub(super) stamp: CallStamp,
}

impl PreparedRpcReply {
    /// The exact original eager framing: any failure becomes the single bare
    /// byte-limit refusal with no rows.
    pub(super) fn encode(self) -> Result<RpcReply, ProtocolError> {
        let too_large = || AppError::bad_request("RPC result byte limit exceeded", None);
        let Self {
            request_id,
            packed,
            stamp,
        } = self;
        let (frames, rows) = match packed {
            Ok((prepared, rows)) => {
                match wire::prepared_result_chunks(request_id, prepared, &stamp) {
                    Ok(frames) => (frames, Some(rows)),
                    Err(_) => (rpc_error(request_id, too_large(), &stamp)?, None),
                }
            }
            Err(error) => (rpc_error(request_id, error, &stamp)?, None),
        };
        Ok(RpcReply {
            request_id,
            frames,
            rows,
        })
    }

    /// Frame and enqueue without retaining all frames. A refusal emits its exact
    /// bare error frame. A success is first framed to a dropping callback: any
    /// encoding failure then becomes the single bare byte-limit refusal under the
    /// same stamp BEFORE any success byte is enqueued. Only after that validation
    /// passes are the same borrowed bytes framed again, each frame routed and
    /// sent. A delivery failure propagates unchanged and never triggers a refusal.
    pub(super) fn send(
        self,
        conn: u32,
        direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ) -> Result<(), ProtocolError> {
        let too_large = || AppError::bad_request("RPC result byte limit exceeded", None);
        let Self {
            request_id,
            packed,
            stamp,
        } = self;
        let (prepared, rows) = match packed {
            Err(error) => {
                for frame in rpc_error(request_id, error, &stamp)? {
                    direct_tx
                        .send(frame)
                        .map_err(|_| ProtocolError::InvalidPayload("reply channel closed"))?;
                }
                return Ok(());
            }
            Ok(ok) => ok,
        };
        let mut drop_frame = |frame: Vec<u8>| -> Result<(), ProtocolError> {
            drop(frame);
            Ok(())
        };
        match wire::write_prepared_result(request_id, &prepared, &stamp, &mut drop_frame) {
            Ok(()) => {}
            Err(wire::ResultFramesError::Delivery(error)) => return Err(error),
            Err(wire::ResultFramesError::Encoding(_)) => {
                for frame in rpc_error(request_id, too_large(), &stamp)? {
                    direct_tx
                        .send(frame)
                        .map_err(|_| ProtocolError::InvalidPayload("reply channel closed"))?;
                }
                return Ok(());
            }
        }
        let mut deliver = |frame: Vec<u8>| -> Result<(), ProtocolError> {
            let routed = routing::wrap(conn, request_id, 0, rows.as_deref(), frame);
            direct_tx
                .send(routed)
                .map_err(|_| ProtocolError::InvalidPayload("reply channel closed"))
        };
        match wire::write_prepared_result(request_id, &prepared, &stamp, &mut deliver) {
            Ok(()) => Ok(()),
            Err(wire::ResultFramesError::Delivery(error)) => Err(error),
            Err(wire::ResultFramesError::Encoding(error)) => Err(error),
        }
    }
}
