//! The home's side of the sealed world-update relay (DEC-0005 fix 8: "The
//! cloud relays its sealed updates between the owner's machines and cannot
//! read them"; CLIP-SYNC = A, FIX 12586).
//!
//! A socket takes part only while its hello listed sealed updates and its
//! machine stands here as one of the owner's own. The home offers its queue at
//! connect, stores each update a machine puts, once per id, answers a
//! machine's catch-up from its cursor, and pushes each update it stores to
//! the other sockets that asked for them. It opens none of them: the bytes
//! name no world, no window and no key.

use oneiron::sync::residence::{sealed_update_queue, sealed_updates_since, store_sealed_update};
use oneiron::sync::transport::{
    SealedUpdateFrame, decode_sealed_update_frame, encode_sealed_update_frame,
};
use tokio::sync::mpsc::UnboundedSender;

use super::conn_state::ConnState;
use crate::protocol::{self, ProtocolError};
use crate::server::SyncServer;

/// Whether this socket takes sealed updates: its hello listed them, and its
/// machine stands here now as one of the owner's own, on the key it proved.
fn takes_sealed_updates(server: &SyncServer, state: &ConnState) -> bool {
    state.sealed_world_updates
        && crate::auth::owned_machine_stands(server.vault(), state.peer_machine(server.vault()))
}

/// The offer a socket that takes sealed updates gets at connect: the home's
/// queue epoch and head. `None` for any other socket, and when the queue
/// cannot be read (logged; the socket syncs as before).
pub(super) fn offer(server: &SyncServer, conn_id: u32, state: &ConnState) -> Option<Vec<u8>> {
    if !takes_sealed_updates(server, state) {
        return None;
    }
    match sealed_update_queue(server.vault()) {
        Ok(queue) => Some(encode_sealed_update_frame(&SealedUpdateFrame::Offer {
            epoch: queue.epoch,
            head: queue.head,
        })),
        Err(error) => {
            tracing::warn!(conn_id, kind = ?error.kind(), "sealed update queue read failed");
            None
        }
    }
}

/// One sealed update frame from a machine, the bytes after its tag. A frame
/// from a socket that takes none is logged and dropped, as is a store fault:
/// the machine's outbox keeps the update and offers it again.
///
/// # Errors
/// [`ProtocolError::InvalidPayload`] for a frame that does not decode, or one
/// only a home sends.
pub(super) fn handle(
    server: &SyncServer,
    conn_id: u32,
    state: &mut ConnState,
    payload: &[u8],
    direct_tx: &UnboundedSender<Vec<u8>>,
) -> Result<(), ProtocolError> {
    let frame = decode_sealed_update_frame(payload)
        .map_err(|error| ProtocolError::InvalidPayload(protocol::transport_err_msg(error)))?;
    if !takes_sealed_updates(server, state) {
        tracing::warn!(
            conn_id,
            "sealed update frame from a socket that takes none: dropped"
        );
        return Ok(());
    }
    match frame {
        SealedUpdateFrame::Since { epoch, after } => {
            state.sealed_updates_live = true;
            let page = match sealed_updates_since(server.vault(), &epoch, after) {
                Ok(page) => page,
                Err(error) => {
                    tracing::warn!(conn_id, kind = ?error.kind(), "sealed update page read failed");
                    return Ok(());
                }
            };
            for (seq, sealed) in &page.entries {
                let _ = direct_tx.send(encode_sealed_update_frame(&SealedUpdateFrame::PageEntry {
                    epoch: page.epoch,
                    seq: *seq,
                    sealed,
                }));
            }
            let _ = direct_tx.send(encode_sealed_update_frame(&SealedUpdateFrame::CaughtUp {
                epoch: page.epoch,
                through: page.through,
                more: page.more,
            }));
        }
        SealedUpdateFrame::Put { id, sealed } => {
            let stored = match store_sealed_update(server.vault(), &id, sealed) {
                Ok(stored) => stored,
                Err(error) => {
                    tracing::warn!(conn_id, kind = ?error.kind(), "sealed update store failed");
                    return Ok(());
                }
            };
            let _ = direct_tx.send(encode_sealed_update_frame(&SealedUpdateFrame::Stored {
                id,
                epoch: stored.epoch,
                seq: stored.seq,
            }));
            if stored.fresh {
                let entry = encode_sealed_update_frame(&SealedUpdateFrame::Entry {
                    epoch: stored.epoch,
                    seq: stored.seq,
                    sealed,
                });
                let _ = crate::broadcast::broadcast(&server.broadcast_tx, conn_id, entry);
            }
        }
        SealedUpdateFrame::Offer { .. }
        | SealedUpdateFrame::Entry { .. }
        | SealedUpdateFrame::PageEntry { .. }
        | SealedUpdateFrame::CaughtUp { .. }
        | SealedUpdateFrame::Stored { .. } => {
            return Err(ProtocolError::InvalidPayload(
                "a home's sealed update frame from a machine",
            ));
        }
    }
    Ok(())
}

/// A stored update another socket's put pushed, as it leaves this socket:
/// only to a socket that asked for sealed updates and still takes them.
pub(super) fn release(server: &SyncServer, state: &ConnState, frame: Vec<u8>) -> Option<Vec<u8>> {
    (state.sealed_updates_live && takes_sealed_updates(server, state)).then_some(frame)
}
