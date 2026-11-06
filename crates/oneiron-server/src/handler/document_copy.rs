//! A marked source's edit notice, delivered to the sockets that hold its
//! document by its copy id (FIX 10730; FIX 7608 slice 4).
//!
//! A home-local edit of a marked snapshot ASSET's document notifies the
//! source id, while a peer that holds only the masked copy subscribed by the
//! copy id. Its delivery runs that subscription's own export of the copy id,
//! as its REQUEST did: the copy lineage, masked, under the copy id, and never
//! the source's text. Nothing raw is relayed; the notice is an invalidation.

use oneiron::EntityId;
use oneiron::sync::transport::{DocumentFrame, document_sub_tags};

use super::conn_state::ConnState;
use super::window_sync::selector_grant_scope;
use crate::server::SyncServer;

/// The frame the subscription `state` holds under the copy id of `doc`'s
/// entity gets for the notice `doc`, when `principal` holds one; `None` for
/// any other notice, and when the export denies it. An export that waited out
/// its turn queues the notice in `retry` again.
pub(super) fn copy_notice_frame(
    server: &SyncServer,
    state: &ConnState,
    doc: &DocumentFrame<'_>,
    principal: &EntityId,
    peer: oneiron::authority::PeerMachine,
    retry: &mut Vec<Vec<u8>>,
) -> Option<Vec<u8>> {
    if doc.kind != document_sub_tags::UPDATE {
        return None;
    }
    let copy = oneiron::sync::selector::repo_document_copy_id(doc.entity).ok()?;
    let request = state
        .documents
        .get(&copy)
        .filter(|request| copy != doc.entity && request.selector.member_ref == *principal)?;
    let exported = crate::server::blocking(|| {
        server.reassert_manager.export_document_for_peer(
            copy,
            selector_grant_scope(),
            &request.selector,
            &request.remote_vv,
            peer,
        )
    });
    match exported {
        Ok(frame) => Some(frame),
        Err(error) => {
            if super::documents::waited_out(&error) {
                retry.extend(super::documents::notice(doc));
            }
            None
        }
    }
}
