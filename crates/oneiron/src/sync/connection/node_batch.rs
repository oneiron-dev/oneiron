//! One bounded node proposal batch per sync tick, its window updates and
//! document frames taking turns (FIX 8870), then at most one owed artifact
//! publication part as its own one-member batch (FIX 9575). A window write
//! larger than a batch keeps its buffered head and sends ordered parts over
//! later ticks (FIX 786).

use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::Message;

use super::session::WsSink;
use super::{LocalUpdate, LoopExit, SyncConnection};
use crate::artifact_hosting::ArtifactPublicationPart;
use crate::side_table::HexId;
use crate::sync::client::{SyncClient, SyncResidenceMode};
use crate::sync::documents::DS_E;
use crate::sync::transport::{self, TransportError, window_sub_tags};
use crate::sync::window::UpdateVerdict;

pub(super) fn fits(frames: &[Vec<u8>], size: usize, next: &[u8]) -> Result<bool, TransportError> {
    let total = size.saturating_add(4).saturating_add(next.len());
    if frames.is_empty() && total > transport::MAX_DECODED_PAYLOAD_BYTES {
        return Err(TransportError::FrameTooLarge {
            size: total,
            max: transport::MAX_DECODED_PAYLOAD_BYTES,
        });
    }
    Ok(frames.len() < transport::MAX_NODE_BATCH_MEMBERS
        && total <= transport::MAX_DECODED_PAYLOAD_BYTES)
}

/// Which lane leads the next tick's batch (FIX 8870). The window update lane
/// and the document lane take turns, one update or one document each, and
/// lead ticks in turn, so sustained traffic on one never starves the other:
/// a buffered edit waits on the edits before it in its own lane only, never
/// on the other lane's traffic, and that bound is its deadline. Each lane
/// keeps its own order.
#[derive(Debug, Default)]
pub(super) struct NodeBatchTurn {
    documents_lead: bool,
    // Only take_update removes the buffered head; these frames belong to it.
    pending: Option<PendingWindowUpdate>,
}

#[derive(Debug)]
struct PendingWindowUpdate {
    frames: std::collections::VecDeque<Vec<u8>>,
    binding: transport::WindowPadBinding,
    first_id: Option<[u8; 32]>,
}

fn forget_pending(
    client: &SyncClient,
    window_key: &str,
    pending: &mut Option<PendingWindowUpdate>,
) {
    if let Some(pending) = pending.take() {
        client.forget_window_send(window_key, &pending.binding, pending.first_id);
    }
}

impl SyncConnection {
    pub(super) async fn flush_node_batch(
        &self,
        write: &mut WsSink,
        client: &SyncClient,
        updates: &mut Vec<LocalUpdate>,
        documents: &mut Vec<Vec<u8>>,
        publication: &mut Option<ArtifactPublicationPart>,
        turn: &mut NodeBatchTurn,
    ) -> Result<Option<(ArtifactPublicationPart, bool)>, LoopExit> {
        let opened = client.config.residence_mode == SyncResidenceMode::Opened;
        let mut frames = Vec::new();
        let mut size = 1;
        let mut full_updates = Vec::new();
        let mut documents_next = turn.documents_lead;
        turn.documents_lead = !turn.documents_lead;
        let prepared = (|| -> Result<(), String> {
            let (mut updates_open, mut documents_open) = (true, true);
            while updates_open || documents_open {
                if (documents_next && documents_open) || !updates_open {
                    documents_open = take_document(client, documents, &mut frames, &mut size)?;
                } else {
                    updates_open = self.take_update(
                        client,
                        opened,
                        updates,
                        &mut frames,
                        &mut size,
                        &mut full_updates,
                        &mut turn.pending,
                    )?;
                }
                documents_next = !documents_next;
            }
            Ok(())
        })();
        let sent = match prepared {
            Err(error) => Err(error),
            Ok(()) if frames.is_empty() => Ok(()),
            Ok(()) => match transport::encode_node_batch(&frames).into_result() {
                Err(error) => Err(error.to_string()),
                Ok(batch) => {
                    let mut left = self.left.subscribe();
                    tokio::select! {
                        biased;
                        _ = left.wait_for(|left| *left) => {
                            self.publish_leave_unqueued(&mut full_updates);
                            return Err(LoopExit::Shutdown);
                        }
                        sent = write.send(Message::Binary(batch.into())) => {
                            sent.map_err(|error| error.to_string())
                        }
                    }
                }
            },
        };
        if sent.is_err() {
            // Opened writes already have durable sequences. Full-window writes
            // keep the original reconnect/VV-confirmation recovery contract.
            for update in full_updates {
                if let Err(error) = self.queue.push(&update.window_key, &update.update_bytes) {
                    tracing::error!(%error, "failed to queue unsent node write");
                }
            }
            // Documents remain in their own durable journal until the home ACK.
        }
        sent.map_err(LoopExit::Disconnected)?;
        send_publication_part(self, write, client, publication).await
    }
}

impl SyncConnection {
    /// Moves the next window update into the batch. An unfinished multipart
    /// send stays at the head until all its frames have been selected.
    fn take_update(
        &self,
        client: &SyncClient,
        opened: bool,
        updates: &mut Vec<LocalUpdate>,
        frames: &mut Vec<Vec<u8>>,
        size: &mut usize,
        full_updates: &mut Vec<LocalUpdate>,
        pending: &mut Option<PendingWindowUpdate>,
    ) -> Result<bool, String> {
        while let Some(update) = updates.first() {
            let verdict = client.update_verdict(&update.window_key, &update.update_bytes);
            let granted =
                verdict == UpdateVerdict::Portable && client.residence_granted(&update.window_key);
            if verdict != UpdateVerdict::Portable || !granted {
                let interrupted = pending.is_some();
                forget_pending(client, &update.window_key, pending);
                if interrupted {
                    // The home may hold a prefix. Ending this socket drops
                    // its connection-local assembly instead of orphaning it.
                    return Err("multipart window release changed".to_owned());
                }
            }
            match verdict {
                UpdateVerdict::Withheld => {
                    updates.remove(0);
                    continue;
                }
                UpdateVerdict::Uninspectable => {
                    self.queue
                        .push(&update.window_key, &update.update_bytes)
                        .map_err(|error| error.to_string())?;
                    updates.remove(0);
                    continue;
                }
                UpdateVerdict::Portable => {}
            }
            // A refused window keeps the same offline/regrant recovery path.
            if !granted {
                self.queue
                    .push(&update.window_key, &update.update_bytes)
                    .map_err(|error| error.to_string())?;
                updates.remove(0);
                continue;
            }
            if pending.is_none() {
                let sub_tag = if opened {
                    window_sub_tags::RESIDENCE_UPDATE
                } else {
                    window_sub_tags::UPDATE
                };
                let context = client.window(&update.window_key);
                let ready = client
                    .prepare_window_send(
                        &update.window_key,
                        &update.update_bytes,
                        context.as_ref().map(|window| &window.doc),
                    )
                    .map_err(|error| error.to_string())?;
                let (candidate, _) = ready
                    .frames(&update.window_key, sub_tag, opened.then_some(1))
                    .map_err(|error| error.to_string())?;
                let multipart = !super::session::fits_all(&[], 1, &candidate);
                if !multipart && !super::session::fits_all(frames, *size, &candidate) {
                    return Ok(false);
                }
                drop(candidate);
                if multipart {
                    let (candidate, _) = ready
                        .frames_batched(&update.window_key, sub_tag, opened.then_some(1))
                        .map_err(|error| error.to_string())?;
                    if !fits(frames, *size, &candidate[0]).map_err(|error| error.to_string())? {
                        return Ok(false);
                    }
                }
                // The probe's sequence has the same fixed-size encoding.
                // Only the actual send reserves and registers a sequence.
                let seq = if opened {
                    Some(
                        self.queue
                            .push(&update.window_key, &update.update_bytes)
                            .map_err(|error| error.to_string())?,
                    )
                } else {
                    None
                };
                if multipart {
                    let (members, binding) = client
                        .window_send_batch_frames(
                            &ready,
                            &update.window_key,
                            sub_tag,
                            seq,
                            &update.update_bytes,
                        )
                        .map_err(|error| error.to_string())?;
                    let first_id = members.first().and_then(|first| {
                        transport::decode_window_sync(&first[1..])
                            .ok()
                            .and_then(|(_, _, payload)| transport::window_pad_frame_id(payload))
                    });
                    *pending = Some(PendingWindowUpdate {
                        frames: members.into(),
                        binding,
                        first_id,
                    });
                } else {
                    let members = client
                        .window_send_frames(
                            &ready,
                            &update.window_key,
                            sub_tag,
                            seq,
                            &update.update_bytes,
                        )
                        .map_err(|error| error.to_string())?;
                    for frame in members {
                        *size += 4 + frame.len();
                        frames.push(frame);
                    }
                }
            }
            if let Some(partial) = pending.as_mut() {
                while let Some(frame) = partial.frames.front() {
                    if !fits(frames, *size, frame).map_err(|error| error.to_string())? {
                        return Ok(false);
                    }
                    let frame = partial
                        .frames
                        .pop_front()
                        .expect("pending frame was just read");
                    *size += 4 + frame.len();
                    frames.push(frame);
                }
            }
            *pending = None;
            let update = updates.remove(0);
            if !opened {
                full_updates.push(update);
            }
            return Ok(true);
        }
        Ok(false)
    }
}

/// Moves the next document frame `documents` holds into the batch `frames`
/// fills, dropping on the way each one no longer subscribed or now withheld.
/// Returns whether it took one: false once the buffer is empty, or once the
/// next frame waits for the next tick's room.
fn take_document(
    client: &SyncClient,
    documents: &mut Vec<Vec<u8>>,
    frames: &mut Vec<Vec<u8>>,
    size: &mut usize,
) -> Result<bool, String> {
    while let Some(frame) = documents.first() {
        let doc = transport::decode_document(&frame[1..]).map_err(|error| error.to_string())?;
        let subscribed = {
            let txn = client
                .vault
                .store
                .env
                .read_txn()
                .map_err(|error| error.to_string())?;
            doc.kind == transport::document_sub_tags::ARTIFACT_PUBLICATION
                || DS_E
                    .contains(&client.vault.store, &txn, &HexId(doc.entity))
                    .map_err(|error| error.to_string())?
        };
        if !subscribed || client.frame_withheld(frame) {
            documents.remove(0);
            continue;
        }
        if !fits(frames, *size, frame).map_err(|error| error.to_string())? {
            return Ok(false);
        }
        *size += 4 + frame.len();
        frames.push(documents.remove(0));
        return Ok(true);
    }
    Ok(false)
}

/// Sends the owed publication part `publication` holds, if any, as its own
/// one-member batch, once it is still owed and not withheld; returns it, and
/// whether the socket took it. A part dropped unsent is a change since
/// replaced or settled, whose debt stays in the outbox.
async fn send_publication_part(
    connection: &SyncConnection,
    write: &mut WsSink,
    client: &SyncClient,
    publication: &mut Option<ArtifactPublicationPart>,
) -> Result<Option<(ArtifactPublicationPart, bool)>, LoopExit> {
    let Some(part) = publication.take() else {
        return Ok(None);
    };
    if !client.artifact_publication_part_current(&part) {
        return Ok(Some((part, false)));
    }
    let batch = transport::encode_node_batch(std::slice::from_ref(&part.frame))
        .into_result()
        .map_err(|error| LoopExit::Disconnected(error.to_string()))?;
    let mut left = connection.left.subscribe();
    tokio::select! {
        biased;
        _ = left.wait_for(|left| *left) => Err(LoopExit::Shutdown),
        sent = write.send(Message::Binary(batch.into())) => {
            sent.map_err(|error| LoopExit::Disconnected(error.to_string()))?;
            Ok(Some((part, true)))
        }
    }
}
