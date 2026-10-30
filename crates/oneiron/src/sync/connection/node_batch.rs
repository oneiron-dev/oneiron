//! One bounded node proposal batch per sync tick, its window updates and
//! document frames taking turns (FIX 8870), then at most one owed artifact
//! publication part as its own one-member batch (FIX 9575).

use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::Message;

use super::session::WsSink;
use super::{LocalUpdate, SyncConnection};
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
    ) -> Result<Option<(ArtifactPublicationPart, bool)>, String> {
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
                Ok(batch) => write
                    .send(Message::Binary(batch.into()))
                    .await
                    .map_err(|error| error.to_string()),
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
        sent?;
        send_publication_part(write, client, publication).await
    }
}

impl SyncConnection {
    /// Moves the next window update `updates` holds into the batch `frames`
    /// fills, queueing on the way each one no batch sends now. Returns
    /// whether it took one: false once the buffer is empty, or once the next
    /// update waits for the next tick's room.
    fn take_update(
        &self,
        client: &SyncClient,
        opened: bool,
        updates: &mut Vec<LocalUpdate>,
        frames: &mut Vec<Vec<u8>>,
        size: &mut usize,
        full_updates: &mut Vec<LocalUpdate>,
    ) -> Result<bool, String> {
        while let Some(update) = updates.first() {
            match client.update_verdict(&update.window_key, &update.update_bytes) {
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
            // A window the home refused to grant again: the write waits
            // queued, as offline, until a grant or sync-all sends it.
            if !client.residence_granted(&update.window_key) {
                self.queue
                    .push(&update.window_key, &update.update_bytes)
                    .map_err(|error| error.to_string())?;
                updates.remove(0);
                continue;
            }
            // The write goes in its window pad envelope for the home,
            // projected and sealed once (FIX 7107). Check room before
            // reserving a durable sequence. Excess work stays in the
            // buffer for the next tick, never a per-op send; a write no
            // batch holds waits queued for the replay, which sends it
            // frame by frame.
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
            if !candidate
                .iter()
                .all(|frame| super::session::fits_alone(frame))
                || (frames.is_empty() && !super::session::fits_all(frames, *size, &candidate))
            {
                self.queue
                    .push(&update.window_key, &update.update_bytes)
                    .map_err(|error| error.to_string())?;
                updates.remove(0);
                continue;
            }
            if !super::session::fits_all(frames, *size, &candidate) {
                return Ok(false);
            }
            let seq = if opened {
                Some(
                    self.queue
                        .push(&update.window_key, &update.update_bytes)
                        .map_err(|error| error.to_string())?,
                )
            } else {
                None
            };
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
    write: &mut WsSink,
    client: &SyncClient,
    publication: &mut Option<ArtifactPublicationPart>,
) -> Result<Option<(ArtifactPublicationPart, bool)>, String> {
    let Some(part) = publication.take() else {
        return Ok(None);
    };
    if !client.artifact_publication_part_current(&part) {
        return Ok(Some((part, false)));
    }
    let batch = transport::encode_node_batch(std::slice::from_ref(&part.frame))
        .into_result()
        .map_err(|error| error.to_string())?;
    write
        .send(Message::Binary(batch.into()))
        .await
        .map_err(|error| error.to_string())?;
    Ok(Some((part, true)))
}
