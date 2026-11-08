//! Ordered NOTE command release; the durable queue retains the logical command.

use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::Message;

use super::session::WsSink;
use super::{LoopExit, SyncConnection};
use crate::side_table::HexId;
use crate::sync::client::SyncClient;
use crate::sync::documents::DS_E;
use crate::sync::transport::{self, document_sub_tags};

impl SyncConnection {
    pub(super) async fn send_document_response(
        &self,
        write: &mut WsSink,
        client: &SyncClient,
        frame: Vec<u8>,
    ) -> Result<(), LoopExit> {
        if frame.first() != Some(&transport::TAG_DOCUMENT)
            || frame.len() <= transport::MAX_DECODED_PAYLOAD_BYTES
        {
            if client.frame_withheld(&frame) {
                return Ok(());
            }
            return self.send_response_frame(write, frame).await;
        }
        let command = transport::decode_unsplit_document(&frame[1..])
            .map_err(|error| LoopExit::Disconnected(error.to_string()))?;
        if command.kind != document_sub_tags::NOTE_OPS {
            return Err(LoopExit::Disconnected(
                "invalid outgoing logical document".into(),
            ));
        }
        let parts = transport::DocumentPartFrames::new(&frame)
            .map_err(|error| LoopExit::Disconnected(error.to_string()))?;
        let mut sent = false;
        for part in parts {
            let subscribed = (|| -> crate::Result<bool> {
                let txn = client.vault.store.env.read_txn()?;
                DS_E.contains(&client.vault.store, &txn, &HexId(command.entity))
            })()
            .map_err(|error| LoopExit::Disconnected(error.to_string()))?;
            if !subscribed || client.frame_withheld(&frame) {
                return if sent {
                    // Drop the home socket's incomplete assembly; QN_E still owes it.
                    Err(LoopExit::Disconnected(
                        "NOTE command release changed".into(),
                    ))
                } else {
                    Ok(())
                };
            }
            self.send_response_frame(write, part).await?;
            sent = true;
        }
        Ok(())
    }

    async fn send_response_frame(
        &self,
        write: &mut WsSink,
        frame: Vec<u8>,
    ) -> Result<(), LoopExit> {
        let mut left = self.left.subscribe();
        tokio::select! {
            biased;
            _ = left.wait_for(|left| *left) => Err(LoopExit::Shutdown),
            sent = write.send(Message::Binary(frame.into())) => {
                sent.map_err(|error| LoopExit::Disconnected(error.to_string()))
            }
        }
    }
}

pub(super) fn response_error(exit: LoopExit) -> String {
    match exit {
        LoopExit::Disconnected(error) => error,
        _ => "sync stopped".into(),
    }
}
