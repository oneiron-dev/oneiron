//! Document import and durable local-journal confirmation on the one socket.
use super::SyncClient;
use crate::sync::transport::{self, DocumentFrame, TransportError, document_sub_tags};

impl SyncClient {
    pub(super) fn handle_document_frame(
        &self,
        frame: DocumentFrame<'_>,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        let doc = self
            .manager
            .documents()
            .open(frame.entity)
            .map_err(storage)?;
        if doc.is_note().map_err(storage)? {
            if self.config.note_session.is_none() || !self.note_session_bound {
                return Err(TransportError::InvalidPayload(
                    "NOTE authority session is not bound",
                ));
            }
            match frame.kind {
                document_sub_tags::STATE | document_sub_tags::UPDATE => {
                    crate::note::import_note_from_authority(
                        &self.vault,
                        frame.entity,
                        frame.kind,
                        frame.payload,
                    )
                    .map_err(storage)?;
                    self.report_note_document(frame.entity).map_err(storage)?;
                    let mut out = vec![
                        transport::encode_document(
                            frame.entity,
                            document_sub_tags::ACK,
                            &doc.version_vector().map_err(storage)?,
                        )
                        .into_result()?,
                    ];
                    out.extend(
                        self.manager
                            .documents()
                            .pending_note_requests(frame.entity)
                            .map_err(storage)?,
                    );
                    return Ok(out);
                }
                document_sub_tags::NOTE_RECEIPT => {
                    let receipt = serde_json::from_slice(frame.payload)
                        .map_err(|_| TransportError::InvalidPayload("invalid NOTE receipt"))?;
                    self.manager
                        .documents()
                        .accept_note_receipt(frame.entity, &receipt)
                        .map_err(storage)?;
                    return Ok(Vec::new());
                }
                document_sub_tags::ACK => return Ok(Vec::new()),
                _ => {
                    return Err(TransportError::InvalidPayload(
                        "invalid NOTE authority frame",
                    ));
                }
            }
        }
        match frame.kind {
            document_sub_tags::ACK => {
                doc.acknowledge(frame.payload).map_err(storage)?;
                Ok(Vec::new())
            }
            document_sub_tags::STATE | document_sub_tags::UPDATE => {
                doc.import(frame.kind, frame.payload).map_err(storage)?;
                let mut out = vec![
                    transport::encode_document(
                        frame.entity,
                        document_sub_tags::ACK,
                        &doc.version_vector().map_err(storage)?,
                    )
                    .into_result()?,
                ];
                out.extend(doc.pending_frames().map_err(storage)?);
                Ok(out)
            }
            _ => Err(TransportError::InvalidPayload(
                "server sent document request",
            )),
        }
    }
}
impl SyncClient {
    /// A document-only change to a NOTE reaches live queries as its entity
    /// path in the NOTE's learned window.
    fn report_note_document(&self, note: crate::EntityId) -> crate::Result<()> {
        let Some(raw) = self.vault.get_raw(&note)? else {
            return Ok(());
        };
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(crate::Error::CorruptedIndex("entity header"))?;
        let window = crate::sync::WindowKey::from_timestamp(header.learned_at);
        self.manager.materializer().notify_live_queries(
            &format!("w:{window}"),
            &crate::sync::bridge::MaterializedDiffSummary {
                containers: vec![format!("w:{window}/entities/{}", note.to_hex())],
                bytes: 0,
            },
            &crate::sync::bridge::OriginMark {
                conn_id: None,
                origin: Some(crate::sync::bridge::BRIDGE_ORIGIN.to_owned()),
            },
        );
        Ok(())
    }

    /// An own device's NOTE client subscribes every NOTE row it holds on the
    /// owner lane: at connect, then each row born here or materialized from
    /// a window.
    pub(super) fn owner_note_requests(&self) -> Result<Vec<Vec<u8>>, TransportError> {
        if self.config.federation_peer.is_some() || self.config.note_session.is_none() {
            return Ok(Vec::new());
        }
        self.manager
            .documents()
            .subscribe_owner_notes()
            .map_err(storage)
    }
}

fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}
