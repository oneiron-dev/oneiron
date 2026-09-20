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
fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}
