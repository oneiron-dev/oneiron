//! Object-scoped have/want state on the existing owner-authenticated sync client.

use super::base::SyncClient;
use crate::origin::lfs::{LfsOid, LfsPutOutcome};
use crate::sync::chunks::ChunkDownload;
use crate::sync::transport::{self, TransportError};

impl SyncClient {
    /// Starts one chunk download. The host sends the returned chunk-lane sync frame.
    pub fn begin_lfs_download(&mut self, oid: LfsOid) -> Result<Vec<u8>, TransportError> {
        if self.lfs_download.is_some() {
            return Err(TransportError::InvalidPayload(
                "lfs transfer already active",
            ));
        }
        let transfer = ChunkDownload::new(oid).map_err(storage)?;
        let frame = transport::encode_lfs_chunk_sync(&transfer.initial_request().map_err(storage)?)
            .into_result()?;
        self.lfs_download = Some(transfer);
        self.last_lfs_download = None;
        Ok(frame)
    }

    /// Completed and verified object from the last transfer, never a partial.
    pub fn last_lfs_download(&self) -> Option<LfsPutOutcome> {
        self.last_lfs_download
    }

    /// Cancels the spool. No staged content can become a durable object.
    pub fn cancel_lfs_download(&mut self) {
        self.lfs_download = None;
    }

    pub(super) fn handle_lfs_chunk_reply(
        &mut self,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        let mut transfer = self
            .lfs_download
            .take()
            .ok_or(TransportError::InvalidPayload(
                "unsolicited lfs chunk reply",
            ))?;
        let next = transfer
            .accept(&self.vault, payload, crate::unix_seconds_now())
            .map_err(storage)?;
        if let Some(next) = next {
            let frame = transport::encode_lfs_chunk_sync(&next).into_result()?;
            self.lfs_download = Some(transfer);
            Ok(vec![frame])
        } else {
            self.last_lfs_download = transfer.outcome();
            Ok(Vec::new())
        }
    }
}
fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}
