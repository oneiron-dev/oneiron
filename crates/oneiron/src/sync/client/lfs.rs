//! Object-scoped have/want state on the existing owner-authenticated sync client.
//!
//! One download runs on a connection at a time; the rest wait their turn in
//! the order they were asked for (FIX 8864), and the oldest starts as the
//! active one completes, fails or is cancelled.

use std::time::Instant;

use super::base::SyncClient;
use crate::origin::lfs::{LfsOid, LfsPutOutcome};
use crate::sync::chunks::ChunkDownload;
use crate::sync::transport::{self, TransportError};

/// A download waiting its turn (CALLS `lfs-chunks queue order`: first asked,
/// first started).
pub(super) struct PendingLfsDownload {
    id: u64,
    oid: LfsOid,
    /// Its caller's own deadline: a download whose turn comes past it is
    /// dropped unstarted. No other clock ends a waiting download.
    deadline: Option<Instant>,
}

impl SyncClient {
    /// Starts one chunk download, or, while another runs, queues it behind
    /// those already waiting (FIX 8864). Returns its id and the chunk-lane
    /// sync frame the host sends now, or `None` while it waits: the frame
    /// that starts it comes back from the reply that ends the one before it.
    /// `deadline` is the caller's own, for a download that waits.
    pub fn begin_lfs_download(
        &mut self,
        oid: LfsOid,
        deadline: Option<Instant>,
    ) -> Result<(u64, Option<Vec<u8>>), TransportError> {
        self.lfs_last_id += 1;
        let id = self.lfs_last_id;
        if self.lfs_download.is_some() {
            self.lfs_waiting
                .push_back(PendingLfsDownload { id, oid, deadline });
            return Ok((id, None));
        }
        let frame = self.start_lfs_download(id, oid)?;
        self.last_lfs_download = None;
        Ok((id, Some(frame)))
    }

    /// Completed and verified object from the last transfer, never a partial.
    pub fn last_lfs_download(&self) -> Option<LfsPutOutcome> {
        self.last_lfs_download
    }

    /// Cancels every download, the active one's spool and each waiting one,
    /// and starts none: a re-bootstrap drops them all. No staged content can
    /// become a durable object.
    pub fn cancel_lfs_download(&mut self) {
        self.lfs_download = None;
        self.lfs_waiting.clear();
    }

    /// Cancels the download `id` (FIX 8864): a waiting one leaves the line;
    /// the active one's spool goes, so no staged content can become a
    /// durable object, and the oldest waiting download starts. Returns the
    /// frame that starts it, which the host sends.
    pub fn cancel_lfs_download_request(
        &mut self,
        id: u64,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        if self
            .lfs_download
            .as_ref()
            .is_some_and(|active| active.request_id() == id)
        {
            self.lfs_download = None;
            return self.start_next_lfs_download();
        }
        self.lfs_waiting.retain(|pending| pending.id != id);
        Ok(None)
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
        let reply = match crate::sync::chunks::decode_chunk_response(payload) {
            Ok(reply) => reply,
            Err(error) => return self.lfs_download_failed(error),
        };
        // A late reply to a download cancelled before this one started is
        // dropped: it never reaches this one, as ids only rise.
        if reply.request() < transfer.request_id() {
            self.lfs_download = Some(transfer);
            return Ok(Vec::new());
        }
        match transfer.accept_reply(&self.vault, reply, crate::unix_seconds_now()) {
            Ok(Some(next)) => {
                let frame = transport::encode_lfs_chunk_sync(&next).into_result()?;
                self.lfs_download = Some(transfer);
                Ok(vec![frame])
            }
            Ok(None) => {
                self.last_lfs_download = transfer.outcome();
                Ok(self.start_next_lfs_download()?.into_iter().collect())
            }
            Err(error) => self.lfs_download_failed(error),
        }
    }

    /// A failed transfer ends as a cancelled one does: the next in line
    /// starts. With none waiting, the failure is the reply's error.
    fn lfs_download_failed(&mut self, error: crate::Error) -> Result<Vec<Vec<u8>>, TransportError> {
        match self.start_next_lfs_download()? {
            Some(frame) => {
                tracing::warn!(%error, "lfs download failed; the next in line starts");
                Ok(vec![frame])
            }
            None => Err(storage(error)),
        }
    }

    fn start_lfs_download(&mut self, id: u64, oid: LfsOid) -> Result<Vec<u8>, TransportError> {
        let transfer = ChunkDownload::new(oid).map_err(storage)?.numbered(id);
        let frame = transport::encode_lfs_chunk_sync(&transfer.initial_request().map_err(storage)?)
            .into_result()?;
        self.lfs_download = Some(transfer);
        Ok(frame)
    }

    /// Starts the oldest waiting download whose caller's deadline has not
    /// passed: its first frame, or `None` when none waits.
    fn start_next_lfs_download(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        while let Some(pending) = self.lfs_waiting.pop_front() {
            if pending
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
            {
                continue;
            }
            return self.start_lfs_download(pending.id, pending.oid).map(Some);
        }
        Ok(None)
    }
}
fn storage(error: crate::Error) -> TransportError {
    TransportError::Storage(error.to_string())
}
