//! Native optional-copy evidence retained with the actual client frames.

use std::sync::Arc;

use loro::LoroDoc;

use super::SyncClient;
use crate::sync::transport::{TransportError, WindowPadBinding, WindowPadKind};
use crate::sync::window::PreparedWindowPads;
use crate::sync::window::claim_frames::WindowClaimCopies;

pub use crate::sync::window::PreparedSyncFrame;
pub(crate) use crate::sync::window::WindowClaimCopyRelease;

/// One prepared send, including the native tokens its selected members keep
/// until the final write. Probe frames never reserve a queue sequence.
pub(crate) struct PreparedWindowClaimSend {
    prepared: PreparedWindowPads,
    window: String,
    sub_tag: u8,
    copies: Option<Arc<WindowClaimCopies>>,
    encoded_copies: Vec<u8>,
}

impl SyncClient {
    pub(crate) fn prepared_window_reply(
        &self,
        window: &str,
        payload: &[u8],
        context: &LoroDoc,
    ) -> Result<Vec<PreparedSyncFrame>, TransportError> {
        let prepared = self.prepare_window_send(window, payload, Some(context))?;
        let prepared = self.prepare_window_claim_send(
            prepared,
            window,
            crate::sync::transport::window_sub_tags::UPDATE,
            Some(context),
        );
        prepared.reply_frames(self, None, payload)
    }

    pub(crate) fn prepare_window_claim_send(
        &self,
        prepared: PreparedWindowPads,
        window: &str,
        sub_tag: u8,
        context: Option<&LoroDoc>,
    ) -> PreparedWindowClaimSend {
        let mut copies = None;
        let mut encoded_copies = Vec::new();
        if self.config.federation_peer.is_none()
            && let Some(kind) = WindowPadKind::of_sub_tag(sub_tag)
        {
            let payload = prepared.envelope(kind, None).payload;
            if let Some((native, encoded)) =
                WindowClaimCopies::prepare(&self.vault, self.home_peer, window, payload, context)
            {
                copies = Some(native);
                encoded_copies = encoded;
            }
        }
        PreparedWindowClaimSend {
            prepared,
            window: window.to_owned(),
            sub_tag,
            copies,
            encoded_copies,
        }
    }
}

impl PreparedWindowClaimSend {
    pub(crate) fn reply_frames(
        &self,
        client: &SyncClient,
        queue_seq: Option<u64>,
        raw: &[u8],
    ) -> Result<Vec<PreparedSyncFrame>, TransportError> {
        let (frames, _, releases) = self.send_frames(client, queue_seq, raw, false)?;
        Ok(frames
            .into_iter()
            .zip(releases)
            .map(|(frame, release)| PreparedSyncFrame::with_release(frame, release))
            .collect())
    }

    fn encoded_frames(
        &self,
        queue_seq: Option<u64>,
        batched: bool,
    ) -> Result<(Vec<Vec<u8>>, WindowPadBinding, Vec<usize>), TransportError> {
        let kind = WindowPadKind::of_sub_tag(self.sub_tag).ok_or(
            TransportError::InvalidPayload("window frame carries no window bytes"),
        )?;
        let mut envelope = self.prepared.envelope(kind, queue_seq);
        if !self.encoded_copies.is_empty() {
            envelope.home_claim_copies.clone_from(&self.encoded_copies);
            let frames = if batched {
                envelope.encode_batch_frames(&self.window, self.sub_tag)
            } else {
                envelope.encode_frames(&self.window, self.sub_tag)
            };
            if let Ok(frames) = frames
                && let Ok(prefixes) = envelope.required_frame_prefixes(&frames)
            {
                return Ok((frames, envelope.binding(), prefixes));
            }
        }
        // Optional preparation or framing faults keep the ordinary send.
        let (frames, binding) = if batched {
            self.prepared
                .frames_batched(&self.window, self.sub_tag, queue_seq)?
        } else {
            self.prepared
                .frames(&self.window, self.sub_tag, queue_seq)?
        };
        Ok((frames, binding, Vec::new()))
    }

    pub(crate) fn frames(
        &self,
        queue_seq: Option<u64>,
        batched: bool,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        // Optional bytes never alter the original raw batch's selection.
        let (frames, _) = if batched {
            self.prepared
                .frames_batched(&self.window, self.sub_tag, queue_seq)?
        } else {
            self.prepared
                .frames(&self.window, self.sub_tag, queue_seq)?
        };
        Ok(frames)
    }

    pub(crate) fn send_frames(
        &self,
        client: &SyncClient,
        queue_seq: Option<u64>,
        raw: &[u8],
        batched: bool,
    ) -> Result<
        (
            Vec<Vec<u8>>,
            WindowPadBinding,
            Vec<Option<WindowClaimCopyRelease>>,
        ),
        TransportError,
    > {
        let (frames, binding, prefixes) = self.encoded_frames(queue_seq, batched)?;
        let releases = (0..frames.len())
            .map(|index| {
                Some(WindowClaimCopyRelease::new(
                    self.copies.as_ref()?.clone(),
                    *prefixes.get(index)?,
                ))
            })
            .collect();
        client.record_window_frames(
            &self.prepared,
            &self.window,
            self.sub_tag,
            queue_seq,
            raw,
            &frames,
            binding,
            batched,
        );
        Ok((frames, binding, releases))
    }
}
