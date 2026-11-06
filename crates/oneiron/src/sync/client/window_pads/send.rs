//! Native optional-copy evidence retained with the actual client frames.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use loro::LoroDoc;

use super::SyncClient;
use crate::embed::home_vectors::{HomeClaimDelivery, PreparedHomeClaimSend};
use crate::sync::transport::{TransportError, WindowPadBinding, WindowPadKind};
use crate::sync::window::PreparedWindowPads;

struct WindowClaimCopies {
    window: String,
    payload: Vec<u8>,
    sends: Vec<PreparedHomeClaimSend>,
    abandoned: AtomicBool,
}

impl WindowClaimCopies {
    fn current(&self, client: &SyncClient) -> bool {
        let delivery = HomeClaimDelivery {
            window: &self.window,
            payload: &self.payload,
        };
        self.sends.iter().all(|send| {
            matches!(
                send.copy_for(&client.vault, client.home_peer, &delivery),
                Ok(Some(_))
            )
        })
    }

    fn encode(&self, client: &SyncClient) -> Option<Vec<u8>> {
        let delivery = HomeClaimDelivery {
            window: &self.window,
            payload: &self.payload,
        };
        let mut signed = Vec::with_capacity(self.sends.len());
        for send in &self.sends {
            signed.push(
                send.copy_for(&client.vault, client.home_peer, &delivery)
                    .ok()??,
            );
        }
        if signed.is_empty() {
            return None;
        }
        rmp_serde::to_vec(&signed).ok()
    }
}

/// This member's native evidence, not its serialized copy as a later grant.
pub(crate) struct WindowClaimCopyRelease {
    copies: Arc<WindowClaimCopies>,
    required_prefix: usize,
    suffix: Vec<u8>,
}

impl std::fmt::Debug for WindowClaimCopyRelease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowClaimCopyRelease")
            .field("required_prefix", &self.required_prefix)
            .finish_non_exhaustive()
    }
}

impl WindowClaimCopyRelease {
    pub(crate) fn required_prefix(&self) -> usize {
        self.required_prefix
    }

    pub(crate) fn stage(&mut self, frame: &mut Vec<u8>) {
        self.suffix = frame.split_off(self.required_prefix);
    }

    pub(crate) fn recheck(&self, client: &SyncClient) {
        if !self.copies.current(client) {
            self.abandon();
        }
    }

    pub(crate) fn abandon(&self) {
        self.copies.abandoned.store(true, Ordering::Relaxed);
    }

    pub(crate) fn retained(&self) -> bool {
        !self.copies.abandoned.load(Ordering::Relaxed)
    }

    pub(crate) fn added_bytes(&self) -> usize {
        self.suffix.len() + if self.adds_member() { 4 } else { 0 }
    }

    pub(crate) fn adds_member(&self) -> bool {
        self.required_prefix == 0 && !self.suffix.is_empty()
    }

    pub(crate) fn append(&mut self, index: usize, frames: &mut Vec<Vec<u8>>) {
        if self.suffix.is_empty() || !self.retained() {
            return;
        }
        if self.required_prefix == 0 {
            frames.insert(index, std::mem::take(&mut self.suffix));
        } else {
            frames[index].extend_from_slice(&self.suffix);
        }
    }
}

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
            let delivery = HomeClaimDelivery {
                window,
                payload: &payload,
            };
            if let Ok(sends) =
                self.vault
                    .prepare_carried_home_claim_sends(self.home_peer, &delivery, context)
            {
                let native = WindowClaimCopies {
                    window: window.to_owned(),
                    payload,
                    sends,
                    abandoned: AtomicBool::new(false),
                };
                if let Some(encoded) = native.encode(self) {
                    copies = Some(Arc::new(native));
                    encoded_copies = encoded;
                }
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
                Some(WindowClaimCopyRelease {
                    copies: self.copies.as_ref()?.clone(),
                    required_prefix: *prefixes.get(index)?,
                    suffix: Vec::new(),
                })
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
