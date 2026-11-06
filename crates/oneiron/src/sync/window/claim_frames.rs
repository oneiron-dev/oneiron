//! Native optional-copy evidence shared by window-frame senders.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use loro::LoroDoc;

use crate::Vault;
use crate::authority::PeerMachine;
use crate::embed::home_vectors::{HomeClaimDelivery, PreparedHomeClaimSend};
use crate::sync::transport::{TransportError, WindowPadKind};

use super::PreparedWindowPads;

/// A response frame and its original optional-copy evidence travel together.
/// The required bytes can be inspected without turning serialized copies into a grant.
pub struct PreparedSyncFrame {
    frame: Vec<u8>,
    release: Option<WindowClaimCopyRelease>,
}

impl PreparedSyncFrame {
    pub(crate) fn with_release(frame: Vec<u8>, release: Option<WindowClaimCopyRelease>) -> Self {
        Self { frame, release }
    }

    /// Keeps native copy evidence beside an optional candidate until the socket's
    /// final send. The required prefix preserves this envelope's id and offsets.
    pub fn into_socket_parts(mut self) -> (Vec<u8>, Option<(Vec<u8>, WindowClaimCopyRelease)>) {
        let Some(mut release) = self.release.take() else {
            return (self.frame, None);
        };
        release.stage(&mut self.frame);
        if release.suffix.is_empty() {
            return (self.frame, None);
        }
        let mut candidate = self.frame.clone();
        candidate.extend_from_slice(&release.suffix);
        (self.frame, Some((candidate, release)))
    }

    /// Required bytes only. An optional-only continuation has no required bytes.
    pub fn as_bytes(&self) -> &[u8] {
        let required = self
            .release
            .as_ref()
            .map_or(self.frame.len(), |release| release.required_prefix());
        &self.frame[..required]
    }

    /// Takes required bytes only; an optional-only continuation returns empty.
    pub fn into_bytes(mut self) -> Vec<u8> {
        if let Some(release) = &mut self.release {
            release.stage(&mut self.frame);
        }
        self.frame
    }

    pub(crate) fn for_policy(&self) -> &[u8] {
        &self.frame
    }

    pub(crate) fn into_batch_parts(mut self) -> (Vec<u8>, Option<WindowClaimCopyRelease>) {
        if let Some(release) = &mut self.release {
            release.stage(&mut self.frame);
        }
        (self.frame, self.release)
    }

    pub(crate) fn release(mut self, vault: &Vault, peer: PeerMachine) -> Option<Vec<u8>> {
        if let Some(release) = &mut self.release {
            release.stage(&mut self.frame);
            release.recheck(vault, peer);
            if release.retained() {
                self.frame.extend_from_slice(&release.suffix);
            }
        }
        (!self.frame.is_empty()).then_some(self.frame)
    }
}

impl From<Vec<u8>> for PreparedSyncFrame {
    fn from(frame: Vec<u8>) -> Self {
        Self {
            frame,
            release: None,
        }
    }
}

pub(crate) struct WindowClaimCopies {
    window: String,
    payload: Vec<u8>,
    sends: Vec<PreparedHomeClaimSend>,
    abandoned: AtomicBool,
}

impl WindowClaimCopies {
    pub(crate) fn prepare(
        vault: &Vault,
        peer: PeerMachine,
        window: &str,
        payload: Vec<u8>,
        context: Option<&LoroDoc>,
    ) -> Option<(Arc<Self>, Vec<u8>)> {
        let delivery = HomeClaimDelivery {
            window,
            payload: &payload,
        };
        let sends = vault
            .prepare_carried_home_claim_sends(peer, &delivery, context)
            .ok()?;
        let copies = Self {
            window: window.to_owned(),
            payload,
            sends,
            abandoned: AtomicBool::new(false),
        };
        let bytes = copies.encode(vault, peer)?;
        Some((Arc::new(copies), bytes))
    }

    fn current(&self, vault: &Vault, peer: PeerMachine) -> bool {
        let delivery = HomeClaimDelivery {
            window: &self.window,
            payload: &self.payload,
        };
        self.sends
            .iter()
            .all(|send| matches!(send.copy_for(vault, peer, &delivery), Ok(Some(_))))
    }

    fn encode(&self, vault: &Vault, peer: PeerMachine) -> Option<Vec<u8>> {
        let delivery = HomeClaimDelivery {
            window: &self.window,
            payload: &self.payload,
        };
        let mut signed = Vec::with_capacity(self.sends.len());
        for send in &self.sends {
            signed.push(send.copy_for(vault, peer, &delivery).ok()??);
        }
        if signed.is_empty() {
            return None;
        }
        rmp_serde::to_vec(&signed).ok()
    }
}

/// This member's native evidence, not its serialized copy as a later grant.
pub struct WindowClaimCopyRelease {
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
    pub(crate) fn new(copies: Arc<WindowClaimCopies>, required_prefix: usize) -> Self {
        Self {
            copies,
            required_prefix,
            suffix: Vec::new(),
        }
    }

    /// Rechecks the native source and proved recipient after the socket's last
    /// wait. A miss discards only the optional suffix for this delivery.
    pub fn is_current(&self, vault: &Vault, peer: PeerMachine) -> bool {
        self.recheck(vault, peer);
        self.retained()
    }

    pub(crate) fn required_prefix(&self) -> usize {
        self.required_prefix
    }

    pub(crate) fn stage(&mut self, frame: &mut Vec<u8>) {
        self.suffix = frame.split_off(self.required_prefix);
    }

    pub(crate) fn recheck(&self, vault: &Vault, peer: PeerMachine) {
        if !self.copies.current(vault, peer) {
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

impl PreparedWindowPads {
    /// Adds optional copies only within the spare room of the original frames.
    /// Required geometry, receipt binding and frame count stay unchanged.
    pub fn frames_with_claim_copies(
        &self,
        vault: &Vault,
        peer: PeerMachine,
        window: &str,
        sub_tag: u8,
        context: Option<&LoroDoc>,
    ) -> Result<Vec<PreparedSyncFrame>, TransportError> {
        let (required, _) = self.frames(window, sub_tag, None)?;
        let optional = (|| {
            let kind = WindowPadKind::of_sub_tag(sub_tag)?;
            if !matches!(kind, WindowPadKind::Update | WindowPadKind::Replacement) {
                return None;
            }
            let mut envelope = self.envelope(kind, None);
            let (copies, bytes) =
                WindowClaimCopies::prepare(vault, peer, window, envelope.payload.clone(), context)?;
            envelope.home_claim_copies = bytes;
            let frames = envelope.encode_frames(window, sub_tag).ok()?;
            let prefixes = envelope.required_frame_prefixes(&frames).ok()?;
            if frames.len() != required.len()
                || prefixes
                    .iter()
                    .zip(&required)
                    .any(|(prefix, frame)| *prefix != frame.len())
            {
                return None;
            }
            Some(
                frames
                    .into_iter()
                    .zip(prefixes)
                    .map(|(frame, prefix)| PreparedSyncFrame {
                        frame,
                        release: Some(WindowClaimCopyRelease::new(Arc::clone(&copies), prefix)),
                    })
                    .collect(),
            )
        })();
        Ok(optional.unwrap_or_else(|| required.into_iter().map(PreparedSyncFrame::from).collect()))
    }
}
