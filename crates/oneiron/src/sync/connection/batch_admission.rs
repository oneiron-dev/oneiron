//! The host's admission for each batch a sync connection applies or sends
//! (FIX 12036), and the pause that keeps its socket open while the host is
//! frozen.
//!
//! A host that sets a [`SyncBatchAdmission`] is asked before each batch: a
//! frame from the home the steady loop applies, a node batch it sends, a
//! promotion request, a housekeeping tick, each upkeep task off the loop,
//! and each connect with its initial sync and queue replay. The guard it
//! answers is held until that batch is done, so a batch in flight when the
//! host freezes finishes as owner work. A `Pause` keeps the socket open: the
//! loop sends and applies nothing, still answers the home's pings, and keeps
//! the frames the home sends meanwhile, in order, for after the thaw, up to
//! [`PAUSED_FRAME_BYTES`]; past that it reads no more and the carrier's
//! flow control holds the home back. The pause has no deadline of its own;
//! steady state has no idle timeout on either side. With no hook every
//! batch is admitted at once.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures_util::SinkExt;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{Bytes, Message};

use crate::sync::client::{SyncClient, SyncEvent, SyncResidenceMode};
use crate::sync::transport::{self, window_sub_tags};
use crate::sync::types::WindowKey;

use super::session::WsSink;
use super::{LocalUpdate, LoopExit, SyncConnection, flush_to_queue};

/// What the host holds for one admitted batch, released as it drops.
pub type SyncBatchGuard = Box<dyn Send>;

/// The host's answer for one batch.
pub enum SyncBatchVerdict {
    /// Admitted: the guard is held until the batch is done.
    Admitted(SyncBatchGuard),
    /// The host is frozen: the connection keeps its socket open and applies
    /// and sends nothing until [`SyncBatchAdmission::thawed`] resolves.
    Pause,
}

/// One admission call in flight.
pub type SyncBatchAdmit<'a> = Pin<Box<dyn Future<Output = SyncBatchVerdict> + Send + 'a>>;

/// One wait for the host's thaw.
pub type SyncBatchThaw<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// The host's admission for each batch a sync connection applies or sends,
/// set with [`SyncConnection::with_batch_admission`].
pub trait SyncBatchAdmission: Send + Sync {
    /// The admission for the next batch, or `Pause` while the host is frozen.
    fn admit(&self) -> SyncBatchAdmit<'_>;

    /// Resolves once the host may admit again. The connection then asks
    /// [`Self::admit`] for its next batch; a host frozen again answers
    /// `Pause` again.
    fn thawed(&self) -> SyncBatchThaw<'_>;
}

/// How many bytes of the home's frames a paused loop keeps for after the
/// thaw before it stops reading: one largest frame.
const PAUSED_FRAME_BYTES: usize = transport::MAX_DECODED_PAYLOAD_BYTES;

/// One loop's side of the host's admission: the pause, its wait for the
/// thaw, and what the pause holds back, in order.
pub(super) struct BatchGate<'a> {
    host: Option<&'a dyn SyncBatchAdmission>,
    /// The wait for the thaw, kept across the loop's turns; `None` while
    /// running.
    thaw: Option<SyncBatchThaw<'a>>,
    /// Frames from the home not yet applied, in arrival order.
    frames: VecDeque<Bytes>,
    frame_bytes: usize,
    /// Promotions asked and not yet sent, in order.
    promotions: VecDeque<WindowKey>,
}

impl<'a> BatchGate<'a> {
    fn new(host: Option<&'a dyn SyncBatchAdmission>) -> Self {
        Self {
            host,
            thaw: None,
            frames: VecDeque::new(),
            frame_bytes: 0,
            promotions: VecDeque::new(),
        }
    }

    /// Whether the host has paused this loop.
    pub(super) fn paused(&self) -> bool {
        self.thaw.is_some()
    }

    /// Whether the loop reads its socket: always while running; while
    /// paused, until the frames held reach [`PAUSED_FRAME_BYTES`].
    pub(super) fn reading(&self) -> bool {
        !self.paused() || self.frame_bytes < PAUSED_FRAME_BYTES
    }

    /// The host's admission for one batch, or `None` while paused. A host
    /// that answers `Pause` pauses the loop until its thaw.
    pub(super) async fn admit(&mut self) -> Option<SyncBatchGuard> {
        if self.paused() {
            return None;
        }
        let Some(host) = self.host else {
            return Some(Box::new(()));
        };
        match host.admit().await {
            SyncBatchVerdict::Admitted(guard) => Some(guard),
            SyncBatchVerdict::Pause => {
                self.thaw = Some(host.thawed());
                None
            }
        }
    }

    /// Resolves once the host thaws, and lifts the pause; never while
    /// running.
    pub(super) async fn thawed(&mut self) {
        match self.thaw.as_mut() {
            Some(thaw) => {
                thaw.await;
                self.thaw = None;
            }
            None => std::future::pending().await,
        }
    }

    /// Keeps `frame` from the home for the loop's head, behind those before it.
    pub(super) fn hold_frame(&mut self, frame: Bytes) {
        self.frame_bytes += frame.len();
        self.frames.push_back(frame);
    }

    /// Keeps a promotion asked for the loop's head, behind those before it.
    pub(super) fn hold_promotion(&mut self, key: WindowKey) {
        self.promotions.push_back(key);
    }

    /// The first frame held, with its admission; `None` while none is held
    /// or the host pauses.
    async fn next_frame(&mut self) -> Option<(SyncBatchGuard, Bytes)> {
        if self.frames.is_empty() {
            return None;
        }
        let guard = self.admit().await?;
        let frame = self.frames.pop_front()?;
        self.frame_bytes = self.frame_bytes.saturating_sub(frame.len());
        Some((guard, frame))
    }

    /// The first promotion held, with its admission; `None` while none is
    /// held or the host pauses.
    async fn next_promotion(&mut self) -> Option<(SyncBatchGuard, WindowKey)> {
        if self.promotions.is_empty() {
            return None;
        }
        let guard = self.admit().await?;
        Some((guard, self.promotions.pop_front()?))
    }
}

/// The admission `host` grants for one round off the loop, its pauses
/// waited out; at once with no host.
pub(super) async fn admit_round(host: Option<&dyn SyncBatchAdmission>) -> SyncBatchGuard {
    let mut gate = BatchGate::new(host);
    loop {
        if let Some(guard) = gate.admit().await {
            return guard;
        }
        gate.thawed().await;
    }
}

impl SyncConnection {
    /// This connection, asking `host` before each batch it applies or sends
    /// and pausing with its socket open while `host` is frozen (FIX 12036).
    #[must_use]
    pub fn with_batch_admission(mut self, host: Arc<dyn SyncBatchAdmission>) -> Self {
        self.batch_admission = Some(host);
        self
    }

    /// The gate one loop asks for its batches.
    pub(super) fn batch_gate(&self) -> BatchGate<'_> {
        BatchGate::new(self.batch_admission.as_deref())
    }

    /// The host's admission for one connect (its dial, initial sync, queue
    /// replay and convergence are one exchange), or for the topology's first
    /// election before it. A paused host is waited out with no socket open;
    /// `None` once `shutdown` or a confirmed leave ends the wait.
    pub(super) async fn admit_or_stop(
        &self,
        shutdown: &mut tokio::sync::oneshot::Receiver<()>,
        left: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Option<SyncBatchGuard> {
        let mut gate = self.batch_gate();
        loop {
            if let Some(guard) = gate.admit().await {
                return Some(guard);
            }
            tokio::select! {
                () = gate.thawed() => {}
                _ = &mut *shutdown => return None,
                _ = left.wait_for(|left| *left) => return None,
            }
        }
    }

    /// The host's admission for one round of a worker beside the loop
    /// (residence directives, home handoff, residence mode), a pause waited
    /// out: the worker ends with the loop, so a stop ends the wait too.
    pub(super) async fn admit_round(&self) -> SyncBatchGuard {
        admit_round(self.batch_admission.as_deref()).await
    }

    /// Queues what the loop buffered as it exits, under the host's admission
    /// when it admits. A paused host's exit queues it all the same: no stop
    /// waits for a thaw, and no buffered update is dropped.
    pub(super) async fn queue_on_exit(
        &self,
        gate: &mut BatchGate<'_>,
        buffer: &mut Vec<LocalUpdate>,
    ) {
        let _queued = if buffer.is_empty() {
            None
        } else {
            gate.admit().await
        };
        flush_to_queue(&self.queue, buffer);
    }

    /// The queue-overflow check between reconnect attempts, under the host's
    /// admission; a paused host leaves it to the next attempt.
    pub(super) async fn admitted_overflow_check(
        &self,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
    ) {
        let Some(_check) = self.batch_gate().admit().await else {
            return;
        };
        self.handle_queue_overflow_check(client, event_tx, self.queue.is_full());
    }

    /// Applies what the gate holds, once running: the home's frames in
    /// order, then the promotions asked, each under its own admission. A
    /// pause keeps the rest for after the thaw.
    pub(super) async fn apply_held(
        &self,
        gate: &mut BatchGate<'_>,
        client: &mut SyncClient,
        write: &mut WsSink,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        machine_history_due: &AtomicBool,
        debounce_buffer: &mut Vec<LocalUpdate>,
    ) -> Result<(), LoopExit> {
        while let Some((_batch, frame)) = gate.next_frame().await {
            self.apply_server_frame(
                &frame,
                client,
                write,
                event_tx,
                machine_history_due,
                debounce_buffer,
            )
            .await?;
        }
        while let Some((_batch, key)) = gate.next_promotion().await {
            self.send_promotion(&key, client, write).await?;
        }
        Ok(())
    }

    /// Applies one frame from the home and sends its answers.
    async fn apply_server_frame(
        &self,
        data: &[u8],
        client: &mut SyncClient,
        write: &mut WsSink,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        machine_history_due: &AtomicBool,
        debounce_buffer: &mut Vec<LocalUpdate>,
    ) -> Result<(), LoopExit> {
        match client.handle_server_message(data) {
            Ok(responses) => {
                if crate::sync::machine_history::take_landed(&client.vault) {
                    machine_history_due.store(true, Ordering::Relaxed);
                }
                // Judged per frame: a device-only flag may turn while an
                // earlier frame waits on the socket.
                for resp in responses
                    .into_iter()
                    .filter(|frame| !client.frame_withheld(frame))
                {
                    let send_result = write.send(Message::Binary(resp.into())).await;
                    if let Err(e) = send_result {
                        return Err(LoopExit::Disconnected(format!("Send failed: {e}")));
                    }
                }
                if client.config.residence_mode == SyncResidenceMode::Opened
                    && !client.residence_acks.is_empty()
                    && let Err(e) = self.clear_residence_acks(client)
                {
                    return Err(LoopExit::Disconnected(e));
                }
            }
            Err(e) => {
                let _ = event_tx.send(SyncEvent::Error(format!("Protocol error: {e}")));
                if matches!(
                    data.first(),
                    Some(&transport::TAG_WINDOW_SYNC)
                        | Some(&transport::TAG_BULK_TRANSFER)
                        | Some(&transport::TAG_BULK_TRANSFER_DONE)
                ) {
                    // A missing causal prefix cannot be repaired by
                    // silently dropping one live delta. Reconnect repeats
                    // the VV handshake for every followed window.
                    flush_to_queue(&self.queue, debounce_buffer);
                    return Err(LoopExit::Disconnected(format!("Window sync error: {e}")));
                }
            }
        }
        Ok(())
    }

    /// Asks the home to promote `key`'s window, and for its vector.
    async fn send_promotion(
        &self,
        key: &WindowKey,
        client: &mut SyncClient,
        write: &mut WsSink,
    ) -> Result<(), LoopExit> {
        if client.config.residence_mode != SyncResidenceMode::Opened {
            return Ok(());
        }
        // A home that may not read the window's world is not asked to promote it,
        // nor for its vector; the `rp:w:` intent stays (FIX 922 item 11).
        if !client.home_may_promote(key) || !client.home_may_request(key) {
            return Ok(());
        }
        let Some(selector) = client.config.residence_selector.as_ref() else {
            return Err(LoopExit::Disconnected(
                "promoted window missing grant selector".into(),
            ));
        };
        let bytes = crate::sync::encode_sync_selector(selector)
            .map_err(|e| LoopExit::Disconnected(format!("promotion selector: {e}")))?;
        let proof =
            transport::encode_window_sync(key.as_str(), window_sub_tags::PROMOTION_REQUEST, &bytes)
                .into_result()
                .map_err(|e| LoopExit::Disconnected(e.to_string()))?;
        let window = client
            .ensure_window(key.as_str())
            .map_err(|e| LoopExit::Disconnected(e.to_string()))?;
        let vv = transport::encode_window_sync(
            key.as_str(),
            window_sub_tags::VV_REQUEST,
            &crate::sync::loro_support::doc_version_vector(&window.doc),
        )
        .into_result()
        .map_err(|e| LoopExit::Disconnected(e.to_string()))?;
        for frame in [proof, vv] {
            if let Err(e) = write.send(Message::Binary(frame.into())).await {
                return Err(LoopExit::Disconnected(e.to_string()));
            }
        }
        Ok(())
    }
}
