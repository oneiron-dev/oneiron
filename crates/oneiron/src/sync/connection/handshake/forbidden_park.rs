//! The wait of a run whose home refused its credential the socket
//! (MEMBER-SELECTOR-SOCKET): it never redials on that credential, and every
//! local commit made while it waits goes to the durable queue.

use tokio::sync::{mpsc, oneshot, watch};

use super::super::{LocalUpdate, SyncConnection};

impl SyncConnection {
    /// Waits for the run's shutdown or a confirmed leave with the run's sink
    /// still attached, queueing each local update as it arrives, under the
    /// host's admission. The queue is fed from this run's own channel, not
    /// from the sink's no-channel fallback: a served host keeps its relay to
    /// its clients attached beside this run, so with this run detached a
    /// commit would go to that relay alone and never to the queue (round-2
    /// review of #8018). A paused host keeps the updates in `buffer` until
    /// its thaw; the run's end queues what is left.
    pub(super) async fn park_forbidden(
        &self,
        local_rx: &mut mpsc::UnboundedReceiver<LocalUpdate>,
        buffer: &mut Vec<LocalUpdate>,
        shutdown_rx: &mut oneshot::Receiver<()>,
        left_rx: &mut watch::Receiver<bool>,
    ) {
        let mut gate = self.batch_gate();
        loop {
            self.queue_on_exit(&mut gate, buffer).await;
            tokio::select! {
                biased;
                _ = &mut *shutdown_rx => return,
                _ = left_rx.wait_for(|left| *left) => return,
                () = gate.thawed() => {}
                Some(update) = local_rx.recv() => buffer.push(update),
            }
        }
    }
}
