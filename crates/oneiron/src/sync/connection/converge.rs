//! Convergence: run_convergence, re_bootstrap, server-frame pump.

use std::collections::BTreeSet;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::sync::client::{SyncClient, SyncEvent};
use crate::sync::queue::QueuedUpdate;

use super::SyncConnection;
use super::session::{
    ConvergenceSession, FullResyncMarker, ITEM11_REBOOTSTRAP_UNREADABLE, MAX_CONVERGENCE_ROUNDS,
    PumpBudget, WsSink, WsSource,
};

impl SyncConnection {
    /// Runs the convergence protocol after queue replay (ARCH-0023b Fig. 2,
    /// ONE-1128).
    ///
    /// Per round: send SyncStep1 (`VV_REQUEST` carrying our VV) for every
    /// not-yet-confirmed window, pump the server's replies (delta `UPDATE`s
    /// and `VV_RESPONSE`s — and our reverse deltas back) through
    /// `handle_server_message`, then check VV equality per window. The queue
    /// is cleared via `clear_through_confirmed` ONLY when ALL replayed
    /// windows are confirmed converged. After `MAX_CONVERGENCE_ROUNDS` unconfirmed
    /// rounds, force a real re-bootstrap (drop Docs + queue, Phase 1-3).
    pub(super) async fn run_convergence(
        &self,
        write: &mut WsSink,
        read: &mut WsSource,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        queued: &[QueuedUpdate],
        force_resync: &BTreeSet<String>,
    ) -> Result<(), String> {
        let mut session = if force_resync.is_empty() {
            ConvergenceSession::from_queued(queued)
        } else {
            ConvergenceSession::from_queued_with_force(queued, force_resync)
        };
        if !self
            .confirm_rounds(write, read, client, event_tx, &mut session, false)
            .await?
        {
            let _ = event_tx.send(SyncEvent::Error(format!(
                "Convergence not confirmed after {MAX_CONVERGENCE_ROUNDS} rounds — \
                 forcing re-bootstrap"
            )));
            // The windows still behind are fetched whole: reloading their durable state
            // would only stall them again.
            let mut refetch = force_resync.clone();
            refetch.extend(session.pending.iter().cloned());
            return self
                .re_bootstrap(write, read, client, event_tx, &refetch)
                .await;
        }
        // The ONLY queue-clear on the convergence path. Every window
        // is VV-confirmed here, so the CONFIRMED variant applies: it
        // also removes delete-bearing rows + their `d:` markers
        // (ONE-1135). If it fails, the rows are replayed (idempotent
        // Loro import) on the next reconnect — retention is the
        // fail-closed side.
        if let Err(e) = self.queue.clear_through_confirmed(session.max_seq) {
            let _ = event_tx.send(SyncEvent::Error(format!(
                "Failed to clear converged queue: {e}"
            )));
        }
        Ok(())
    }

    /// VV rounds over the session's pending windows: `true` once all of them
    /// confirm, `false` when the round budget runs out first.
    async fn confirm_rounds(
        &self,
        write: &mut WsSink,
        read: &mut WsSource,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        session: &mut ConvergenceSession,
        strict: bool,
    ) -> Result<bool, String> {
        loop {
            let frames = session
                .begin_round(client)
                .map_err(|e| format!("Convergence round failed: {e}"))?;
            let Some(frames) = frames else {
                return Ok(false);
            };
            for frame in frames {
                write
                    .send(Message::Binary(frame.into()))
                    .await
                    .map_err(|e| format!("Convergence send failed: {e}"))?;
            }
            self.pump_server_frames(
                read,
                write,
                client,
                event_tx,
                PumpBudget::standard(),
                strict,
            )
            .await?;
            session.note_progress(client);
            if session.all_converged() {
                return Ok(true);
            }
        }
    }

    /// Forces the ARCH-0023b Fig. 2 re-bootstrap on the live connection:
    /// drop in-memory Docs + clear the queue, then re-run the Phase 1-3
    /// initial sync (without the per-connection protocol hello).
    pub(super) async fn re_bootstrap(
        &self,
        write: &mut WsSink,
        read: &mut WsSource,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        force_resync: &BTreeSet<String>,
    ) -> Result<(), String> {
        let frames = self
            .re_bootstrap_local_state(client, force_resync)
            .map_err(|e| format!("Re-bootstrap queue clear failed: {e}"))?;
        // A forced window's replacement retires its queued sends, deletes included, into the
        // window itself: until this re-bootstrap proves the window, `fr:w:` is what makes a later
        // connect, after a restart too, fetch and prove it again.
        let markers: Vec<FullResyncMarker> = force_resync
            .iter()
            .map(|window_key| FullResyncMarker {
                window_key: window_key.clone(),
            })
            .collect();
        self.set_full_resync_markers(&markers)?;
        for frame in frames {
            write
                .send(Message::Binary(frame.into()))
                .await
                .map_err(|e| format!("Re-bootstrap send failed: {e}"))?;
        }
        let received = self
            .pump_server_frames(read, write, client, event_tx, PumpBudget::standard(), true)
            .await?;
        if received == 0 {
            return Err("Re-bootstrap sync timeout".to_string());
        }
        // F25 H17/H21: a reply proves nothing about a given window. The delete
        // rows the queue clear kept are sent again, and every forced or
        // replayed window must be VV-confirmed against this re-bootstrap's
        // own server witness before the caller clears `fr:w:` or says Synced.
        let kept = self.queue.drain_updates().map_err(|e| format!("{e}"))?;
        let sent = self
            .replay_queued_updates(write, client, event_tx, kept)
            .await?;
        let mut session = ConvergenceSession::confirming(&sent, force_resync);
        session.note_progress(client);
        if !session.all_converged()
            && !self
                .confirm_rounds(write, read, client, event_tx, &mut session, true)
                .await?
        {
            return Err(format!(
                "Re-bootstrap not confirmed after {MAX_CONVERGENCE_ROUNDS} rounds"
            ));
        }
        if !sent.is_empty()
            && let Err(e) = self.queue.clear_through_confirmed(session.max_seq)
        {
            let _ = event_tx.send(SyncEvent::Error(format!(
                "Failed to clear converged queue: {e}"
            )));
        }
        self.clear_full_resync_markers(&markers)
    }

    /// The queue clear of every re-bootstrap (`clear_all`). A row a
    /// device-only verdict could not judge was never sent: it and every row
    /// behind it stay queued for a later replay to judge again.
    pub(super) fn clear_queue_for_re_bootstrap(
        &self,
        client: &SyncClient,
    ) -> crate::error::Result<()> {
        let unjudged = self.queue.drain_updates()?.into_iter().find(|update| {
            client.update_verdict(&update.window_key, &update.encoded)
                == crate::sync::window::UpdateVerdict::Uninspectable
        });
        match unjudged {
            Some(update) => self.queue.clear_through(update.seq.saturating_sub(1)),
            None => self.queue.clear_all(),
        }
    }

    /// Local half of the re-bootstrap, shared by the convergence and
    /// queue-overflow paths: clear the queue FIRST (`q:`/`e:` rows only —
    /// the `h:`/`m:`/`x:` families and delete-bearing rows + `d:` markers
    /// survive per ARCH-0038/ONE-1135), then drop the
    /// in-memory Docs and produce fresh Phase 1-2 sync frames. If the queue
    /// clear fails, the docs are left intact and the error propagates —
    /// nothing is half-dropped.
    pub(super) fn re_bootstrap_local_state(
        &self,
        client: &mut SyncClient,
        force_resync: &BTreeSet<String>,
    ) -> crate::error::Result<Vec<Vec<u8>>> {
        if client.config.residence_mode == crate::sync::SyncResidenceMode::Opened {
            return Err(crate::Error::InvariantViolation(
                "opened-item queue cannot use full-window re-bootstrap",
            ));
        }
        self.clear_queue_for_re_bootstrap(client)?;
        let encode = |e| {
            crate::error::Error::sync_engine(crate::error::SyncEngineContext::RebootstrapEncode, e)
        };
        let mut frames = client
            .generate_re_bootstrap_sync_for_windows(force_resync.iter().cloned())
            .map_err(encode)?;
        // Each forced window is fetched whole from the server, which answers with its
        // replacement: the dropped document reloads from the same durable state that could not
        // come level. One whose world the home may not read is not asked of it: the convergence
        // round settles it for this home (FIX 922 item 11).
        let fetched: BTreeSet<String> = force_resync
            .iter()
            .filter(|key| {
                !ITEM11_REBOOTSTRAP_UNREADABLE
                    || crate::sync::types::WindowKey::try_new(key.as_str())
                        .is_none_or(|window| client.home_may_request(&window))
            })
            .cloned()
            .collect();
        frames.extend(client.replacement_requests(&fetched).map_err(encode)?);
        Ok(frames)
    }

    /// Reads server frames until the stream goes quiet (or the frame cap is
    /// hit), feeding each binary frame through `handle_server_message` and
    /// sending any produced responses. Returns the number of binary frames
    /// processed. Protocol errors are surfaced as events, not failures —
    /// fail-closed for the queue: an unconfirmed window simply stays
    /// unconfirmed. A `strict` pump (re-bootstrap) fails on the first one.
    async fn pump_server_frames(
        &self,
        read: &mut WsSource,
        write: &mut WsSink,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
        budget: PumpBudget,
        strict: bool,
    ) -> Result<usize, String> {
        let mut received = 0usize;
        let mut wait = budget.first_frame;
        while received < budget.max_frames {
            let msg = match tokio::time::timeout(wait, read.next()).await {
                // Quiet window elapsed — the burst is over.
                Err(_) => break,
                Ok(msg) => msg,
            };
            match msg {
                Some(Ok(Message::Binary(data))) => {
                    match client.handle_server_message(&data) {
                        Ok(responses) => {
                            // Judged per frame: a device-only flag may turn while an
                            // earlier frame waits on the socket.
                            for resp in responses
                                .into_iter()
                                .filter(|frame| !client.frame_withheld(frame))
                            {
                                write
                                    .send(Message::Binary(resp.into()))
                                    .await
                                    .map_err(|e| format!("Send response failed: {e}"))?;
                            }
                        }
                        Err(e) if strict => return Err(format!("Protocol error: {e}")),
                        Err(e) => {
                            let _ = event_tx.send(SyncEvent::Error(format!("Protocol error: {e}")));
                        }
                    }
                    received += 1;
                    wait = budget.quiet;
                }
                Some(Ok(Message::Ping(data))) => {
                    write
                        .send(Message::Pong(data))
                        .await
                        .map_err(|e| format!("Pong failed: {e}"))?;
                }
                Some(Ok(Message::Pong(_) | Message::Text(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Close(frame))) => {
                    return Err(format!("Server closed connection: {frame:?}"));
                }
                Some(Err(e)) => return Err(format!("WS error: {e}")),
                None => return Err("WS stream ended".to_string()),
            }
        }
        Ok(received)
    }
}
