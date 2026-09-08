//! Session types: WS aliases, pump budget, convergence session, resync markers.

use std::collections::BTreeSet;
use std::time::Duration;

use futures_util::stream::{SplitSink, SplitStream};
use tokio_tungstenite::tungstenite::Message;

use crate::sync::client::SyncClient;
use crate::sync::loro_support::doc_version_vector;
use crate::sync::queue::QueuedUpdate;
use crate::sync::transport::TransportError;
use crate::sync::transport::{self, window_sub_tags};

/// Maximum convergence rounds before forcing re-bootstrap
/// (ARCH-0023b Fig. 2: "Max 5 rounds before force re-bootstrap").
pub(super) const MAX_CONVERGENCE_ROUNDS: u32 = 5;

pub(super) const FULL_RESYNC_MARKER_PREFIX: &str = "fr:w:";

pub(super) const EPHEMERAL_HOUSEKEEPING_INTERVAL_SECS: u64 = 1;

pub(super) type WsSink = SplitSink<WsStream, Message>;

pub(super) type WsSource = SplitStream<WsStream>;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Read-budget for one server-frame pump: how long to wait for the first
/// frame, how long a quiet gap ends the pump, and a frame cap.
pub(super) struct PumpBudget {
    pub(super) first_frame: Duration,
    pub(super) quiet: Duration,
    pub(super) max_frames: usize,
}

impl PumpBudget {
    /// Matches the initial-sync loop: 30 s for the first frame, 200 ms quiet
    /// window, 100-frame cap.
    pub(super) fn standard() -> Self {
        Self {
            first_frame: Duration::from_secs(30),
            quiet: Duration::from_millis(200),
            max_frames: 100,
        }
    }
}

/// Tracks which replayed windows still need VV-confirmed convergence and
/// enforces the round budget (ARCH-0023b Fig. 2, ONE-1128).
pub(super) struct ConvergenceSession {
    /// Replayed windows not yet VV-confirmed by the server.
    pub(super) pending: BTreeSet<String>,
    /// Windows with `fr:w:` markers. VV equality cannot prove these safe, so
    /// they intentionally remain pending until the round budget forces
    /// re-bootstrap.
    pub(super) force_resync: BTreeSet<String>,
    /// Highest queue sequence covered by this replay — the
    /// `clear_through_confirmed` bound once ALL windows are confirmed.
    pub(super) max_seq: u64,
    /// Rounds started so far.
    pub(super) rounds_started: u32,
}

impl ConvergenceSession {
    pub(super) fn from_queued(queued: &[QueuedUpdate]) -> Self {
        Self::from_queued_with_force(queued, &BTreeSet::new())
    }

    pub(super) fn from_queued_with_force(
        queued: &[QueuedUpdate],
        force_resync: &BTreeSet<String>,
    ) -> Self {
        let mut pending: BTreeSet<String> = queued.iter().map(|u| u.window_key.clone()).collect();
        pending.extend(force_resync.iter().cloned());
        let max_seq = queued.iter().map(|u| u.seq).max().unwrap_or(0);
        Self {
            pending,
            force_resync: force_resync.clone(),
            max_seq,
            rounds_started: 0,
        }
    }

    /// Starts the next convergence round: returns SyncStep1 `VV_REQUEST`
    /// frames (carrying our VV) for every pending window, or `None` once the
    /// `MAX_CONVERGENCE_ROUNDS` budget is exhausted (→ force re-bootstrap).
    pub(super) fn begin_round(
        &mut self,
        client: &mut SyncClient,
    ) -> Result<Option<Vec<Vec<u8>>>, TransportError> {
        if self.rounds_started >= MAX_CONVERGENCE_ROUNDS {
            return Ok(None);
        }
        self.rounds_started += 1;
        let mut frames = Vec::with_capacity(self.pending.len());
        for key in &self.pending {
            let window = client.ensure_window(key)?;
            frames.push(
                transport::encode_window_sync(
                    key,
                    window_sub_tags::VV_REQUEST,
                    &doc_version_vector(&window.doc),
                )
                .into_result()?,
            );
        }
        Ok(Some(frames))
    }

    /// Drops every pending window whose local doc is now VV-identical to a
    /// server-witnessed VV. `None` (no witness yet) is fail-closed: NOT
    /// converged.
    pub(super) fn note_progress(&mut self, client: &SyncClient) {
        let force_resync = &self.force_resync;
        self.pending
            .retain(|key| force_resync.contains(key) || client.window_converged(key) != Some(true));
    }

    pub(super) fn all_converged(&self) -> bool {
        self.pending.is_empty()
    }
}

#[derive(Debug, Clone)]
pub(super) struct FullResyncMarker {
    pub(super) key: String,
    pub(super) window_key: String,
}
