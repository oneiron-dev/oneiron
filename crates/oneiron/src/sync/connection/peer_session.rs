//! FIX 4748: a device's sessions while its home is down (owner RULING B,
//! 2026-10-19; ARCH-0023b `#home-down`, `#peer-fetch`).
//!
//! The home served a session once the session's first round completed: its
//! opening (`SyncConnection::open_sync_session`) applied the home's root
//! and windows, replayed the queue and saw the home take it (vector rounds
//! to convergence, or the home's residence acknowledgments), and said
//! `Synced`.
//! A session that ends before that, by a close or an error, the home did not
//! serve, whatever it sent first.
//!
//! The reconnect loop keeps one [`HomeReach`]. Each home session the home did
//! not serve counts: a dial nobody answers, an upgrade or a hello the home
//! refuses, a window export fault, a queue replay or convergence the home
//! failed, a close before the round completes. Once they have counted for
//! [`HOME_DOWN_AFTER_SECS`] in a row, the home is down, said once in the log,
//! and the next sessions go to the machines the peer dialer lists, the
//! standby home first, a failed one giving way to the next at the next
//! attempt. When every listed peer has failed once, one attempt goes to the
//! home again, then the peers once more. Only a home session the home served
//! resets the count and ends peer mode, said once; however that session ends
//! later, it counts nothing. A home session that fails on a fault of this
//! machine's own instead (FIX 22107: its store or queue, its full-resync
//! markers, an encode, the recovery it needs first; FIX 22153: its store as
//! it applies the home's frames or index; FIX 22217: a carrier it cannot set
//! up for the home's URL) says nothing of the home: it counts nothing,
//! resets nothing, and a turn a probe gave the home stays.
//!
//! A peer session (`SyncClient::peer_session`) exchanges
//! updates both ways as a home session does (queue replay, vector rounds,
//! the steady loop), so each device imports the other's writes. It confirms
//! nothing: no queue row and no document journal row clears on its answers,
//! no document drops, and it never re-bootstraps; where a home session would
//! re-bootstrap, it ends. It sends what the machine the peer proved on the
//! upgrade may read (`SyncClient::home_peer`, the destination every send is
//! judged for), and it takes none of the home's roles: no residence call,
//! directive, home handoff round, machine history, authority catch-up,
//! sealed or leaf-key relay, NOTE authority or publication receipt.
//!
//! A peer session probes the home every [`HOME_PROBE_SECS`] ([`HomeProbe`]):
//! it opens a socket as a home session does, sends the session's hello and
//! reads the home's first frame. The probe only gives the home a turn: once
//! that frame is the home's root ([`first_frame_is_root`]), the peer session
//! ends and the next session is the home's, which replays the queue the peer
//! sessions never cleared, so everything converges at the home. The home
//! stays down through that turn. A turn the far end ends before its round
//! completes sends the next session straight back to a peer, with no new
//! count, so a home that sends its root and then fails costs one failed
//! session per probe, not a gap in sync. A turn this machine's own fault ends
//! stays with the home for the next session (FIX 22107). A probe whose
//! upgrade the home answers with a 403 to the credential it carried ends the
//! peer session too: the home refuses this credential the socket, so the
//! connection stops as on a home dial's 403 and the probe never redials on it
//! (MEMBER-SELECTOR-SOCKET).
//!
//! With no peer dialer (no mesh here) nothing in this module moves: the home
//! is never counted down.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;

use crate::sync::SyncPeerDialer;
use crate::sync::client::{SyncClient, SyncClientConfig, SyncEvent};
use crate::sync::peer_route::{HOME_DOWN_AFTER_SECS, HOME_PROBE_SECS, HOME_PROBE_TIMEOUT_SECS};
use crate::sync::transport::{TAG_ROOT_PART, TAG_SYNC_UPDATE};
use crate::{EntityId, Vault};

use super::session::SessionFault;

/// Whether the first frame the far end sent a session is its root
/// (`TAG_SYNC_UPDATE`, or a large root's first `TAG_ROOT_PART`). A home
/// sends its root first only once it has admitted this machine's upgrade
/// and taken the session's hello, its root read from its own store; a
/// refused upgrade, a refused hello, a fault or a close sends none. It
/// proves no more: a probe that reads it gives the home a turn, and only a
/// completed first round counts the home served ([`HomeReach`]).
const fn first_frame_is_root(first_frame: &[u8]) -> bool {
    matches!(
        first_frame.first(),
        Some(&(TAG_SYNC_UPDATE | TAG_ROOT_PART))
    )
}

/// Whether the home serves this machine's sync, as the reconnect loop has
/// seen it: a home session the home served completed its first round.
#[derive(Debug)]
pub(super) struct HomeReach {
    /// A peer dialer is set: without one the home is never counted down.
    enabled: bool,
    /// When the home sessions began ending unserved, in a row.
    unserved_since: Option<Instant>,
    /// The home is down: sessions go to peers. Only a home session the home
    /// served clears it.
    down: bool,
    /// A peer session's probe received the home's root: the next session is
    /// the home's, the home still down.
    home_turn: bool,
    /// The peers whose session failed to open since the home went down.
    tried: BTreeSet<EntityId>,
}

impl HomeReach {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            unserved_since: None,
            down: false,
            home_turn: false,
            tried: BTreeSet::new(),
        }
    }

    /// Whether the home is counted down now.
    pub(super) fn down(&self) -> bool {
        self.down
    }

    /// The peer the next session dials: `None` while the home is not down,
    /// on the turn a probe gave the home, when no peer may serve, and once
    /// each listed peer has failed, when the next attempt goes to the home
    /// and the round starts again.
    pub(super) fn next_peer(&mut self, dialer: Option<&dyn SyncPeerDialer>) -> Option<EntityId> {
        if !self.down || self.home_turn {
            return None;
        }
        let peers = dialer?.peers();
        let next = peers
            .iter()
            .copied()
            .find(|peer| !self.tried.contains(peer));
        if next.is_none() {
            self.tried.clear();
        }
        next
    }

    /// A session to `peer` (or to the home, `None`) opened. A home session
    /// opens only once its first round completed: the home served it. That
    /// resets the count and ends peer mode, said once; however the session
    /// ends later, it counts nothing.
    pub(super) fn opened(&mut self, peer: Option<EntityId>) {
        if peer.is_some() {
            return;
        }
        self.unserved_since = None;
        self.home_turn = false;
        self.tried.clear();
        if std::mem::take(&mut self.down) {
            tracing::info!(
                "device sync: the home serves this machine's sync again; sessions go to it"
            );
        }
    }

    /// A session to `peer` (or to the home, `None`) ended on `fault` before
    /// its first round completed. A home session the far end failed counts,
    /// the home answering it or not: once the home has served none for
    /// [`HOME_DOWN_AFTER_SECS`] in a row, it is down, said once. A home
    /// already down stays down, said nothing, and the turn a probe gave it
    /// ends here. A home session that failed on this machine's own fault
    /// (FIX 22107) counts nothing, resets nothing and ends no turn. Returns
    /// whether the next session goes to a peer on the first backoff step: the
    /// home was counted down by this session, or its turn failed.
    pub(super) fn failed(&mut self, peer: Option<EntityId>, fault: &SessionFault) -> bool {
        if let Some(peer) = peer {
            self.tried.insert(peer);
            return false;
        }
        if fault.is_local() {
            return false;
        }
        let since = *self.unserved_since.get_or_insert_with(Instant::now);
        let turn = std::mem::take(&mut self.home_turn);
        if self.down {
            return turn;
        }
        if !self.enabled || since.elapsed() < Duration::from_secs(HOME_DOWN_AFTER_SECS) {
            return false;
        }
        self.down = true;
        tracing::warn!(
            after_secs = HOME_DOWN_AFTER_SECS,
            "device sync: the home has served this machine no sync; syncing with this vault's \
             other machines over the mesh until it does"
        );
        true
    }

    /// A peer session's probe received the home's root: the next session is
    /// the home's. The home stays down until a home session completes its
    /// first round; a turn the far end fails sends the next session back to
    /// a peer with no new count.
    pub(super) fn home_returned(&mut self) {
        self.tried.clear();
        self.home_turn = true;
        tracing::debug!("device sync: the home sent a probe its root; the next session tries it");
    }
}

/// What the home answered a peer session's probe that ends the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HomeAnswer {
    /// The home sent the probe its root first: the next session is the
    /// home's (FIX 4748).
    Root,
    /// The home answered the probe's upgrade with a 403 to the credential it
    /// carried: it refuses this credential the socket, so the connection
    /// stops as on a home dial's 403 (MEMBER-SELECTOR-SOCKET).
    Forbidden,
}

/// A peer session's probe of the home every [`HOME_PROBE_SECS`]. A home
/// session's probe never fires. Each probe runs as its own task, so the
/// steady loop's other arms never cancel one in flight; dropping the probe
/// stops it.
pub(super) struct HomeProbe {
    /// The home probed; `None` for a home session.
    home: Option<ProbedHome>,
    interval: tokio::time::Interval,
    task: Option<JoinHandle<Option<HomeAnswer>>>,
}

impl HomeProbe {
    /// The probe of a peer session (`peer`) of `vault` over `config`'s home,
    /// which tells a refused credential on `events`; one that never fires for
    /// a home session.
    pub(super) fn new(
        peer: bool,
        vault: &Arc<Vault>,
        config: &SyncClientConfig,
        events: &mpsc::UnboundedSender<SyncEvent>,
    ) -> Self {
        let period = Duration::from_secs(HOME_PROBE_SECS);
        let mut interval = tokio::time::interval_at(Instant::now() + period, period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Self {
            home: peer.then(|| ProbedHome {
                vault: Arc::clone(vault),
                config: config.clone(),
                events: events.clone(),
            }),
            interval,
            task: None,
        }
    }

    /// Returns the home's answer once a probe gets one that ends the peer
    /// session: its root first, or a 403 to the probe's credential. Any
    /// other outcome probes again on the cadence. Cancel-safe: a probe in
    /// flight runs on in its task, and the cadence stays.
    pub(super) async fn home_answer(&mut self) -> HomeAnswer {
        let Some(home) = self.home.as_ref() else {
            return std::future::pending().await;
        };
        loop {
            if let Some(task) = self.task.as_mut() {
                let answer = task.await.ok().flatten();
                self.task = None;
                if let Some(answer) = answer {
                    return answer;
                }
            }
            self.interval.tick().await;
            let home = home.clone();
            self.task = Some(tokio::spawn(async move { home.answer().await }));
        }
    }
}

impl Drop for HomeProbe {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

/// What one probe of the home needs: the vault that signs its upgrade, the
/// session's configuration, and the sink a refused credential is told on.
#[derive(Clone)]
struct ProbedHome {
    vault: Arc<Vault>,
    config: SyncClientConfig,
    events: mpsc::UnboundedSender<SyncEvent>,
}

impl ProbedHome {
    /// The home's answer to one probe within [`HOME_PROBE_TIMEOUT_SECS`]
    /// ([`Self::probe`]), when it ends the peer session; `None` when no
    /// answer came in time.
    async fn answer(&self) -> Option<HomeAnswer> {
        let probe =
            tokio::time::timeout(Duration::from_secs(HOME_PROBE_TIMEOUT_SECS), self.probe());
        probe.await.ok().flatten()
    }

    /// One probe of the home: a socket opened as a home session's is, on the
    /// home's carrier, its upgrade proved the same way, sends the session's
    /// own hello and reads the home's first frame. Returns
    /// [`HomeAnswer::Root`] when [`first_frame_is_root`] holds on that frame,
    /// and `None` on another first frame, a close or a read error first, or
    /// no socket. The socket closes then; nothing the home sent is applied.
    /// A 401 or 403 on its upgrade is told as the home dial tells it, and the
    /// host asks the home (FIX 12442). A 403 to the credential the upgrade
    /// carried is [`HomeAnswer::Forbidden`]: the home refuses this credential
    /// the socket, and the probe never redials on it (MEMBER-SELECTOR-SOCKET).
    async fn probe(&self) -> Option<HomeAnswer> {
        let (request, binding, _) =
            super::handshake::upgrade_request(&self.vault, &self.config, false).ok()?;
        let carried = super::handshake::upgrade_carries_credential(&request, binding.as_ref());
        let dialer = self.config.mesh_dialer.as_deref();
        let mut socket = match crate::sync::carrier::connect_sync_socket(request, dialer).await {
            Ok((socket, _)) => socket,
            Err(error) => {
                let refusal = crate::sync::carrier::upgrade_refusal(&error, carried)?;
                let _ = self.events.send(refusal.event());
                return (refusal == crate::sync::carrier::UpgradeRefusal::Forbidden)
                    .then_some(HomeAnswer::Forbidden);
            }
        };
        socket
            .send(Message::Binary(
                SyncClient::session_hello(&self.config).into(),
            ))
            .await
            .ok()?;
        let root = loop {
            match socket.next().await {
                Some(Ok(Message::Binary(frame))) => break first_frame_is_root(&frame),
                Some(Ok(Message::Close(_)) | Err(_)) | None => break false,
                Some(Ok(_)) => {}
            }
        };
        let _ = socket.send(Message::Close(None)).await;
        root.then_some(HomeAnswer::Root)
    }
}
