//! FIX 4748: a device's sessions while its home is down (owner RULING B,
//! 2026-10-19; ARCH-0023b `#home-down`, `#peer-fetch`).
//!
//! The home served a session when the first frame it sent was its root
//! ([`home_served`]): it admitted this machine's upgrade, took the session's
//! hello and read its own root for it. The countdown and the probe below
//! read that one test.
//!
//! The reconnect loop keeps one [`HomeReach`]. Each home session that ends
//! before the home served it counts: a dial nobody answers, an upgrade or a
//! hello the home refuses, a fault or a close before its root. Once they
//! have counted for [`HOME_DOWN_AFTER_SECS`] in a row, the home is down,
//! said once in the log, and the next sessions go to the machines the peer
//! dialer lists, the standby home first, a failed one giving way to the next
//! at the next attempt. When every listed peer has failed once, one attempt
//! goes to the home again, then the peers once more. A home session the home
//! served resets the count; however that session ends later, it counts
//! nothing.
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
//! reads the home's first frame. A home that opens a connection but serves
//! no sync leaves the peer session running. Once the home serves the probe,
//! the peer session ends and the next connect is the home's; that session
//! replays the queue the peer sessions never cleared, and everything
//! converges at the home.
//!
//! With no peer dialer (no mesh here) nothing in this module moves: the home
//! is never counted down.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;

use crate::sync::SyncPeerDialer;
use crate::sync::client::{SyncClient, SyncClientConfig};
use crate::sync::peer_route::{HOME_DOWN_AFTER_SECS, HOME_PROBE_SECS, HOME_PROBE_TIMEOUT_SECS};
use crate::sync::transport::TAG_SYNC_UPDATE;
use crate::{EntityId, Vault};

/// Whether the far end of a sync session served this machine's sync, read on
/// the first frame it sent the session: its root (`TAG_SYNC_UPDATE`). A home
/// sends its root first only once it has admitted this machine's upgrade and
/// taken the session's hello, and its root read from its own store; a
/// refused upgrade, a refused hello, a fault or a close sends none. The
/// countdown ([`HomeReach`]) and the probe ([`HomeProbe`]) read this test.
pub(super) const fn home_served(first_frame: &[u8]) -> bool {
    matches!(first_frame.first(), Some(&TAG_SYNC_UPDATE))
}

/// Whether the home serves this machine's sync, as the reconnect loop has
/// seen it ([`home_served`]).
#[derive(Debug)]
pub(super) struct HomeReach {
    /// A peer dialer is set: without one the home is never counted down.
    enabled: bool,
    /// When the home sessions began ending unserved, in a row.
    unserved_since: Option<Instant>,
    /// The home is down: sessions go to peers.
    down: bool,
    /// The peers whose session failed to open since the home went down.
    tried: BTreeSet<EntityId>,
}

impl HomeReach {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            unserved_since: None,
            down: false,
            tried: BTreeSet::new(),
        }
    }

    /// Whether the home is counted down now.
    pub(super) fn down(&self) -> bool {
        self.down
    }

    /// The peer the next session dials: `None` while the home is not down,
    /// when no peer may serve, and once each listed peer has failed, when
    /// the next attempt goes to the home and the round starts again.
    pub(super) fn next_peer(&mut self, dialer: Option<&dyn SyncPeerDialer>) -> Option<EntityId> {
        if !self.down {
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

    /// A session to `peer` (or to the home, `None`) opened; `served` says
    /// whether the far end served its sync ([`home_served`]).
    pub(super) fn opened(&mut self, peer: Option<EntityId>, served: bool) {
        if peer.is_none() {
            self.home_session(served);
        }
    }

    /// A session to `peer` (or to the home, `None`) failed to open; `served`
    /// says whether the far end served its sync before it failed. Returns
    /// whether the home was counted down by this failure.
    pub(super) fn failed(&mut self, peer: Option<EntityId>, served: bool) -> bool {
        if let Some(peer) = peer {
            self.tried.insert(peer);
            return false;
        }
        self.home_session(served)
    }

    /// A home session's opening ended. One the home served resets the count
    /// and ends peer mode, said once. Any other counts, the home answering
    /// it or not: once the home has served none for [`HOME_DOWN_AFTER_SECS`]
    /// in a row, it is down, said once. Returns whether this session counted
    /// the home down.
    fn home_session(&mut self, served: bool) -> bool {
        if served {
            self.unserved_since = None;
            self.tried.clear();
            if std::mem::take(&mut self.down) {
                tracing::info!(
                    "device sync: the home serves this machine's sync again; sessions go to it"
                );
            }
            return false;
        }
        let since = *self.unserved_since.get_or_insert_with(Instant::now);
        if !self.enabled || self.down || since.elapsed() < Duration::from_secs(HOME_DOWN_AFTER_SECS)
        {
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

    /// A peer session's probe found the home serving this machine's sync:
    /// the next connect goes to it. The run of unserved sessions stands, so
    /// a home session the home does not serve counts the home down at once.
    pub(super) fn home_returned(&mut self) {
        self.tried.clear();
        if std::mem::take(&mut self.down) {
            tracing::info!("device sync: the home serves a probe; the peer session ends");
        }
    }
}

/// A peer session's probe of the home every [`HOME_PROBE_SECS`]. A home
/// session's probe never fires. Each probe runs as its own task, so the
/// steady loop's other arms never cancel one in flight; dropping the probe
/// stops it.
pub(super) struct HomeProbe {
    /// The vault and the session's configuration, whose home is probed;
    /// `None` for a home session.
    home: Option<(Arc<Vault>, SyncClientConfig)>,
    interval: tokio::time::Interval,
    task: Option<JoinHandle<bool>>,
}

impl HomeProbe {
    /// The probe of a peer session (`peer`) of `vault` over `config`'s home;
    /// one that never fires for a home session.
    pub(super) fn new(peer: bool, vault: &Arc<Vault>, config: &SyncClientConfig) -> Self {
        let period = Duration::from_secs(HOME_PROBE_SECS);
        let mut interval = tokio::time::interval_at(Instant::now() + period, period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Self {
            home: peer.then(|| (Arc::clone(vault), config.clone())),
            interval,
            task: None,
        }
    }

    /// Returns once a probe finds the home serving this machine's sync.
    /// Cancel-safe: a probe in flight runs on in its task, and the cadence
    /// stays.
    pub(super) async fn served(&mut self) {
        let Some((vault, config)) = self.home.as_ref() else {
            return std::future::pending().await;
        };
        loop {
            if let Some(task) = self.task.as_mut() {
                let served = task.await.unwrap_or(false);
                self.task = None;
                if served {
                    return;
                }
            }
            self.interval.tick().await;
            let (vault, config) = (Arc::clone(vault), config.clone());
            self.task = Some(tokio::spawn(async move {
                home_serves_sync(&vault, &config).await
            }));
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

/// Whether the home serves this machine's sync within
/// [`HOME_PROBE_TIMEOUT_SECS`], by [`home_served`] on the first frame of a
/// probe ([`probe_home`]).
async fn home_serves_sync(vault: &Vault, config: &SyncClientConfig) -> bool {
    let probe = tokio::time::timeout(
        Duration::from_secs(HOME_PROBE_TIMEOUT_SECS),
        probe_home(vault, config),
    );
    matches!(probe.await, Ok(Some(true)))
}

/// One probe of the home: a socket opened as a home session's is, on the
/// home's carrier, its upgrade proved the same way, sends the session's own
/// hello and reads the home's first frame. Returns [`home_served`] on that
/// frame, `false` on a close or a read error first, and `None` when no
/// socket opened. The socket closes then; nothing the home sent is applied.
async fn probe_home(vault: &Vault, config: &SyncClientConfig) -> Option<bool> {
    let (request, _, _) = super::handshake::upgrade_request(vault, config, false).ok()?;
    let (mut socket, _) =
        crate::sync::carrier::connect_sync_socket(request, config.mesh_dialer.as_deref())
            .await
            .ok()?;
    socket
        .send(Message::Binary(SyncClient::session_hello(config).into()))
        .await
        .ok()?;
    let served = loop {
        match socket.next().await {
            Some(Ok(Message::Binary(frame))) => break home_served(&frame),
            Some(Ok(Message::Close(_)) | Err(_)) | None => break false,
            Some(Ok(_)) => {}
        }
    };
    let _ = socket.send(Message::Close(None)).await;
    Some(served)
}
