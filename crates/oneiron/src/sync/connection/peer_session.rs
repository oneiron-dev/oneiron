//! FIX 4748: a device's sessions while its home is down (owner RULING B,
//! 2026-10-19; ARCH-0023b `#home-down`, `#peer-fetch`).
//!
//! The reconnect loop keeps one [`HomeReach`]. Each connect to the home that
//! fails before the home answers counts; once they have failed for
//! [`HOME_DOWN_AFTER_SECS`] in a row, the home is down, said once in the log,
//! and the next sessions go to the machines the peer dialer lists, the
//! standby home first, a failed one giving way to the next at the next
//! attempt. When every listed peer has failed once, one attempt goes to the
//! home again, then the peers once more.
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
//! A peer session probes the home every [`HOME_PROBE_SECS`] ([`HomeProbe`]).
//! Once the home answers, the peer session ends and the next connect is the
//! home's; that session replays the queue the peer sessions never cleared,
//! and everything converges at the home.
//!
//! With no peer dialer (no mesh here) nothing in this module moves: the home
//! is never counted down.

use std::collections::BTreeSet;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::EntityId;
use crate::sync::SyncPeerDialer;
use crate::sync::client::SyncClientConfig;
use crate::sync::peer_route::{HOME_DOWN_AFTER_SECS, HOME_PROBE_SECS, HOME_PROBE_TIMEOUT_SECS};

/// Whether the home answers, as the reconnect loop has seen it.
#[derive(Debug)]
pub(super) struct HomeReach {
    /// A peer dialer is set: without one the home is never counted down.
    enabled: bool,
    /// When the dials to the home began failing unanswered, in a row.
    failing_since: Option<Instant>,
    /// The home is down: sessions go to peers.
    down: bool,
    /// The peers whose session failed to open since the home went down.
    tried: BTreeSet<EntityId>,
}

impl HomeReach {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            failing_since: None,
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

    /// A session to `peer` (or to the home, `None`) opened. A home session
    /// ends peer mode, said once.
    pub(super) fn opened(&mut self, peer: Option<EntityId>) {
        if peer.is_some() {
            return;
        }
        self.failing_since = None;
        self.tried.clear();
        if std::mem::take(&mut self.down) {
            tracing::info!("device sync: the home answers again; sessions go to it");
        }
    }

    /// A session to `peer` (or to the home, `None`) failed to open;
    /// `answered` says whether the far end answered the upgrade. Returns
    /// whether the home was counted down by this failure.
    pub(super) fn failed(&mut self, peer: Option<EntityId>, answered: bool) -> bool {
        if let Some(peer) = peer {
            self.tried.insert(peer);
            return false;
        }
        // A home that answers, if only to refuse, is not down.
        if answered {
            self.failing_since = None;
            if std::mem::take(&mut self.down) {
                tracing::info!("device sync: the home answers again; sessions go to it");
            }
            return false;
        }
        let since = *self.failing_since.get_or_insert_with(Instant::now);
        if !self.enabled || self.down || since.elapsed() < Duration::from_secs(HOME_DOWN_AFTER_SECS)
        {
            return false;
        }
        self.down = true;
        tracing::warn!(
            after_secs = HOME_DOWN_AFTER_SECS,
            "device sync: the home has not answered; syncing with this vault's other machines \
             over the mesh until it does"
        );
        true
    }

    /// A peer session's probe found the home answering: the next connect
    /// goes to it. The run of failures stands, so a home connect that fails
    /// again counts the home down at once.
    pub(super) fn home_returned(&mut self) {
        self.tried.clear();
        if std::mem::take(&mut self.down) {
            tracing::info!("device sync: the home answers a probe; the peer session ends");
        }
    }
}

/// A connect that failed, and whether the far end answered the upgrade: a
/// refusal or a fault after the upgrade is an answer; a carrier that never
/// opened, or an upgrade nobody answered, is not.
#[derive(Debug)]
pub(super) struct ConnectError {
    pub(super) answered: bool,
    message: String,
}

impl ConnectError {
    /// A failure before any upgrade answer.
    pub(super) fn unanswered(message: String) -> Self {
        Self {
            answered: false,
            message,
        }
    }
}

impl From<String> for ConnectError {
    /// A failure once the far end answered.
    fn from(message: String) -> Self {
        Self {
            answered: true,
            message,
        }
    }
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// A peer session's probe of the home every [`HOME_PROBE_SECS`]. A home
/// session's probe never fires. Each probe runs as its own task, so the
/// steady loop's other arms never cancel one in flight; dropping the probe
/// stops it.
pub(super) struct HomeProbe {
    /// The home's configuration; `None` for a home session.
    config: Option<SyncClientConfig>,
    interval: tokio::time::Interval,
    task: Option<JoinHandle<bool>>,
}

impl HomeProbe {
    /// The probe of a peer session (`peer`) over `config`'s home carrier;
    /// one that never fires for a home session.
    pub(super) fn new(peer: bool, config: &SyncClientConfig) -> Self {
        let period = Duration::from_secs(HOME_PROBE_SECS);
        let mut interval = tokio::time::interval_at(Instant::now() + period, period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Self {
            config: peer.then(|| config.clone()),
            interval,
            task: None,
        }
    }

    /// Returns once a probe finds the home answering. Cancel-safe: a probe
    /// in flight runs on in its task, and the cadence stays.
    pub(super) async fn answered(&mut self) {
        let Some(config) = self.config.as_ref() else {
            return std::future::pending().await;
        };
        loop {
            if let Some(task) = self.task.as_mut() {
                let answered = task.await.unwrap_or(false);
                self.task = None;
                if answered {
                    return;
                }
            }
            self.interval.tick().await;
            let config = config.clone();
            self.task = Some(tokio::spawn(async move { home_answers(&config).await }));
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

/// Whether the home's carrier opens within [`HOME_PROBE_TIMEOUT_SECS`]: its
/// mesh stream, or TCP to its URL. Nothing is sent on it.
async fn home_answers(config: &SyncClientConfig) -> bool {
    let Ok(request) = config.server_url.as_str().into_client_request() else {
        return false;
    };
    let carrier = crate::sync::carrier::open_carrier(request.uri(), config.mesh_dialer.as_deref());
    matches!(
        tokio::time::timeout(Duration::from_secs(HOME_PROBE_TIMEOUT_SECS), carrier).await,
        Ok(Ok(_))
    )
}
