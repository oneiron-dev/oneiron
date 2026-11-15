//! A home's HTTP 403 to a sync upgrade is a typed stop
//! (FIX-LIST [MEMBER-SELECTOR-SOCKET]): the home accepted the credential and
//! refuses that credential the socket, so the connection tells its host
//! `SyncEvent::UpgradeForbidden` once and never redials on it. It waits for
//! its shutdown instead. A 401 and any other failed upgrade still redial with
//! backoff, as before, and so does a 403 to an upgrade that carried no
//! credential: it refuses nothing the device holds (Astra review of #8018).
//! A 403 that names its reason in `oneiron-upgrade-refusal` is told with it
//! (MEMBER-SYNC-WORLD-PACT = C): a member lane under a world-bounded pact is
//! refused as `WorldBoundedPact`, so the member sees why its lane never runs.
//! While it waits, a local commit goes to the durable queue, never to a
//! channel nobody reads; and a peer session's probe of the home that gets the
//! 403 ends that session, so the probe never redials on it either (round-1
//! review of #8018, P1 1 and P1 2).
//!
//! Each case runs a real reconnecting `SyncConnection` against a fake home on
//! a loopback port that answers every upgrade with one fixed HTTP status and
//! counts the upgrades it was sent. A loopback `ws` home admits credentials
//! (FIX 11111), so a configured bearer token rides each upgrade.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! sync_upgrade_forbidden`; the probe case reaches the probe through
//! `oneiron::test_doors::home_probe`.
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oneiron::sync::bridge::Materializer;
use oneiron::sync::connection::{ConnectionConfig, SyncConnection};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::sync::{SyncClientConfig, SyncEvent, SyncQueue};
use oneiron::{Vault, VaultConfig};

/// How long each connection runs before its shutdown: dozens of backoff
/// steps at the steps below.
const RUN_WINDOW: Duration = Duration::from_millis(1_500);

/// The bearer token a credentialed device's upgrades carry.
const DEVICE_TOKEN: &str = "owen-device-token";

/// The window a commit made while the run waits lands in.
const PARKED_WINDOW: &str = "2026-02";

/// The sync upgrades a fake home was sent.
#[derive(Default)]
struct Upgrades {
    /// Every WebSocket upgrade request.
    sent: AtomicUsize,
    /// The ones that carried an `Authorization` header.
    credentialed: AtomicUsize,
}

/// A fake home on a loopback port that answers every request with `status`
/// (an HTTP status line's code and reason) and counts the WebSocket upgrade
/// requests among them. When `extra_header` is `Some`, the answer carries one
/// extra header line `name: value` (wire strings, not engine constants).
/// Returns its sync URL and the counts (MEMBER-SYNC-WORLD-PACT = C: the typed
/// 403 names its reason in `oneiron-upgrade-refusal`).
fn refusing_home(
    status: &'static str,
    extra_header: Option<(&'static str, &'static str)>,
) -> (String, Arc<Upgrades>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake home");
    let url = format!(
        "ws://{}/ws",
        listener.local_addr().expect("fake home address")
    );
    let upgrades = Arc::new(Upgrades::default());
    let counted = Arc::clone(&upgrades);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            while !request.windows(4).any(|end| end == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => request.extend_from_slice(&buf[..read]),
                }
            }
            if !request.windows(4).any(|end| end == b"\r\n\r\n") {
                continue;
            }
            let head = String::from_utf8_lossy(&request).to_ascii_lowercase();
            if head.contains("upgrade: websocket") {
                counted.sent.fetch_add(1, Ordering::SeqCst);
                if head.contains("authorization:") {
                    counted.credentialed.fetch_add(1, Ordering::SeqCst);
                }
            }
            let answer = match extra_header {
                Some((name, value)) => format!(
                    "HTTP/1.1 {status}\r\n{name}: {value}\r\nContent-Length: 0\r\nConnection: \
                     close\r\n\r\n"
                ),
                None => {
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                }
            };
            let _ = stream.write_all(answer.as_bytes());
            let _ = stream.flush();
        }
    });
    (url, upgrades)
}

/// What one run against a refusing home saw.
struct Run {
    /// The upgrades the home was sent.
    upgrades: usize,
    /// The upgrades among them that carried a credential.
    credentialed: usize,
    /// Every event the host was told, by its `Debug` form.
    events: Vec<String>,
}

impl Run {
    fn told(&self, event: &str) -> usize {
        self.events.iter().filter(|told| *told == event).count()
    }
}

/// A reconnecting connection of `manager` to the home at `url`, on short
/// backoff steps. Its upgrades carry [`DEVICE_TOKEN`] when `credentialed`,
/// else none.
fn reconnecting_connection(
    manager: Arc<WindowManager>,
    url: String,
    credentialed: bool,
) -> SyncConnection {
    SyncConnection::new(
        manager,
        ConnectionConfig {
            client_config: SyncClientConfig {
                server_url: url,
                auth_token: if credentialed {
                    DEVICE_TOKEN.to_owned()
                } else {
                    String::new()
                },
                reconnect_initial_ms: 20,
                reconnect_backoff_max_ms: 40,
                ..SyncClientConfig::default()
            },
            auto_reconnect: true,
        },
    )
    .expect("connection")
}

/// Runs a reconnecting connection against a home answering `status` for
/// [`RUN_WINDOW`], then shuts it down; the run must end on that shutdown.
/// Its upgrades carry [`DEVICE_TOKEN`] when `credentialed`, else none. When
/// `extra_header` is `Some`, the home's answer carries that header line
/// (MEMBER-SYNC-WORLD-PACT = C: the typed 403 names its reason).
async fn run_against(
    status: &'static str,
    credentialed: bool,
    extra_header: Option<(&'static str, &'static str)>,
) -> Run {
    let (url, upgrades) = refusing_home(status, extra_header);
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    let manager = Arc::new(WindowManager::new(
        vault,
        Arc::new(Materializer::new()),
        "owen",
    ));
    let connection = reconnecting_connection(manager, url, credentialed);
    let (stop, shutdown) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        tokio::time::sleep(RUN_WINDOW).await;
        let _ = stop.send(());
    });
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    // The variant this fix adds is matched by its `Debug` form, so this file
    // also builds on the tree before the fix and fails there by behaviour.
    let run = connection.run_observed(shutdown, move |event: SyncEvent| {
        sink.lock().expect("event sink").push(format!("{event:?}"));
    });
    tokio::time::timeout(RUN_WINDOW + Duration::from_secs(20), run)
        .await
        .expect("the run ends on its shutdown")
        .expect("the run ends cleanly");
    let events = events.lock().expect("event sink").clone();
    Run {
        upgrades: upgrades.sent.load(Ordering::SeqCst),
        credentialed: upgrades.credentialed.load(Ordering::SeqCst),
        events,
    }
}

/// Polls `done` every 20 ms for up to 10 s; whether it held by then.
async fn wait_until(mut done: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    done()
}

/// The rows of window `window` that `queue` holds.
fn queued_in(queue: &SyncQueue, window: &str) -> usize {
    queue
        .drain_updates()
        .expect("read the sync queue")
        .iter()
        .filter(|update| update.window_key == window)
        .count()
}

/// Runs the future `case` makes on a thread with room for the engine's sync
/// futures; the future is made on that thread.
fn on_sync_runtime<F, Fut>(name: &str, case: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()>,
{
    let run = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime")
                .block_on(case());
        })
        .expect("test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn a_forbidden_upgrade_is_told_once_and_never_redialed() {
    on_sync_runtime("forbidden_upgrade", || async {
        let run = run_against("403 Forbidden", true, None).await;
        assert_eq!(
            run.credentialed, run.upgrades,
            "the device's upgrades carry its credential"
        );
        assert_eq!(
            run.upgrades, 1,
            "a 403 refuses the credential the socket: the connection never redials on it \
             (events: {:?})",
            run.events
        );
        assert_eq!(
            run.told("UpgradeForbidden { reason: None }"),
            1,
            "the host is told the 403 once, as its own event (events: {:?})",
            run.events
        );
        assert_eq!(
            run.told("UpgradeUnauthorized"),
            0,
            "a 403 is not told as a 401"
        );
    });
}

#[test]
fn an_unauthorized_upgrade_still_redials() {
    on_sync_runtime("unauthorized_upgrade", || async {
        let run = run_against("401 Unauthorized", true, None).await;
        assert!(
            run.upgrades >= 3,
            "a 401 redials with backoff as before: {} upgrades",
            run.upgrades
        );
        // The last upgrade may be in flight when the shutdown lands.
        assert!(
            run.told("UpgradeUnauthorized") + 1 >= run.upgrades,
            "each 401 is told: {} upgrades, events {:?}",
            run.upgrades,
            run.events
        );
        assert_eq!(
            run.told("UpgradeForbidden { reason: None }"),
            0,
            "a 401 is not told as a 403"
        );
    });
}

#[test]
fn a_failing_home_still_redials() {
    on_sync_runtime("failing_home", || async {
        let run = run_against("503 Service Unavailable", true, None).await;
        assert!(
            run.upgrades >= 3,
            "any other failed upgrade redials with backoff as before: {} upgrades",
            run.upgrades
        );
        assert_eq!(run.told("UpgradeForbidden { reason: None }"), 0);
        assert_eq!(run.told("UpgradeUnauthorized"), 0);
    });
}

#[test]
fn a_forbidden_upgrade_without_a_credential_still_redials() {
    on_sync_runtime("forbidden_uncredentialed_upgrade", || async {
        let run = run_against("403 Forbidden", false, None).await;
        assert_eq!(run.credentialed, 0, "the device holds no credential");
        assert!(
            run.upgrades >= 3,
            "a 403 to an upgrade that carried no credential refuses nothing this device \
             holds: it redials with backoff ({} upgrades, events {:?})",
            run.upgrades,
            run.events
        );
        assert_eq!(
            run.told("UpgradeForbidden { reason: None }"),
            0,
            "no credential was refused, so none is told"
        );
    });
}

#[test]
fn a_world_bounded_pact_refusal_is_told_with_its_reason() {
    on_sync_runtime("world_bounded_pact_refusal", || async {
        let run = run_against(
            "403 Forbidden",
            true,
            Some(("oneiron-upgrade-refusal", "world-bounded-pact")),
        )
        .await;
        assert_eq!(
            run.credentialed, run.upgrades,
            "the device's upgrades carry its credential"
        );
        assert_eq!(
            run.upgrades, 1,
            "a typed 403 refuses the credential the socket: the connection never redials on it \
             (events: {:?})",
            run.events
        );
        assert_eq!(
            run.told("UpgradeForbidden { reason: Some(WorldBoundedPact) }"),
            1,
            "the host is told the typed 403 once, with its reason (MEMBER-SYNC-WORLD-PACT = C) \
             (events: {:?})",
            run.events
        );
        assert_eq!(
            run.told("UpgradeForbidden { reason: None }"),
            0,
            "the typed refusal is not told as an untyped one"
        );
        assert_eq!(
            run.told("UpgradeUnauthorized"),
            0,
            "a 403 is not told as a 401"
        );
    });
}

#[test]
fn a_commit_made_while_the_run_waits_on_a_403_is_queued_at_once() {
    on_sync_runtime("forbidden_wait_commit", || async {
        let (url, upgrades) = refusing_home("403 Forbidden", None);
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            Arc::new(Materializer::new()),
            "owen",
        ));
        let window = manager
            .open_window(&WindowKey::new(PARKED_WINDOW))
            .expect("open the window");
        let queue = SyncQueue::new(Arc::clone(&vault)).expect("the sync queue");
        let connection = reconnecting_connection(manager, url, true);
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        let run = connection.run_observed(shutdown, move |event: SyncEvent| {
            sink.lock().expect("event sink").push(format!("{event:?}"));
        });
        let waiting = async {
            let refused = wait_until(|| {
                events
                    .lock()
                    .expect("event sink")
                    .iter()
                    .any(|told| told == "UpgradeForbidden { reason: None }")
            })
            .await;
            let before = queued_in(&queue, PARKED_WINDOW);
            window
                .doc
                .get_map("parked_commits")
                .insert("commit", "made while the run waits")
                .expect("a local edit");
            window.doc.commit();
            let queued = wait_until(|| queued_in(&queue, PARKED_WINDOW) > before).await;
            let _ = stop.send(());
            (refused, before, queued)
        };
        let (ran, (refused, before, queued)) =
            tokio::join!(tokio::time::timeout(Duration::from_secs(60), run), waiting);
        ran.expect("the run ends on its shutdown")
            .expect("the run ends cleanly");
        assert!(refused, "the home's 403 is told");
        assert_eq!(
            upgrades.sent.load(Ordering::SeqCst),
            1,
            "the run never redials on the refused credential"
        );
        assert!(
            queued,
            "a commit made while the run waits on a refused credential goes to the durable \
             queue at once, never to a channel nobody reads ({before} rows of the window \
             queued before it)"
        );
        assert_eq!(
            queued_in(&queue, PARKED_WINDOW),
            before + 1,
            "the commit is queued once, and the run's end adds no copy"
        );
    });
}

#[cfg(oneiron_test_support)]
#[test]
fn a_peer_sessions_home_probe_ends_on_a_403() {
    use oneiron::sync::peer_route::HOME_PROBE_SECS;
    on_sync_runtime("forbidden_home_probe", || async {
        let (url, upgrades) = refusing_home("403 Forbidden", None);
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
        let config = SyncClientConfig {
            server_url: url,
            auth_token: DEVICE_TOKEN.to_owned(),
            ..SyncClientConfig::default()
        };
        // The first probe goes one probe period in; the wait leaves room for
        // a second one.
        let wait = Duration::from_secs(2 * HOME_PROBE_SECS + 5);
        let (answer, events) =
            oneiron::test_doors::home_probe::home_answer_within(&vault, &config, wait).await;
        assert_eq!(
            answer.as_deref(),
            Some("Forbidden"),
            "a 403 to the probe's credential ends the peer session: the home refuses this \
             credential the socket ({} upgrades, events {events:?})",
            upgrades.sent.load(Ordering::SeqCst)
        );
        assert_eq!(
            upgrades.sent.load(Ordering::SeqCst),
            1,
            "the probe never redials on the refused credential"
        );
        assert_eq!(
            events
                .iter()
                .filter(|told| *told == "UpgradeForbidden { reason: None }")
                .count(),
            1,
            "the host is told the 403 once (events: {events:?})"
        );
    });
}
