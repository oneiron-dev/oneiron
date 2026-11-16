#![cfg(all(oneiron_test_support, feature = "mesh"))]
//! serve as a device of another home serves its peers the root its link learned (FIX-LIST
//! SERVE-DEVICE-PEER-STALE-ROOT).
//!
//! serve's link to its home imports the home's root into its own doc and persists it to `d:root`,
//! while the server serve builds loaded `d:root` once, at start. These tests run the server serve
//! builds over an enrolled device vault (`commands::build_server`), its link started as serve
//! starts it (`DeviceSyncHost::start`, no mesh; the home is a loopback port no one listens on),
//! and stand in for the link's import by persisting a root that names a window the home added,
//! as `persist_link_learned_window` does for the macOS app's tests (`embedded_peer_serve`).
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test serve_device_peer_root`.

use std::future::Future;
use std::sync::Arc;

use oneiron_server::ENGINE_THREAD_STACK_BYTES;
use oneiron_server::test_doors::embedded_peer_fixture::enrolled_device;
use oneiron_server::test_doors::embedded_peer_path::persist_link_learned_window;
use oneiron_server::test_doors::serve_device_link::{
    ServedDeviceLink, persisted_root_windows, root_windows, root_windows_after,
    start_served_device_link,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The window the home adds after serve started, which the link learns.
const LEARNED: &str = "2019-04";
/// A window serve's own server opens afterwards.
const OPENED: &str = "2019-05";

/// Runs `test` on a multi-thread runtime whose threads have the engine's
/// stack, driven from a thread that has it too, as the server's binary runs.
fn on_engine_stack<F, Fut>(test: F) -> TestResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = TestResult>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(test())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        // A failed assertion fails the test with its own message.
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// serve over a fresh enrolled device vault, its link opened and serving as a peer, its root
/// naming no [`LEARNED`] window yet; with the root snapshot it served at that point.
async fn started_device(
    dir: &std::path::Path,
) -> TestResult<(Arc<oneiron::Vault>, ServedDeviceLink, Vec<u8>)> {
    let (vault, config) = enrolled_device(dir)?;
    let served = start_served_device_link(Arc::clone(&vault), &config).await?;
    assert!(
        served.linked(),
        "serve's link to the fixture's enrolled home opens (its home is down, so it only dials)"
    );
    assert!(
        served.serves_as_peer(),
        "serve as a device of another home serves the vault's other machines as a peer"
    );
    let start = served.served_root_snapshot()?;
    assert!(
        !root_windows(&start, None)?.iter().any(|key| key == LEARNED),
        "a fresh device's server names no window {LEARNED}"
    );
    Ok((vault, served, start))
}

#[test]
fn served_device_serves_its_peers_a_window_its_link_learned_after_start() -> TestResult {
    on_engine_stack(serves_a_window_learned_after_start)
}

async fn serves_a_window_learned_after_start() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, served, start) = started_device(dir.path()).await?;
    persist_link_learned_window(&vault, LEARNED)?;
    let snapshot = served.served_root_snapshot()?;
    assert!(
        root_windows(&snapshot, None)?
            .iter()
            .any(|key| key == LEARNED),
        "serve's server names to a new peer a window its link learned after start"
    );
    let updates = served.served_root_updates_since(&start)?;
    assert!(
        root_windows(&start, Some(&updates))?
            .iter()
            .any(|key| key == LEARNED),
        "serve's server sends a peer holding its start root the window its link learned since"
    );
    served.stop().await;
    Ok(())
}

#[test]
fn served_device_keeps_a_link_learned_window_across_its_own_root_write() -> TestResult {
    on_engine_stack(keeps_a_learned_window_across_its_own_root_write)
}

async fn keeps_a_learned_window_across_its_own_root_write() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, served, _start) = started_device(dir.path()).await?;
    persist_link_learned_window(&vault, LEARNED)?;
    // The server adds a window of its own to its root and persists the root.
    served.open_window(OPENED).await?;
    assert!(
        persisted_root_windows(&vault)?
            .iter()
            .any(|key| key == LEARNED),
        "serve's own root write keeps in d:root the window its link persisted"
    );
    let snapshot = served.served_root_snapshot()?;
    let windows = root_windows(&snapshot, None)?;
    assert!(
        windows.iter().any(|key| key == LEARNED) && windows.iter().any(|key| key == OPENED),
        "serve's server names to a peer both the window its link learned and the one it opened: \
         {windows:?}"
    );
    served.stop().await;
    Ok(())
}

#[test]
fn served_device_sends_its_open_sockets_the_window_its_link_learned() -> TestResult {
    on_engine_stack(sends_open_sockets_the_learned_window_and_its_own)
}

async fn sends_open_sockets_the_learned_window_and_its_own() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, served, start) = started_device(dir.path()).await?;
    // A socket open since the start root: it holds that root and receives each update sent.
    let mut socket = served.subscribe_root_notices();
    persist_link_learned_window(&vault, LEARNED)?;
    served.open_window(OPENED).await?;
    let updates = socket.drain();
    let windows = root_windows_after(&start, updates.iter().map(Vec::as_slice))?;
    assert!(
        windows.iter().any(|key| key == LEARNED) && windows.iter().any(|key| key == OPENED),
        "a socket open since start learns from serve's root updates both the window its link \
         learned and the one it opened after: {windows:?} from {} updates",
        updates.len()
    );
    served.stop().await;
    Ok(())
}
