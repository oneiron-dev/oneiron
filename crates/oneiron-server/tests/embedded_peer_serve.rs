#![cfg(all(oneiron_test_support, feature = "mesh"))]
//! The macOS app's mesh peer path (L7-47, RULING L7-47-PR2-TESTS = A).
//!
//! PR2 carries exactly these three tests, over one vault each: with a mesh bind the app's
//! listener offers the sync ALPN alone and its server serves as a peer; with no bind the device
//! sync still starts over the home URL with no listener and no peer dialer; and the link has a
//! peer dialer exactly when its listener runs. The two-machine serve/ask proof is FIX-LIST row
//! [MESH-TWO-MACHINE-PEER-E2E], not these tests.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test embedded_peer_serve`.

use std::future::Future;
use std::net::SocketAddr;

use oneiron::sync::mesh_path::SYNC_ALPN;
use oneiron_server::ENGINE_THREAD_STACK_BYTES;
use oneiron_server::test_doors::embedded_peer_fixture::enrolled_device;
use oneiron_server::test_doors::embedded_peer_path::{
    has_peer_dialer, listener_alpns, serves_as_peer, start_on_mesh_bind,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

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

#[test]
fn embedded_device_with_a_mesh_bind_serves_sync_alone_as_a_peer() -> TestResult {
    on_engine_stack(serves_sync_alone_as_a_peer)
}

async fn serves_sync_alone_as_a_peer() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, config) = enrolled_device(dir.path())?;
    let bind: SocketAddr = "127.0.0.1:0".parse()?;
    let sync = start_on_mesh_bind(vault, &config, Some(bind))
        .await
        .ok_or("the device sync did not start: the fixture's enrolment must dial a home")?;
    assert_eq!(
        listener_alpns(&sync),
        Some(vec![SYNC_ALPN.to_vec()]),
        "with a mesh bind the Mac app's listener offers the sync ALPN alone"
    );
    assert!(
        serves_as_peer(&sync),
        "with a mesh bind the Mac app's server serves as a peer, not as the elected home"
    );
    sync.stop().await;
    Ok(())
}

#[test]
fn embedded_device_without_a_mesh_bind_has_no_listener_and_no_peer_dialer() -> TestResult {
    on_engine_stack(no_bind_has_no_listener_and_no_peer_dialer)
}

async fn no_bind_has_no_listener_and_no_peer_dialer() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, config) = enrolled_device(dir.path())?;
    let sync = start_on_mesh_bind(vault, &config, None)
        .await
        .ok_or("the device sync did not start: the fixture's enrolment must dial a home")?;
    assert!(
        listener_alpns(&sync).is_none(),
        "with no mesh bind the Mac app starts no listener"
    );
    assert!(
        !has_peer_dialer(&sync),
        "with no mesh bind the Mac app's link has no peer dialer"
    );
    sync.stop().await;
    Ok(())
}

#[test]
fn embedded_device_has_a_peer_dialer_exactly_when_its_listener_runs() -> TestResult {
    on_engine_stack(peer_dialer_matches_listener)
}

async fn peer_dialer_matches_listener() -> TestResult {
    let bound_dir = tempfile::tempdir()?;
    let (bound_vault, bound_config) = enrolled_device(bound_dir.path())?;
    let bind: SocketAddr = "127.0.0.1:0".parse()?;
    let bound = start_on_mesh_bind(bound_vault, &bound_config, Some(bind))
        .await
        .ok_or("the device sync did not start: the fixture's enrolment must dial a home")?;
    let plain_dir = tempfile::tempdir()?;
    let (plain_vault, plain_config) = enrolled_device(plain_dir.path())?;
    let plain = start_on_mesh_bind(plain_vault, &plain_config, None)
        .await
        .ok_or("the device sync did not start: the fixture's enrolment must dial a home")?;
    assert_eq!(
        has_peer_dialer(&bound),
        listener_alpns(&bound).is_some(),
        "with a mesh bind the Mac app's link has a peer dialer exactly when its listener runs"
    );
    assert_eq!(
        has_peer_dialer(&plain),
        listener_alpns(&plain).is_some(),
        "with no mesh bind the Mac app's link has a peer dialer exactly when its listener runs"
    );
    assert!(
        listener_alpns(&bound).is_some() && has_peer_dialer(&bound),
        "with a mesh bind the Mac app has both a listener and a peer dialer"
    );
    bound.stop().await;
    plain.stop().await;
    Ok(())
}
