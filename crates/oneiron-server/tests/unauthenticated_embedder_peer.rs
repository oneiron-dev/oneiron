//! An app made by `build_app` keeps the unauthenticated development hatch on
//! this device, however its embedder serves it (ARCH-0028
//! #unauth-loopback-open). With `allow_unauthenticated` and no `auth_secret`
//! a request with no credential acts as the owner, so a caller off this
//! device by the DEC-0005 rule (a peer off loopback, a connection that
//! recorded no peer, or any forwarding header) is refused 401 before any
//! route. A loopback caller is answered as before, and with a secret set the
//! app answers as it did.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use engine_stack::run_on_engine_stack;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use tower::ServiceExt;

/// An owner read the hatch admits with no credential (`check_legacy_read_auth`).
const OWNER_READ: &str = "/api/search/text?query=anything";
/// The public health route: it takes no credential at all.
const HEALTH: &str = "/api/health";

fn loopback_peer() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 41_000))
}

fn network_peer() -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 10], 41_000))
}

/// The app over a fresh device vault, with `config`.
fn app(config: SyncServerConfig) -> (tempfile::TempDir, Router) {
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = Arc::new(
        oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).expect("open vault"),
    );
    let server = Arc::new(SyncServer::new(vault, config).expect("sync server"));
    (dir, build_app(server))
}

fn hatch() -> SyncServerConfig {
    SyncServerConfig {
        allow_unauthenticated: true,
        ..Default::default()
    }
}

/// The status `app` answers a GET of `uri` with no credential, from `peer`
/// (none: the connection recorded no peer), with `forwarded_for` as an
/// `X-Forwarded-For` header when given.
async fn status_of(
    app: &Router,
    uri: &str,
    peer: Option<SocketAddr>,
    forwarded_for: Option<&str>,
) -> StatusCode {
    let mut request = Request::builder().method("GET").uri(uri);
    if let Some(forwarded_for) = forwarded_for {
        request = request.header("x-forwarded-for", forwarded_for);
    }
    let mut request = request.body(Body::empty()).expect("request");
    if let Some(peer) = peer {
        request.extensions_mut().insert(ConnectInfo(peer));
    }
    app.clone()
        .oneshot(request)
        .await
        .expect("the app answers")
        .status()
}

/// FIXTURE: the owner read needs a credential, so a status other than 401
/// under the hatch is the hatch admitting the caller as the owner.
async fn assert_owner_read_needs_a_credential() {
    let (_dir, closed) = app(SyncServerConfig::default());
    assert_eq!(
        status_of(&closed, OWNER_READ, Some(loopback_peer()), None).await,
        StatusCode::UNAUTHORIZED,
        "FIXTURE: with no secret and the hatch off, the owner read with no credential is refused"
    );
}

#[test]
fn a_hatch_server_refuses_a_caller_off_loopback() {
    run_on_engine_stack("hatch-network-peer", || async {
        assert_owner_read_needs_a_credential().await;
        let (_dir, app) = app(hatch());
        assert_eq!(
            status_of(&app, OWNER_READ, Some(network_peer()), None).await,
            StatusCode::UNAUTHORIZED,
            "a hatch server refuses a caller whose peer is off loopback, before any route"
        );
        assert_eq!(
            status_of(&app, HEALTH, Some(network_peer()), None).await,
            StatusCode::UNAUTHORIZED,
            "a hatch server answers no route at all to a caller off loopback"
        );
    });
}

#[test]
fn a_hatch_server_refuses_a_connection_that_recorded_no_peer() {
    run_on_engine_stack("hatch-no-peer", || async {
        assert_owner_read_needs_a_credential().await;
        let (_dir, app) = app(hatch());
        assert_eq!(
            status_of(&app, OWNER_READ, None, None).await,
            StatusCode::UNAUTHORIZED,
            "a hatch server served with no peer (a plain axum::serve) refuses every caller"
        );
    });
}

#[test]
fn a_hatch_server_refuses_a_forwarded_caller_on_loopback() {
    run_on_engine_stack("hatch-forwarded", || async {
        assert_owner_read_needs_a_credential().await;
        let (_dir, app) = app(hatch());
        assert_eq!(
            status_of(&app, OWNER_READ, Some(loopback_peer()), Some("192.0.2.10")).await,
            StatusCode::UNAUTHORIZED,
            "a proxy on loopback that forwards a caller does not carry the hatch to it"
        );
    });
}

#[test]
fn a_hatch_server_admits_a_loopback_caller_as_before() {
    run_on_engine_stack("hatch-loopback", || async {
        assert_owner_read_needs_a_credential().await;
        let (_dir, app) = app(hatch());
        let status = status_of(&app, OWNER_READ, Some(loopback_peer()), None).await;
        assert_ne!(
            status,
            StatusCode::UNAUTHORIZED,
            "the hatch still admits a loopback caller with no credential"
        );
        assert!(
            status.is_success(),
            "the loopback owner read answers: {status}"
        );
    });
}

#[test]
fn with_a_secret_set_a_caller_off_loopback_is_answered_as_before() {
    run_on_engine_stack("secret-network-peer", || async {
        let (_dir, app) = app(SyncServerConfig {
            auth_secret: Some("embedder-peer-fixture-secret".to_owned()),
            allow_unauthenticated: true,
            ..Default::default()
        });
        assert_eq!(
            status_of(&app, HEALTH, Some(network_peer()), None).await,
            StatusCode::OK,
            "with a secret set, the public health route answers a caller off loopback"
        );
        assert_eq!(
            status_of(&app, HEALTH, None, None).await,
            StatusCode::OK,
            "with a secret set, a connection that recorded no peer is answered too"
        );
    });
}
