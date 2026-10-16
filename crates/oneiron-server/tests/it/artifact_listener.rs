//! F02 (H103): ordinary `oneiron serve` serves artifacts on a listener of
//! their own, beside the API. `/api/health` names its port, that port routes
//! `/a/` and no API route, and SIGTERM closes it with the API.
use std::net::TcpStream;

use serde_json::Value;

use super::reopen_after_restart::{oneiron, serve, sigterm, stdout};

#[test]
fn ordinary_serve_answers_artifacts_on_a_port_of_their_own() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let config = dir.path().join("oneiron.toml");
    stdout(oneiron(
        &["init", vault.to_str().unwrap(), "--embedder", "none"],
        &config,
    ));
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let server = serve(&config, port, &dir.path().join("serve.log"));
    let client = reqwest::blocking::Client::new();

    let health: Value = client
        .get(format!("http://127.0.0.1:{port}/api/health"))
        .send()
        .expect("health")
        .json()
        .expect("health JSON");
    let artifact_port = health["artifact_port"]
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
        .unwrap_or_else(|| panic!("health names no artifact port: {health:#}"));
    assert_ne!(artifact_port, port);
    let artifacts = format!("http://127.0.0.1:{artifact_port}");

    // `/a/` routes there: a bundle that does not exist gets the artifact
    // route's own JSON refusal, not the empty answer of an unknown path.
    let missing = client
        .get(format!("{artifacts}/a/missing/"))
        .send()
        .expect("artifact request");
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
    let refusal: Value = missing.json().expect("the artifact route answered");
    assert!(refusal.is_object(), "{refusal}");
    for path in [
        "/api/health",
        "/.well-known/oneiron",
        "/api/core/discover",
        "/api/openapi.json",
    ] {
        let response = client
            .get(format!("{artifacts}{path}"))
            .send()
            .expect("API path on the artifact port");
        assert_eq!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND,
            "{path} answered on the artifact port"
        );
        assert!(
            response.bytes().expect("body").is_empty(),
            "{path} reached a route on the artifact port"
        );
    }

    sigterm(server);
    assert!(
        TcpStream::connect(("127.0.0.1", artifact_port)).is_err(),
        "the artifact listener outlived the daemon"
    );
}
