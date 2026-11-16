#![cfg(oneiron_test_support)]
//! The operator's private networks (HOSTED-EGRESS-OPERATOR-SETTING) reach the
//! guard a managed node checks its owner's fetches with, the way managed boot
//! carries them, and never the guard for a URL an outside party names (an
//! OAuth client's metadata document, review #6478). A self-hosted node keeps
//! no hosted guard (HOSTED-EGRESS-SELF-HOST = A).
//!
//! Main has no `--hosted-private-network` and no door to the guards, so main
//! cannot build this file; `tests/hosted_egress_private_networks.rs` holds
//! the red pin. Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --test hosted_egress_guard_wiring`.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use clap::Parser;
use oneiron::web_fetch::HostedEgressRefusal;
use oneiron_server::config::ServeArgs;
use oneiron_server::managed::ManagedArgs;
use oneiron_server::test_doors::web_egress_guards::egress_guards;
use oneiron_vault_contract::CONTRACT_VERSION;

#[derive(Parser)]
struct ArgvProbe {
    #[command(flatten)]
    serve: ServeArgs,
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("a test address")
}

fn open_vault(dir: &Path) -> Arc<oneiron::Vault> {
    Arc::new(oneiron::Vault::open(dir, oneiron::VaultConfig::server()).expect("a test vault"))
}

/// The managed args a complete managed argv rooted at `root`, plus `extra`,
/// resolves to.
fn managed_with(root: &Path, extra: &[&str]) -> ManagedArgs {
    let path = |name: &str| root.join(name).display().to_string();
    let mut argv = vec![
        "oneiron-server".to_owned(),
        "--managed-by-hypnos".to_owned(),
        "--contract-version".to_owned(),
        CONTRACT_VERSION.to_string(),
        "--vault-name".to_owned(),
        "egress-wiring".to_owned(),
        "--derivation-owner".to_owned(),
        "09".repeat(32),
        "--data-dir".to_owned(),
        path("data"),
        "--http-socket".to_owned(),
        path("http.sock"),
        "--ctl-socket".to_owned(),
        path("ctl.sock"),
        "--hypnos-socket".to_owned(),
        path("sup.sock"),
        "--ready-fd".to_owned(),
        "1".to_owned(),
        "--credentials-fd".to_owned(),
        "0".to_owned(),
    ];
    argv.extend(extra.iter().copied().map(str::to_owned));
    let args = ArgvProbe::try_parse_from(argv)
        .expect("a managed argv")
        .serve;
    ManagedArgs::from_serve_args(&args)
        .expect("managed boot reads the argv")
        .expect("--managed-by-hypnos selects managed mode")
}

#[tokio::test]
async fn the_operators_networks_reach_the_managed_guard_and_never_the_outside_partys() {
    let dir = tempfile::tempdir().unwrap();
    let managed = managed_with(dir.path(), &["--hosted-private-network", "cgnat"]);
    let (hosted, outside) =
        egress_guards(open_vault(&dir.path().join("vault")), &managed, true).unwrap();
    let hosted = hosted.expect("a managed node has a hosted guard");

    assert_eq!(
        hosted.refuses(ip("100.64.0.1")),
        None,
        "the admitted network"
    );
    assert_eq!(
        hosted.refuses(ip("10.0.0.5")),
        Some(HostedEgressRefusal::PrivateNetwork),
        "a network the operator did not name"
    );
    for infrastructure in ["100.100.100.200", "100.100.100.100", "127.0.0.1"] {
        assert_eq!(
            hosted.refuses(ip(infrastructure)),
            Some(HostedEgressRefusal::Infrastructure),
            "{infrastructure}"
        );
    }
    assert_eq!(
        outside.refuses(ip("100.64.0.1")),
        Some(HostedEgressRefusal::PrivateNetwork),
        "an outside party's URL never reaches the operator's networks"
    );
}

#[tokio::test]
async fn without_the_flag_the_managed_guard_refuses_todays_set() {
    let dir = tempfile::tempdir().unwrap();
    let managed = managed_with(dir.path(), &[]);
    let (hosted, _) = egress_guards(open_vault(&dir.path().join("vault")), &managed, true).unwrap();
    let hosted = hosted.expect("a managed node has a hosted guard");
    for private in ["10.0.0.5", "100.64.0.1", "fd12:3456::1"] {
        assert_eq!(
            hosted.refuses(ip(private)),
            Some(HostedEgressRefusal::PrivateNetwork),
            "{private}"
        );
    }
}

#[tokio::test]
async fn a_self_hosted_server_keeps_no_hosted_guard() {
    let dir = tempfile::tempdir().unwrap();
    let managed = managed_with(dir.path(), &["--hosted-private-network", "rfc1918"]);
    let (hosted, outside) =
        egress_guards(open_vault(&dir.path().join("vault")), &managed, false).unwrap();
    assert!(hosted.is_none(), "a self-hosted node fetches as before");
    assert_eq!(
        outside.refuses(ip("10.0.0.5")),
        Some(HostedEgressRefusal::PrivateNetwork)
    );
}
