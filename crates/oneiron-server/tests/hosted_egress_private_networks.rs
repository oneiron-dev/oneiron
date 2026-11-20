//! The hosting operator sets which private networks a hosted node's web
//! fetch reaches (HOSTED-EGRESS-OPERATOR-SETTING; the lead, 16 Nov 03:1x: an
//! operator setting in the server config, default today's refusal set, never
//! a vault owner key on Oneiron's hosted nodes). It is the managed-boot flag
//! `--hosted-private-network`, one of `rfc1918`, `cgnat` or `ula` per use;
//! a self-hosted serve has no such flag, and a managed settings file that
//! names it is refused as the supervisor's binding. The guard's own rules
//! (an admitted network never admits infrastructure; with none, today's
//! refusal set) are pinned in oneiron-web-fetch's
//! `tests/hosted_egress_private_networks.rs`.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

#[path = "support/owner_only_file.rs"]
mod owner_only_file;

use std::path::Path;
use std::process::{Command, Stdio};

use clap::Parser;
use clap::error::ErrorKind;
use oneiron_server::config::ServeArgs;
use oneiron_server::managed::ManagedArgs;
use oneiron_vault_contract::CONTRACT_VERSION;

#[derive(Parser)]
struct ArgvProbe {
    #[command(flatten)]
    serve: ServeArgs,
}

fn parse_serve(argv: &[String]) -> Result<ServeArgs, clap::Error> {
    let mut full = vec!["oneiron-server".to_owned()];
    full.extend_from_slice(argv);
    ArgvProbe::try_parse_from(full).map(|probe| probe.serve)
}

fn managed_argv(root: &Path) -> Vec<String> {
    let path = |name: &str| root.join(name).display().to_string();
    vec![
        "--managed-by-hypnos".to_owned(),
        "--contract-version".to_owned(),
        CONTRACT_VERSION.to_string(),
        "--vault-name".to_owned(),
        "egress-operator".to_owned(),
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
    ]
}

/// The managed args `extra` resolves to on a complete managed argv.
fn managed_with(root: &Path, extra: &[&str]) -> ManagedArgs {
    let mut argv = managed_argv(root);
    argv.extend(extra.iter().copied().map(str::to_owned));
    let args = parse_serve(&argv)
        .unwrap_or_else(|error| panic!("managed boot must parse {extra:?}: {error}"));
    ManagedArgs::from_serve_args(&args)
        .unwrap_or_else(|error| panic!("managed boot must read {extra:?}: {error}"))
        .expect("--managed-by-hypnos selects managed mode")
}

#[test]
fn a_managed_boot_reads_each_private_network_the_operator_names() {
    let dir = tempfile::tempdir().unwrap();
    let none = managed_with(dir.path(), &[]);
    let cgnat = managed_with(dir.path(), &["--hosted-private-network", "cgnat"]);
    let cgnat_and_ula = managed_with(
        dir.path(),
        &[
            "--hosted-private-network",
            "cgnat",
            "--hosted-private-network=ula",
        ],
    );
    // A set: order and a repeat name the same networks.
    let ula_and_cgnat = managed_with(
        dir.path(),
        &[
            "--hosted-private-network=ula",
            "--hosted-private-network",
            "cgnat",
            "--hosted-private-network",
            "cgnat",
        ],
    );

    assert_ne!(cgnat, none, "the flag is read, never accepted and dropped");
    assert_ne!(cgnat_and_ula, cgnat, "each use names one more network");
    assert_eq!(cgnat_and_ula, ula_and_cgnat);
    let shown = format!("{cgnat_and_ula:?}");
    assert!(
        shown.contains("hosted_private_networks: {Cgnat, Ula}"),
        "the operator's two networks, and only those: {shown}"
    );
    let shown = format!("{none:?}");
    assert!(
        shown.contains("hosted_private_networks: {}"),
        "no flag, no network: the default is today's refusal set: {shown}"
    );
}

#[test]
fn a_serve_without_managed_boot_refuses_the_private_network_flag() {
    // A self-hosted node carries no egress guard (HOSTED-EGRESS-SELF-HOST =
    // A, Engine 16 Nov 23:59): the flag is the hosting operator's alone.
    let error = parse_serve(&["--hosted-private-network".to_owned(), "cgnat".to_owned()])
        .expect_err("plain serve must refuse a managed-only flag");
    assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument, "{error}");
    assert!(error.to_string().contains("--managed-by-hypnos"), "{error}");
}

#[test]
fn a_private_network_outside_the_three_spellings_stops_the_start() {
    for value in [
        "RFC1918",
        "Cgnat",
        "10.0.0.0/8",
        "private",
        "cgnat,ula",
        " ula",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut argv = managed_argv(dir.path());
        argv.push(format!("--hosted-private-network={value}"));
        let Err(error) = parse_serve(&argv) else {
            panic!("{value:?} names no private network");
        };
        assert_eq!(
            error.kind(),
            ErrorKind::ValueValidation,
            "{value:?}: {error}"
        );
    }
}

#[test]
fn a_managed_settings_file_that_names_the_private_networks_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("settings.toml");
    crate::owner_only_file::write_owner_only_file(
        &settings,
        "hosted_private_networks = [\"rfc1918\"]\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oneiron-server"))
        .arg("serve")
        .args(managed_argv(dir.path()))
        .arg("--settings-file")
        .arg(&settings)
        .env_clear()
        // Settings are refused before credentials or sockets are read.
        .stdin(Stdio::null())
        .output()
        .expect("run managed oneiron-server");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a vault owner's file set the operator's networks"
    );
    assert!(
        stderr.contains("--settings-file sets `hosted_private_networks`"),
        "the refusal names the leaf: {stderr}"
    );
    // A server whose schema lacks the leaf refuses it too, as an unknown
    // field; the reason is what this checks: the operator owns the setting.
    assert!(
        stderr.contains("the supervisor owns this binding"),
        "the refusal must be SupervisorOwned: {stderr}"
    );
    assert!(output.stdout.is_empty(), "no ready byte before refusal");
    for name in ["data", "http.sock", "ctl.sock", "sup.sock"] {
        assert!(
            !dir.path().join(name).exists(),
            "refused boot created {name}"
        );
    }
}
