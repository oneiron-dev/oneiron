//! `oneiron host init` on a fresh node path (FIX-LIST
//! [T0I-HOST-INIT-SYSTEMD-DIR-TWICE]): the reference deployment holds
//! several templates under `systemd/`, so the scaffold creates that
//! directory once and writes each file. Among them is the separate-user
//! credential broker (census L6-29, ARCH-0069 `#broker-design`, OSH-2): a
//! template unit keyed by the daemon's uid, and the sysusers file that makes
//! the broker's own user.
//!
//! Each reference template is read from `deploy/` when the test runs, so the
//! test builds on a tree that lacks one, and fails there.

use std::path::{Path, PathBuf};

use oneiron_server::cli::HostInitArgs;
use oneiron_server::commands::host_init;

/// Each reference template, by its path under the node and under `deploy/`.
const REFERENCE: &[&str] = &[
    "systemd/oneiron.service",
    "systemd/oneiron.socket",
    "systemd/oneiron-broker@.service",
    "sysusers.d/oneiron-broker.conf",
    "launchd/com.oneiron.server.plist",
    "install-oneiron-server.sh",
];

/// The reference template `name` as `deploy/` holds it.
fn reference(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// A node made by `host init` at a fresh path under `dir`.
fn fresh_node(dir: &Path) -> (PathBuf, HostInitArgs) {
    let path = dir.join("node");
    let args = HostInitArgs {
        path: path.clone(),
        encryption_hook: None,
    };
    host_init(args.clone()).expect("a fresh node path initialises");
    (path, args)
}

/// The node's copy of the template `name`, as text.
fn written(node: &Path, name: &str) -> String {
    let bytes = std::fs::read(node.join(name)).unwrap_or_else(|error| {
        panic!("the node has no {name}: {error}");
    });
    assert_eq!(bytes, reference(name), "{name} differs from deploy/{name}");
    String::from_utf8(bytes).expect("a text template")
}

#[test]
fn a_fresh_node_gets_every_reference_template_and_a_second_init_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (path, args) = fresh_node(dir.path());
    for name in REFERENCE {
        assert_eq!(
            std::fs::read(path.join(name)).expect("template written"),
            reference(name),
            "{name}"
        );
    }
    assert!(
        host_init(args).is_err(),
        "an existing node is never overwritten"
    );
}

#[test]
fn a_fresh_node_gets_the_separate_user_broker_unit() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (path, _) = fresh_node(dir.path());
    let unit = written(&path, "systemd/oneiron-broker@.service");
    let lines: Vec<&str> = unit.lines().map(str::trim).collect();
    for line in [
        "User=oneiron-broker",
        "Group=oneiron-broker",
        "RuntimeDirectory=oneiron-broker/%i",
        "RuntimeDirectoryMode=0750",
        "NoNewPrivileges=true",
        "LimitCORE=0",
        "WantedBy=multi-user.target",
    ] {
        assert!(lines.contains(&line), "the broker unit lacks `{line}`");
    }
    let exec: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|line| line.starts_with("ExecStart="))
        .collect();
    assert_eq!(exec.len(), 1, "one ExecStart: {exec:?}");
    assert!(
        exec[0].ends_with(
            "oneiron-broker serve --socket /run/oneiron-broker/%i/broker.sock --client-uid %i"
        ),
        "the broker serves its instance's socket for the daemon of that uid: {}",
        exec[0]
    );
    let users = written(&path, "sysusers.d/oneiron-broker.conf");
    assert!(
        users
            .lines()
            .any(|line| line.trim_start().starts_with("u oneiron-broker ")),
        "the sysusers file declares the broker's user: {users}"
    );
}
