//! `oneiron host init` on a fresh node path (FIX-LIST
//! [T0I-HOST-INIT-SYSTEMD-DIR-TWICE]): the reference deployment holds two
//! templates under `systemd/`, so the scaffold creates that directory once
//! and writes both files.

use oneiron_server::cli::HostInitArgs;
use oneiron_server::commands::host_init;

const REFERENCE: &[(&str, &[u8])] = &[
    (
        "systemd/oneiron.service",
        include_bytes!("../../../deploy/systemd/oneiron.service"),
    ),
    (
        "systemd/oneiron.socket",
        include_bytes!("../../../deploy/systemd/oneiron.socket"),
    ),
    (
        "launchd/com.oneiron.server.plist",
        include_bytes!("../../../deploy/launchd/com.oneiron.server.plist"),
    ),
    (
        "install-oneiron-server.sh",
        include_bytes!("../../../deploy/install-oneiron-server.sh"),
    ),
];

#[test]
fn a_fresh_node_gets_every_reference_template_and_a_second_init_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("node");
    let args = HostInitArgs {
        path: path.clone(),
        encryption_hook: None,
    };
    host_init(args.clone()).expect("a fresh node path initialises");
    for (name, bytes) in REFERENCE {
        assert_eq!(
            std::fs::read(path.join(name)).expect("template written"),
            *bytes,
            "{name}"
        );
    }
    assert!(
        host_init(args).is_err(),
        "an existing node is never overwritten"
    );
}
