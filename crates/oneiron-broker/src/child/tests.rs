//! A live child that let its channel go is not taken as ready (Astra on
//! #1416): the daemon replaces it, or refuses, before a call's permit starts.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::ChildBroker;

/// A stand-in child: `/bin/sh` running `body`, with no environment and the
/// channel on fd 3, as the daemon starts the broker.
fn fake(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let program = dir.join(name);
    std::fs::write(&program, format!("#!/bin/sh\n{body}")).expect("fake child");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    program
}

#[test]
fn a_child_that_let_its_channel_go_is_replaced_or_refused() {
    let dir = tempfile::tempdir().expect("dir");
    // Gone before it says it serves: it never served.
    let before = fake(
        dir.path(),
        "before",
        "exec 3>&-\necho listening\nexec /bin/cat >/dev/null\n",
    );
    let child = ChildBroker::new(before, &[], Duration::from_secs(20));
    assert!(child.ensure().is_err(), "a child with no channel was ready");

    // Gone a second after it served: the next check starts a new child.
    let starts = dir.path().join("starts");
    let after = fake(
        dir.path(),
        "after",
        &format!(
            "echo start >> '{}'\necho listening\n/bin/sleep 1\nexec 3>&-\nexec /bin/cat >/dev/null\n",
            starts.display()
        ),
    );
    let child = ChildBroker::new(after, &[], Duration::from_secs(20));
    child.ensure().expect("the first child");
    std::thread::sleep(Duration::from_secs(2));
    child.ensure().expect("a new child");
    let count = std::fs::read_to_string(&starts).expect("starts").lines().count();
    assert_eq!(count, 2, "the child that let its channel go was kept");
}
