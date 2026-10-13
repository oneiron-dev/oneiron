//! A live child that let its channel go is not taken as ready (Astra on
//! #1416): the daemon replaces it, or refuses, before a call's permit starts.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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

    // Gone after it served, when the test says: the next check starts a new
    // child. Only the first child closes; the one that replaces it keeps its
    // channel.
    let first = dir.path().join("first");
    let go = dir.path().join("go");
    let closed = dir.path().join("closed");
    let starts = dir.path().join("starts");
    let after = fake(
        dir.path(),
        "after",
        &format!(
            "echo start >> '{starts}'\n\
             echo listening\n\
             if /bin/mkdir '{first}' 2>/dev/null; then\n\
             i=0\n\
             while [ ! -e '{go}' ] && [ $i -lt 400 ]; do /bin/sleep 0.05; i=$((i+1)); done\n\
             exec 3>&-\n\
             : > '{closed}'\n\
             fi\n\
             exec /bin/cat >/dev/null\n",
            starts = starts.display(),
            first = first.display(),
            go = go.display(),
            closed = closed.display(),
        ),
    );
    let child = ChildBroker::new(after, &[], Duration::from_secs(20));
    child.ensure().expect("the first child");
    std::fs::write(&go, b"").expect("go");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !closed.exists() {
        assert!(Instant::now() < deadline, "the first child never let its channel go");
        std::thread::sleep(Duration::from_millis(10));
    }
    child.ensure().expect("a new child");
    let count = std::fs::read_to_string(&starts).expect("starts").lines().count();
    assert_eq!(count, 2, "the child that let its channel go was kept");
}
