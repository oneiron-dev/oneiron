//! Census row L6-04 item A (ARCH-0038 #restore-path-open): the check of a
//! restore's path reads each macOS directory's extended access-control list,
//! not only its mode bits. macOS only: `chmod +a` writes the entries. It
//! names only main's paths, so it runs red on main.
#![cfg(target_os = "macos")]
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts /bin/chmod and /usr/bin/id; the rule covers the server's crates"
)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use oneiron_store::root_directory::{SharedPath, refuse_shared_vault_root, shared_path};

/// A fresh directory on a temp path the check passes before any entry is
/// added. Its entries come off again before the directory is removed.
struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("a temporary directory");
        assert_eq!(
            shared_path(dir.path()).expect("the check reads the temp path"),
            None,
            "the temp path is shared before any entry is added: set TMPDIR to a directory \
             only this user can change"
        );
        Self { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The directory as the check names it: every link on the way resolved
    /// (the macOS temp directory sits under the /var link).
    fn resolved(&self) -> PathBuf {
        std::fs::canonicalize(self.path()).expect("the directory resolves")
    }

    fn child(&self, name: &str) -> PathBuf {
        let child = self.path().join(name);
        std::fs::create_dir(&child).expect("a child directory");
        child
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = Command::new("/bin/chmod")
            .args(["-R", "-N"])
            .arg(self.dir.path())
            .status();
    }
}

fn add_entry(path: &Path, entry: &str) {
    let status = Command::new("/bin/chmod")
        .arg("+a")
        .arg(entry)
        .arg(path)
        .status()
        .expect("chmod starts");
    assert!(
        status.success(),
        "chmod +a {entry:?} {} exited {status}",
        path.display()
    );
}

fn this_user() -> String {
    let output = Command::new("/usr/bin/id")
        .arg("-un")
        .output()
        .expect("id starts");
    assert!(output.status.success(), "id -un exited {}", output.status);
    String::from_utf8(output.stdout)
        .expect("a UTF-8 user name")
        .trim()
        .to_owned()
}

fn finding(path: &Path, what: &str) -> SharedPath {
    shared_path(path)
        .expect("the check reads the path")
        .unwrap_or_else(|| panic!("{what} left {} unshared", path.display()))
}

#[test]
fn each_right_that_lets_every_user_change_a_directory_shares_it() {
    for right in [
        "add_file",
        "add_subdirectory",
        "delete_child",
        "delete",
        "writesecurity",
        "chown",
    ] {
        let fixture = Fixture::new();
        add_entry(fixture.path(), &format!("group:everyone allow {right}"));
        let shared = finding(
            fixture.path(),
            &format!("an entry letting every user {right}"),
        );
        assert_eq!(shared.directory, fixture.resolved(), "{right}");
        assert!(
            shared.to_string().contains("access-control list"),
            "the finding names the list: {shared}"
        );
    }
}

#[test]
fn a_parent_whose_list_lets_every_user_remove_entries_shares_the_path_below_it() {
    let fixture = Fixture::new();
    let vault = fixture.child("vault");
    add_entry(fixture.path(), "group:everyone allow delete_child");
    let shared = finding(&vault, "a parent letting every user remove entries");
    assert_eq!(shared.directory, fixture.resolved(), "the parent is named");
}

#[test]
fn a_sticky_directory_whose_list_lets_every_user_remove_entries_is_shared() {
    let fixture = Fixture::new();
    std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o1700))
        .expect("the sticky bit is set");
    add_entry(fixture.path(), "group:everyone allow delete_child");
    let shared = finding(
        fixture.path(),
        "a sticky directory letting every user remove entries",
    );
    assert_eq!(shared.directory, fixture.resolved());
}

#[test]
fn a_vault_root_whose_list_lets_a_group_add_entries_is_refused() {
    let fixture = Fixture::new();
    let vault = fixture.child("vault");
    add_entry(&vault, "group:staff allow add_file,add_subdirectory");
    let refusal = refuse_shared_vault_root(&vault)
        .expect_err("a vault root a group may add entries to is refused");
    assert!(
        refusal.to_string().contains("access-control list"),
        "the refusal names the list: {refusal}"
    );
}

#[test]
fn a_deny_only_list_leaves_the_directory_unshared() {
    let fixture = Fixture::new();
    add_entry(
        fixture.path(),
        "group:everyone deny add_file,add_subdirectory,delete_child",
    );
    assert_eq!(shared_path(fixture.path()).expect("the check reads"), None);
}

#[test]
fn a_read_only_allow_list_leaves_the_directory_unshared() {
    let fixture = Fixture::new();
    add_entry(
        fixture.path(),
        "group:everyone allow list,search,readattr,readextattr,readsecurity",
    );
    assert_eq!(shared_path(fixture.path()).expect("the check reads"), None);
}

#[test]
fn entries_for_this_user_and_root_leave_the_directory_unshared() {
    let fixture = Fixture::new();
    let user = this_user();
    add_entry(
        fixture.path(),
        &format!(
            "user:{user} allow add_file,add_subdirectory,delete_child,delete,writesecurity,chown"
        ),
    );
    add_entry(fixture.path(), "user:root allow add_file,delete_child");
    assert_eq!(shared_path(fixture.path()).expect("the check reads"), None);
}
