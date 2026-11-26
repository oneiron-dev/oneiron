//! RECALL-SESSION-PROJECT PR 1 (Engine ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov: the
//! binding stores a hash plus a label): a folder's workspace identity is its canonical checkout
//! root's tagged SHA-256, a linked worktree names its main checkout's id second, and the
//! `oneiron project bind` request carries the id and the folder's name, never its path.
//!
//! Red on the base: `oneiron_server::workspace_identity` and the `oneiron project` requests do
//! not exist there, so this file does not build.
//!
//! `cargo test --locked -p oneiron-server --all-features --test workspace_identity` (needs git).

use std::path::Path;
use std::time::{Duration, Instant};

use oneiron_server::commands::{workspace_bind_request, workspace_unbind_request};
use oneiron_server::workspace_identity::{WorkspaceIdentity, workspace_id};

const PROJECT: &str = "5b0e3f9c2d4a4e1f8a7c6b5d4e3f2a1b";

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

/// Runs git in `dir` with no user or system config, so the host's own (a signing key, hooks)
/// never reaches the test repository.
fn git(dir: &Path, args: &[&str]) {
    let status = oneiron_spawn::command("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=Owen",
            "-c",
            "user.email=owen@example.com",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .expect("git runs");
    assert!(status.success(), "git {args:?} in {}", dir.display());
}

/// A git repository at `<parent>/alpha` with one commit.
fn repository(parent: &Path) -> std::path::PathBuf {
    let repo = parent.join("alpha");
    std::fs::create_dir(&repo).expect("repository folder");
    git(&repo, &["init", "--quiet"]);
    git(
        &repo,
        &["commit", "--quiet", "--allow-empty", "-m", "first"],
    );
    repo
}

fn canonical(path: &Path) -> std::path::PathBuf {
    std::fs::canonicalize(path).expect("canonical path")
}

#[test]
fn the_workspace_id_is_the_tagged_sha256_of_the_root_path() {
    assert_eq!(
        workspace_id(Path::new("/srv/checkouts/alpha")),
        "cecd80212ccc8285c06b009c54be19cec87d53d6dc2118ed28633a9d7f55df95",
        "sha256(\"oneiron.workspace.v1\\0\" + path), lower-case hex"
    );
}

#[test]
fn a_folder_outside_git_is_its_own_root() {
    let parent = tempfile::tempdir().expect("temp folder");
    let folder = parent.path().join("notes");
    std::fs::create_dir(&folder).expect("folder");
    let identity = WorkspaceIdentity::of_folder(&folder, deadline()).expect("identity");
    assert_eq!(identity.ids, vec![workspace_id(&canonical(&folder))]);
    assert_eq!(identity.label, "notes");
}

#[test]
fn a_subfolder_of_a_checkout_names_the_checkout_root() {
    let parent = tempfile::tempdir().expect("temp folder");
    let repo = repository(parent.path());
    let sub = repo.join("src").join("deep");
    std::fs::create_dir_all(&sub).expect("subfolder");
    let identity = WorkspaceIdentity::of_folder(&sub, deadline()).expect("identity");
    assert_eq!(
        identity.ids,
        vec![workspace_id(&canonical(&repo))],
        "the main checkout names itself once"
    );
    assert_eq!(identity.label, "alpha");
}

#[test]
fn a_linked_worktree_names_itself_then_its_main_checkout() {
    let parent = tempfile::tempdir().expect("temp folder");
    let repo = repository(parent.path());
    let worktree = parent.path().join("alpha-fork");
    git(
        &repo,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "fork",
            worktree.to_str().expect("utf-8 temp path"),
        ],
    );
    let identity = WorkspaceIdentity::of_folder(&worktree, deadline()).expect("identity");
    assert_eq!(
        identity.ids,
        vec![
            workspace_id(&canonical(&worktree)),
            workspace_id(&canonical(&repo)),
        ]
    );
    assert_eq!(identity.label, "alpha-fork");
    assert_eq!(identity.own_id(), identity.ids[0]);
}

#[cfg(unix)]
#[test]
fn a_symlinked_path_names_the_same_checkout() {
    let parent = tempfile::tempdir().expect("temp folder");
    let repo = repository(parent.path());
    let link = parent.path().join("alpha-link");
    std::os::unix::fs::symlink(&repo, &link).expect("symlink");
    assert_eq!(
        WorkspaceIdentity::of_folder(&link, deadline()).expect("identity via the link"),
        WorkspaceIdentity::of_folder(&repo, deadline()).expect("identity")
    );
}

#[test]
fn the_bind_request_carries_the_id_and_name_never_the_path() {
    let parent = tempfile::tempdir().expect("temp folder");
    let repo = repository(parent.path());
    let identity = WorkspaceIdentity::of_folder(&repo, deadline()).expect("identity");
    let request = workspace_bind_request(&identity, PROJECT).expect("bind request");
    assert_eq!(
        request,
        serde_json::json!({
            "key": "workspace.project",
            "item": identity.own_id(),
            "scope": { "kind": "vault" },
            "value": { "project": PROJECT, "label": "alpha" },
        })
    );
    let sent = request.to_string();
    let path = canonical(&repo).display().to_string();
    assert!(!sent.contains(&path), "the request names no path: {sent}");
    assert_eq!(
        workspace_unbind_request(&identity),
        serde_json::json!({
            "key": "workspace.project",
            "item": identity.own_id(),
            "scope": { "kind": "vault" },
        })
    );
}

#[test]
fn a_bind_request_refuses_a_ref_that_is_not_an_id() {
    let parent = tempfile::tempdir().expect("temp folder");
    let identity = WorkspaceIdentity::of_folder(parent.path(), deadline()).expect("identity");
    assert!(workspace_bind_request(&identity, "alpha").is_err());
}
