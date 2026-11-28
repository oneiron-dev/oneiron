//! RECALL-SESSION-PROJECT PR 1 (Engine ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov: the
//! binding stores a hash plus a label): a folder's digest is its canonical checkout root's
//! fingerprint under `oneiron.workspace.v1` (BLAKE3, the fingerprint door; Engine NOTE 01:25,
//! 27 Nov), a linked worktree names its main checkout's digest second, and the
//! `oneiron project bind` request carries the digest and the folder's name, never its path.
//! Review round 1 of #10550: a path that ends in a space is its own checkout; a bare
//! repository's linked worktree, and one of a repository with a separate git directory, name
//! only themselves, as git names no checkout for them.
//!
//! Red on the base: `oneiron_server::workspace_identity` and the `oneiron project` requests do
//! not exist there, so this file does not build.
//!
//! `cargo test --locked -p oneiron-server --all-features --test workspace_identity` (needs git).

use std::path::Path;

use oneiron_server::commands::{workspace_bind_request, workspace_unbind_request};
use oneiron_server::workspace_identity::{WorkspaceIdentity, folder_digest};

const PROJECT: &str = "5b0e3f9c2d4a4e1f8a7c6b5d4e3f2a1b";

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
    repository_named(parent, "alpha")
}

/// A git repository at `<parent>/<name>` with one commit.
fn repository_named(parent: &Path, name: &str) -> std::path::PathBuf {
    let repo = parent.join(name);
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
fn the_folder_digest_is_the_fingerprint_of_the_root_path() {
    assert_eq!(
        folder_digest(Path::new("/srv/checkouts/alpha")),
        "blake3:80da07eefc0533649c661d4095ab29882a70a363f77460c375e098b0bf5c6cd6",
        "BLAKE3 derive-key under \"oneiron.workspace.v1\" of the path as one framed part, \
         as blake3: and lower-case hex"
    );
}

#[test]
fn a_folder_outside_git_is_its_own_root() {
    let parent = tempfile::tempdir().expect("temp folder");
    let folder = parent.path().join("notes");
    std::fs::create_dir(&folder).expect("folder");
    let identity = WorkspaceIdentity::of_folder(&folder).expect("identity");
    assert_eq!(identity.digests, vec![folder_digest(&canonical(&folder))]);
    assert_eq!(identity.label, "notes");
}

#[test]
fn a_subfolder_of_a_checkout_names_the_checkout_root() {
    let parent = tempfile::tempdir().expect("temp folder");
    let repo = repository(parent.path());
    let sub = repo.join("src").join("deep");
    std::fs::create_dir_all(&sub).expect("subfolder");
    let identity = WorkspaceIdentity::of_folder(&sub).expect("identity");
    assert_eq!(
        identity.digests,
        vec![folder_digest(&canonical(&repo))],
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
    let identity = WorkspaceIdentity::of_folder(&worktree).expect("identity");
    assert_eq!(
        identity.digests,
        vec![
            folder_digest(&canonical(&worktree)),
            folder_digest(&canonical(&repo)),
        ]
    );
    assert_eq!(identity.label, "alpha-fork");
    assert_eq!(identity.own_digest(), identity.digests[0]);
}

#[test]
fn a_checkout_whose_path_ends_in_a_space_is_its_own() {
    let parent = tempfile::tempdir().expect("temp folder");
    let plain = repository_named(parent.path(), "alpha");
    let spaced = repository_named(parent.path(), "alpha ");
    let identity = WorkspaceIdentity::of_folder(&spaced).expect("identity");
    assert_eq!(
        identity.digests,
        vec![folder_digest(&canonical(&spaced))],
        "git's path is read whole, its trailing space kept"
    );
    assert_ne!(
        identity.digests,
        WorkspaceIdentity::of_folder(&plain)
            .expect("identity")
            .digests,
        "the two checkouts never share a binding"
    );
    assert_eq!(identity.label, "alpha ");
}

#[test]
fn a_bare_repositorys_linked_worktree_names_only_itself() {
    let parent = tempfile::tempdir().expect("temp folder");
    let repo = repository(parent.path());
    // A bare repository in a folder named `.git`: its parent is no checkout.
    let holder = parent.path().join("meta");
    std::fs::create_dir(&holder).expect("folder");
    let bare = holder.join(".git");
    git(
        parent.path(),
        &[
            "clone",
            "--quiet",
            "--bare",
            repo.to_str().expect("utf-8 temp path"),
            bare.to_str().expect("utf-8 temp path"),
        ],
    );
    let worktree = parent.path().join("bare-fork");
    git(
        &bare,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "fork",
            worktree.to_str().expect("utf-8 temp path"),
        ],
    );
    let identity = WorkspaceIdentity::of_folder(&worktree).expect("identity");
    assert_eq!(
        identity.digests,
        vec![folder_digest(&canonical(&worktree))],
        "a bare repository has no main checkout"
    );
}

#[test]
fn a_separate_git_dirs_linked_worktree_names_only_itself() {
    let parent = tempfile::tempdir().expect("temp folder");
    let checkout = parent.path().join("alpha");
    let git_dir = parent.path().join("meta").join("alpha.git");
    std::fs::create_dir(parent.path().join("meta")).expect("folder");
    git(
        parent.path(),
        &[
            "init",
            "--quiet",
            "--separate-git-dir",
            git_dir.to_str().expect("utf-8 temp path"),
            checkout.to_str().expect("utf-8 temp path"),
        ],
    );
    git(
        &checkout,
        &["commit", "--quiet", "--allow-empty", "-m", "first"],
    );
    let worktree = parent.path().join("alpha-fork");
    git(
        &checkout,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "fork",
            worktree.to_str().expect("utf-8 temp path"),
        ],
    );
    // Git names the git directory itself as the primary worktree here, not the checkout: it
    // holds no `.git`, so it is no main checkout to fall back to.
    let identity = WorkspaceIdentity::of_folder(&worktree).expect("identity");
    assert_eq!(identity.digests, vec![folder_digest(&canonical(&worktree))]);
    assert_eq!(
        WorkspaceIdentity::of_folder(&checkout)
            .expect("identity")
            .digests,
        vec![folder_digest(&canonical(&checkout))],
        "the checkout itself names its own root"
    );
    // Review round 2 of #10550: a `.git` placed inside the git directory makes it no checkout,
    // a file or a folder: neither is the repository's own git directory.
    std::fs::write(git_dir.join(".git"), b"").expect("an empty .git file");
    assert_eq!(
        WorkspaceIdentity::of_folder(&worktree)
            .expect("identity")
            .digests,
        vec![folder_digest(&canonical(&worktree))],
        "an empty .git file in the git directory"
    );
    std::fs::remove_file(git_dir.join(".git")).expect("remove the file");
    std::fs::create_dir(git_dir.join(".git")).expect("a .git folder");
    assert_eq!(
        WorkspaceIdentity::of_folder(&worktree)
            .expect("identity")
            .digests,
        vec![folder_digest(&canonical(&worktree))],
        "a .git folder in the git directory"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_path_names_the_same_checkout() {
    let parent = tempfile::tempdir().expect("temp folder");
    let repo = repository(parent.path());
    let link = parent.path().join("alpha-link");
    std::os::unix::fs::symlink(&repo, &link).expect("symlink");
    assert_eq!(
        WorkspaceIdentity::of_folder(&link).expect("identity via the link"),
        WorkspaceIdentity::of_folder(&repo).expect("identity")
    );
}

#[test]
fn the_bind_request_carries_the_digest_and_name_never_the_path() {
    let parent = tempfile::tempdir().expect("temp folder");
    let repo = repository(parent.path());
    let identity = WorkspaceIdentity::of_folder(&repo).expect("identity");
    let request = workspace_bind_request(&identity, PROJECT).expect("bind request");
    assert_eq!(
        request,
        serde_json::json!({
            "folder_digest": identity.own_digest(),
            "project": PROJECT,
            "label": "alpha",
        })
    );
    let sent = request.to_string();
    let path = canonical(&repo).display().to_string();
    assert!(!sent.contains(&path), "the request names no path: {sent}");
    assert_eq!(
        workspace_unbind_request(&identity),
        serde_json::json!({ "folder_digest": identity.own_digest() })
    );
}

#[test]
fn a_bind_request_refuses_a_ref_that_is_not_an_id() {
    let parent = tempfile::tempdir().expect("temp folder");
    let identity = WorkspaceIdentity::of_folder(parent.path()).expect("identity");
    assert!(workspace_bind_request(&identity, "alpha").is_err());
}

/// Set in a child process this binary starts for one of its ignored tests ([`in_child`]).
const CHILD_MARK: &str = "ONEIRON_TEST_WORKSPACE_IDENTITY_CHILD";
/// The folder a child test reads, from its parent.
const CHILD_FOLDER: &str = "ONEIRON_TEST_WORKSPACE_IDENTITY_FOLDER";
/// The digests the child test must see, one per line, from its parent.
const CHILD_DIGESTS: &str = "ONEIRON_TEST_WORKSPACE_IDENTITY_DIGESTS";

/// Runs this binary's ignored test `name` alone in a child process with `env` added to this
/// process's own, and the folder and digests it checks: a variable set there never reaches the
/// other tests, which run beside it in this process.
fn in_child(name: &str, folder: &Path, digests: &[String], env: &[(&str, std::ffi::OsString)]) {
    let binary = std::env::current_exe().expect("this test binary");
    let status = oneiron_spawn::command(binary)
        .args(["--exact", name, "--ignored", "--test-threads=1", "--quiet"])
        .envs(env.iter().map(|(name, value)| (*name, value.as_os_str())))
        .env(CHILD_MARK, "1")
        .env(CHILD_FOLDER, folder)
        .env(CHILD_DIGESTS, digests.join("\n"))
        .status()
        .expect("the child test runs");
    assert!(status.success(), "{name} failed in its child process");
}

/// In a child process [`in_child`] started: the identity of its folder has the digests its
/// parent named. Anywhere else it checks nothing.
fn check_child_identity() {
    let (Some(folder), Some(digests)) = (
        std::env::var_os(CHILD_FOLDER).filter(|_| std::env::var_os(CHILD_MARK).is_some()),
        std::env::var(CHILD_DIGESTS).ok(),
    ) else {
        return;
    };
    let identity = WorkspaceIdentity::of_folder(Path::new(&folder)).expect("identity");
    let digests: Vec<String> = digests.lines().map(str::to_owned).collect();
    assert_eq!(identity.digests, digests);
}

/// Review round 2 of #10550: a git variable this process inherited names no other checkout.
/// With `GIT_DIR` and `GIT_WORK_TREE` naming repository `alpha`, the folder `beta` still names
/// `beta`; on the base git read `alpha` for it.
#[test]
fn inherited_git_repository_variables_never_name_another_checkout() {
    let parent = tempfile::tempdir().expect("temp folder");
    let alpha = repository_named(parent.path(), "alpha");
    let beta = repository_named(parent.path(), "beta");
    in_child(
        "inherited_git_variables_child",
        &beta,
        &[folder_digest(&canonical(&beta))],
        &[
            ("GIT_DIR", alpha.join(".git").into_os_string()),
            ("GIT_WORK_TREE", alpha.clone().into_os_string()),
        ],
    );
}

#[test]
#[ignore = "run in a child process by its parent test"]
fn inherited_git_variables_child() {
    check_child_identity();
}

/// Review round 2 of #10550: a process git leaves behind with its output pipe open never holds
/// the identity past git's deadline. A `git` on `PATH` that starts a long background process
/// and then runs git: the identity gives up on git at the deadline and the folder is its own
/// root; on the base the read of git's output waited for the background process.
#[cfg(unix)]
#[test]
fn a_git_that_leaves_its_output_open_is_given_up_at_the_deadline() {
    use std::os::unix::fs::PermissionsExt as _;
    let parent = tempfile::tempdir().expect("temp folder");
    let repo = repository(parent.path());
    let sub = repo.join("src");
    std::fs::create_dir(&sub).expect("subfolder");
    let real_git = oneiron_spawn::command("sh")
        .args(["-c", "command -v git"])
        .output()
        .expect("sh finds git");
    let real_git = String::from_utf8(real_git.stdout).expect("utf-8 path");
    let bin = parent.path().join("bin");
    std::fs::create_dir(&bin).expect("bin folder");
    let wrapper = bin.join("git");
    std::fs::write(
        &wrapper,
        format!("#!/bin/sh\nsleep 5 &\nexec {} \"$@\"\n", real_git.trim()),
    )
    .expect("the wrapper");
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).expect("mode");
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(&inherited)))
        .expect("a PATH");
    in_child(
        "git_left_output_open_child",
        &sub,
        &[folder_digest(&canonical(&sub))],
        &[("PATH", path)],
    );
}

#[cfg(unix)]
#[test]
#[ignore = "run in a child process by its parent test"]
fn git_left_output_open_child() {
    check_child_identity();
}
