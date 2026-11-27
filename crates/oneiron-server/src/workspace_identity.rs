//! A folder's workspace identity (RECALL-SESSION-PROJECT; Engine ANSWER
//! RECALL-SESSION-PROJECT-INTENT, 26 Nov: the binding stores a hash plus a label): the folder
//! digests an attached session names its folder by, and the one `oneiron project bind` binds.
//!
//! The folder's checkout root is its git top-level, else the folder itself, as a canonical path
//! (symlinks resolved). Its folder digest is the fingerprint of that path's bytes under the
//! purpose `oneiron.workspace.v1` (BLAKE3, the engine's fingerprint door), written as `blake3:`
//! and lower-case hex. Only the digest leaves this machine: the vault keys it with its own id
//! into the workspace id its `workspace.project` row is named by, so the vault never receives
//! the path. A linked worktree also names its main checkout's digest, second: a worktree with
//! no binding of its own reads its main checkout's. The main checkout is the primary worktree
//! git names (`git worktree list`): a bare repository has none, and neither has a repository
//! with a separate git directory, which git names in place of its checkout. Nothing here is
//! inferred from a folder name, a branch, a remote or a session id. The label is the root's
//! folder name, for display.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use oneiron::session_project::digest_text;
use oneiron_contracts::fingerprint::Fingerprint;
use oneiron_contracts::fingerprint::purposes::session_project::FOLDER_DIGEST;

/// The longest a git call here may take.
pub const GIT_TIMEOUT: Duration = Duration::from_secs(2);

/// The variables that choose a repository for git, whatever folder `-C` names: the list
/// `git rev-parse --local-env-vars` prints, and the two that bound its discovery. Each git call
/// here clears them, so a variable this process inherited (a git hook's `GIT_DIR`, an editor's
/// `GIT_WORK_TREE`) never puts another checkout's identity on the folder.
const GIT_REPOSITORY_VARIABLES: [&str; 17] = [
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_OBJECT_DIRECTORY",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_PREFIX",
    "GIT_SHALLOW_FILE",
    "GIT_COMMON_DIR",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
];

/// A folder's digests and label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceIdentity {
    /// The folder's checkout's digest, then its main checkout's when it is a linked worktree.
    pub digests: Vec<String>,
    /// The checkout root's folder name.
    pub label: String,
}

impl WorkspaceIdentity {
    /// The identity of `folder`: its checkout root's digest, its main checkout's for a linked
    /// worktree, and its root's name. Git gets at most [`GIT_TIMEOUT`]; a folder git does not
    /// answer for is its own root. `None` when the folder does not resolve to a canonical path.
    #[must_use]
    pub fn of_folder(folder: &Path) -> Option<Self> {
        let folder = std::fs::canonicalize(folder).ok()?;
        let (root, main) = match git_checkout(&folder) {
            Some(GitCheckout { top, primary }) => {
                let root = std::fs::canonicalize(&top).unwrap_or(top);
                (
                    root,
                    primary.and_then(|primary| std::fs::canonicalize(primary).ok()),
                )
            }
            None => (folder, None),
        };
        let mut digests = vec![folder_digest(&root)];
        if let Some(main) = main.filter(|main| *main != root) {
            digests.push(folder_digest(&main));
        }
        let label = root
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        Some(Self { digests, label })
    }

    /// [`Self::of_folder`] for a folder an agent session runs in: `None` as well when the
    /// folder is not a directory, and when the folder itself or its checkout root is the
    /// filesystem root or the home directory, which hold no one project. The folder itself is
    /// judged before git places it, so a home directory inside a checkout never takes that
    /// checkout's project.
    #[must_use]
    pub fn of_session_folder(folder: &Path) -> Option<Self> {
        Self::of_session_folder_with_home(folder, home_directory())
    }

    /// [`Self::of_session_folder`] with `home` as the home directory.
    fn of_session_folder_with_home(folder: &Path, home: Option<PathBuf>) -> Option<Self> {
        let folder = std::fs::canonicalize(folder).ok()?;
        // FIX SESSION-PROJECT-NOTE-MESSAGE-PLACEMENT PR D review: no directory, no session folder.
        if !folder.is_dir() {
            return None;
        }
        let not_workspaces: Vec<PathBuf> = [Some(PathBuf::from("/")), home]
            .into_iter()
            .flatten()
            .map(|path| std::fs::canonicalize(&path).unwrap_or(path))
            .collect();
        // FIX SESSION-PROJECT-NOTE-MESSAGE-PLACEMENT PR D review: the folder itself goes first.
        if not_workspaces.contains(&folder) {
            return None;
        }
        let identity = Self::of_folder(&folder)?;
        let own = identity.own_digest();
        not_workspaces
            .iter()
            .all(|root| folder_digest(root) != own)
            .then_some(identity)
    }

    /// The folder's own digest: the one `oneiron project bind` binds.
    #[must_use]
    pub fn own_digest(&self) -> &str {
        &self.digests[0]
    }
}

/// The folder digest of the canonical checkout root `root`: the fingerprint of the path's bytes
/// under [`FOLDER_DIGEST`] (`oneiron.workspace.v1`), as `blake3:` and lower-case hex.
#[must_use]
pub fn folder_digest(root: &Path) -> String {
    digest_text(&Fingerprint::of_parts(
        FOLDER_DIGEST,
        &[path_bytes(root).as_ref()],
    ))
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> std::borrow::Cow<'_, [u8]> {
    use std::os::unix::ffi::OsStrExt as _;
    std::borrow::Cow::Borrowed(path.as_os_str().as_bytes())
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> std::borrow::Cow<'_, [u8]> {
    std::borrow::Cow::Owned(path.to_string_lossy().into_owned().into_bytes())
}

/// This user's home directory, from `HOME` (`USERPROFILE` where it is unset).
fn home_directory() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
}

/// Where git places a folder: its working tree's top level, and its repository's primary
/// checkout when git names one that is a checkout, both absolute.
struct GitCheckout {
    top: PathBuf,
    primary: Option<PathBuf>,
}

/// Each path is read from a git call of its own, as raw bytes with only git's final newline
/// taken off, so a path that ends in a space, or holds one, is never read as another checkout's.
fn git_checkout(folder: &Path) -> Option<GitCheckout> {
    let deadline = Instant::now() + GIT_TIMEOUT;
    let top = git_output(
        folder,
        &["rev-parse", "--path-format=absolute", "--show-toplevel"],
        deadline,
    )?;
    let top = path_of(top.strip_suffix(b"\n")?);
    let primary = git_output(folder, &["worktree", "list", "--porcelain", "-z"], deadline)
        .and_then(|listed| primary_checkout(&listed))
        .filter(|primary| is_checkout_of(folder, primary, deadline));
    Some(GitCheckout { top, primary })
}

/// Whether `primary` is a checkout of the repository `folder` is in: its `.git` is a folder,
/// and that folder is the repository's common git directory. A `.git` file, or any `.git` of
/// another repository, makes it none: in a repository with a separate git directory git names
/// that directory as the primary, and a `.git` placed inside it is not its checkout.
fn is_checkout_of(folder: &Path, primary: &Path, deadline: Instant) -> bool {
    let Some(common) = git_output(
        folder,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        deadline,
    ) else {
        return false;
    };
    let Some(common) = common.strip_suffix(b"\n").map(path_of) else {
        return false;
    };
    let dot_git = primary.join(".git");
    if !dot_git.is_dir() {
        return false;
    }
    match (
        std::fs::canonicalize(&dot_git),
        std::fs::canonicalize(&common),
    ) {
        (Ok(dot_git), Ok(common)) => dot_git == common,
        _ => false,
    }
}

/// The primary checkout `git worktree list --porcelain -z` names first, when it holds a `.git`
/// ([`is_checkout_of`] then holds it to the repository). None for a bare repository (`bare`),
/// and none where git names a separate git directory itself as the primary: git cannot name
/// that repository's checkout, and the git directory is none, so such a linked worktree reads
/// only its own binding.
fn primary_checkout(listed: &[u8]) -> Option<PathBuf> {
    let mut fields = listed.split(|byte| *byte == 0);
    let primary = path_of(fields.next()?.strip_prefix(b"worktree ")?);
    if fields
        .take_while(|field| !field.is_empty())
        .any(|field| field == b"bare")
    {
        return None;
    }
    primary.join(".git").exists().then_some(primary)
}

/// `git -C <folder> <args>`'s standard output, when git exits 0 and its output is read by
/// `deadline`, with no inherited repository variable ([`GIT_REPOSITORY_VARIABLES`]). The output
/// is read beside the wait, so a long one (a repository with many worktrees) never holds git
/// past the deadline, and the read is held to the deadline too: a process git left behind can
/// keep the pipe open after git exits, and then the call gives up at the deadline and leaves the
/// reader to end when that process closes the pipe.
fn git_output(folder: &Path, args: &[&str], deadline: Instant) -> Option<Vec<u8>> {
    if Instant::now() >= deadline {
        return None;
    }
    let mut command = oneiron_spawn::command("git");
    command
        .arg("-C")
        .arg(folder)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for variable in GIT_REPOSITORY_VARIABLES {
        command.env_remove(variable);
    }
    let mut child = command.spawn().ok()?;
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    let (sender, output) = std::sync::mpsc::sync_channel(1);
    let read = move || {
        let mut out = Vec::new();
        // The call may have given up and gone: then no one receives this.
        let _ = sender.send(stdout.read_to_end(&mut out).map(|_| out));
    };
    if crate::engine_thread("git-output".into())
        .spawn(read)
        .is_err()
    {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }
    let Some(status) = wait_until(&mut child, deadline) else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    let out = output
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok()?
        .ok()?;
    status.success().then_some(out)
}

#[cfg(unix)]
fn path_of(bytes: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt as _;
    PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
}

#[cfg(not(unix))]
fn path_of(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
}

/// Waits for `child` to exit until `deadline`; `None` if it has not.
fn wait_until(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs git in `dir` with no user or system config, so the host's own (hooks, a template)
    /// never reaches the test repository.
    fn git(dir: &Path, args: &[&str]) {
        let status = oneiron_spawn::command("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("git runs");
        assert!(status.success(), "git {args:?} in {}", dir.display());
    }

    #[test]
    fn a_home_directory_inside_a_checkout_is_no_session_folder() {
        let parent = tempfile::tempdir().expect("temp folder");
        let repo = parent.path().join("repo");
        std::fs::create_dir(&repo).expect("repository folder");
        git(&repo, &["init", "--quiet"]);
        let home = repo.join("home").join("alice");
        std::fs::create_dir_all(&home).expect("home folder inside the checkout");

        let elsewhere = WorkspaceIdentity::of_session_folder_with_home(&home, None)
            .expect("with no home named, the folder is placed in its checkout");
        assert_eq!(
            elsewhere.own_digest(),
            folder_digest(&std::fs::canonicalize(&repo).expect("canonical checkout")),
            "git places the folder at its checkout root"
        );
        assert!(
            WorkspaceIdentity::of_session_folder_with_home(&home, Some(home.clone())).is_none(),
            "the home directory holds no one project, even inside a checkout"
        );
    }
}
