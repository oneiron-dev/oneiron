//! A folder's workspace identity (RECALL-SESSION-PROJECT; Engine ANSWER
//! RECALL-SESSION-PROJECT-INTENT, 26 Nov: the binding stores a hash plus a label): the folder
//! digests an attached session names its folder by, and the one `oneiron project bind` binds.
//!
//! The folder's checkout root is its git top-level, else the folder itself, as a canonical path
//! (symlinks resolved). Its folder digest is the SHA-256 of a domain tag and that path's bytes,
//! in lower-case hex. Only the digest leaves this machine: the vault keys it with its own id
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

use sha2::{Digest as _, Sha256};

/// What a folder digest covers before the path: the scheme and its version.
const FOLDER_DIGEST_DOMAIN: &[u8] = b"oneiron.workspace.v1\0";

/// The longest a git call here may take.
pub const GIT_TIMEOUT: Duration = Duration::from_secs(2);

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
    /// worktree, and its root's name. Git gets until `deadline` (and at most [`GIT_TIMEOUT`]);
    /// a folder git does not answer for is its own root. `None` when the folder does not
    /// resolve to a canonical path.
    #[must_use]
    pub fn of_folder(folder: &Path, deadline: Instant) -> Option<Self> {
        let folder = std::fs::canonicalize(folder).ok()?;
        let (root, main) = match git_checkout(&folder, deadline) {
            Some(GitCheckout { top, primary }) => {
                let root = std::fs::canonicalize(&top).unwrap_or(top);
                (root, primary.and_then(|primary| std::fs::canonicalize(primary).ok()))
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
    /// checkout root is the filesystem root or the home directory, which hold no one project.
    #[must_use]
    pub fn of_session_folder(folder: &Path, deadline: Instant) -> Option<Self> {
        let identity = Self::of_folder(folder, deadline)?;
        let not_workspaces = [Some(PathBuf::from("/")), home_directory()];
        let roots = not_workspaces.iter().flatten().map(|path| {
            folder_digest(&std::fs::canonicalize(path).unwrap_or_else(|_| path.clone()))
        });
        let own = identity.own_digest().to_owned();
        roots
            .into_iter()
            .all(|root| root != own)
            .then_some(identity)
    }

    /// The folder's own digest: the one `oneiron project bind` binds.
    #[must_use]
    pub fn own_digest(&self) -> &str {
        &self.digests[0]
    }
}

/// The folder digest of the canonical checkout root `root`: the SHA-256 of
/// [`FOLDER_DIGEST_DOMAIN`] and the path's bytes, in lower-case hex.
#[must_use]
pub fn folder_digest(root: &Path) -> String {
    let mut digest = Sha256::new();
    digest.update(FOLDER_DIGEST_DOMAIN);
    digest.update(path_bytes(root).as_ref());
    oneiron_hex::encode(&digest.finalize())
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
fn git_checkout(folder: &Path, deadline: Instant) -> Option<GitCheckout> {
    let deadline = deadline.min(Instant::now() + GIT_TIMEOUT);
    let top = git_output(
        folder,
        &["rev-parse", "--path-format=absolute", "--show-toplevel"],
        deadline,
    )?;
    let top = path_of(top.strip_suffix(b"\n")?);
    let primary = git_output(folder, &["worktree", "list", "--porcelain", "-z"], deadline)
        .and_then(|listed| primary_checkout(&listed));
    Some(GitCheckout { top, primary })
}

/// The primary checkout `git worktree list --porcelain -z` names first, when it holds a `.git`.
/// None for a bare repository (`bare`), and none where git names a separate git directory
/// itself as the primary: git cannot name that repository's checkout, and the git directory is
/// none, so such a linked worktree reads only its own binding.
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

/// `git -C <folder> <args>`'s standard output, when git exits 0 by `deadline`. The output is
/// read beside the wait, so a long one (a repository with many worktrees) never holds git past
/// the deadline.
fn git_output(folder: &Path, args: &[&str], deadline: Instant) -> Option<Vec<u8>> {
    if Instant::now() >= deadline {
        return None;
    }
    let mut child = oneiron_spawn::command("git")
        .arg("-C")
        .arg(folder)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    let read = move || {
        let mut out = Vec::new();
        stdout.read_to_end(&mut out).map(|_| out)
    };
    let Ok(reader) = crate::engine_thread("git-output".into()).spawn(read) else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    let status = wait_until(&mut child, deadline);
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let out = reader.join().ok()?.ok()?;
    status?.success().then_some(out)
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
