//! A folder's workspace identity (RECALL-SESSION-PROJECT; Engine ANSWER
//! RECALL-SESSION-PROJECT-INTENT, 26 Nov: the binding stores a hash plus a label): the ids an
//! attached session names its folder by, and the one `oneiron project bind` binds.
//!
//! The folder's checkout root is its git top-level, else the folder itself, as a canonical path
//! (symlinks resolved). Its workspace id is the SHA-256 of a domain tag and that path's bytes,
//! in lower-case hex: the vault's `workspace.project` key is keyed by it, so the vault never
//! holds the path. A linked worktree also names its main checkout's id, second: a worktree with
//! no binding of its own reads its main checkout's. Nothing here is inferred from a folder name,
//! a branch, a remote or a session id. The label is the root's folder name, for display.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

/// What a workspace id's digest covers before the path: the scheme and its version.
const WORKSPACE_ID_DOMAIN: &[u8] = b"oneiron.workspace.v1\0";

/// The longest a git call here may take.
pub const GIT_TIMEOUT: Duration = Duration::from_secs(2);

/// A folder's workspace ids and label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceIdentity {
    /// The folder's checkout's id, then its main checkout's when it is a linked worktree.
    pub ids: Vec<String>,
    /// The checkout root's folder name.
    pub label: String,
}

impl WorkspaceIdentity {
    /// The identity of `folder`: its checkout root's id, its main checkout's for a linked
    /// worktree, and its root's name. Git gets until `deadline` (and at most [`GIT_TIMEOUT`]);
    /// a folder git does not answer for is its own root. `None` when the folder does not
    /// resolve to a canonical path.
    #[must_use]
    pub fn of_folder(folder: &Path, deadline: Instant) -> Option<Self> {
        let folder = std::fs::canonicalize(folder).ok()?;
        let (root, main) = match git_checkout(&folder, deadline) {
            Some(GitCheckout { top, common_dir }) => {
                let root = std::fs::canonicalize(&top).unwrap_or(top);
                (root, main_checkout(&common_dir))
            }
            None => (folder, None),
        };
        let mut ids = vec![workspace_id(&root)];
        if let Some(main) = main.filter(|main| *main != root) {
            ids.push(workspace_id(&main));
        }
        let label = root
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        Some(Self { ids, label })
    }

    /// [`Self::of_folder`] for a folder an agent session runs in: `None` as well when the
    /// checkout root is the filesystem root or the home directory, which hold no one project.
    #[must_use]
    pub fn of_session_folder(folder: &Path, deadline: Instant) -> Option<Self> {
        let identity = Self::of_folder(folder, deadline)?;
        let not_workspaces = [Some(PathBuf::from("/")), home_directory()];
        let roots = not_workspaces.iter().flatten().map(|path| {
            workspace_id(&std::fs::canonicalize(path).unwrap_or_else(|_| path.clone()))
        });
        let own = identity.own_id().to_owned();
        roots
            .into_iter()
            .all(|root| root != own)
            .then_some(identity)
    }

    /// The folder's own id: the item `oneiron project bind` binds.
    #[must_use]
    pub fn own_id(&self) -> &str {
        &self.ids[0]
    }
}

/// The workspace id of the canonical checkout root `root`: the SHA-256 of
/// [`WORKSPACE_ID_DOMAIN`] and the path's bytes, in lower-case hex.
#[must_use]
pub fn workspace_id(root: &Path) -> String {
    let mut digest = Sha256::new();
    digest.update(WORKSPACE_ID_DOMAIN);
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

/// Where git places a folder: its working tree's top level and its repository's common
/// directory, both absolute.
struct GitCheckout {
    top: PathBuf,
    common_dir: PathBuf,
}

fn git_checkout(folder: &Path, deadline: Instant) -> Option<GitCheckout> {
    let deadline = deadline.min(Instant::now() + GIT_TIMEOUT);
    if Instant::now() >= deadline {
        return None;
    }
    let mut child = oneiron_spawn::command("git")
        .arg("-C")
        .arg(folder)
        .args([
            "rev-parse",
            "--path-format=absolute",
            "--show-toplevel",
            "--git-common-dir",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let Some(status) = wait_until(&mut child, deadline) else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    let mut out = String::new();
    child.stdout.take()?.read_to_string(&mut out).ok()?;
    if !status.success() {
        return None;
    }
    let mut lines = out.lines().map(str::trim).filter(|line| !line.is_empty());
    let top = PathBuf::from(lines.next()?);
    let common_dir = PathBuf::from(lines.next()?);
    Some(GitCheckout { top, common_dir })
}

/// The main checkout whose repository is `common_dir`: the folder that holds it when it is a
/// `.git` folder. A bare repository has no main checkout.
fn main_checkout(common_dir: &Path) -> Option<PathBuf> {
    let common_dir = std::fs::canonicalize(common_dir).ok()?;
    if common_dir.file_name()? != ".git" {
        return None;
    }
    common_dir.parent().map(Path::to_path_buf)
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
