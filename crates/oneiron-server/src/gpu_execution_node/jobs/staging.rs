//! Staging (design pass 33, `33-exec-node/DESIGN.md` section 7.4; row R3c):
//! the code of a key's pin, exported from its template's host-local mirror
//! at the pinned commit into `<work_dir>/<key id>/checkout/`, and the check
//! that the pin's contract file hashes to the pinned digest.
//!
//! - **Code comes only from the mirror's own objects.** The node never
//!   fetches. git runs on a git directory the stager writes for each
//!   staging ([`GIT_VIEW_DIR_NAME`] in the payload directory): no
//!   configuration but the object format, no refs, no hooks, and the
//!   mirror's object directory as `GIT_OBJECT_DIRECTORY`. git therefore
//!   reads nothing of the mirror but its objects: no filter driver or other
//!   command from the mirror's configuration, no promisor remote to fetch
//!   from, no attributes file. It runs with an empty environment but `PATH`,
//!   reads no system or global configuration or attributes, and has every
//!   transport refused. A mirror whose object directory borrows from another
//!   (`objects/info/alternates`) is refused, so a commit only another
//!   repository holds never stages. A commit the mirror lacks ends the key
//!   as `LaunchRefused { commit_missing }`.
//! - **The mirror is the pinned template's.** The stager takes the
//!   template's mirror from a reading of the node's configuration in which
//!   that template's digest is still the pin's.
//! - **The checkout** is `git archive` of the commit, unpacked here: files,
//!   directories and symbolic links only, nothing written outside
//!   `checkout/`, and its size counted against the pin's `disk_mib`, each
//!   entry at least one block. The count is an early refusal; the payload
//!   directory's disk use is the engine's 5 s check (design 7.9). It belongs
//!   to the engine's account, files 0644 or 0755 and directories 0755, so
//!   the job account reads the code and cannot change it.
//! - **The payload directory is the engine's alone.** The work directory is
//!   owned by the engine's account and no other account may write in it;
//!   each of its ancestors is owned by root or the engine's account, and no
//!   other account may rename in it (it is not writable by them, or it is
//!   sticky); the key's payload directory is a directory, not a symbolic
//!   link, owned by the engine's account. Else the key ends as
//!   `LaunchRefused { work_dir_unsafe }`, and nothing is removed there.
//! - **The contract.** The file at `contract_path`, opened beneath the
//!   checkout with no symbolic link at any step, is a regular file whose
//!   sha256 is `contract_sha256`. Else the key ends as `LaunchRefused`.
//! - **Host data and caches** are not copied and not hashed here. The
//!   template names them by path (read-only for the job: row R3b), and the
//!   workload's contract names what it expects of them by hash and checks
//!   that itself. Nothing from the vault is staged (a later row, R10).
//!
//! Staging runs outside the admission lock, as the engine's account, and
//! asks `closed` before each step and between the contract's read chunks.
//! Each git leads its own process group, and its output and error output
//! are read while it runs. Once git exits, the stager kills the group
//! before it reaps git, while git's id still names the group, so no process
//! git started outlives it; once the key is closed or the staging limit
//! passes, it kills the group at once. A staging that does not complete
//! removes `checkout/`, and so does a staged key that does not launch
//! ([`Stager::unstage`]), so a closed key keeps no code on the node's disk.

use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};
use sha2::{Digest, Sha256};

use super::node_parts::{StageFailure, StageOrder, Stager};
use crate::gpu_execution_node::node::ExecutionNode;

/// The checkout's directory name inside a key's payload directory.
pub const CHECKOUT_DIR_NAME: &str = "checkout";

/// The git directory the stager writes for one staging, inside the key's
/// payload directory. The staging removes it when it ends.
pub const GIT_VIEW_DIR_NAME: &str = "stage-git";

/// The git program the stager runs, found on the engine's `PATH`.
pub const GIT_PROGRAM: &str = "git";

/// How often the stager looks at a running git and at `closed`.
const GIT_POLL: Duration = Duration::from_millis(20);

/// The disk block every checkout entry is counted in: a file's size rounded
/// up to it (an empty file takes one), and one for each directory and
/// symbolic link.
const CHECKOUT_BLOCK_BYTES: u64 = 4096;

/// The most of git's error output the stager keeps for its log.
const GIT_STDERR_KEPT_BYTES: u64 = 4096;

/// The most of git's batch answer the stager reads: one line.
const GIT_ANSWER_KEPT_BYTES: u64 = 512;

/// The contract's read chunk; `closed` is asked before each.
const CONTRACT_CHUNK_BYTES: usize = 64 * 1024;

/// The mode bits that let the group or other accounts write in a directory.
const GROUP_OTHER_WRITE: u32 = 0o022;

/// The sticky bit: in such a directory only an entry's owner renames it.
const STICKY: u32 = 0o1000;

/// Why staging refused a key. Each ends the key as
/// `LaunchRefused { reason: code }`: not started, zero seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StagingRefusal {
    /// The node holds no template of the pin's name now.
    TemplateUnknown,
    /// The template's digest is no longer the pin's.
    TemplateChanged,
    /// The node's own file does not read.
    NodeFileUnreadable,
    /// The pin's commit is not 40 or 64 lower-hex characters.
    CommitInvalid,
    /// The template's mirror holds no commit of that id.
    CommitMissing,
    /// git could not read the template's mirror.
    MirrorUnreadable,
    /// The mirror's object directory borrows objects from another
    /// (`objects/info/alternates`).
    MirrorNotSelfContained,
    /// The work directory, one of its ancestors, or the key's payload
    /// directory is not the engine's alone.
    WorkDirUnsafe,
    /// The export did not complete: git failed, or an entry was not a file,
    /// a directory or a symbolic link, or would land outside the checkout.
    CheckoutFailed,
    /// The checkout alone is larger than the pin's `disk_mib`.
    CheckoutOverDiskRequest,
    /// The pin's `contract_path` is not a relative path inside the checkout.
    ContractPathInvalid,
    /// The checkout has no file at `contract_path`.
    ContractMissing,
    /// `contract_path` names a symbolic link, a directory, or a path through
    /// a symbolic link.
    ContractNotAFile,
    /// The contract file does not read.
    ContractUnreadable,
    /// The contract file's sha256 is not the pin's `contract_sha256`.
    ContractChanged,
}

impl StagingRefusal {
    /// The reason the key's `LaunchRefused` end carries.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TemplateUnknown => "template_unknown",
            Self::TemplateChanged => "template_changed",
            Self::NodeFileUnreadable => "node_file_unreadable",
            Self::CommitInvalid => "commit_invalid",
            Self::CommitMissing => "commit_missing",
            Self::MirrorUnreadable => "mirror_unreadable",
            Self::MirrorNotSelfContained => "mirror_not_self_contained",
            Self::WorkDirUnsafe => "work_dir_unsafe",
            Self::CheckoutFailed => "checkout_failed",
            Self::CheckoutOverDiskRequest => "checkout_over_disk_request",
            Self::ContractPathInvalid => "contract_path_invalid",
            Self::ContractMissing => "contract_missing",
            Self::ContractNotAFile => "contract_not_a_file",
            Self::ContractUnreadable => "contract_unreadable",
            Self::ContractChanged => "contract_changed",
        }
    }
}

impl std::fmt::Display for StagingRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl From<StagingRefusal> for StageFailure {
    fn from(refusal: StagingRefusal) -> Self {
        Self::Refused(refusal.code().to_owned())
    }
}

/// Where each template's code comes from: the template's host-local mirror,
/// read from the node's own configuration at each staging.
pub trait TemplateMirrors: Send + Sync {
    /// The mirror of `template`, from one reading of the node's
    /// configuration in which that template's digest is `template_digest`.
    ///
    /// # Errors
    ///
    /// [`StagingRefusal::TemplateUnknown`] when the node holds no such
    /// template now; [`StagingRefusal::TemplateChanged`] when its digest is
    /// another (or does not compute); [`StagingRefusal::NodeFileUnreadable`]
    /// when the node's file does not read.
    fn mirror(&self, template: &str, template_digest: &str) -> Result<PathBuf, StagingRefusal>;
}

impl TemplateMirrors for ExecutionNode {
    fn mirror(&self, template: &str, template_digest: &str) -> Result<PathBuf, StagingRefusal> {
        let settings = match self.settings() {
            Ok(Some(settings)) => settings,
            Ok(None) => return Err(StagingRefusal::TemplateUnknown),
            Err(why) => {
                tracing::warn!(template, %why, "job staging: the node's file does not read");
                return Err(StagingRefusal::NodeFileUnreadable);
            }
        };
        let found = settings
            .templates
            .get(template)
            .ok_or(StagingRefusal::TemplateUnknown)?;
        match found.digest() {
            Ok(digest) if digest == template_digest => Ok(found.repo.clone()),
            Ok(_) => Err(StagingRefusal::TemplateChanged),
            Err(why) => {
                tracing::warn!(template, %why, "job staging: the template's digest does not compute");
                Err(StagingRefusal::TemplateChanged)
            }
        }
    }
}

/// The node's stager: the checkout from the template's mirror at the pinned
/// commit, then the contract check (row R3c). It replaces
/// [`super::StagingNotBuilt`] in the parts the server gives the job service.
#[derive(Clone)]
pub struct MirrorStager {
    mirrors: Arc<dyn TemplateMirrors>,
    git: PathBuf,
}

impl std::fmt::Debug for MirrorStager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MirrorStager")
            .field("git", &self.git)
            .finish_non_exhaustive()
    }
}

/// What a git that exited left: its status, what the output's reader made
/// of it, and the first [`GIT_STDERR_KEPT_BYTES`] of its error output.
struct GitEnd<T> {
    status: ExitStatus,
    output: T,
    errors: String,
}

impl MirrorStager {
    /// A stager that reads each template's mirror from `mirrors` and runs
    /// [`GIT_PROGRAM`].
    #[must_use]
    pub fn new(mirrors: Arc<dyn TemplateMirrors>) -> Self {
        Self {
            mirrors,
            git: PathBuf::from(GIT_PROGRAM),
        }
    }

    fn stage_checkout(
        &self,
        order: &StageOrder,
        closed: &dyn Fn() -> bool,
    ) -> Result<(), StageFailure> {
        let pin = &order.pin;
        if !commit_id(&pin.commit) {
            return Err(StagingRefusal::CommitInvalid.into());
        }
        if !relative_inside(&pin.contract_path) {
            return Err(StagingRefusal::ContractPathInvalid.into());
        }
        open_unless_closed(closed)?;
        let mirror = self.mirrors.mirror(&pin.template, &pin.template_digest)?;
        let objects = mirror_objects(&mirror)?;
        open_unless_closed(closed)?;
        payload_dir_owned(&order.payload_dir, true)?;
        let view = GitView::write(&order.payload_dir, objects, &pin.commit).map_err(|error| {
            tracing::warn!(key = %order.key, %error, "job staging: the git view was not written");
            StagingRefusal::CheckoutFailed
        })?;
        open_unless_closed(closed)?;
        self.commit_present(&view, &pin.commit, closed)?;
        open_unless_closed(closed)?;
        let checkout = order.payload_dir.join(CHECKOUT_DIR_NAME);
        fresh_checkout(&checkout).map_err(|error| {
            tracing::warn!(key = %order.key, %error, "job staging: the checkout directory was not made");
            StagingRefusal::CheckoutFailed
        })?;
        let budget = pin.request.disk_mib.saturating_mul(1024 * 1024);
        self.export(&view, &pin.commit, &checkout, budget, closed)?;
        open_unless_closed(closed)?;
        contract_matches(&checkout, &pin.contract_path, &pin.contract_sha256, closed)?;
        open_unless_closed(closed)
    }

    /// Runs git on `view` with `args` to its end: `input` written to it, its
    /// output read by `consume` and its error output by a second reader
    /// while it runs, so a full pipe never stalls it. Once `closed` answers
    /// true, git's group is killed.
    fn run_git<T: Send>(
        &self,
        view: &GitView,
        args: &[&str],
        input: Option<&[u8]>,
        consume: impl FnOnce(ChildStdout) -> T + Send,
        closed: &dyn Fn() -> bool,
        failed: StagingRefusal,
    ) -> Result<GitEnd<T>, StageFailure> {
        let mut command = view.command(&self.git);
        command
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut git = GitChild::spawn(command).map_err(|error| {
            tracing::warn!(%error, "job staging: git did not start");
            failed
        })?;
        let stdin = git.child.stdin.take();
        let (Some(stdout), Some(stderr)) = (git.child.stdout.take(), git.child.stderr.take())
        else {
            // Dropping `git` kills its group and reaps it.
            return Err(failed.into());
        };
        std::thread::scope(|scope| {
            // Owned in here, so every early return ends git before the scope
            // joins the readers, and they see their pipes close.
            let mut git = git;
            let reader = |name: &str| std::thread::Builder::new().name(name.to_owned());
            let output = reader("oneiron-job-stage-out")
                .spawn_scoped(scope, move || consume(stdout))
                .map_err(|error| {
                    tracing::warn!(%error, "job staging: git's output reader not started");
                    failed
                })?;
            let errors = reader("oneiron-job-stage-err")
                .spawn_scoped(scope, move || kept_text(stderr, GIT_STDERR_KEPT_BYTES))
                .map_err(|error| {
                    tracing::warn!(%error, "job staging: git's error reader not started");
                    failed
                })?;
            if let (Some(mut stdin), Some(input)) = (stdin, input) {
                // A failed write shows as git's answer or its exit status;
                // the pipe closes here.
                let _ = stdin.write_all(input);
            }
            let status = git.wait(closed, failed)?;
            let output = output.join().map_err(|_| failed)?;
            let errors = errors.join().unwrap_or_default();
            Ok(GitEnd {
                status,
                output,
                errors,
            })
        })
    }

    /// Whether the mirror holds `commit` as a commit object. Asks git's
    /// batch check, which answers `<id> missing` for an object it lacks and
    /// never fetches one.
    fn commit_present(
        &self,
        view: &GitView,
        commit: &str,
        closed: &dyn Fn() -> bool,
    ) -> Result<(), StageFailure> {
        let line = format!("{commit}\n");
        let ended = self.run_git(
            view,
            &["cat-file", "--batch-check"],
            Some(line.as_bytes()),
            |answer| kept_text(answer, GIT_ANSWER_KEPT_BYTES),
            closed,
            StagingRefusal::MirrorUnreadable,
        )?;
        if !ended.status.success() {
            tracing::warn!(objects = %view.objects.display(), status = %ended.status, errors = %ended.errors, "job staging: git could not read the mirror");
            return Err(StagingRefusal::MirrorUnreadable.into());
        }
        let mut fields = ended.output.split_whitespace();
        match (fields.next(), fields.next()) {
            (Some(id), Some("commit")) if id == commit => Ok(()),
            _ => Err(StagingRefusal::CommitMissing.into()),
        }
    }

    /// `git archive` of `commit`, unpacked into `checkout` as it streams.
    fn export(
        &self,
        view: &GitView,
        commit: &str,
        checkout: &Path,
        budget_bytes: u64,
        closed: &dyn Fn() -> bool,
    ) -> Result<(), StageFailure> {
        let ended = self.run_git(
            view,
            &["-c", "tar.umask=022", "archive", "--format=tar", commit],
            None,
            |archive| unpack_checkout(archive, checkout, budget_bytes),
            closed,
            StagingRefusal::CheckoutFailed,
        )?;
        // An unpacking that stopped early dropped the pipe, and git ended.
        ended.output?;
        if ended.status.success() {
            Ok(())
        } else {
            tracing::warn!(objects = %view.objects.display(), commit, status = %ended.status, errors = %ended.errors, "job staging: git archive failed");
            Err(StagingRefusal::CheckoutFailed.into())
        }
    }
}

impl Stager for MirrorStager {
    fn stage(&self, order: &StageOrder, closed: &dyn Fn() -> bool) -> Result<(), StageFailure> {
        let staged = self.stage_checkout(order, closed);
        // Paths are removed only beneath a payload directory that is the
        // engine's alone.
        if matches!(payload_dir_owned(&order.payload_dir, false), Ok(true)) {
            remove_logged(&order.payload_dir.join(GIT_VIEW_DIR_NAME));
            if let Err(failure) = &staged {
                tracing::info!(key = %order.key, %failure, "job staging did not complete; its checkout is removed");
                remove_logged(&order.payload_dir.join(CHECKOUT_DIR_NAME));
            }
        }
        staged
    }

    fn unstage(&self, order: &StageOrder) {
        if matches!(payload_dir_owned(&order.payload_dir, false), Ok(true)) {
            tracing::info!(key = %order.key, "job staging: the key did not launch; its checkout is removed");
            remove_logged(&order.payload_dir.join(CHECKOUT_DIR_NAME));
        }
    }
}

/// The git directory of one staging: a `HEAD` with no ref behind it, an
/// empty `refs/` and `objects/`, and a configuration that names the object
/// format alone.
/// The mirror's object directory is git's `GIT_OBJECT_DIRECTORY`.
struct GitView {
    dir: PathBuf,
    objects: PathBuf,
}

impl GitView {
    /// Writes the view beneath `payload_dir`, in place of one an earlier
    /// staging of the key left. A 64-character commit id is a SHA-256
    /// repository's; a 40-character one, a SHA-1 repository's.
    fn write(payload_dir: &Path, objects: PathBuf, commit: &str) -> std::io::Result<Self> {
        let dir = payload_dir.join(GIT_VIEW_DIR_NAME);
        remove_tree(&dir)?;
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        // `refs/` and an empty `objects/` make it a git directory to every
        // git; the objects git reads are the mirror's.
        for part in ["refs", "objects"] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(dir.join(part))?;
        }
        std::fs::write(dir.join("HEAD"), b"ref: refs/heads/staging\n")?;
        let config: &[u8] = if commit.len() == 64 {
            b"[core]\n\trepositoryformatversion = 1\n\tbare = true\n[extensions]\n\tobjectformat = sha256\n"
        } else {
            b"[core]\n\trepositoryformatversion = 0\n\tbare = true\n"
        };
        std::fs::write(dir.join("config"), config)?;
        Ok(Self { dir, objects })
    }

    /// git on the view with the node's fences: an empty environment but
    /// `PATH`, no system or global configuration or attributes, no replace
    /// refs, no lazy fetch, every transport refused, and git the leader of
    /// its own process group.
    fn command(&self, git: &Path) -> Command {
        let mut command = Command::new(git);
        command.env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            command.env("PATH", path);
        }
        command
            .env("GIT_DIR", &self.dir)
            .env("GIT_OBJECT_DIRECTORY", &self.objects)
            .envs([
                ("GIT_CONFIG_NOSYSTEM", "1"),
                ("GIT_CONFIG_GLOBAL", "/dev/null"),
                ("GIT_ATTR_NOSYSTEM", "1"),
                ("GIT_NO_REPLACE_OBJECTS", "1"),
                ("GIT_NO_LAZY_FETCH", "1"),
                // Set and empty: no transport is allowed, whatever a
                // `protocol.<name>.allow` says.
                ("GIT_ALLOW_PROTOCOL", ""),
                ("GIT_TERMINAL_PROMPT", "0"),
                ("LC_ALL", "C"),
            ])
            .args([
                "-c",
                "core.attributesFile=/dev/null",
                "-c",
                "protocol.allow=never",
            ])
            .current_dir("/")
            .process_group(0);
        command
    }
}

/// A started git, the leader of its own process group. Its end kills the
/// group before git is reaped, while git's id still names the group, so no
/// process git started outlives it. Dropped unreaped, it does the same.
struct GitChild {
    child: Child,
    reaped: bool,
}

impl GitChild {
    fn spawn(mut command: Command) -> std::io::Result<Self> {
        command.spawn().map(|child| Self {
            child,
            reaped: false,
        })
    }

    /// Waits for git to exit, ending it once `closed` answers true.
    fn wait(
        &mut self,
        closed: &dyn Fn() -> bool,
        failed: StagingRefusal,
    ) -> Result<ExitStatus, StageFailure> {
        let pid = Pid::from_child(&self.child);
        let exited = WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG;
        loop {
            match rustix::process::waitid(WaitId::Pid(pid), exited) {
                Ok(Some(_)) => {
                    // git has exited and is not reaped yet.
                    self.kill_group();
                    self.reaped = true;
                    return self.child.wait().map_err(|error| {
                        tracing::warn!(%error, "job staging: git's exit status does not read");
                        failed.into()
                    });
                }
                Ok(None) | Err(rustix::io::Errno::INTR) => {}
                Err(error) => {
                    tracing::warn!(%error, "job staging: git's state does not read");
                    self.end();
                    return Err(failed.into());
                }
            }
            if closed() {
                self.end();
                return Err(StageFailure::Closed);
            }
            std::thread::sleep(GIT_POLL);
        }
    }

    fn kill_group(&self) {
        // A group with no process left answers ESRCH.
        let _ = rustix::process::kill_process_group(Pid::from_child(&self.child), Signal::KILL);
    }

    /// Kills git's group and reaps git.
    fn end(&mut self) {
        if self.reaped {
            return;
        }
        self.kill_group();
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.reaped = true;
    }
}

impl Drop for GitChild {
    fn drop(&mut self) {
        self.end();
    }
}

/// `Closed` once the key is closed or the staging limit passed.
fn open_unless_closed(closed: &dyn Fn() -> bool) -> Result<(), StageFailure> {
    if closed() {
        Err(StageFailure::Closed)
    } else {
        Ok(())
    }
}

/// A commit id: 40 (SHA-1) or 64 (SHA-256) lower-hex characters. It can
/// never be read by git as an option or a revision expression.
fn commit_id(commit: &str) -> bool {
    matches!(commit.len(), 40 | 64)
        && commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A relative path of plain segments: no empty segment, no `.` or `..`, no
/// leading `/`, no backslash and no NUL.
fn relative_inside(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(['\\', '\0'])
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

/// The mirror's object directory, when the mirror's objects are its own: an
/// object directory that names another in `info/alternates` could lend a
/// commit the mirror lacks.
fn mirror_objects(mirror: &Path) -> Result<PathBuf, StagingRefusal> {
    let objects = mirror.join("objects");
    match std::fs::metadata(&objects) {
        Ok(found) if found.is_dir() => {}
        Ok(_) => {
            tracing::warn!(objects = %objects.display(), "job staging: the mirror's object directory is not a directory");
            return Err(StagingRefusal::MirrorUnreadable);
        }
        Err(error) => {
            tracing::warn!(objects = %objects.display(), %error, "job staging: the mirror's object directory does not read");
            return Err(StagingRefusal::MirrorUnreadable);
        }
    }
    let alternates = objects.join("info").join("alternates");
    match std::fs::symlink_metadata(&alternates) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(objects),
        Ok(_) => {
            tracing::warn!(alternates = %alternates.display(), "job staging: the mirror borrows objects from another repository");
            Err(StagingRefusal::MirrorNotSelfContained)
        }
        Err(error) => {
            tracing::warn!(alternates = %alternates.display(), %error, "job staging: the mirror's alternates do not read");
            Err(StagingRefusal::MirrorUnreadable)
        }
    }
}

/// Whether the key's payload directory exists and is the engine's alone:
/// the work directory is owned by the engine's account and no other account
/// writes in it, each ancestor is owned by root or the engine's account and
/// no other account renames in it, and the payload directory is a
/// directory (not a symbolic link) owned by the engine's account. With
/// `make`, the work directory and the payload directory are made (0755)
/// when missing; the payload directory is made only once the work directory
/// passed. Path-based writes and removals beneath it are then safe: no
/// other account can move an entry on the path.
fn payload_dir_owned(payload_dir: &Path, make: bool) -> Result<bool, StagingRefusal> {
    let not_owned = |path: &Path, why: &str| {
        tracing::warn!(path = %path.display(), why, "job staging: the payload directory is not the engine's alone");
        StagingRefusal::WorkDirUnsafe
    };
    let Some(work_dir) = payload_dir.parent() else {
        return Err(not_owned(payload_dir, "it has no work directory"));
    };
    if make {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(work_dir)
            .map_err(|error| {
                tracing::warn!(work_dir = %work_dir.display(), %error, "job staging: the work directory was not made");
                StagingRefusal::CheckoutFailed
            })?;
    }
    let canonical = match std::fs::canonicalize(work_dir) {
        Ok(found) => found,
        Err(error) if !make && error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(not_owned(work_dir, &error.to_string())),
    };
    let engine = rustix::process::geteuid().as_raw();
    let work = std::fs::symlink_metadata(&canonical)
        .map_err(|error| not_owned(&canonical, &error.to_string()))?;
    if !work.is_dir() || work.uid() != engine || work.mode() & GROUP_OTHER_WRITE != 0 {
        return Err(not_owned(
            &canonical,
            "the work directory is not the engine's, or others may write in it",
        ));
    }
    for ancestor in canonical.ancestors().skip(1) {
        let found = std::fs::symlink_metadata(ancestor)
            .map_err(|error| not_owned(ancestor, &error.to_string()))?;
        let owner_trusted = found.uid() == 0 || found.uid() == engine;
        let renames_closed = found.mode() & GROUP_OTHER_WRITE == 0 || found.mode() & STICKY != 0;
        if !owner_trusted || !renames_closed {
            return Err(not_owned(
                ancestor,
                "an ancestor another account owns or may rename in",
            ));
        }
    }
    if make {
        match std::fs::DirBuilder::new().mode(0o755).create(payload_dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                tracing::warn!(payload_dir = %payload_dir.display(), %error, "job staging: the payload directory was not made");
                return Err(StagingRefusal::CheckoutFailed);
            }
        }
    }
    match std::fs::symlink_metadata(payload_dir) {
        Ok(found) if found.is_dir() && found.uid() == engine => {}
        Ok(_) => {
            return Err(not_owned(
                payload_dir,
                "the payload directory is a link, not a directory, or not the engine's",
            ));
        }
        Err(error) if !make && error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(not_owned(payload_dir, &error.to_string())),
    }
    if make {
        // The job account passes through and reads; only the engine writes.
        std::fs::set_permissions(payload_dir, std::fs::Permissions::from_mode(0o755)).map_err(
            |error| {
                tracing::warn!(payload_dir = %payload_dir.display(), %error, "job staging: the payload directory's mode was not set");
                StagingRefusal::CheckoutFailed
            },
        )?;
    }
    Ok(true)
}

/// The first `kept` bytes of `pipe` as text; the rest is read and dropped,
/// so its writer never waits on a full pipe.
fn kept_text(mut pipe: impl Read, kept: u64) -> String {
    let mut bytes = Vec::new();
    let _ = pipe.by_ref().take(kept).read_to_end(&mut bytes);
    let _ = std::io::copy(&mut pipe, &mut std::io::sink());
    String::from_utf8_lossy(&bytes).trim().to_owned()
}

/// An empty `checkout/` (0755) in place of one an earlier staging of the
/// key left: a restart restages from nothing.
fn fresh_checkout(checkout: &Path) -> std::io::Result<()> {
    remove_tree(checkout)?;
    std::fs::DirBuilder::new().mode(0o755).create(checkout)?;
    std::fs::set_permissions(checkout, std::fs::Permissions::from_mode(0o755))
}

/// Removes `path` and everything beneath it, never following a symbolic
/// link; a missing path is already removed.
fn remove_tree(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

fn remove_logged(path: &Path) {
    if let Err(error) = remove_tree(path) {
        tracing::warn!(path = %path.display(), %error, "job staging: a staged path was not removed");
    }
}

/// Unpacks git's tar stream into `checkout`. Only files, directories and
/// symbolic links; git's global header (the commit id) is skipped. Every
/// entry is counted against `budget_bytes` before it is written. Nothing
/// lands outside `checkout`: the unpacker refuses a path with `..` and a
/// path through a symbolic link that leaves the checkout.
fn unpack_checkout(
    archive: impl Read,
    checkout: &Path,
    budget_bytes: u64,
) -> Result<(), StagingRefusal> {
    let mut archive = tar::Archive::new(archive);
    archive.set_mask(0o022);
    archive.set_preserve_permissions(false);
    archive.set_overwrite(false);
    let entries = archive.entries().map_err(|error| {
        tracing::warn!(%error, "job staging: git's archive does not read");
        StagingRefusal::CheckoutFailed
    })?;
    let mut counted: u64 = 0;
    for entry in entries {
        let mut entry = entry.map_err(|error| {
            tracing::warn!(%error, "job staging: an archive entry does not read");
            StagingRefusal::CheckoutFailed
        })?;
        let kind = entry.header().entry_type();
        let bytes = if kind.is_pax_global_extensions() {
            continue;
        } else if kind.is_file() {
            entry.size().div_ceil(CHECKOUT_BLOCK_BYTES).max(1) * CHECKOUT_BLOCK_BYTES
        } else if kind.is_dir() || kind.is_symlink() {
            CHECKOUT_BLOCK_BYTES
        } else {
            tracing::warn!(?kind, path = %entry.path_bytes().escape_ascii(), "job staging: an archive entry is not a file, a directory or a symbolic link");
            return Err(StagingRefusal::CheckoutFailed);
        };
        counted = counted.saturating_add(bytes);
        if counted > budget_bytes {
            return Err(StagingRefusal::CheckoutOverDiskRequest);
        }
        match entry.unpack_in(checkout) {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(path = %entry.path_bytes().escape_ascii(), "job staging: an archive entry would land outside the checkout");
                return Err(StagingRefusal::CheckoutFailed);
            }
            Err(error) => {
                tracing::warn!(path = %entry.path_bytes().escape_ascii(), %error, "job staging: an archive entry was not written");
                return Err(StagingRefusal::CheckoutFailed);
            }
        }
    }
    Ok(())
}

/// Design 7.4: the file at `contract_path` hashes to `contract_sha256`. It
/// is opened beneath the checkout one segment at a time, never following a
/// symbolic link, and must be a regular file. `closed` is asked before each
/// read chunk.
fn contract_matches(
    checkout: &Path,
    contract_path: &str,
    contract_sha256: &str,
    closed: &dyn Fn() -> bool,
) -> Result<(), StageFailure> {
    let mut contract = open_beneath(checkout, contract_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; CONTRACT_CHUNK_BYTES];
    loop {
        open_unless_closed(closed)?;
        match contract.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => hasher.update(&buffer[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                tracing::warn!(contract_path, %error, "job staging: the contract does not read");
                return Err(StagingRefusal::ContractUnreadable.into());
            }
        }
    }
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if digest == contract_sha256 {
        Ok(())
    } else {
        Err(StagingRefusal::ContractChanged.into())
    }
}

/// Opens the regular file at `relative` beneath `root`, segment by segment,
/// with no symbolic link followed at any step.
fn open_beneath(root: &Path, relative: &str) -> Result<std::fs::File, StagingRefusal> {
    use rustix::fs::{FileType, Mode, OFlags};

    let refusal = |error: rustix::io::Errno| match error {
        rustix::io::Errno::NOENT => StagingRefusal::ContractMissing,
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => StagingRefusal::ContractNotAFile,
        other => {
            tracing::warn!(contract_path = relative, error = %other, "job staging: the contract does not open");
            StagingRefusal::ContractUnreadable
        }
    };
    let directory = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut parent = rustix::fs::open(root, directory, Mode::empty()).map_err(refusal)?;
    let mut segments = relative.split('/').peekable();
    while let Some(segment) = segments.next() {
        if segments.peek().is_some() {
            parent =
                rustix::fs::openat(&parent, segment, directory, Mode::empty()).map_err(refusal)?;
            continue;
        }
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let file = rustix::fs::openat(&parent, segment, flags, Mode::empty()).map_err(refusal)?;
        let stat = rustix::fs::fstat(&file).map_err(refusal)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(StagingRefusal::ContractNotAFile);
        }
        return Ok(std::fs::File::from(file));
    }
    Err(StagingRefusal::ContractPathInvalid)
}
