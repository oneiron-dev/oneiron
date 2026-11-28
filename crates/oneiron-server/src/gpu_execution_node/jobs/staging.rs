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
//!   transport refused. It reads no multi-pack index and no commit graph, so
//!   a pack is found only in `pack/` and a commit's tree is the one its
//!   object names. A mirror whose object directory borrows from another
//!   store (`objects/info/alternates`, or a symbolic link as the object
//!   directory, in it, in a loose-object directory or in `pack/`) is
//!   refused, so a commit only another repository holds never stages. A
//!   commit the mirror lacks ends the key as
//!   `LaunchRefused { commit_missing }`. The mirror is checked once, before
//!   git runs: the account that pushes to it is trusted not to change it
//!   while staging runs.
//! - **The mirror is the pinned template's.** The stager takes the
//!   template's mirror from a reading of the node's configuration in which
//!   that template's digest is still the pin's.
//! - **The checkout** is `git archive` of the commit, unpacked here: the
//!   commit's tree as committed (the view's own attributes turn
//!   `export-subst` and `export-ignore` off, so no `$Format:` text is filled
//!   in, no signature program runs and no path is left out), files,
//!   directories and symbolic links only, nothing written outside
//!   `checkout/`, and its size counted against the pin's `disk_mib`, each
//!   entry at least one block. The count is an early refusal; the payload
//!   directory's disk use is the engine's 5 s check (design 7.9). It belongs
//!   to the engine's account, files 0644 or 0755 and directories 0755, so
//!   the job account reads the code and cannot change it.
//! - **The payload directory is the engine's alone.** The work directory's
//!   path is walked from `/` one component at a time: each directory on it
//!   is owned by root or the engine's account and no other account may
//!   rename in it (it is not writable by them, or it is sticky), and each
//!   symbolic link on it is owned by root or the engine's account and is
//!   followed from the directory that holds it. A missing component is made
//!   only once its parent passed. The work directory itself is owned by the
//!   engine's account and no other account may write in it, and the key's
//!   payload directory is a directory, not a symbolic link, owned by the
//!   engine's account. No other account can then change what the path
//!   names. Else the key ends as `LaunchRefused { work_dir_unsafe }`, and
//!   nothing is removed there.
//! - **The contract.** The file at `contract_path`, opened beneath the
//!   checkout with no symbolic link at any step, is a regular file whose
//!   sha256 is `contract_sha256`. Else the key ends as `LaunchRefused`.
//! - **Host data and caches** are not copied and not hashed here. The
//!   template names them by path (read-only for the job: row R3b), and the
//!   workload's contract names what it expects of them by hash and checks
//!   that itself. Nothing from the vault is staged (a later row, R10).
//! - **Warm inputs** (pass 34, row P2): each warm key the signed submit
//!   lists that the node's file maps to a path that is not a cache must
//!   exist once the contract passed, or the key ends as
//!   `LaunchRefused { warm_key_missing:<key> }`. A key names one thing on
//!   one machine, so any template's mapping counts, as the issuer's facts
//!   count it. Nothing is fetched; an absent cache is a cold start. The
//!   map comes from the same reading of the node's file in which the pin's
//!   template has the pin's digest.
//!
//! Staging runs outside the admission lock, as the engine's account, and
//! asks `closed` before each step and between the contract's read chunks.
//! Each git leads its own process group, and its output and error output
//! are read while it runs. Once git exits, the stager kills the group
//! before it reaps git, while git's id still names the group, so no process
//! git started outlives it; once the key is closed or the staging limit
//! passes, it kills the group at once. A staging that does not complete
//! removes `checkout/`. A staged key that will not launch has its staged
//! code removed ([`Stager::unstage`]) before its end is recorded, while its
//! disk is still booked; a refusal of the launch commit itself removes it
//! just after; the recovery at each start removes it for every key that
//! ended before its launch; and the release check removes it for a key that
//! launched. So a closed key keeps no code on the node's disk.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{ChildStdout, ExitStatus, Stdio};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::node_parts::{StageFailure, StageOrder, Stager};
use super::warm::{WARM_KEY_MISSING, WarmPath, missing_input, warm_paths};
use crate::gpu_execution_node::node::ExecutionNode;
use crate::gpu_execution_node::node_settings::ExecutionNodeSettings;

mod git_process;
mod payload_dir;

pub(in crate::gpu_execution_node::jobs) use payload_dir::trusted_work_dir;

use git_process::{GitChild, GitView};
use payload_dir::payload_dir_owned;
pub use payload_dir::{
    WorkDirAccess, WorkDirFault, WorkDirUnsafe, WorkDirVerdict, work_dir_verdict,
    work_dir_verdict_for,
};

/// The checkout's directory name inside a key's payload directory.
pub const CHECKOUT_DIR_NAME: &str = "checkout";

/// The git directory the stager writes for one staging, inside the key's
/// payload directory. The staging removes it when it ends.
pub const GIT_VIEW_DIR_NAME: &str = "stage-git";

/// The git program the stager runs, found on the engine's `PATH`.
pub const GIT_PROGRAM: &str = "git";

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
    /// The mirror's object directory borrows objects from another store
    /// (`objects/info/alternates`, or a symbolic link as the object
    /// directory, in it, in a loose-object directory or in `pack/`).
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

    /// Every warm key the node's templates map, with its path (pass 34,
    /// row P2), from one reading of the node's configuration in which
    /// `template`'s digest is `template_digest`. The default maps none.
    ///
    /// # Errors
    ///
    /// As [`TemplateMirrors::mirror`].
    fn node_warm_paths(
        &self,
        template: &str,
        template_digest: &str,
    ) -> Result<BTreeMap<String, WarmPath>, StagingRefusal> {
        let _ = (template, template_digest);
        Ok(BTreeMap::new())
    }
}

impl ExecutionNode {
    /// One reading of the node's file in which the template `template`'s
    /// digest is `template_digest`.
    fn pinned_settings(
        &self,
        template: &str,
        template_digest: &str,
    ) -> Result<ExecutionNodeSettings, StagingRefusal> {
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
            Ok(digest) if digest == template_digest => Ok(settings),
            Ok(_) => Err(StagingRefusal::TemplateChanged),
            Err(why) => {
                tracing::warn!(template, %why, "job staging: the template's digest does not compute");
                Err(StagingRefusal::TemplateChanged)
            }
        }
    }
}

impl TemplateMirrors for ExecutionNode {
    fn mirror(&self, template: &str, template_digest: &str) -> Result<PathBuf, StagingRefusal> {
        let mut settings = self.pinned_settings(template, template_digest)?;
        settings
            .templates
            .remove(template)
            .map(|found| found.repo)
            .ok_or(StagingRefusal::TemplateUnknown)
    }

    fn node_warm_paths(
        &self,
        template: &str,
        template_digest: &str,
    ) -> Result<BTreeMap<String, WarmPath>, StagingRefusal> {
        self.pinned_settings(template, template_digest)
            .map(|settings| warm_paths(&settings))
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
        open_unless_closed(closed)?;
        let warm = self
            .mirrors
            .node_warm_paths(&pin.template, &pin.template_digest)?;
        if let Some(key) = missing_input(&warm, &order.warm) {
            tracing::info!(key = %order.key, warm_key = key, "job staging: a warm input the attempt lists is not on this node");
            return Err(StageFailure::Refused(format!("{WARM_KEY_MISSING}:{key}")));
        }
        Ok(())
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
            if let Err(failure) = &staged {
                tracing::info!(key = %order.key, %failure, "job staging did not complete; its checkout is removed");
                remove_logged(&order.payload_dir.join(CHECKOUT_DIR_NAME));
            }
            // The git view goes last: a checkout beside no view is complete.
            remove_logged(&order.payload_dir.join(GIT_VIEW_DIR_NAME));
        }
        staged
    }

    fn unstage(&self, key: &str, payload_dir: &Path) {
        // Nothing is made here, and paths are removed only beneath a
        // payload directory that is the engine's alone.
        if !matches!(payload_dir_owned(payload_dir, false), Ok(true)) {
            return;
        }
        for staged in [CHECKOUT_DIR_NAME, GIT_VIEW_DIR_NAME] {
            let path = payload_dir.join(staged);
            if std::fs::symlink_metadata(&path).is_ok() {
                tracing::info!(key, path = %path.display(), "job staging: the key's staged code is removed");
                remove_logged(&path);
            }
        }
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
/// commit the mirror lacks, and so could a symbolic link as the object
/// directory, in it, in a loose-object directory or in `pack/`. The check
/// is made once, before git runs.
fn mirror_objects(mirror: &Path) -> Result<PathBuf, StagingRefusal> {
    let borrowed = |path: &Path| {
        tracing::warn!(path = %path.display(), "job staging: the mirror borrows objects from another store");
        StagingRefusal::MirrorNotSelfContained
    };
    let unreadable = |path: &Path, error: &std::io::Error| {
        tracing::warn!(path = %path.display(), %error, "job staging: the mirror's object directory does not read");
        StagingRefusal::MirrorUnreadable
    };
    let objects = mirror.join("objects");
    let found =
        std::fs::symlink_metadata(&objects).map_err(|error| unreadable(&objects, &error))?;
    if found.file_type().is_symlink() {
        return Err(borrowed(&objects));
    }
    if !found.is_dir() {
        tracing::warn!(objects = %objects.display(), "job staging: the mirror's object directory is not a directory");
        return Err(StagingRefusal::MirrorUnreadable);
    }
    let listed = |dir: &Path| std::fs::read_dir(dir).map_err(|error| unreadable(dir, &error));
    for entry in listed(&objects)? {
        let entry = entry.map_err(|error| unreadable(&objects, &error))?;
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|error| unreadable(&path, &error))?;
        if kind.is_symlink() {
            return Err(borrowed(&path));
        }
        // `info/` lends objects only through `alternates`, checked below.
        if !kind.is_dir() || entry.file_name() == "info" {
            continue;
        }
        for inner in listed(&path)? {
            let inner = inner.map_err(|error| unreadable(&path, &error))?;
            let inner_path = inner.path();
            let inner_kind = inner
                .file_type()
                .map_err(|error| unreadable(&inner_path, &error))?;
            if inner_kind.is_symlink() {
                return Err(borrowed(&inner_path));
            }
        }
    }
    let alternates = objects.join("info").join("alternates");
    match std::fs::symlink_metadata(&alternates) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(objects),
        Ok(_) => Err(borrowed(&alternates)),
        Err(error) => Err(unreadable(&alternates, &error)),
    }
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
    // git writes the archive's last record past its end blocks, where the
    // unpacker stops; read to the end, git finishes its write and exits
    // instead of failing on a closed pipe.
    let mut rest = archive.into_inner();
    std::io::copy(&mut rest, &mut std::io::sink()).map_err(|error| {
        tracing::warn!(%error, "job staging: the end of git's archive does not read");
        StagingRefusal::CheckoutFailed
    })?;
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
