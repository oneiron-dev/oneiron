//! Staging (design pass 33, `33-exec-node/DESIGN.md` section 7.4; row R3c):
//! the code of a key's pin, exported from its template's host-local mirror
//! at the pinned commit into `<work_dir>/<key id>/checkout/`, and the check
//! that the pin's contract file hashes to the pinned digest.
//!
//! - **Code comes only from the mirror.** The node never fetches. git runs
//!   with an empty environment, reads no system or global configuration,
//!   ignores replace refs, may not fetch a missing object lazily (a partial
//!   clone), and has every transport refused. A commit the mirror lacks ends
//!   the key as `LaunchRefused { commit_missing }`.
//! - **The checkout** is `git archive` of the commit, unpacked here: files,
//!   directories and symbolic links only, nothing written outside
//!   `checkout/`, and its size counted against the pin's `disk_mib`. It
//!   belongs to the engine's account, files 0644 or 0755 and directories
//!   0755, so the job account reads the code and cannot change it.
//! - **The contract.** The file at `contract_path`, opened beneath the
//!   checkout with no symbolic link at any step, is a regular file whose
//!   sha256 is `contract_sha256`. Else the key ends as `LaunchRefused`.
//! - **Host data and caches** are not copied and not hashed here. The
//!   template names them by path (read-only for the job: row R3b), and the
//!   workload's contract names what it expects of them by hash and checks
//!   that itself. Nothing from the vault is staged (a later row, R10).
//!
//! Staging runs outside the admission lock, as the engine's account, and
//! asks `closed` before each step. While git runs, the stager watches
//! `closed` and kills git once the key is closed or the staging limit
//! passes. A staging that does not complete removes `checkout/`, so a closed
//! key keeps no code on the node's disk.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::node_parts::{StageFailure, StageOrder, Stager};
use crate::gpu_execution_node::node::ExecutionNode;

/// The checkout's directory name inside a key's payload directory.
pub const CHECKOUT_DIR_NAME: &str = "checkout";

/// The git program the stager runs, found on the engine's `PATH`.
pub const GIT_PROGRAM: &str = "git";

/// How often the stager looks at a running git and at `closed`.
const GIT_POLL: Duration = Duration::from_millis(20);

/// The disk block every checkout entry is counted in: a file's size rounded
/// up to it, and one for each directory and symbolic link.
const CHECKOUT_BLOCK_BYTES: u64 = 4096;

/// The most of git's error output the stager keeps for its log.
const GIT_STDERR_KEPT_BYTES: u64 = 4096;

/// Why staging refused a key. Each ends the key as
/// `LaunchRefused { reason: code }`: not started, zero seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StagingRefusal {
    /// The node holds no template of the pin's name now.
    TemplateUnknown,
    /// The node's own file does not read.
    NodeFileUnreadable,
    /// The pin's commit is not 40 or 64 lower-hex characters.
    CommitInvalid,
    /// The template's mirror holds no commit of that id.
    CommitMissing,
    /// git could not read the template's mirror.
    MirrorUnreadable,
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
            Self::NodeFileUnreadable => "node_file_unreadable",
            Self::CommitInvalid => "commit_invalid",
            Self::CommitMissing => "commit_missing",
            Self::MirrorUnreadable => "mirror_unreadable",
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
    /// The mirror of `template`, as the node's configuration names it now.
    ///
    /// # Errors
    ///
    /// [`StagingRefusal::TemplateUnknown`] when the node holds no such
    /// template now; [`StagingRefusal::NodeFileUnreadable`] when its file
    /// does not read.
    fn mirror(&self, template: &str) -> Result<PathBuf, StagingRefusal>;
}

impl TemplateMirrors for ExecutionNode {
    fn mirror(&self, template: &str) -> Result<PathBuf, StagingRefusal> {
        match self.settings() {
            Ok(Some(settings)) => settings
                .templates
                .get(template)
                .map(|found| found.repo.clone())
                .ok_or(StagingRefusal::TemplateUnknown),
            Ok(None) => Err(StagingRefusal::TemplateUnknown),
            Err(why) => {
                tracing::warn!(template, %why, "job staging: the node's file does not read");
                Err(StagingRefusal::NodeFileUnreadable)
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
        checkout: &Path,
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
        let mirror = self.mirrors.mirror(&pin.template)?;
        open_unless_closed(closed)?;
        self.commit_present(&mirror, &pin.commit, closed)?;
        open_unless_closed(closed)?;
        fresh_checkout(&order.payload_dir, checkout).map_err(|error| {
            tracing::warn!(key = %order.key, %error, "job staging: the checkout directory was not made");
            StagingRefusal::CheckoutFailed
        })?;
        let budget = pin.request.disk_mib.saturating_mul(1024 * 1024);
        self.export(&mirror, &pin.commit, checkout, budget, closed)?;
        open_unless_closed(closed)?;
        contract_matches(checkout, &pin.contract_path, &pin.contract_sha256)?;
        open_unless_closed(closed)
    }

    /// git on `mirror` with the node's fences: an empty environment but
    /// `PATH`, no system or global configuration, no replace refs, no lazy
    /// fetch, every transport refused, and the mirror named as a safe
    /// directory (its owner may be another account).
    fn git(&self, mirror: &Path) -> Command {
        let mut command = Command::new(&self.git);
        command.env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            command.env("PATH", path);
        }
        command.envs([
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_NO_REPLACE_OBJECTS", "1"),
            ("GIT_NO_LAZY_FETCH", "1"),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("LC_ALL", "C"),
        ]);
        let mut git_dir = OsString::from("--git-dir=");
        git_dir.push(mirror);
        let mut safe_directory = OsString::from("safe.directory=");
        safe_directory.push(mirror);
        command
            .arg(git_dir)
            .arg("-c")
            .arg(safe_directory)
            .args(["-c", "protocol.allow=never"])
            .current_dir("/");
        command
    }

    /// Whether the mirror holds `commit` as a commit object. Asks git's
    /// batch check, which answers `<id> missing` for an object it lacks and
    /// never fetches one.
    fn commit_present(
        &self,
        mirror: &Path,
        commit: &str,
        closed: &dyn Fn() -> bool,
    ) -> Result<(), StageFailure> {
        let mut child = self
            .git(mirror)
            .args(["cat-file", "--batch-check"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                tracing::warn!(mirror = %mirror.display(), %error, "job staging: git did not start");
                StagingRefusal::MirrorUnreadable
            })?;
        if let Some(mut stdin) = child.stdin.take() {
            // A failed write shows as git's answer or its exit status.
            let _ = writeln!(stdin, "{commit}");
        }
        let status = wait_for_git(&mut child, closed, StagingRefusal::MirrorUnreadable)?;
        let mut answer = String::new();
        if let Some(stdout) = child.stdout.take() {
            let _ = stdout.take(512).read_to_string(&mut answer);
        }
        if !status.success() {
            let errors = child.stderr.take().map(kept_stderr).unwrap_or_default();
            tracing::warn!(mirror = %mirror.display(), %status, errors = %errors, "job staging: git could not read the mirror");
            return Err(StagingRefusal::MirrorUnreadable.into());
        }
        let mut fields = answer.split_whitespace();
        match (fields.next(), fields.next()) {
            (Some(id), Some("commit")) if id == commit => Ok(()),
            _ => Err(StagingRefusal::CommitMissing.into()),
        }
    }

    /// `git archive` of `commit`, unpacked into `checkout` as it streams.
    fn export(
        &self,
        mirror: &Path,
        commit: &str,
        checkout: &Path,
        budget_bytes: u64,
        closed: &dyn Fn() -> bool,
    ) -> Result<(), StageFailure> {
        let mut child = self
            .git(mirror)
            .args(["-c", "tar.umask=022", "archive", "--format=tar", commit])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                tracing::warn!(mirror = %mirror.display(), %error, "job staging: git did not start");
                StagingRefusal::CheckoutFailed
            })?;
        let Some(archive) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(StagingRefusal::CheckoutFailed.into());
        };
        let stderr = child.stderr.take();
        std::thread::scope(|scope| {
            let errors = scope.spawn(move || stderr.map(kept_stderr).unwrap_or_default());
            let unpacking = scope.spawn(move || unpack_checkout(archive, checkout, budget_bytes));
            while !unpacking.is_finished() {
                if closed() {
                    // git's end closes the pipe, and the unpacking ends.
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = unpacking.join();
                    return Err(StageFailure::Closed);
                }
                std::thread::sleep(GIT_POLL);
            }
            let unpacked = unpacking
                .join()
                .unwrap_or(Err(StagingRefusal::CheckoutFailed));
            // An unpacking that stopped early dropped the pipe: git ends.
            let status = wait_for_git(&mut child, closed, StagingRefusal::CheckoutFailed)?;
            let errors = errors.join().unwrap_or_default();
            unpacked?;
            if status.success() {
                Ok(())
            } else {
                tracing::warn!(mirror = %mirror.display(), commit, %status, errors = %errors, "job staging: git archive failed");
                Err(StagingRefusal::CheckoutFailed.into())
            }
        })
    }
}

impl Stager for MirrorStager {
    fn stage(&self, order: &StageOrder, closed: &dyn Fn() -> bool) -> Result<(), StageFailure> {
        let checkout = order.payload_dir.join(CHECKOUT_DIR_NAME);
        let staged = self.stage_checkout(order, &checkout, closed);
        if let Err(failure) = &staged {
            tracing::info!(key = %order.key, %failure, "job staging did not complete; its checkout is removed");
            remove_checkout(&checkout);
        }
        staged
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

/// Waits for git, killing it once `closed` answers true.
fn wait_for_git(
    child: &mut Child,
    closed: &dyn Fn() -> bool,
    failed: StagingRefusal,
) -> Result<ExitStatus, StageFailure> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, "job staging: git's state does not read");
                let _ = child.kill();
                let _ = child.wait();
                return Err(failed.into());
            }
        }
        if closed() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(StageFailure::Closed);
        }
        std::thread::sleep(GIT_POLL);
    }
}

/// The first [`GIT_STDERR_KEPT_BYTES`] of git's error output; the rest is
/// read and dropped, so git never waits on a full pipe.
fn kept_stderr(mut stderr: ChildStderr) -> String {
    let mut kept = Vec::new();
    let _ = stderr
        .by_ref()
        .take(GIT_STDERR_KEPT_BYTES)
        .read_to_end(&mut kept);
    let _ = std::io::copy(&mut stderr, &mut std::io::sink());
    String::from_utf8_lossy(&kept).trim().to_owned()
}

/// Makes the key's payload directory if it is missing and an empty
/// `checkout/` in it, removing a checkout an earlier staging of the key left
/// (a restart restages from nothing). Both are 0755: the job account
/// passes through and reads, and only the engine's account writes.
fn fresh_checkout(payload_dir: &Path, checkout: &Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(payload_dir)?;
    std::fs::set_permissions(payload_dir, std::fs::Permissions::from_mode(0o755))?;
    match std::fs::remove_dir_all(checkout) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    std::fs::DirBuilder::new().mode(0o755).create(checkout)?;
    std::fs::set_permissions(checkout, std::fs::Permissions::from_mode(0o755))
}

fn remove_checkout(checkout: &Path) {
    match std::fs::remove_dir_all(checkout) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(checkout = %checkout.display(), %error, "job staging: the checkout was not removed");
        }
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
            entry.size().div_ceil(CHECKOUT_BLOCK_BYTES) * CHECKOUT_BLOCK_BYTES
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
/// symbolic link, and must be a regular file.
fn contract_matches(
    checkout: &Path,
    contract_path: &str,
    contract_sha256: &str,
) -> Result<(), StagingRefusal> {
    let mut contract = open_beneath(checkout, contract_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        match contract.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => hasher.update(&buffer[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                tracing::warn!(contract_path, %error, "job staging: the contract does not read");
                return Err(StagingRefusal::ContractUnreadable);
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
        Err(StagingRefusal::ContractChanged)
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
