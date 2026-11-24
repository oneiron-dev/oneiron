//! The key directory of the two tiers that keep one file per slot: the Unix
//! file tier (`LocalFileKeystore`, which the TPM tier writes through)
//! and the Windows DPAPI tier. Both follow the same rules for it.
//!
//! - It lies outside every vault directory, because a vault's checkpoints and
//!   backups copy what is inside it. A directory that would lie inside one is
//!   refused, and the refusal leaves nothing behind ([`create_key_dir`]).
//! - Each new file is written to a temporary file beside it, then linked or
//!   renamed into place. A writer that dies in between leaves that file, which
//!   holds a copy of the secret, so a sweep removes it ([`sweep_temps`], FIX
//!   8019).
//! - The directory holds `temp-writers.lock`, an empty file that each writer
//!   of a temporary file locks shared and each sweep locks exclusively. The
//!   system ends a process's hold when the process ends, however it ends, so
//!   under the exclusive lock every temporary file is one whose writer is gone.
//!   Each write that puts a new value over an old one, and each erase, sweeps
//!   the file's temporary files first or after and reports a copy it could
//!   not remove.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};
use std::{fs, io};

use crate::{KeystoreError, Result};

/// The key directory's lock file: each writer of a temporary file holds it
/// shared, and each sweep of stale temporary files exclusively. It holds no
/// bytes.
pub(crate) const TEMP_WRITERS_LOCK: &str = "temp-writers.lock";

const INSIDE_A_VAULT: &str = "the key directory is inside a vault directory";

/// A temporary file beside the file it will become, with its writer's shared
/// hold on the key directory's lock file, taken before the file was created.
/// Dropping it ends the hold, so the writer keeps it until the file is linked
/// or renamed into place and its temporary name is gone. The hold is `None`
/// where the file system gives no lock.
pub(crate) struct TempFile {
    pub(crate) path: PathBuf,
    _hold: Option<File>,
}

/// Makes the key directory `dir` and answers its canonical path. `make`
/// makes one directory whose parent exists. A directory at or inside any of
/// `vault_dirs` is refused, and a refusal leaves nothing behind:
///
/// - First `dir` is taken as it will resolve once made ([`resolved`]), so a
///   directory refused by its name, through a link, or past a `..` is
///   refused before anything is made.
/// - Then each missing directory is made alone, from the root down, and the
///   path made so far is checked against every vault directory as soon as
///   it exists ([`make_each`]). So the volume's own rules for names decide
///   (`VAULT` names a vault directory `vault` not made yet, where the volume
///   ignores case), and so does a link that moved meanwhile. A refusal there
///   removes the directories this call made.
///
/// A vault directory that does not resolve is not compared.
pub(crate) fn create_key_dir(
    dir: &Path,
    vault_dirs: &[&Path],
    make: impl Fn(&Path) -> io::Result<()>,
) -> Result<PathBuf> {
    refuse_inside_vaults(&resolved(dir).map_err(io_error)?, vault_dirs)?;
    let mut made = Vec::new();
    let walked = make_each(dir, vault_dirs, make, &mut made);
    if walked.is_err() {
        // The last one made first. A directory something was put in stays.
        for path in made.iter().rev() {
            let _ = fs::remove_dir(path);
        }
    }
    walked
}

/// Makes each missing directory of `dir` with `make`, from the root down,
/// recording each one in `made`, and refuses as soon as the path made so
/// far resolves at or inside a vault directory. Answers the canonical path.
fn make_each(
    dir: &Path,
    vault_dirs: &[&Path],
    make: impl Fn(&Path) -> io::Result<()>,
    made: &mut Vec<PathBuf>,
) -> Result<PathBuf> {
    let absolute = std::path::absolute(dir).map_err(io_error)?;
    let mut ancestors: Vec<&Path> = absolute.ancestors().collect();
    ancestors.reverse();
    let mut walked = PathBuf::new();
    for ancestor in ancestors {
        // Every part before the last one exists by now, so only the last
        // one can be missing.
        let at = resolved(ancestor).map_err(io_error)?;
        if fs::symlink_metadata(&at).is_err() {
            match make(&at) {
                Ok(()) => made.push(at.clone()),
                Err(_) if at.is_dir() => {}
                Err(e) => return Err(io_error(e)),
            }
        }
        walked = at.canonicalize().map_err(io_error)?;
        refuse_inside_vaults(&walked, vault_dirs)?;
    }
    Ok(walked)
}

fn refuse_inside_vaults(dir: &Path, vault_dirs: &[&Path]) -> Result<()> {
    for vault in vault_dirs {
        if let Ok(vault) = resolved(vault)
            && dir.starts_with(&vault)
        {
            return Err(KeystoreError::Unavailable(INSIDE_A_VAULT));
        }
    }
    Ok(())
}

/// `path` as it will resolve once its missing directories are made, taken
/// part by part from the root as the system takes it: each part against the
/// canonical path of the parts before it, so a link counts wherever it lies,
/// also one reached past a missing part and a `..`. A missing part stays as
/// named, and a `..` after it takes it back, as making it would. A link
/// whose target is missing is an error: no directory is made through it.
fn resolved(path: &Path) -> io::Result<PathBuf> {
    let mut resolved = PathBuf::new();
    for part in std::path::absolute(path)?.components() {
        match part {
            Component::Prefix(_) => {
                resolved.push(part);
                continue;
            }
            Component::CurDir => continue,
            // The path so far is canonical or missing, so its parent is the
            // directory `..` names.
            Component::ParentDir => {
                resolved.pop();
                continue;
            }
            Component::RootDir | Component::Normal(_) => resolved.push(part),
        }
        match resolved.canonicalize() {
            Ok(canonical) => resolved = canonical,
            Err(e)
                if e.kind() == ErrorKind::NotFound && fs::symlink_metadata(&resolved).is_err() => {}
            Err(e) => return Err(e),
        }
    }
    Ok(resolved)
}

/// The key directory's lock file, open for reading and writing: NFS grants an
/// exclusive lock only on a file open for writing.
fn temp_writers_lock(dir: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(dir.join(TEMP_WRITERS_LOCK))
}

/// A temporary file holding `bytes` in the key directory `dir`, beside the
/// file it will become, written under the writer's hold on the directory.
/// `stem` is that file's name; a sweep removes a temporary file under any
/// stem once no writer holds the directory. On Unix the file is private
/// (0600). `refuse_new` sees the new file before `bytes` reach it, and its
/// error stops the write. The caller removes the file on every path.
pub(crate) fn write_temp(
    dir: &Path,
    stem: &str,
    bytes: &[u8],
    refuse_new: impl FnOnce(&File) -> io::Result<()>,
) -> (TempFile, io::Result<()>) {
    let hold = match temp_writers_lock(dir) {
        Ok(lock) if lock.lock_shared().is_ok() => Some(lock),
        _ => None,
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let path = dir.join(format!(".{stem}.{}.{nanos}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options.open(&path).and_then(|mut file| {
        refuse_new(&file)?;
        file.write_all(bytes)?;
        file.sync_all()
    });
    (TempFile { path, _hold: hold }, written)
}

/// Removes the stale temporary files in the key directory `dir` under
/// `stem`, or under every stem (FIX 8019). Every writer holds the
/// directory's lock file shared from before its temporary file exists until
/// after it is gone ([`write_temp`]). So under the exclusive lock each
/// temporary file is one whose writer died or failed to remove it, whichever
/// process its pid names now: the system may have given that pid to another.
/// One stem's sweep, at a write or an erase, waits for the writers in
/// flight; the open-time sweep of every stem does not wait, and leaves the
/// files to a later sweep while one writes. Where the file system gives no
/// lock, nothing is removed. Every file is tried; the first removal that
/// failed, other than of a file already gone, is the answer.
pub(crate) fn sweep_temps(dir: &Path, stem: Option<&str>) -> io::Result<()> {
    let lock = temp_writers_lock(dir)?;
    let locked = if stem.is_some() {
        lock.lock().is_ok()
    } else {
        lock.try_lock().is_ok()
    };
    if !locked {
        return Ok(());
    }
    let mut swept = Ok(());
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some((file_stem, pid)) = file_name.to_str().and_then(temp_name_parts) else {
            continue;
        };
        if stem.is_some_and(|wanted| wanted != file_stem) || left_to_another_process(pid) {
            continue;
        }
        if let Err(e) = fs::remove_file(entry.path())
            && e.kind() != ErrorKind::NotFound
            && swept.is_ok()
        {
            swept = Err(e);
        }
    }
    // Dropping `lock` here closes it, which ends the exclusive hold.
    swept
}

/// Unix: this process leaves its own temporary files to another process's
/// sweep. Where the file system keeps locks per process (NFS), its own
/// writers' shared holds do not stop its exclusive lock.
#[cfg(unix)]
fn left_to_another_process(pid: u32) -> bool {
    pid == std::process::id()
}

/// Windows locks each handle apart: a shared hold on another handle stops the
/// exclusive lock, also within this process, so a file under this process's
/// pid is stale too (a dead writer's pid handed on to this process).
#[cfg(not(unix))]
fn left_to_another_process(_pid: u32) -> bool {
    false
}

/// The stem and the writer's pid of a temporary file's name,
/// `.<stem>.<pid>.<nanos>.tmp`, or `None` for a name of another shape. A
/// stem is dot-separated words, none empty.
fn temp_name_parts(name: &str) -> Option<(&str, u32)> {
    let inner = name.strip_prefix('.')?.strip_suffix(".tmp")?;
    let (prefix, nanos) = inner.rsplit_once('.')?;
    let (stem, pid) = prefix.rsplit_once('.')?;
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    if stem.split('.').any(str::is_empty) || !digits(pid) || !digits(nanos) {
        return None;
    }
    nanos.parse::<u128>().ok()?;
    Some((stem, pid.parse().ok()?))
}

fn io_error(e: io::Error) -> KeystoreError {
    KeystoreError::Platform("io", e.raw_os_error().map_or(-1, i64::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_temporary_files_name_gives_its_stem_and_pid() {
        assert_eq!(
            temp_name_parts(".0707.0303.machine-encryption.41.17.tmp"),
            Some(("0707.0303.machine-encryption", 41))
        );
        assert_eq!(
            temp_name_parts(".device-pin-key.sealed.9.1.tmp"),
            Some(("device-pin-key.sealed", 9))
        );
        for other in [
            "temp-writers.lock",
            "CACHEDIR.TAG",
            "0707.machine-encryption.key",
            ".stem.41.17",
            "stem.41.17.tmp",
            "..41.17.tmp",
            ".a..b.41.17.tmp",
            ".stem.4x.17.tmp",
            ".stem.41..tmp",
            ".stem.41.tmp",
            ".stem.99999999999.17.tmp",
        ] {
            assert_eq!(temp_name_parts(other), None, "{other}");
        }
    }

    /// A path whose directories do not exist yet resolves part by part:
    /// through a link wherever it lies, also one reached past a missing part
    /// and a `..`, and with `..` taking back a part not yet made.
    #[test]
    fn a_path_resolves_as_it_will_once_made() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let base = root.path().canonicalize().expect("the root resolves");
        fs::create_dir(base.join("vault")).expect("the vault directory");
        assert_eq!(
            resolved(&base.join("vault")).expect("an existing path"),
            base.join("vault")
        );
        assert_eq!(
            resolved(&base.join("a/b/../c/./keys")).expect("a missing path"),
            base.join("a/c/keys")
        );
        assert_eq!(
            resolved(&base.join("vault/../absent/..")).expect("a missing path"),
            base
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(base.join("vault"), base.join("link"))
                .expect("a link to the vault");
            assert_eq!(
                resolved(&base.join("link/keys")).expect("a path through a link"),
                base.join("vault/keys")
            );
            assert_eq!(
                resolved(&base.join("gap/../link/keys")).expect("a link past a missing part"),
                base.join("vault/keys")
            );
        }
    }

    /// FIX FILE-KEYSTORE-CREATES-DIR-BEFORE-VAULT-CHECK: a key directory at
    /// or inside a vault directory, also one reached through a link or one
    /// inside a vault directory not made yet, is refused before anything is
    /// made.
    #[test]
    fn a_key_directory_inside_a_vault_is_refused_before_it_is_made() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let vault = root.path().join("vault");
        fs::create_dir(&vault).expect("the vault directory");
        let later = root.path().join("later-vault");
        let refused = [
            (vault.clone(), &vault),
            (vault.join("keys"), &vault),
            (vault.join("a/b/keys"), &vault),
            (root.path().join("x/../vault/keys"), &vault),
            (later.join("keys"), &later),
        ];
        for (dir, vault_dir) in &refused {
            let made = create_key_dir(dir, &[vault_dir.as_path()], |d| fs::create_dir_all(d));
            assert_eq!(
                made,
                Err(KeystoreError::Unavailable(INSIDE_A_VAULT)),
                "{}",
                dir.display()
            );
        }
        #[cfg(unix)]
        {
            let link = root.path().join("link");
            std::os::unix::fs::symlink(&vault, &link).expect("a link to the vault");
            assert_eq!(
                create_key_dir(&link.join("keys"), &[&vault], |d| fs::create_dir_all(d)),
                Err(KeystoreError::Unavailable(INSIDE_A_VAULT)),
                "a key directory reached through a link"
            );
        }
        assert_eq!(
            fs::read_dir(&vault).expect("the vault lists").count(),
            0,
            "a refused key directory was made inside the vault"
        );
        assert!(!later.exists(), "a refusal made the later vault directory");
        assert!(
            !root.path().join("x").exists(),
            "a refusal made a directory"
        );

        let keys = root.path().join("keys");
        let made = create_key_dir(&keys, &[&vault, &later], |d| fs::create_dir_all(d))
            .expect("a key directory outside every vault");
        assert_eq!(made, keys.canonicalize().expect("the made directory"));
    }

    /// Review of #10420: a link reached past a missing part and a `..`
    /// (`gap/../link/keys`, the link naming the vault directory) is refused
    /// before anything is made: neither the missing part nor a directory
    /// inside the vault.
    #[cfg(unix)]
    #[test]
    fn a_key_directory_through_a_link_past_a_missing_part_is_refused_before_it_is_made() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let vault = root.path().join("vault");
        fs::create_dir(&vault).expect("the vault directory");
        std::os::unix::fs::symlink(&vault, root.path().join("link")).expect("a link to the vault");
        let dir = root.path().join("gap").join("..").join("link").join("keys");
        assert_eq!(
            create_key_dir(&dir, &[&vault], |d| fs::create_dir_all(d)),
            Err(KeystoreError::Unavailable(INSIDE_A_VAULT))
        );
        assert_eq!(
            fs::read_dir(&vault).expect("the vault lists").count(),
            0,
            "a refused key directory was made inside the vault"
        );
        assert!(
            !root.path().join("gap").exists(),
            "a refusal made a directory"
        );
    }

    /// Review of #10420: a vault directory may resolve only once a directory
    /// of the key directory's path exists, as `vault` does when `VAULT` is
    /// made on a volume that ignores case. Here the vault directory is a
    /// link to `x/y`, which is missing until made. The directory that makes
    /// it resolve is refused as soon as it is made, nothing is made inside
    /// it, and the directories made are removed.
    #[cfg(unix)]
    #[test]
    fn a_directory_that_resolves_as_a_vault_once_made_is_refused_and_removed() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let base = root.path().canonicalize().expect("the root resolves");
        let vault = base.join("vault-link");
        std::os::unix::fs::symlink(base.join("x/y"), &vault).expect("a link to a missing vault");
        assert_eq!(
            create_key_dir(&base.join("x/y/keys"), &[&vault], |d| fs::create_dir_all(d)),
            Err(KeystoreError::Unavailable(INSIDE_A_VAULT))
        );
        assert!(
            !base.join("x").exists(),
            "a refusal left a directory it made"
        );
    }

    /// Review of #10420: a stale file the sweep cannot remove is reported,
    /// and the sweep still removes every other one.
    #[test]
    fn a_sweep_reports_a_stale_file_it_could_not_remove() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let dir = root.path();
        let stuck = dir.join(".slot.1.1.tmp");
        fs::create_dir(&stuck).expect("a directory under a temporary file's name");
        fs::write(stuck.join("inner"), [2; 32]).expect("a file inside it");
        let stale = dir.join(".slot.1.2.tmp");
        fs::write(&stale, [2; 32]).expect("a stale file");
        assert!(
            sweep_temps(dir, Some("slot")).is_err(),
            "the sweep reported no failure"
        );
        assert!(!stale.exists(), "the sweep stopped at the failure");
    }

    /// While one writer holds the directory, the open-time sweep keeps every
    /// temporary file; once the hold ends, a sweep removes another process's
    /// stale file and leaves every other file.
    #[test]
    fn a_sweep_removes_stale_temporary_files_only_while_no_writer_holds_the_directory() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let dir = root.path();
        let (writing, written) = write_temp(dir, "slot", &[1; 32], |_| Ok(()));
        written.expect("the temporary file is written");
        let stale = dir.join(".slot.1.1.tmp");
        let other = dir.join(".other.sealed.1.1.tmp");
        let kept = dir.join("slot.key");
        for path in [&stale, &other, &kept] {
            fs::write(path, [2; 32]).expect("a file is written");
        }
        sweep_temps(dir, None).expect("the open-time sweep");
        assert!(stale.exists() && other.exists(), "a sweep did not wait");
        fs::remove_file(&writing.path).expect("the writer removes its file");
        drop(writing);
        sweep_temps(dir, Some("slot")).expect("the stem's sweep");
        assert!(!stale.exists(), "the stem's sweep kept a stale file");
        assert!(
            other.exists(),
            "the stem's sweep removed another stem's file"
        );
        sweep_temps(dir, None).expect("the open-time sweep");
        assert!(!other.exists(), "the open-time sweep kept a stale file");
        assert!(
            kept.exists(),
            "a sweep removed a file that is not temporary"
        );
    }

    /// `refuse_new` stops the write before the bytes reach the file.
    #[test]
    fn a_refused_temporary_file_gets_no_bytes() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let (tmp, written) = write_temp(root.path(), "slot", &[1; 32], |_| {
            Err(io::Error::from(ErrorKind::PermissionDenied))
        });
        assert_eq!(
            written.map_err(|e| e.kind()),
            Err(ErrorKind::PermissionDenied)
        );
        assert_eq!(fs::read(&tmp.path).expect("the file was made"), b"");
    }
}
