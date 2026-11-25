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
//!   not remove. A write over an old value keeps its sweep's exclusive hold
//!   until its new file is in place ([`sweep_and_hold`]), so no other writer's
//!   copy can appear, and stay, between that sweep and that write.
//!
//! The directories above the key directory stay the owner's: every call
//! after the open reaches the key files by the key directory's path, so one
//! who could put a link in place of such a directory could send any later
//! write anywhere, whatever the open checked. The checks here keep out a path
//! that names a vault directory: by its name, through a link, past a `..`, or
//! under the volume's own rules for names.

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

/// A temporary file beside the file it will become, with its writer's hold on
/// the key directory's lock file, taken before the file was created: shared,
/// or the exclusive hold of the sweep before it ([`SweepHold`]). Dropping it
/// ends the hold, so the writer keeps it until the file is linked or renamed
/// into place and its temporary name is gone. The hold is `None` where the
/// file system gives no lock.
pub(crate) struct TempFile {
    pub(crate) path: PathBuf,
    _hold: Option<File>,
}

/// The exclusive hold of one stem's sweep on the key directory's lock file
/// ([`sweep_and_hold`]). A write over an old value hands it to
/// [`write_temp`], whose [`TempFile`] keeps it until the new file is in
/// place. `None` where the file system gives no lock, or the key directory is
/// gone.
pub(crate) struct SweepHold(Option<File>);

/// Makes the key directory `dir` and answers its canonical path. `make`
/// makes one directory whose parent exists. A directory at or inside any of
/// `vault_dirs` is refused, and a refusal leaves nothing behind:
///
/// - First `dir` is taken as it will resolve once made ([`resolved`]), and
///   each vault directory too ([`vault_resolved`]), so a directory refused by
///   its name, through a link, or past a `..` is refused before anything is
///   made.
/// - Then each missing directory is made alone, from the root down
///   ([`make_each`]). Each one is checked against every vault directory just
///   before it is made and again as soon as it exists, and so is the
///   directory reached at the end. A refusal there removes the directories
///   this call made, each one that is still empty.
///
/// Each check compares the directories themselves as well as their paths
/// ([`refuse_inside_vaults`]). So the volume's own rules for names decide:
/// where it ignores case, `VAULT` is the vault directory `vault`, also one
/// that this call's `VAULT` makes exist, even where the system's canonical
/// path keeps the spelling it was given (Linux). The checks take the
/// directories above the key directory as they stand; those stay the
/// owner's (the module's note).
///
/// A path may pass through a vault directory and leave it by `..`, as long
/// as nothing is made inside it. A vault directory that does not resolve is
/// not compared by its path, and one that does not exist is not compared as
/// a directory.
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
/// recording each one in `made`. A directory that lies at or inside a vault
/// directory is refused just before it is made and as soon as it exists, and
/// so is the directory reached at the end. Answers its canonical path.
fn make_each(
    dir: &Path,
    vault_dirs: &[&Path],
    make: impl Fn(&Path) -> io::Result<()>,
    made: &mut Vec<PathBuf>,
) -> Result<PathBuf> {
    let absolute = std::path::absolute(dir).map_err(io_error)?;
    let mut ancestors: Vec<&Path> = absolute.ancestors().collect();
    ancestors.reverse();
    let mut at = PathBuf::new();
    for ancestor in ancestors {
        // Every part before the last one exists by now, so only the last
        // one can be missing.
        at = resolved(ancestor).map_err(io_error)?;
        if fs::symlink_metadata(&at).is_err() {
            refuse_inside_vaults(&at, vault_dirs)?;
            match make(&at) {
                Ok(()) => made.push(at.clone()),
                Err(_) if at.is_dir() => {}
                Err(e) => return Err(io_error(e)),
            }
            refuse_inside_vaults(&at.canonicalize().map_err(io_error)?, vault_dirs)?;
        }
    }
    let walked = at.canonicalize().map_err(io_error)?;
    refuse_inside_vaults(&walked, vault_dirs)?;
    Ok(walked)
}

/// Refuses `dir` at or inside a vault directory: by path, each vault
/// directory as it resolves ([`vault_resolved`]), or as a directory, when one
/// of the directories of `dir` that exist is a vault directory that exists
/// ([`directory_identity`]). The second sees one directory under two
/// spellings that canonical paths keep apart: `VAULT` and `vault` on a Linux
/// volume that ignores case.
fn refuse_inside_vaults(dir: &Path, vault_dirs: &[&Path]) -> Result<()> {
    let on_path: Vec<DirectoryIdentity> = dir.ancestors().filter_map(directory_identity).collect();
    for vault in vault_dirs {
        let by_path = vault_resolved(vault).is_ok_and(|vault| dir.starts_with(vault));
        let by_identity = directory_identity(vault).is_some_and(|vault| on_path.contains(&vault));
        if by_path || by_identity {
            return Err(KeystoreError::Unavailable(INSIDE_A_VAULT));
        }
    }
    Ok(())
}

/// A directory's device and inode number: equal for each path that reaches
/// it, however spelled.
#[cfg(unix)]
type DirectoryIdentity = (u64, u64);

/// Windows answers no identity without opening a handle, and needs none
/// here: its canonical path holds each part's name as the volume keeps it,
/// so two spellings of one directory have one canonical path.
#[cfg(not(unix))]
type DirectoryIdentity = std::convert::Infallible;

/// The identity of the directory at `path`, following links; `None` for a
/// path that is missing or not a directory.
#[cfg(unix)]
fn directory_identity(path: &Path) -> Option<DirectoryIdentity> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path)
        .ok()
        .filter(fs::Metadata::is_dir)
        .map(|meta| (meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn directory_identity(_path: &Path) -> Option<DirectoryIdentity> {
    None
}

/// The most links whose target is missing that [`vault_resolved`] follows
/// for one path, as many as a system lookup follows links.
const DANGLING_LINKS_MAX: usize = 40;

/// `path` as it will resolve once its missing directories are made, taken
/// part by part from the root as the system takes it: each part against the
/// canonical path of the parts before it, so a link counts wherever it lies,
/// also one reached past a missing part and a `..`. A missing part stays as
/// named, and a `..` after it takes it back, as making it would. A `..` after
/// a file is an error, as it is to the system. A link whose target is missing
/// is an error too: no directory is made through it.
fn resolved(path: &Path) -> io::Result<PathBuf> {
    resolve(path, &mut 0)
}

/// A vault directory as it will resolve once made: as [`resolved`], except
/// that a link whose target is missing stands for that target as it will
/// resolve once made, since the vault's own maker may make it.
fn vault_resolved(path: &Path) -> io::Result<PathBuf> {
    let mut links = DANGLING_LINKS_MAX;
    resolve(path, &mut links)
}

/// [`resolved`], following up to `links` links whose target is missing; one
/// more is an error.
fn resolve(path: &Path, links: &mut usize) -> io::Result<PathBuf> {
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
                if fs::metadata(&resolved).is_ok_and(|meta| !meta.is_dir()) {
                    return Err(io::Error::from(ErrorKind::NotADirectory));
                }
                resolved.pop();
                continue;
            }
            Component::RootDir | Component::Normal(_) => resolved.push(part),
        }
        match resolved.canonicalize() {
            Ok(canonical) => resolved = canonical,
            // A missing part stays as named; a link whose target is missing
            // stands for that target, or is an error.
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if fs::symlink_metadata(&resolved).is_ok() {
                    if *links == 0 {
                        return Err(e);
                    }
                    *links -= 1;
                    let target = fs::read_link(&resolved)?;
                    resolved.pop();
                    resolved = resolve(&resolved.join(target), links)?;
                }
            }
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
/// stem once no writer holds the directory. `swept` is the hold of the
/// stem's sweep that a write over an old value keeps ([`sweep_and_hold`]);
/// without it the writer takes a shared hold. On Unix the file is private
/// (0600). `refuse_new` sees the new file before `bytes` reach it, and its
/// error stops the write. The caller removes the file on every path.
pub(crate) fn write_temp(
    dir: &Path,
    stem: &str,
    bytes: &[u8],
    swept: Option<SweepHold>,
    refuse_new: impl FnOnce(&File) -> io::Result<()>,
) -> (TempFile, io::Result<()>) {
    let hold = match swept {
        Some(SweepHold(hold)) => hold,
        None => match temp_writers_lock(dir) {
            Ok(lock) if lock.lock_shared().is_ok() => Some(lock),
            _ => None,
        },
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
/// process its pid names now: the system may have given that pid to another
/// process, or to this one.
///
/// - One stem's sweep serves an erase or a write over an old value, which
///   must leave no copy behind. It waits for the writers in flight, so a lock
///   file it cannot open is an error. Then it removes every file of its stem,
///   also where the file system gives no lock: a writer whose file it takes
///   fails its own write and leaves no copy.
/// - The open-time sweep of every stem does not wait. While a writer holds
///   the directory, or where the file system gives no lock, it removes
///   nothing, and on Unix it leaves this process's own files
///   ([`left_to_another_process`]).
///
/// Every file is tried; the first removal that failed, other than of a file
/// already gone, is the answer. A key directory that is gone holds no file.
pub(crate) fn sweep_temps(dir: &Path, stem: Option<&str>) -> io::Result<()> {
    match stem {
        Some(stem) => sweep_and_hold(dir, stem).map(|_hold| ()),
        None => sweep_every_stem(dir),
    }
}

/// One stem's sweep ([`sweep_temps`]), answering its exclusive hold, which
/// lasts until the answer is dropped. A write over an old value keeps it
/// until its new file is in place ([`write_temp`]), so no other writer's
/// temporary file is made, and left, between this sweep and that write.
///
/// A lock file that does not open is an error, since the sweep could not
/// wait for the writers in flight, except where the key directory itself is
/// gone, and every file in it with it.
pub(crate) fn sweep_and_hold(dir: &Path, stem: &str) -> io::Result<SweepHold> {
    let lock = match temp_writers_lock(dir) {
        Ok(lock) => lock,
        Err(e) if e.kind() == ErrorKind::NotFound && is_gone(dir) => return Ok(SweepHold(None)),
        Err(e) => return Err(e),
    };
    // Where the file system gives no lock, the sweep goes on all the same.
    let held = lock.lock().is_ok();
    remove_temps(dir, |file_stem, _pid| file_stem == stem)?;
    Ok(SweepHold(held.then_some(lock)))
}

/// The open-time sweep of every stem ([`sweep_temps`]), which does not wait.
fn sweep_every_stem(dir: &Path) -> io::Result<()> {
    let Ok(lock) = temp_writers_lock(dir) else {
        return Ok(());
    };
    if lock.try_lock().is_err() {
        return Ok(());
    }
    let swept = remove_temps(dir, |_stem, pid| !left_to_another_process(pid));
    // Dropping `lock` here closes it, which ends the exclusive hold.
    drop(lock);
    swept
}

/// Removes each temporary file in `dir` that `taken` takes by its stem and
/// its writer's pid. Every file is tried; the first removal that failed,
/// other than of a file already gone, is the answer.
fn remove_temps(dir: &Path, taken: impl Fn(&str, u32) -> bool) -> io::Result<()> {
    let mut swept = Ok(());
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some((stem, pid)) = file_name.to_str().and_then(temp_name_parts) else {
            continue;
        };
        if !taken(stem, pid) {
            continue;
        }
        if let Err(e) = fs::remove_file(entry.path())
            && e.kind() != ErrorKind::NotFound
            && swept.is_ok()
        {
            swept = Err(e);
        }
    }
    swept
}

/// Whether nothing is at `path`, not even a link.
fn is_gone(path: &Path) -> bool {
    matches!(fs::symlink_metadata(path), Err(e) if e.kind() == ErrorKind::NotFound)
}

/// Unix: the open-time sweep leaves this process's own files to another
/// process's sweep, or to a stem's sweep. Where the file system keeps locks
/// per process (NFS), this process's own writers' shared holds do not stop
/// its lock, so a file under its pid may be one of them in flight.
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
        // Windows takes `..` by name before any lookup, as joining onto a
        // canonical path already does.
        #[cfg(unix)]
        {
            fs::write(base.join("file"), b"").expect("a file");
            assert!(
                resolved(&base.join("file/../keys")).is_err(),
                "a file has no `..`"
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

    /// Review of #10420: a vault directory reached through a dangling link
    /// (one whose target is missing) stands for that target as it will be
    /// made, so a key directory inside it is refused before anything is
    /// made. Also when the vault directory leaves that target by `..`
    /// (`alias/..`, the link naming `store/keys`), which makes it `store` once
    /// `store/keys` exists.
    #[cfg(unix)]
    #[test]
    fn a_key_directory_inside_a_vault_behind_a_dangling_link_is_refused_before_it_is_made() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let base = root.path().canonicalize().expect("the root resolves");
        let vault = base.join("vault-link");
        std::os::unix::fs::symlink(base.join("x/y"), &vault).expect("a link to a missing vault");
        assert_eq!(
            create_key_dir(&base.join("x/y/keys"), &[&vault], |d| fs::create_dir_all(d)),
            Err(KeystoreError::Unavailable(INSIDE_A_VAULT))
        );
        assert!(!base.join("x").exists(), "a refusal made a directory");

        fs::create_dir(base.join("store")).expect("a directory");
        std::os::unix::fs::symlink(base.join("store/keys"), base.join("alias"))
            .expect("a link to a missing directory");
        let vault = base.join("alias/..");
        let keys = base.join("store/keys");
        assert_eq!(
            create_key_dir(&keys, &[&vault], |d| fs::create_dir_all(d)),
            Err(KeystoreError::Unavailable(INSIDE_A_VAULT))
        );
        assert!(!keys.exists(), "a refusal made a directory");
    }

    /// Review of #10420: a vault directory may come to name a directory only
    /// once that directory is made, as `vault` names `VAULT` on a volume that
    /// ignores case. Here the vault directory's link appears as `x/y` is made.
    /// That directory is refused as soon as it exists, nothing is made inside
    /// it, and the directories made are removed.
    #[cfg(unix)]
    #[test]
    fn a_directory_that_a_vault_names_once_made_is_refused_and_removed() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let base = root.path().canonicalize().expect("the root resolves");
        let vault = base.join("vault-link");
        let named = base.join("x/y");
        let make = |d: &Path| -> io::Result<()> {
            fs::create_dir_all(d)?;
            if named.exists() && fs::symlink_metadata(&vault).is_err() {
                std::os::unix::fs::symlink(&named, &vault)?;
            }
            Ok(())
        };
        assert_eq!(
            create_key_dir(&base.join("x/y/keys"), &[&vault], make),
            Err(KeystoreError::Unavailable(INSIDE_A_VAULT))
        );
        assert!(
            !base.join("x").exists(),
            "a refusal left a directory it made"
        );
    }

    /// Review of #10420: a path may pass through a vault directory and leave
    /// it by `..`, but a directory it would make inside the vault directory on
    /// the way is refused before it is made. Unix only: Windows takes `..` by
    /// name before any lookup, so it makes nothing on the way.
    #[cfg(unix)]
    #[test]
    fn a_path_through_a_vault_makes_nothing_inside_it() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let base = root.path().canonicalize().expect("the root resolves");
        let vault = base.join("vault");
        fs::create_dir(&vault).expect("the vault directory");
        assert_eq!(
            create_key_dir(&vault.join("a/../../keys"), &[&vault], |d| {
                fs::create_dir_all(d)
            }),
            Err(KeystoreError::Unavailable(INSIDE_A_VAULT))
        );
        assert_eq!(
            fs::read_dir(&vault).expect("the vault lists").count(),
            0,
            "a directory was made inside the vault"
        );
        assert!(!base.join("keys").exists(), "a refusal made a directory");
        assert_eq!(
            create_key_dir(&vault.join("../keys"), &[&vault], |d| fs::create_dir_all(d)),
            Ok(base.join("keys"))
        );
    }

    /// Review of #10420: a stale file the sweep cannot remove is reported,
    /// and the sweep still removes every other one.
    #[test]
    fn a_sweep_reports_a_stale_file_it_could_not_remove() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let dir = root.path();
        // A pid no process has: above every Unix pid limit, and every
        // Windows pid is a multiple of four.
        let stuck = dir.join(".slot.4294967295.1.tmp");
        fs::create_dir(&stuck).expect("a directory under a temporary file's name");
        fs::write(stuck.join("inner"), [2; 32]).expect("a file inside it");
        let stale = dir.join(".slot.4294967295.2.tmp");
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
        let (writing, written) = write_temp(dir, "slot", &[1; 32], None, |_| Ok(()));
        written.expect("the temporary file is written");
        // A pid no process has, so the open-time sweep never takes it for
        // this process's own.
        let stale = dir.join(".slot.4294967295.1.tmp");
        let other = dir.join(".other.sealed.4294967295.1.tmp");
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
        let (tmp, written) = write_temp(root.path(), "slot", &[1; 32], None, |_| {
            Err(io::Error::from(ErrorKind::PermissionDenied))
        });
        assert_eq!(
            written.map_err(|e| e.kind()),
            Err(ErrorKind::PermissionDenied)
        );
        assert_eq!(fs::read(&tmp.path).expect("the file was made"), b"");
    }

    /// Review of #10420, round 2: the vault check compares directories, not
    /// only their spellings. A path that names a vault directory under
    /// another spelling, which its canonical path keeps (`VAULT` for `vault`
    /// on a Linux volume that ignores case), is refused. A link stands for
    /// that spelling here, since the check takes the path as given.
    #[cfg(unix)]
    #[test]
    fn the_vault_check_compares_directories_not_only_their_spellings() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let base = root.path().canonicalize().expect("the root resolves");
        let vault = base.join("vault");
        fs::create_dir(&vault).expect("the vault directory");
        let alias = base.join("alias");
        std::os::unix::fs::symlink(&vault, &alias).expect("another name for the vault");
        for dir in [
            alias.clone(),
            alias.join("keys"),
            alias.join("a").join("keys"),
        ] {
            assert_eq!(
                refuse_inside_vaults(&dir, &[&vault]),
                Err(KeystoreError::Unavailable(INSIDE_A_VAULT)),
                "{}",
                dir.display()
            );
        }
        assert_eq!(refuse_inside_vaults(&base.join("keys"), &[&vault]), Ok(()));
    }

    /// Review of #10420, round 2: where the volume ignores case, `VAULT/keys`
    /// lies inside the vault directory `vault` as soon as `VAULT` is made,
    /// whatever spelling the system's canonical path keeps. It is refused,
    /// and the directory made is removed. A volume that keeps case apart
    /// (most Linux ones) has nothing to show, and the test says so.
    #[test]
    fn a_key_directory_under_another_case_of_a_vault_is_refused_where_the_volume_ignores_case() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let base = root.path().canonicalize().expect("the root resolves");
        fs::create_dir(base.join("probe")).expect("a directory");
        if !base.join("PROBE").exists() {
            eprintln!("the temporary volume keeps case apart: nothing to show here");
            return;
        }
        let vault = base.join("vault");
        assert_eq!(
            create_key_dir(&base.join("VAULT").join("keys"), &[&vault], |d| {
                fs::create_dir(d)
            }),
            Err(KeystoreError::Unavailable(INSIDE_A_VAULT))
        );
        assert!(!vault.exists(), "a refusal left the directory it made");
    }

    /// Review of #10420, round 2: a write over an old value keeps its sweep's
    /// exclusive hold until its new file is in place, so no other writer
    /// takes its shared hold, and writes a copy, in between.
    #[test]
    fn a_write_over_an_old_value_keeps_its_sweeps_hold_until_its_file_is_in_place() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let dir = root.path();
        let writer_holds = || {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(dir.join(TEMP_WRITERS_LOCK))
                .expect("the lock file opens")
                .try_lock_shared()
                .is_ok()
        };
        let stale = dir.join(".slot.4294967295.1.tmp");
        fs::write(&stale, [2; 32]).expect("a stale file");
        let swept = sweep_and_hold(dir, "slot").expect("the stem's sweep");
        assert!(!stale.exists(), "the sweep kept a stale file");
        assert!(!writer_holds(), "a writer took its hold after the sweep");
        let (tmp, written) = write_temp(dir, "slot", &[1; 32], Some(swept), |_| Ok(()));
        written.expect("the temporary file is written");
        assert!(!writer_holds(), "a writer took its hold during the write");
        fs::rename(&tmp.path, dir.join("slot.key")).expect("the file goes in place");
        assert!(
            !writer_holds(),
            "a writer took its hold before the hold ended"
        );
        drop(tmp);
        assert!(writer_holds(), "the hold outlived the write");
    }

    /// Review of #10420, round 2 (Sol read of the fix): a vault directory is
    /// compared as a directory also as it resolves, so one named past a
    /// missing part and a `..` (`gap/../vault`, which the system cannot stat)
    /// is still seen under another spelling of the key path.
    #[cfg(unix)]
    #[test]
    fn the_vault_check_compares_a_vault_directory_as_it_resolves() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let base = root.path().canonicalize().expect("the root resolves");
        let vault = base.join("vault");
        fs::create_dir(&vault).expect("the vault directory");
        let alias = base.join("alias");
        std::os::unix::fs::symlink(&vault, &alias).expect("another name for the vault");
        let named = base.join("gap").join("..").join("vault");
        assert_eq!(
            refuse_inside_vaults(&alias.join("keys"), &[&named]),
            Err(KeystoreError::Unavailable(INSIDE_A_VAULT))
        );
    }

    /// Review of #10420, round 2 (Sol read of the fix): a write handed a
    /// sweep's hold that holds nothing, as one whose key directory was gone,
    /// takes its own shared hold, so a sweep of a key directory made since
    /// cannot run beside it.
    #[test]
    fn a_write_after_a_sweep_that_holds_nothing_takes_its_own_hold() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let dir = root.path().join("keys");
        let swept = sweep_and_hold(&dir, "slot").expect("a key directory that is gone");
        fs::create_dir(&dir).expect("the key directory is made again");
        let (tmp, written) = write_temp(&dir, "slot", &[1; 32], Some(swept), |_| Ok(()));
        written.expect("the temporary file is written");
        // The lock file as a sweep opens it, made if no writer made it.
        let sweep_holds = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(TEMP_WRITERS_LOCK))
            .expect("the lock file opens")
            .try_lock()
            .is_ok();
        assert!(!sweep_holds, "a sweep took its hold beside a writer");
        fs::remove_file(&tmp.path).expect("the writer removes its file");
    }
}
