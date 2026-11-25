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
//!   not remove. Where the file system gives locks, a write over an old value
//!   keeps its sweep's exclusive hold until its new file is in place
//!   ([`sweep_and_hold`]), so no other writer's copy can appear, and stay,
//!   between that sweep and that write.
//!
//! The directories above the key directory stay the owner's, and stay put
//! while the key directory is opened: every call after the open reaches the
//! key files by the key directory's path, so one who could put a link in
//! place of such a directory could send any later write anywhere, whatever
//! the open checked. The checks here keep out a path that names a vault
//! directory: by its name, through a link, past a `..`, or under the volume's
//! own rules for names.

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
/// place. `None` where the file system gives no lock, or the key directory
/// was gone; then the writer takes its own shared hold, as any writer does.
pub(crate) struct SweepHold(Option<File>);

/// Makes the key directory `dir` and answers its canonical path. `make`
/// makes one directory whose parent exists. A directory at or inside any of
/// `vault_dirs` is refused, and a refusal leaves nothing behind, while the
/// directories above `dir` stay put during the call (the module's note):
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
/// path keeps the spelling it was given (Linux).
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
/// of the directories of `dir` that exist is a vault directory that exists,
/// named as given or as it resolves ([`directory_identity`]). The second sees
/// one directory under two spellings that canonical paths keep apart:
/// `VAULT` and `vault` on a Linux volume that ignores case.
fn refuse_inside_vaults(dir: &Path, vault_dirs: &[&Path]) -> Result<()> {
    let on_path: Vec<DirectoryIdentity> = dir.ancestors().filter_map(directory_identity).collect();
    for vault in vault_dirs {
        let resolved = vault_resolved(vault).ok();
        let by_path = resolved
            .as_ref()
            .is_some_and(|vault| dir.starts_with(vault));
        let by_identity = [Some(*vault), resolved.as_deref()]
            .into_iter()
            .flatten()
            .filter_map(directory_identity)
            .any(|vault| on_path.contains(&vault));
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

/// Windows answers no identity without opening a handle: its canonical path
/// holds each part's name as the volume keeps it, so two spellings that
/// differ by case have one canonical path. Two shares or mounts that reach
/// one directory are not seen as one there.
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
/// without it, or with a sweep that holds nothing, the writer takes a shared
/// hold. On Unix the file is private (0600). `refuse_new` sees the new file
/// before `bytes` reach it, and its error stops the write. The caller removes
/// the file on every path.
pub(crate) fn write_temp(
    dir: &Path,
    stem: &str,
    bytes: &[u8],
    swept: Option<SweepHold>,
    refuse_new: impl FnOnce(&File) -> io::Result<()>,
) -> (TempFile, io::Result<()>) {
    let hold = match swept {
        Some(SweepHold(Some(lock))) => Some(lock),
        // A sweep that found no key directory, or no lock, holds nothing: a
        // key directory made since then has a lock a sweep may hold.
        _ => match temp_writers_lock(dir) {
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
mod tests;
