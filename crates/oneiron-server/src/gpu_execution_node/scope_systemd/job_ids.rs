//! The node's job ids (FIX EXEC-UNIT-CROSS-JOB-SAME-UID, ruling A): each job
//! unit runs as its own uid from the node's range (`job_uid_first`,
//! `job_uid_count`), with a group id of the same number, so the kernel refuses
//! one job's signals, `/proc` reads and tracing of another job's processes on
//! every kernel. No account names these ids.
//!
//! The service manager cannot give a template's instances a uid each:
//! `DynamicUser=` names the user after the unit's prefix, so every instance
//! shares one (systemd's `user_from_unit_name`), a `User=` of the instance
//! would be longer than the 31 characters a user name may have, and an
//! instance's own drop-in is not read without a daemon reload. So the unit
//! starts `job-exec` as root with only `CAP_SETUID` and `CAP_SETGID`, and
//! `job-exec` takes the id the prepare step gave it ([`super::exec`]).
//!
//! The table is `JOB_IDS_ROOT`, root's alone: one file per id in use, named by
//! the id and holding the unit's name. The prepare step takes the lowest id
//! with no file, no account or group of that number, and no process holding
//! it in any of its real, effective, saved or file-system ids. A file is
//! taken back only when its unit is no longer running and no process holds
//! the id. The end step removes the file once the unit's group is empty and
//! the job's files are the engine's ([`super::handover`]). Every change is
//! made under one lock on the table.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::io;
use std::mem::MaybeUninit;
use std::ops::Range;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::exchange::root_dir;
use super::safe_fs::{borrow, read_beneath, remove_beneath, write_beneath};
use super::systemd_unit::show_within;
use super::{PROBE_UNIT_PREFIX, is_job_instance};

/// The table of the ids in use.
pub const JOB_IDS_ROOT: &str = "/run/oneiron-job-ids";

/// The table's lock file.
const LOCK_NAME: &str = ".lock";

/// The longest a step waits for the table's lock.
const LOCK_WAIT: Duration = Duration::from_secs(10);

/// The largest entry the table holds: one unit name.
const ENTRY_MAX_BYTES: u64 = 256;

/// The longest the prepare step waits for the service manager to say whether
/// the unit of a taken id still runs.
const UNIT_STATE_WAIT: Duration = Duration::from_secs(2);

/// The uid and gid one job unit runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobIdentity {
    pub uid: u32,
    pub gid: u32,
}

impl JobIdentity {
    /// The identity of the id `uid`: its group id is the same number.
    #[must_use]
    pub const fn of(uid: u32) -> Self {
        Self { uid, gid: uid }
    }
}

/// What [`choose`] found for a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Choice {
    /// The table names this unit already: its id again.
    Own(u32),
    /// An id with no file.
    Free(u32),
    /// An id whose file names a unit that no longer runs, held by no process.
    TakeBack(u32),
    /// No id of the range can be given.
    Exhausted,
}

/// The id the table gives `unit`. `taken` is the table (id, unit name),
/// `held` every id a process holds, `unit_ended` whether a taken id's unit no
/// longer runs, `named` whether an account or a group has the id. The
/// engine's uid is never given.
pub(super) fn choose(
    range: Range<u32>,
    unit: &str,
    engine_uid: u32,
    taken: &BTreeMap<u32, String>,
    held: &BTreeSet<u32>,
    unit_ended: &mut dyn FnMut(&str) -> bool,
    named: &mut dyn FnMut(u32) -> bool,
) -> Choice {
    if let Some((uid, _)) = taken
        .iter()
        .find(|(uid, owner)| range.contains(uid) && owner.as_str() == unit)
    {
        return Choice::Own(*uid);
    }
    for uid in range {
        if uid == engine_uid || held.contains(&uid) {
            continue;
        }
        let choice = match taken.get(&uid) {
            Some(owner) if unit_ended(owner) => Choice::TakeBack(uid),
            Some(_) => continue,
            None => Choice::Free(uid),
        };
        if named(uid) {
            continue;
        }
        return choice;
    }
    Choice::Exhausted
}

/// Gives `unit` an id of `range` and records it in the table.
///
/// # Errors
///
/// The table could not be locked, read or written, the processes could not
/// be read, or every id is in use.
pub fn allocate(range: Range<u32>, unit: &str, engine_uid: u32) -> Result<JobIdentity, String> {
    let table = Table::lock()?;
    let taken = table.entries()?;
    let held = ids_held_by_processes()?;
    let mut lookup_failures = 0_u32;
    let choice = choose(
        range.clone(),
        unit,
        engine_uid,
        &taken,
        &held,
        &mut unit_ended,
        &mut |uid| match id_is_named(uid) {
            Ok(named) => named,
            Err(_) => {
                lookup_failures += 1;
                true
            }
        },
    );
    let uid = match choice {
        Choice::Own(uid) => return Ok(JobIdentity::of(uid)),
        Choice::Free(uid) => uid,
        Choice::TakeBack(uid) => {
            table.remove(uid)?;
            uid
        }
        Choice::Exhausted => {
            return Err(format!(
                "job_uids_exhausted: no id of {}..{} is free ({} taken, {lookup_failures} account lookups failed)",
                range.start,
                range.end,
                taken.len()
            ));
        }
    };
    table.write(uid, unit)?;
    Ok(JobIdentity::of(uid))
}

/// Removes `identity`'s file when it names `unit`. Returns whether it did.
///
/// # Errors
///
/// The table could not be locked, read or written.
pub fn release(identity: JobIdentity, unit: &str) -> Result<bool, String> {
    let table = Table::lock()?;
    match table.entries()?.get(&identity.uid) {
        Some(owner) if owner == unit => {
            table.remove(identity.uid)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// The table, open and locked until it is dropped.
struct Table {
    dir: OwnedFd,
    _lock: OwnedFd,
}

impl Table {
    fn lock() -> Result<Self, String> {
        let dir = root_dir(JOB_IDS_ROOT, 0o700).map_err(|why| format!("job_ids_table: {why}"))?;
        let name = CString::new(LOCK_NAME).map_err(|error| error.to_string())?;
        // SAFETY: name is NUL terminated; O_NOFOLLOW refuses a link.
        let raw = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw < 0 {
            return Err(format!(
                "job_ids_table: {LOCK_NAME}: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: openat returned a new descriptor this call owns.
        let lock = unsafe { OwnedFd::from_raw_fd(raw) };
        let until = Instant::now() + LOCK_WAIT;
        loop {
            // SAFETY: lock is an open descriptor; flock takes no pointer.
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::WouldBlock || Instant::now() >= until {
                return Err(format!("job_ids_table: not locked: {error}"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(Self { dir, _lock: lock })
    }

    /// Every id the table names, with its unit; an entry that does not read
    /// is an id taken by a unit no one knows.
    fn entries(&self) -> Result<BTreeMap<u32, String>, String> {
        let listing =
            std::fs::read_dir(JOB_IDS_ROOT).map_err(|error| format!("job_ids_table: {error}"))?;
        let mut taken = BTreeMap::new();
        for entry in listing.flatten() {
            let Some(uid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse().ok())
            else {
                continue;
            };
            let owner = read_beneath(
                borrow(&self.dir),
                &uid.to_string(),
                ENTRY_MAX_BYTES,
                Some(0),
            )
            .ok()
            .flatten()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .map(|text| text.trim().to_owned())
            .unwrap_or_default();
            taken.insert(uid, owner);
        }
        Ok(taken)
    }

    fn write(&self, uid: u32, unit: &str) -> Result<(), String> {
        write_beneath(
            borrow(&self.dir),
            &uid.to_string(),
            format!("{unit}\n").as_bytes(),
            0o600,
            Some((0, 0)),
        )
        .map_err(|error| format!("job_ids_table: {uid}: {error}"))
    }

    fn remove(&self, uid: u32) -> Result<(), String> {
        remove_beneath(borrow(&self.dir), &uid.to_string())
            .map_err(|error| format!("job_ids_table: {uid}: {error}"))
    }
}

/// Whether a unit the table names no longer runs: the service manager knows
/// it as inactive, failed or not found. An entry that names no job or probe
/// unit is a write that did not complete. A unit whose state does not come
/// within [`UNIT_STATE_WAIT`] still runs.
fn unit_ended(owner: &str) -> bool {
    if !is_table_unit(owner) {
        return true;
    }
    show_within(owner, &["ActiveState", "LoadState"], UNIT_STATE_WAIT).is_ok_and(|found| {
        found
            .get("LoadState")
            .is_some_and(|state| state == "not-found")
            || found
                .get("ActiveState")
                .is_some_and(|state| state == "inactive" || state == "failed")
    })
}

/// Whether `name` is a unit the table may hold: a job unit or a probe unit.
pub(super) fn is_table_unit(name: &str) -> bool {
    let instance = name
        .strip_prefix("oneiron-job@")
        .and_then(|rest| rest.strip_suffix(".service"))
        .or_else(|| {
            name.strip_prefix(PROBE_UNIT_PREFIX)
                .map(|rest| rest.strip_suffix(".service").unwrap_or(rest))
        });
    instance.is_some_and(is_job_instance)
}

/// Every uid and gid some process holds, as `/proc/<pid>/status` lists them
/// (real, effective, saved and file-system ids).
///
/// # Errors
///
/// `/proc` could not be listed.
pub(super) fn ids_held_by_processes() -> Result<BTreeSet<u32>, String> {
    let listing = std::fs::read_dir("/proc").map_err(|error| format!("/proc: {error}"))?;
    let mut held = BTreeSet::new();
    for entry in listing.flatten() {
        let name = entry.file_name();
        if !name
            .to_str()
            .is_some_and(|pid| pid.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        let path = std::path::Path::new("/proc").join(&name).join("status");
        // A process that ended while the list was read holds nothing.
        if let Ok(text) = std::fs::read_to_string(path) {
            held.extend(ids_in_status(&text));
        }
    }
    Ok(held)
}

/// The ids on the `Uid:` and `Gid:` lines of a `/proc/<pid>/status` text.
pub(super) fn ids_in_status(text: &str) -> Vec<u32> {
    text.lines()
        .filter_map(|line| {
            line.strip_prefix("Uid:")
                .or_else(|| line.strip_prefix("Gid:"))
        })
        .flat_map(|ids| {
            ids.split_whitespace()
                .filter_map(|id| id.parse::<u32>().ok())
        })
        .collect()
}

/// Whether an account or a group has the id `id`, as the system's name
/// service says.
///
/// # Errors
///
/// A lookup failed (the id then counts as taken).
fn id_is_named(id: u32) -> io::Result<bool> {
    let mut buffer = vec![0_u8; 16 * 1024];
    let mut account = MaybeUninit::<libc::passwd>::uninit();
    let mut found_account: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call; buffer outlives it.
    let answer = unsafe {
        libc::getpwuid_r(
            id,
            account.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &raw mut found_account,
        )
    };
    if answer != 0 {
        return Err(io::Error::from_raw_os_error(answer));
    }
    if !found_account.is_null() {
        return Ok(true);
    }
    let mut group = MaybeUninit::<libc::group>::uninit();
    let mut found_group: *mut libc::group = std::ptr::null_mut();
    // SAFETY: as above.
    let answer = unsafe {
        libc::getgrgid_r(
            id,
            group.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &raw mut found_group,
        )
    };
    if answer != 0 {
        return Err(io::Error::from_raw_os_error(answer));
    }
    Ok(!found_group.is_null())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNIT_A: &str = "oneiron-job@0123456789abcdef0123456789abcdef.service";
    const UNIT_B: &str = "oneiron-job@fedcba9876543210fedcba9876543210.service";

    fn pick(
        taken: &BTreeMap<u32, String>,
        held: &BTreeSet<u32>,
        ended: &[&str],
        named: &[u32],
    ) -> Choice {
        choose(
            100..104,
            UNIT_A,
            101,
            taken,
            held,
            &mut |owner| ended.contains(&owner),
            &mut |uid| named.contains(&uid),
        )
    }

    #[test]
    fn the_lowest_id_no_file_process_or_account_holds_is_given_and_never_the_engines() {
        let taken = BTreeMap::from([(100, UNIT_B.to_owned())]);
        // 100 is B's (running), 101 the engine's, 102 a process's.
        assert_eq!(
            pick(&taken, &BTreeSet::from([102]), &[], &[]),
            Choice::Free(103)
        );
        assert_eq!(
            pick(&taken, &BTreeSet::new(), &[], &[102]),
            Choice::Free(103)
        );
        assert_eq!(
            pick(&taken, &BTreeSet::from([102, 103]), &[], &[]),
            Choice::Exhausted
        );
    }

    #[test]
    fn an_id_is_taken_back_only_when_its_unit_ended_and_no_process_holds_it() {
        let taken = BTreeMap::from([(100, UNIT_B.to_owned())]);
        let busy = BTreeSet::from([102, 103]);
        assert_eq!(pick(&taken, &busy, &[UNIT_B], &[]), Choice::TakeBack(100));
        // B ended, but a process still holds 100.
        assert_eq!(
            pick(&taken, &BTreeSet::from([100, 102, 103]), &[UNIT_B], &[]),
            Choice::Exhausted
        );
        // B still runs.
        assert_eq!(pick(&taken, &busy, &[], &[]), Choice::Exhausted);
    }

    #[test]
    fn a_unit_the_table_names_gets_its_own_id_again() {
        let taken = BTreeMap::from([(102, UNIT_A.to_owned())]);
        assert_eq!(pick(&taken, &BTreeSet::new(), &[], &[]), Choice::Own(102));
    }

    #[test]
    fn the_status_ids_are_the_real_effective_saved_and_file_system_ids() {
        let text = "Name:\tsleep\nUid:\t1879048192\t1879048192\t0\t1879048193\nGid:\t5\t6\t7\t8\nGroups:\t9\n";
        assert_eq!(
            ids_in_status(text),
            vec![1_879_048_192, 1_879_048_192, 0, 1_879_048_193, 5, 6, 7, 8]
        );
    }

    #[test]
    fn the_table_holds_only_job_and_probe_unit_names() {
        assert!(is_table_unit(UNIT_A));
        assert!(is_table_unit(&format!(
            "{PROBE_UNIT_PREFIX}0123456789abcdef0123456789abcdef"
        )));
        assert!(!is_table_unit("oneiron-job@x.service"));
        assert!(!is_table_unit("sshd.service"));
        assert!(!is_table_unit(""));
    }
}
