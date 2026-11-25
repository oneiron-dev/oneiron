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
//! it in any of its real, effective, saved or file-system ids or as a
//! supplementary group. A file is taken back only when its unit is no longer
//! running and no process holds the id. The end step removes the file once
//! the unit's group is empty and the job's files are the engine's
//! ([`super::handover`]). Every change is made under one lock on the table;
//! the slow questions (the units' states, the name service) are asked before
//! the lock is taken, so a step holds it only to read the table and
//! `/proc` and to write one file.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::io;
use std::mem::MaybeUninit;
use std::ops::Range;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::exchange::root_dir;
use super::safe_fs::{borrow, read_beneath, remove_beneath, write_beneath};
use super::systemd_unit::{parse_show_units, run_tool};
use super::{PROBE_UNIT_PREFIX, is_job_instance};

/// The table of the ids in use.
pub const JOB_IDS_ROOT: &str = "/run/oneiron-job-ids";

/// The table's lock file.
const LOCK_NAME: &str = ".lock";

/// The longest the prepare step and the probe wait for the table's lock.
pub const LOCK_WAIT: Duration = Duration::from_secs(10);

/// The suffix of a file `write_beneath` stages before it renames it; one the
/// lock holder finds is a write that did not complete.
const STAGING_SUFFIX: &str = ".new";

/// The largest entry the table holds: one unit name.
const ENTRY_MAX_BYTES: u64 = 256;

/// The longest the prepare step waits, in all, for the service manager to
/// say which units of the table still run.
const UNIT_STATE_WAIT: Duration = Duration::from_secs(2);

/// The most units one `systemctl show` names.
const UNITS_PER_QUERY: usize = 256;

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

/// The name service's answers for the ids one allocation tries, kept so that
/// the choice made under the lock asks again only for an id the first choice
/// did not try.
#[derive(Default)]
struct NameAnswers {
    named: BTreeMap<u32, bool>,
    failures: u32,
}

impl NameAnswers {
    /// Whether `uid` is an account's or a group's; a lookup that fails counts
    /// as named.
    fn named(&mut self, uid: u32) -> bool {
        if let Some(named) = self.named.get(&uid) {
            return *named;
        }
        let named = id_is_named(uid).unwrap_or_else(|_| {
            self.failures += 1;
            true
        });
        self.named.insert(uid, named);
        named
    }
}

/// Gives `unit` an id of `range` and records it in the table.
///
/// The units' states and the name service are asked first, without the lock:
/// one choice made then names the ids to ask about. The choice is then made
/// again under the lock, on the table and `/proc` as they are then, and with
/// those answers: a unit the first read did not name counts as running.
///
/// # Errors
///
/// The table could not be locked, read or written, the processes could not
/// be read, or every id is in use.
pub fn allocate(range: Range<u32>, unit: &str, engine_uid: u32) -> Result<JobIdentity, String> {
    let before = entries_in(&open_table()?)?;
    let owners: BTreeSet<String> = before
        .values()
        .map(String::as_str)
        .filter(|owner| *owner != unit && is_table_unit(owner))
        .map(unit_id)
        .collect();
    let ended = units_ended(&owners);
    let mut owner_ended = |owner: &str| !is_table_unit(owner) || ended.contains(&unit_id(owner));
    let mut names = NameAnswers::default();
    let _ = choose(
        range.clone(),
        unit,
        engine_uid,
        &before,
        &ids_held_by_processes()?,
        &mut owner_ended,
        &mut |uid| names.named(uid),
    );
    let table = Table::lock(LOCK_WAIT)?;
    let taken = table.entries()?;
    let held = ids_held_by_processes()?;
    let choice = choose(
        range.clone(),
        unit,
        engine_uid,
        &taken,
        &held,
        &mut owner_ended,
        &mut |uid| names.named(uid),
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
                "job_uids_exhausted: no id of {}..{} is free ({} taken, {} account lookups failed)",
                range.start,
                range.end,
                taken.len(),
                names.failures
            ));
        }
    };
    table.write(uid, unit)?;
    Ok(JobIdentity::of(uid))
}

/// Removes `identity`'s file when it names `unit`, waiting at most `wait` for
/// the table's lock. Returns whether it did.
///
/// # Errors
///
/// The table could not be locked, read or written.
pub fn release(identity: JobIdentity, unit: &str, wait: Duration) -> Result<bool, String> {
    let table = Table::lock(wait)?;
    if table.owner(identity.uid).as_deref() == Some(unit) {
        table.remove(identity.uid)?;
        return Ok(true);
    }
    Ok(false)
}

/// The identity the table gives `unit`, read without the lock: the end step's
/// answer when the job's exchange file was never written.
#[must_use]
pub fn identity_of(unit: &str) -> Option<JobIdentity> {
    let dir = open_table().ok()?;
    entries_in(&dir)
        .ok()?
        .into_iter()
        .find(|(_, owner)| owner == unit)
        .map(|(uid, _)| JobIdentity::of(uid))
}

/// The table's directory, made root's alone when it is missing.
fn open_table() -> Result<OwnedFd, String> {
    root_dir(JOB_IDS_ROOT, 0o700).map_err(|why| format!("job_ids_table: {why}"))
}

/// Every id the table `dir` names, with its unit; an entry that does not read
/// is an id taken by a unit no one knows.
fn entries_in(dir: &OwnedFd) -> Result<BTreeMap<u32, String>, String> {
    let listing =
        std::fs::read_dir(JOB_IDS_ROOT).map_err(|error| format!("job_ids_table: {error}"))?;
    let mut taken = BTreeMap::new();
    for entry in listing.flatten() {
        let Some(uid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        taken.insert(uid, owner_in(dir, uid).unwrap_or_default());
    }
    Ok(taken)
}

/// The unit the entry of `uid` names, if it reads.
fn owner_in(dir: &OwnedFd, uid: u32) -> Option<String> {
    read_beneath(borrow(dir), &uid.to_string(), ENTRY_MAX_BYTES, Some(0))
        .ok()
        .flatten()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(|text| text.trim().to_owned())
}

/// The table, open and locked until it is dropped.
struct Table {
    dir: OwnedFd,
    _lock: OwnedFd,
}

impl Table {
    fn lock(wait: Duration) -> Result<Self, String> {
        let dir = open_table()?;
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
        let until = Instant::now() + wait;
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

    /// Every id the table names, with its unit. A staged file the lock holder
    /// finds is a write that did not complete, so it is removed.
    fn entries(&self) -> Result<BTreeMap<u32, String>, String> {
        let listing =
            std::fs::read_dir(JOB_IDS_ROOT).map_err(|error| format!("job_ids_table: {error}"))?;
        for entry in listing.flatten() {
            let name = entry.file_name();
            if let Some(name) = name.to_str()
                && name
                    .strip_suffix(STAGING_SUFFIX)
                    .is_some_and(|uid| uid.parse::<u32>().is_ok())
            {
                remove_beneath(borrow(&self.dir), name)
                    .map_err(|error| format!("job_ids_table: {name}: {error}"))?;
            }
        }
        entries_in(&self.dir)
    }

    fn owner(&self, uid: u32) -> Option<String> {
        owner_in(&self.dir, uid)
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

/// The unit's full name, as `systemctl show` gives it in `Id`: a probe unit's
/// entry names it without the `.service` suffix.
fn unit_id(owner: &str) -> String {
    if owner.ends_with(".service") {
        owner.to_owned()
    } else {
        format!("{owner}.service")
    }
}

/// Which of `units` no longer run, from `systemctl show` naming at most
/// [`UNITS_PER_QUERY`] at once, within [`UNIT_STATE_WAIT`] in all. A unit
/// whose state does not come in time still runs.
fn units_ended(units: &BTreeSet<String>) -> BTreeSet<String> {
    let until = Instant::now() + UNIT_STATE_WAIT;
    let names: Vec<&str> = units.iter().map(String::as_str).collect();
    let mut ended = BTreeSet::new();
    for chunk in names.chunks(UNITS_PER_QUERY) {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let mut args = vec!["show", "--property=Id,ActiveState,LoadState"];
        args.extend(chunk.iter().copied());
        match run_tool("systemctl", &args, left) {
            Ok(text) => ended.extend(ended_in_show(&text, chunk)),
            Err(_) => break,
        }
    }
    ended
}

/// The units of `units` one `systemctl show` answer says no longer run: the
/// service manager knows them as inactive, failed or not found. A unit the
/// answer leaves out still runs.
pub(super) fn ended_in_show(text: &str, units: &[&str]) -> Vec<String> {
    parse_show_units(text)
        .into_iter()
        .filter(|found| {
            found
                .get("LoadState")
                .is_some_and(|state| state == "not-found")
                || found
                    .get("ActiveState")
                    .is_some_and(|state| state == "inactive" || state == "failed")
        })
        .filter_map(|found| found.get("Id").cloned())
        .filter(|id| units.contains(&id.as_str()))
        .collect()
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
/// (real, effective, saved and file-system ids, and supplementary groups).
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
        let path = Path::new("/proc").join(&name).join("status");
        // A process that ended while the list was read holds nothing.
        if let Ok(text) = std::fs::read_to_string(path) {
            held.extend(ids_in_status(&text));
        }
    }
    Ok(held)
}

/// The ids on the `Uid:`, `Gid:` and `Groups:` lines of a
/// `/proc/<pid>/status` text.
pub(super) fn ids_in_status(text: &str) -> Vec<u32> {
    text.lines()
        .filter_map(|line| {
            line.strip_prefix("Uid:")
                .or_else(|| line.strip_prefix("Gid:"))
                .or_else(|| line.strip_prefix("Groups:"))
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
    fn one_show_answer_names_the_ended_units_and_a_unit_it_leaves_out_still_runs() {
        let probe = format!("{PROBE_UNIT_PREFIX}00000000000000000000000000000000.service");
        let text = format!(
            "Id={UNIT_A}\nActiveState=inactive\nLoadState=loaded\n\n\
             Id={UNIT_B}\nActiveState=deactivating\nLoadState=loaded\n\n\
             Id={probe}\nActiveState=inactive\nLoadState=not-found\n\n\
             Id=sshd.service\nActiveState=failed\nLoadState=loaded\n"
        );
        let left_out = "oneiron-job@11111111111111111111111111111111.service";
        let ended = ended_in_show(&text, &[UNIT_A, UNIT_B, probe.as_str(), left_out]);
        assert_eq!(ended, vec![UNIT_A.to_owned(), probe.clone()]);
        assert_eq!(unit_id(probe.trim_end_matches(".service")), probe);
        assert_eq!(unit_id(UNIT_A), UNIT_A);
    }

    #[test]
    fn the_status_ids_are_every_user_and_group_id_and_the_supplementary_groups() {
        let text = "Name:\tsleep\nUid:\t1879048192\t1879048192\t0\t1879048193\nGid:\t5\t6\t7\t8\nGroups:\t9 10 \nNgid:\t0\n";
        assert_eq!(
            ids_in_status(text),
            vec![
                1_879_048_192,
                1_879_048_192,
                0,
                1_879_048_193,
                5,
                6,
                7,
                8,
                9,
                10
            ]
        );
        assert!(ids_in_status("Groups:\t\n").is_empty());
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
