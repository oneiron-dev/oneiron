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
//! the id and holding the unit's name and the process that reserved it (its
//! pid and start time). The prepare step takes the lowest id
//! with no file, no account or group of that number, and no process holding
//! it in any of its real, effective, saved or file-system ids or as a
//! supplementary group. A file is taken back only when its unit is no longer
//! running, its reserving process has ended (a probe reserves its id before
//! its unit exists) and no process holds the id. The end step removes the file once
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
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use super::exchange::root_dir;
use super::safe_fs::{borrow, read_beneath, remove_beneath, write_beneath};
use super::systemd_unit::{parse_show_units, run_tool};
use super::{EXCHANGE_ROOT, PROBE_UNIT_PREFIX, is_job_instance};

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

/// The most times one allocation takes the lock: again only for an id the
/// name service had not been asked about.
const ALLOCATE_ROUNDS: u32 = 3;

/// The most units one allocation asks about again under the lock before it
/// takes one's id back.
const CONFIRMATIONS_MAX: u32 = 2;

/// How long after a probe's exchange was made the probe unit may still be
/// started: the check's whole probe (its start and its deadline) and its
/// stop take far less.
const PROBE_START_WINDOW: Duration = Duration::from_secs(600);

/// The most ids one round under the lock leaves for the name service to be
/// asked about after the lock is dropped (review r10 R10-03).
const UNANSWERED_PER_ROUND: usize = 8;

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
    /// The table names this unit already, for an id it cannot have again:
    /// outside the range, the engine's, an account's or group's, held by a
    /// process (its reserving process included), or one of two entries of
    /// the unit (review r10 R10-01, R10-06).
    OwnRefused(u32),
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
    let own: Vec<u32> = taken
        .iter()
        .filter(|(_, owner)| owner.as_str() == unit)
        .map(|(uid, _)| *uid)
        .collect();
    if let Some(&uid) = own.first() {
        let fits = own.len() == 1
            && range.contains(&uid)
            && uid != engine_uid
            && !held.contains(&uid)
            && !named(uid);
        return if fits {
            Choice::Own(uid)
        } else {
            Choice::OwnRefused(uid)
        };
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

/// The name service's answers for the ids one allocation tries. The choice
/// made under the lock only reads them: an id it has no answer for is
/// looked up after the lock is dropped, and the choice is made again.
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

/// The ids a process holds: those `/proc` lists, and those whose entry's
/// reserving process still runs (a probe reserves its id before its unit
/// exists).
fn held_ids(entries: &Entries) -> Result<BTreeSet<u32>, String> {
    let mut held = ids_held_by_processes()?;
    held.extend(entries.reserved.iter().copied());
    Ok(held)
}

/// Gives `unit` an id of `range` and records it in the table, with this
/// process as the entry's reserving process.
///
/// The units' states and the name service are asked first, without the lock:
/// one choice made then names the ids to ask about. The choice is made again
/// under the lock, on the table and `/proc` as they are then. Under the lock
/// it asks the name service nothing (an id with no answer yet sends the
/// allocation round again), and an id is taken back only after one more
/// question to the service manager about that one unit: a unit started
/// since the first answer is running again (review r9 R9-01, R9-04).
///
/// # Errors
///
/// The table could not be locked, read or written, the processes could not
/// be read, or every id is in use.
pub fn allocate(range: Range<u32>, unit: &str, engine_uid: u32) -> Result<JobIdentity, String> {
    let before = entries_in(&open_table()?)?;
    let owners: BTreeSet<String> = before
        .owners
        .values()
        .map(String::as_str)
        .filter(|owner| *owner != unit && is_table_unit(owner))
        .map(unit_id)
        .collect();
    let mut ended = units_ended(&owners);
    let mut names = NameAnswers::default();
    let mut confirmations = 0;
    for round in 1..=ALLOCATE_ROUNDS {
        let before = entries_in(&open_table()?)?;
        let _ = choose(
            range.clone(),
            unit,
            engine_uid,
            &before.owners,
            &held_ids(&before)?,
            &mut |owner: &str| owner_ended(owner, &ended),
            &mut |uid| names.named(uid),
        );
        let table = Table::lock(LOCK_WAIT)?;
        let taken = table.entries()?;
        let held = held_ids(&taken)?;
        let mut unanswered = Vec::new();
        let choice = loop {
            let choice = choose(
                range.clone(),
                unit,
                engine_uid,
                &taken.owners,
                &held,
                &mut |owner: &str| owner_ended(owner, &ended),
                &mut |uid| {
                    names.named.get(&uid).copied().unwrap_or_else(|| {
                        if unanswered.len() < UNANSWERED_PER_ROUND {
                            unanswered.push(uid);
                        }
                        true
                    })
                },
            );
            let Choice::TakeBack(uid) = choice else {
                break choice;
            };
            // A round that goes again for the name service asks nothing
            // more now; every question counts (review r11 R11-04).
            if !unanswered.is_empty() && round < ALLOCATE_ROUNDS {
                break choice;
            }
            let owner = taken.owners.get(&uid).cloned().unwrap_or_default();
            if confirmations < CONFIRMATIONS_MAX {
                confirmations += 1;
                if unit_ended_now(&owner) {
                    break choice;
                }
            }
            // Running again, or not asked again: it is not taken back.
            ended.remove(&unit_id(&owner));
        };
        if !unanswered.is_empty() && round < ALLOCATE_ROUNDS {
            drop(table);
            for uid in unanswered {
                names.named(uid);
            }
            continue;
        }
        let uid = match choice {
            Choice::Own(uid) | Choice::Free(uid) => uid,
            Choice::OwnRefused(uid) => {
                return Err(format!(
                    "job_uid_still_taken: the table names {unit} for uid {uid}, outside {}..{}, held by a process, an account's, or one of two entries of it: its end step or its processes have not finished",
                    range.start, range.end
                ));
            }
            Choice::TakeBack(uid) => {
                // A probe's exchange left by a check that ended early goes
                // with its id (review r11 R11-03).
                if let Some(instance) = taken
                    .owners
                    .get(&uid)
                    .and_then(|owner| probe_instance(owner))
                {
                    let _ = std::fs::remove_dir_all(Path::new(EXCHANGE_ROOT).join(instance));
                }
                table.remove(uid)?;
                uid
            }
            Choice::Exhausted => {
                return Err(format!(
                    "job_uids_exhausted: no id of {}..{} is free ({} taken, {} account lookups failed)",
                    range.start,
                    range.end,
                    taken.owners.len(),
                    names.failures
                ));
            }
        };
        table.write(uid, unit)?;
        return Ok(JobIdentity::of(uid));
    }
    Err("job_uids_exhausted: no allocation round completed".to_owned())
}

/// Whether the table's `owner` no longer runs, as `ended` (one answer of the
/// service manager) says. An entry that names no job or probe unit is no
/// write of this table's and is never taken back.
fn owner_ended(owner: &str, ended: &BTreeSet<String>) -> bool {
    is_table_unit(owner) && ended.contains(&unit_id(owner))
}

/// Whether `owner` no longer runs, asked now about that one unit. A probe
/// unit whose exchange directory is younger than [`PROBE_START_WINDOW`] may
/// still be started by the `execution-node check` that made it (its job-exec
/// reads its ids from there), so it counts as running (review r10 R10-02);
/// past that window no start the check asked for can still come (review r11
/// R11-03).
fn unit_ended_now(owner: &str) -> bool {
    is_table_unit(owner) && !probe_start_possible(owner) && unit_has_ended(&unit_id(owner))
}

/// Whether the service manager says now that `unit` no longer runs: it is
/// inactive, failed or not found. No answer within [`UNIT_STATE_WAIT`] is
/// "still runs".
pub(super) fn unit_has_ended(unit: &str) -> bool {
    let id = unit_id(unit);
    let mut args = vec!["show", "--property=Id,ActiveState,LoadState"];
    args.push(&id);
    run_tool("systemctl", &args, UNIT_STATE_WAIT)
        .is_ok_and(|text| !ended_in_show(&text, &[id.as_str()]).is_empty())
}

/// The probe instance an entry's unit names, if it is a probe unit.
fn probe_instance(owner: &str) -> Option<&str> {
    owner
        .strip_prefix(PROBE_UNIT_PREFIX)
        .map(|rest| rest.strip_suffix(".service").unwrap_or(rest))
}

/// Whether `owner` is a probe unit whose exchange directory is there and
/// younger than [`PROBE_START_WINDOW`]; one that cannot be looked at counts
/// as there and young.
fn probe_start_possible(owner: &str) -> bool {
    probe_instance(owner).is_some_and(|instance| {
        match Path::new(EXCHANGE_ROOT).join(instance).symlink_metadata() {
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(_) => true,
            Ok(found) => found
                .modified()
                .ok()
                .and_then(|made| SystemTime::now().duration_since(made).ok())
                .is_none_or(|age| age < PROBE_START_WINDOW),
        }
    })
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
/// answer for the job's ids (review r8 R8-04, r9 R9-13). `None` unless one
/// entry alone names the unit (review r10 R10-06).
#[must_use]
pub fn identity_of(unit: &str) -> Option<JobIdentity> {
    let dir = open_table().ok()?;
    let owners = entries_in(&dir).ok()?.owners;
    let mut uids = owners
        .into_iter()
        .filter(|(_, owner)| owner == unit)
        .map(|(uid, _)| uid);
    let uid = uids.next()?;
    uids.next().is_none().then_some(JobIdentity::of(uid))
}

/// The table's directory, made root's alone when it is missing.
fn open_table() -> Result<OwnedFd, String> {
    root_dir(JOB_IDS_ROOT, 0o700).map_err(|why| format!("job_ids_table: {why}"))
}

/// The table as one read gives it.
struct Entries {
    /// Every id the table names, with its unit; an entry that does not read
    /// is an id taken by a unit no one knows.
    owners: BTreeMap<u32, String>,
    /// The ids whose entry's reserving process still runs.
    reserved: BTreeSet<u32>,
}

/// The table in `dir`.
fn entries_in(dir: &OwnedFd) -> Result<Entries, String> {
    let listing =
        std::fs::read_dir(JOB_IDS_ROOT).map_err(|error| format!("job_ids_table: {error}"))?;
    let mut entries = Entries {
        owners: BTreeMap::new(),
        reserved: BTreeSet::new(),
    };
    for entry in listing.flatten() {
        let Some(uid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let (owner, reserver) = entry_text(dir, uid)
            .map(|text| parse_entry(&text))
            .unwrap_or_default();
        if reserver.is_some_and(|(pid, started)| process_started_at(pid) == Some(started)) {
            entries.reserved.insert(uid);
        }
        entries.owners.insert(uid, owner);
    }
    Ok(entries)
}

/// The text of the entry of `uid`, if it reads.
fn entry_text(dir: &OwnedFd, uid: u32) -> Option<String> {
    read_beneath(borrow(dir), &uid.to_string(), ENTRY_MAX_BYTES, Some(0))
        .ok()
        .flatten()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

/// The unit the entry of `uid` names, if it reads.
fn owner_in(dir: &OwnedFd, uid: u32) -> Option<String> {
    entry_text(dir, uid).map(|text| parse_entry(&text).0)
}

/// An entry's unit (its first line) and its reserving process (pid and
/// start time, the second line), when it names one.
pub(super) fn parse_entry(text: &str) -> (String, Option<(u32, u64)>) {
    let mut lines = text.lines();
    let owner = lines.next().unwrap_or_default().trim().to_owned();
    let reserver = lines.next().and_then(|line| {
        let (pid, started) = line.trim().split_once(' ')?;
        Some((pid.parse().ok()?, started.parse().ok()?))
    });
    (owner, reserver)
}

/// The start time of process `pid` (field 22 of `/proc/<pid>/stat`, in clock
/// ticks since boot): with the pid, it names one process, never a later one
/// that reused the pid.
fn process_started_at(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    start_time_in_stat(&text)
}

/// The start time in a `/proc/<pid>/stat` text: the 20th field after the
/// command name, which ends at the last `)`.
pub(super) fn start_time_in_stat(text: &str) -> Option<u64> {
    let (_, after_name) = text.rsplit_once(')')?;
    after_name.split_whitespace().nth(19)?.parse().ok()
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

    /// The table. A staged file the lock holder finds is a write that did not
    /// complete, so it is removed.
    fn entries(&self) -> Result<Entries, String> {
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

    /// Writes the entry of `uid`: `unit`, and this process as its reserving
    /// process.
    fn write(&self, uid: u32, unit: &str) -> Result<(), String> {
        let pid = std::process::id();
        let reserver = process_started_at(pid)
            .map(|started| format!("{pid} {started}\n"))
            .unwrap_or_default();
        write_beneath(
            borrow(&self.dir),
            &uid.to_string(),
            format!("{unit}\n{reserver}").as_bytes(),
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
mod tests;
