//! [HELD-WHOLE-READ-OFF-PRE-IDLE] (Engine RULING 15 Nov 22:17, FIX 6729): a
//! backup before an idle reap reuses the last accepted backup only while its
//! file is still that backup, and it read the whole artifact to know, inside
//! the reap preparation's window, every time. The whole read now also runs in
//! the background after a pass and on a timer, and the reuse takes its fresh
//! verdict in place of its own read; a changed or unverified backup is still
//! read whole before reuse.
//!
//! Each test backs up a vault holding text through the managed pass
//! (`oneiron_server::test_doors::pre_idle_reuse`), runs the background verify
//! on the thread a tick starts it on where it asks for one, then runs one
//! backup before an idle reap and counts the bytes this thread read
//! meanwhile (`rchar` in `/proc/thread-self/io`):
//! - a backup the background verify read whole is reused with under a
//!   quarter of its bytes read: no whole read (`FIXHELD-PREIDLE`, which
//!   prints the time, the bytes read and the artifact's size: the
//!   measurement main and the fix are compared by);
//! - a backup changed after its verdict, one byte rewritten in place, is
//!   never reused: a new backup is taken (`FIXHELD-CHANGED`);
//! - a backup changed after its verdict is read whole again by the next
//!   background verify, which finds it not held, and is not reused
//!   (`FIXHELD-REVERIFY`);
//! - a backup no verify read is read whole and reused, as before
//!   (`FIXHELD-UNVERIFIED`);
//! - a backup whose verdict no longer answers, its modification time moved
//!   and its bytes unchanged, is read whole and reused, and that reuse opens
//!   the artifact as often as one with no verdict: the whole read takes the
//!   open the verdict was checked on (`FIXHELD-REJECTED`, Astra
//!   fixperf-8419-r2 F2; the opens are counted by an inotify watch).
//!
//! On main there is no background verify, so each test that asks for one
//! fails; the first fails at its read count, which is the measurement.
//!
//! Linux only: the read count is per thread from procfs, and the opens come
//! from inotify.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test pre_idle_held_verdict`
#![cfg(all(target_os = "linux", oneiron_test_support))]

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::{EntityId, TimeRange};
use oneiron_server::test_doors::pre_idle_reuse::{ManagedBackups, managed_backups};
use rustix::fs::inotify::{self, CreateFlags, ReadFlags, WatchFlags};

/// The first test's vault: 1,024 texts of 32 KiB.
const BODIES: u64 = 1_024;
/// The other tests' vaults, small: they time nothing.
const SMALL_BODIES: u64 = 64;
const BODY_BYTES: usize = 32 * 1024;

/// Text no compressor shrinks much: letters and digits from a xorshift.
fn body(seed: u64) -> Vec<u8> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..BODY_BYTES)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            ALPHABET[usize::try_from(state % 36).expect("an index")]
        })
        .collect()
}

/// The bytes this thread has read through read calls, page cache included.
fn thread_rchar() -> u64 {
    let io = std::fs::read_to_string("/proc/thread-self/io").expect("this thread's io counters");
    io.lines()
        .find_map(|line| line.strip_prefix("rchar:"))
        .and_then(|value| value.trim().parse().ok())
        .expect("an rchar line")
}

/// A managed vault holding `bodies` texts with one accepted backup; the
/// directories live as long as it does, and the vault drops first. Bind it
/// whole: a pattern that leaves the directories out drops them, and with
/// them the vault's files and its backups, at the end of its statement.
struct Backed {
    managed: ManagedBackups,
    size: u64,
    _vault_dir: tempfile::TempDir,
    _backups: tempfile::TempDir,
}

fn backed_up(bodies: u64) -> Backed {
    let vault_dir = tempfile::tempdir().expect("tempdir");
    let backups = tempfile::tempdir().expect("backup dir");
    let managed = managed_backups(vault_dir.path(), backups.path());
    for seed in 0..bodies {
        managed
            .vault()
            .put_entity(
                &EntityId::now(),
                ENTITY_TYPE_ASSET,
                TimeRange { start: 7, end: 7 },
                9,
                &body(seed),
            )
            .expect("a text asset");
    }
    assert!(
        managed.pass().expect("the managed pass"),
        "the first managed pass takes a backup"
    );
    let file = managed.accepted_file().expect("the accepted backup");
    let size = std::fs::metadata(&file).expect("artifact metadata").len();
    Backed {
        managed,
        size,
        _vault_dir: vault_dir,
        _backups: backups,
    }
}

/// One backup before an idle reap: whether it reused the accepted backup,
/// the bytes this thread read meanwhile and its time in ms.
fn timed_before_idle(managed: &ManagedBackups) -> (bool, u64, f64) {
    let read_before = thread_rchar();
    let started = Instant::now();
    let reused = managed
        .before_idle()
        .expect("the backup before an idle reap")
        .expect("it settled");
    let ms = started.elapsed().as_secs_f64() * 1000.0;
    (reused, thread_rchar().saturating_sub(read_before), ms)
}

/// What `run` returns, and how often the file at `path` was opened, by
/// anyone, while it ran: the `IN_OPEN` events of an inotify watch on the
/// file. The watch takes its closes as well, so two opens are never adjacent
/// in the queue, where inotify merges two identical events into one.
fn opens_during<T>(path: &Path, run: impl FnOnce() -> T) -> (T, usize) {
    let watch =
        inotify::init(CreateFlags::NONBLOCK | CreateFlags::CLOEXEC).expect("an inotify instance");
    inotify::add_watch(
        &watch,
        path,
        WatchFlags::OPEN | WatchFlags::CLOSE_WRITE | WatchFlags::CLOSE_NOWRITE,
    )
    .expect("a watch on the artifact");
    let ran = run();
    let mut buffer = [std::mem::MaybeUninit::uninit(); 4096];
    let mut events = inotify::Reader::new(&watch, &mut buffer);
    let mut opens = 0;
    loop {
        match events.next() {
            Ok(event) => {
                if event.events().contains(ReadFlags::OPEN) {
                    opens += 1;
                }
            }
            Err(rustix::io::Errno::AGAIN) => break,
            Err(error) => panic!("the artifact's inotify events read: {error}"),
        }
    }
    (ran, opens)
}

/// Sets the artifact's modification time two seconds past the one it had,
/// its bytes unchanged: its identity moves, so a verdict no longer answers
/// for it, and it is still the backup its marker recorded.
fn touch_later(path: &Path) {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("the artifact opens for writing");
    let modified = file
        .metadata()
        .and_then(|metadata| metadata.modified())
        .expect("the artifact's modification time");
    file.set_modified(modified + Duration::from_secs(2))
        .expect("a later modification time");
}

/// Turns the artifact's byte at `at` into its complement, in place, and sets
/// its modification time two seconds past the one it had, so the change shows
/// in the file's identity on a filesystem whose clock ticks coarser than this
/// test runs too. A change that keeps the identity is the verdict's named
/// residual, not what this proves.
fn flip_byte(path: &Path, at: u64) {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("the artifact opens for writing");
    let mut byte = [0_u8; 1];
    file.seek(SeekFrom::Start(at)).expect("seek");
    file.read_exact(&mut byte).expect("read the byte");
    byte[0] = !byte[0];
    file.seek(SeekFrom::Start(at)).expect("seek back");
    file.write_all(&byte).expect("write the byte");
    let modified = file
        .metadata()
        .and_then(|metadata| metadata.modified())
        .expect("the artifact's modification time");
    file.set_modified(modified + Duration::from_secs(2))
        .expect("a later modification time");
    file.sync_all().expect("sync");
}

#[test]
fn a_verified_backup_is_reused_before_an_idle_reap_without_a_whole_read() {
    let backed = backed_up(BODIES);
    let (managed, size) = (&backed.managed, backed.size);
    assert!(size >= 8 * 1024 * 1024, "a large backup: {size} bytes");
    let verified = managed.verify_in_background();
    let (reused, read, ms) = timed_before_idle(managed);
    println!(
        "FIXHELD-PREIDLE verified={verified:?} reused={reused} read_bytes={read} \
         backup_bytes={size} ms={ms:.3}"
    );
    assert!(reused, "the verified backup covers the vault and is reused");
    assert!(
        read < size / 4,
        "a fresh verdict spares the reuse its whole read: {read} of {size} bytes read"
    );
    assert_eq!(
        verified,
        Some(true),
        "the background verify read the accepted backup whole and found it held"
    );
}

#[test]
fn a_backup_changed_after_its_verdict_is_never_reused() {
    let backed = backed_up(SMALL_BODIES);
    let (managed, size) = (&backed.managed, backed.size);
    let verified = managed.verify_in_background();
    assert_eq!(verified, Some(true), "a verdict stands before the change");
    let file = managed.accepted_file().expect("the accepted backup");
    let before = std::fs::metadata(&file).expect("artifact metadata");
    flip_byte(&file, size / 2);
    let after = std::fs::metadata(&file).expect("artifact metadata");
    let moved = {
        use std::os::unix::fs::MetadataExt;
        (
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    };
    assert!(moved, "the rewrite moved the artifact's identity");
    let (reused, read, ms) = timed_before_idle(managed);
    let now_accepted = managed.accepted_file().expect("an accepted backup");
    println!(
        "FIXHELD-CHANGED verified={verified:?} identity_moved={moved} reused={reused} \
         read_bytes={read} backup_bytes={size} ms={ms:.3}"
    );
    assert!(!reused, "a backup changed after its verdict is not reused");
    assert_ne!(now_accepted, file, "a new backup is taken and accepted");
}

#[test]
fn the_next_background_verify_reads_a_changed_backup_again() {
    let backed = backed_up(SMALL_BODIES);
    let (managed, size) = (&backed.managed, backed.size);
    let first = managed.verify_in_background();
    assert_eq!(first, Some(true), "a verdict stands before the change");
    let file = managed.accepted_file().expect("the accepted backup");
    flip_byte(&file, size / 2);
    let taken = managed.pass().expect("the managed pass");
    let again = managed.verify_in_background();
    let (reused, read, ms) = timed_before_idle(managed);
    println!(
        "FIXHELD-REVERIFY first={first:?} pass_took={taken} again={again:?} reused={reused} \
         read_bytes={read} backup_bytes={size} ms={ms:.3}"
    );
    assert!(
        !taken,
        "the vault did not change, so the pass takes no backup"
    );
    assert_eq!(
        again,
        Some(false),
        "the moved identity makes the next verify due, and its whole read finds the change"
    );
    assert!(!reused, "the backup the verify found changed is not reused");
}

#[test]
fn an_unverified_backup_is_read_whole_and_reused() {
    let backed = backed_up(SMALL_BODIES);
    let (managed, size) = (&backed.managed, backed.size);
    let (reused, read, ms) = timed_before_idle(managed);
    println!("FIXHELD-UNVERIFIED reused={reused} read_bytes={read} backup_bytes={size} ms={ms:.3}");
    assert!(reused, "the unchanged backup is reused");
    assert!(
        read >= size,
        "with no verdict the reuse reads it whole: {read} of {size} bytes"
    );
}

#[test]
fn a_verdict_that_does_not_answer_adds_no_open_before_the_whole_read() {
    let backed = backed_up(SMALL_BODIES);
    let (managed, size) = (&backed.managed, backed.size);
    let file = managed.accepted_file().expect("the accepted backup");
    let ((unverified_reused, unverified_read, _), unverified_opens) =
        opens_during(&file, || timed_before_idle(managed));
    let verified = managed.verify_in_background();
    assert_eq!(verified, Some(true), "a verdict stands before the change");
    touch_later(&file);
    let ((reused, read, ms), opens) = opens_during(&file, || timed_before_idle(managed));
    println!(
        "FIXHELD-REJECTED verified={verified:?} unverified_opens={unverified_opens} \
         rejected_opens={opens} reused={reused} read_bytes={read} backup_bytes={size} ms={ms:.3}"
    );
    assert!(
        unverified_reused && unverified_read >= size,
        "with no verdict the reuse reads it whole: {unverified_read} of {size} bytes"
    );
    assert!(
        reused,
        "its bytes are still the backup its marker recorded, so it is reused"
    );
    assert!(
        read >= size,
        "a verdict that does not answer leaves the reuse its whole read: {read} of {size} bytes"
    );
    assert_eq!(
        opens, unverified_opens,
        "a verdict that does not answer opens the artifact no more often than none: the whole \
         read takes the open the verdict was checked on"
    );
}
