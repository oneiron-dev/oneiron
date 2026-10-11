//! The reader table two processes get over one vault, whichever opens first.
//!
//! LMDB sizes the table when a process opens the vault with no other process
//! holding it, and a process that opens beside a holder gets the holder's
//! table. One process's own second open never sees another holder, so the
//! other opener here is a child process: this test binary run again, told by
//! the environment what to open, which holds it until its stdin closes.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdout, Command, Stdio};

use heed::{EnvFlags, EnvOpenOptions};

use crate::config::READER_SLOTS;
use crate::{Vault, VaultConfig};

const HOLD_ROOT: &str = "ONEIRON_READER_TABLE_ROOT";
const HOLD_MODE: &str = "ONEIRON_READER_TABLE_MODE";
/// The table every opener asked for before [`READER_SLOTS`]: LMDB's default.
const OLD_SLOTS: u32 = 126;

fn config(max_readers: u32) -> VaultConfig {
    let mut config = crate::test_util::embedding_test_config();
    config.max_readers = max_readers;
    config
}

/// Child half: opens the vault at `HOLD_ROOT` as `HOLD_MODE` says, reports
/// the reader slots it got, and holds the open until its stdin closes.
#[test]
fn reader_table_holder_child() {
    let Some(root) = std::env::var_os(HOLD_ROOT) else {
        return;
    };
    let root = Path::new(&root).canonicalize().expect("vault root");
    let report = |slots: u32| {
        let mut out = std::io::stdout().lock();
        writeln!(out, "SLOTS {slots}").expect("report");
        out.flush().expect("flush report");
    };
    let hold = || {
        std::io::stdin()
            .read_to_end(&mut Vec::new())
            .expect("wait for the parent");
    };
    match std::env::var(HOLD_MODE).expect("mode").as_str() {
        // A vault an older build created, with the old table.
        "create-old" => {
            let vault = Vault::open(&root, config(OLD_SLOTS)).expect("create vault");
            report(vault.reader_slots());
        }
        "door" => {
            let (env, _registered) = super::open_read_only(&root).expect("read-only door");
            report(env.info().maximum_number_of_readers);
            hold();
        }
        // The read-only door as it opened before it asked for READER_SLOTS.
        "old-door" => {
            // SAFETY: a read-only environment over a closed test vault, the
            // only environment over these files in this process.
            let env = unsafe {
                EnvOpenOptions::new()
                    .max_dbs(1)
                    .flags(EnvFlags::READ_ONLY)
                    .open(&root)
                    .expect("old read-only door")
            };
            report(env.info().maximum_number_of_readers);
            hold();
        }
        mode => panic!("unknown mode {mode}"),
    }
}

/// A child holding its open, and its output still to read: the parent reads
/// it to the end, so the child's test harness never writes to a closed pipe.
struct Holder {
    child: Child,
    stdout: BufReader<ChildStdout>,
}

/// Runs the child in `mode` over `root` and returns it, with the reader slots
/// it reported, while it holds its open.
fn open_in_child(root: &Path, mode: &str) -> (Holder, u32) {
    let mut child = Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "store::open_gates::read_only_door::tests::reader_table_holder_child",
            "--nocapture",
        ])
        .env(HOLD_ROOT, root)
        .env(HOLD_MODE, mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("run child");
    let mut stdout = BufReader::new(child.stdout.take().expect("child stdout"));
    let mut line = String::new();
    while stdout.read_line(&mut line).expect("child line") > 0 {
        if let Some(slots) = line.trim().strip_prefix("SLOTS ") {
            let slots = slots.parse().expect("slot count");
            return (Holder { child, stdout }, slots);
        }
        line.clear();
    }
    panic!(
        "the {mode} child ended before it opened: {:?}",
        child.wait()
    );
}

/// Lets the child close its open and checks it ended cleanly.
fn release(mut holder: Holder) {
    drop(holder.child.stdin.take());
    let mut rest = String::new();
    holder
        .stdout
        .read_to_string(&mut rest)
        .expect("child output");
    let status = holder.child.wait().expect("child exit");
    assert!(status.success(), "child {status}:\n{rest}");
}

/// A vault created with the old table, by a process that has ended.
fn old_vault() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let (creator, slots) = open_in_child(dir.path(), "create-old");
    assert_eq!(slots, OLD_SLOTS);
    release(creator);
    dir
}

#[test]
fn a_door_that_opens_first_builds_the_full_table_for_the_vault_beside_it() {
    let dir = old_vault();
    let (door, door_slots) = open_in_child(dir.path(), "door");
    assert_eq!(door_slots, READER_SLOTS);
    let vault = Vault::open(dir.path(), config(READER_SLOTS)).expect("open beside the door");
    assert_eq!(vault.reader_slots(), READER_SLOTS);
    assert_eq!(vault.reader_table_shortfall(), None);
    drop(vault);
    release(door);
}

#[test]
fn a_door_that_opens_beside_the_vault_gets_the_full_table() {
    let dir = old_vault();
    let vault = Vault::open(dir.path(), config(READER_SLOTS)).expect("open first");
    assert_eq!(vault.reader_slots(), READER_SLOTS);
    let (door, door_slots) = open_in_child(dir.path(), "door");
    assert_eq!(door_slots, READER_SLOTS);
    release(door);
    drop(vault);
}

/// A process that holds the old table keeps it: the vault opened beside it
/// reports the shortfall, and still reads.
#[test]
fn a_smaller_table_held_by_another_process_is_reported() {
    let dir = old_vault();
    let (old_door, old_slots) = open_in_child(dir.path(), "old-door");
    assert_eq!(old_slots, OLD_SLOTS);
    let vault = Vault::open(dir.path(), config(READER_SLOTS)).expect("open beside the old door");
    assert_eq!(
        vault.reader_table_shortfall(),
        Some(crate::ReaderTableShortfall {
            requested: READER_SLOTS,
            granted: OLD_SLOTS,
        })
    );
    drop(vault.store.env.read_txn().expect("a read still opens"));
    drop(vault);
    release(old_door);
}
