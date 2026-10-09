//! Group commit (OF-536), checked against outside truth: LMDB's own
//! transaction id counts the durable commits, and every write is read back
//! from the vault, after a reopen where a crash is involved.

use std::io::Write;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use crate::entity_id::EntityId;
use crate::error::Error;
use crate::temporal::TimeRange;
use crate::{Vault, VaultConfig};

/// One logical write's rows: three entities that land together or not at all.
fn rows(writer: usize, write: usize) -> [EntityId; 3] {
    std::array::from_fn(|part| {
        let mut bytes = [0x5a_u8; 16];
        bytes[1..9].copy_from_slice(&(writer as u64).to_be_bytes());
        bytes[9..13].copy_from_slice(&(write as u32).to_be_bytes());
        bytes[13] = part as u8;
        EntityId::from_bytes(bytes).expect("non-reserved id")
    })
}

fn put_rows(batch: crate::BatchBuilder<'_>, ids: &[EntityId]) -> crate::BatchBuilder<'_> {
    ids.iter().fold(batch, |batch, id| {
        batch
            .put(id, 1, TimeRange { start: 1, end: 1 }, 1, b"group-commit")
            .text(id, &[("body", "group commit row")])
    })
}

fn present(vault: &Vault, ids: &[EntityId]) -> usize {
    ids.iter()
        .filter(|id| vault.get(id).expect("read row").is_some())
        .count()
}

/// Write transactions LMDB has committed in this environment so far. Each
/// one is a durable commit: one data sync plus its meta page.
fn lmdb_commits(vault: &Vault) -> usize {
    vault.store.env.info().last_txn_id
}

fn wait_until_leading(vault: &Vault) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !vault.store.group_commit.lock().leading {
        assert!(Instant::now() < deadline, "no write took the lead");
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[derive(Debug, PartialEq)]
enum Answer {
    Refused { writer: usize, write: usize },
    Engine(String),
}

impl From<Error> for Answer {
    fn from(err: Error) -> Self {
        Self::Engine(err.to_string())
    }
}

/// e2e: N concurrent writers through both write doors. Every accepted write
/// lands whole, every refused one leaves nothing, each caller gets exactly its
/// own answer, and LMDB committed fewer transactions than there were writes.
#[test]
fn concurrent_writers_land_with_their_own_outcomes_in_fewer_commits() {
    const WRITERS: usize = 24;
    const WRITES: usize = 20;
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).expect("open vault"));
    let before = lmdb_commits(&vault);
    let stats_before = vault.diagnostics().group_commit_snapshot();
    // Every writer's first write is accepted, so the first group carries one
    // write from each of them.
    vault
        .store
        .group_commit
        .hooks
        .hold_next_group_until(WRITERS);
    let start = Arc::new(Barrier::new(WRITERS));
    let threads: Vec<_> = (0..WRITERS)
        .map(|writer| {
            let (vault, start) = (Arc::clone(&vault), Arc::clone(&start));
            std::thread::spawn(move || {
                start.wait();
                let mut accepted = 0;
                for write in 0..WRITES {
                    let ids = rows(writer, write);
                    match write % 4 {
                        // The batch terminal.
                        0 | 3 => {
                            put_rows(vault.batch(), &ids)
                                .commit()
                                .expect("batch commits");
                            accepted += 1;
                        }
                        // The caller-transaction door.
                        1 => {
                            vault
                                .with_write_txn(|txn| put_rows(vault.batch_in(), &ids).apply(txn))
                                .expect("write commits");
                            accepted += 1;
                        }
                        // Stages its rows, then refuses inside the transaction.
                        _ => {
                            let answer = vault.try_with_write_txn(|txn| {
                                put_rows(vault.batch_in(), &ids).apply(txn)?;
                                Err::<(), _>(Answer::Refused { writer, write })
                            });
                            assert_eq!(answer, Err(Answer::Refused { writer, write }));
                        }
                    }
                }
                accepted
            })
        })
        .collect();
    let accepted: usize = threads
        .into_iter()
        .map(|thread| thread.join().expect("writer"))
        .sum();

    for writer in 0..WRITERS {
        for write in 0..WRITES {
            let expected = if write % 4 == 2 { 0 } else { 3 };
            assert_eq!(
                present(&vault, &rows(writer, write)),
                expected,
                "writer {writer} write {write}"
            );
        }
    }
    let commits = lmdb_commits(&vault) - before;
    assert!(
        commits < accepted,
        "{commits} durable commits for {accepted} accepted writes"
    );
    let stats = vault.diagnostics().group_commit_snapshot();
    assert_eq!(stats.writes - stats_before.writes, accepted as u64);
    assert!(stats.largest_group >= WRITERS as u64, "{stats:?}");
}

/// A refused write and a panicking one in a group leave their neighbours
/// committed, in one durable commit, and keep none of their own rows.
#[test]
fn refused_and_panicking_members_leave_their_group_committed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).expect("open vault"));
    let before = lmdb_commits(&vault);
    let stats_before = vault.diagnostics().group_commit_snapshot();
    vault.store.group_commit.hooks.hold_next_group_until(4);

    let leader = {
        let vault = Arc::clone(&vault);
        std::thread::spawn(move || put_rows(vault.batch(), &rows(0, 0)).commit())
    };
    // The others join the group the accepted first write opened.
    wait_until_leading(&vault);
    let refused = {
        let vault = Arc::clone(&vault);
        std::thread::spawn(move || {
            vault.try_with_write_txn(|txn| {
                put_rows(vault.batch_in(), &rows(1, 0)).apply(txn)?;
                Err::<(), _>(Answer::Refused {
                    writer: 1,
                    write: 0,
                })
            })
        })
    };
    let panicking = {
        let vault = Arc::clone(&vault);
        std::thread::spawn(move || {
            vault.with_write_txn(|txn| {
                put_rows(vault.batch_in(), &rows(2, 0)).apply(txn)?;
                panic!("a member panics after staging its rows");
            })
        })
    };
    let neighbour = {
        let vault = Arc::clone(&vault);
        std::thread::spawn(move || put_rows(vault.batch(), &rows(3, 0)).commit())
    };

    leader
        .join()
        .expect("leader thread")
        .expect("leader commits");
    assert_eq!(
        refused.join().expect("refused thread"),
        Err(Answer::Refused {
            writer: 1,
            write: 0
        })
    );
    assert!(
        panicking.join().is_err(),
        "the panic reaches its own caller"
    );
    neighbour
        .join()
        .expect("neighbour thread")
        .expect("neighbour commits");

    assert_eq!(present(&vault, &rows(0, 0)), 3);
    assert_eq!(present(&vault, &rows(1, 0)), 0);
    assert_eq!(present(&vault, &rows(2, 0)), 0);
    assert_eq!(present(&vault, &rows(3, 0)), 3);
    assert_eq!(lmdb_commits(&vault) - before, 1, "one durable commit");
    let stats = vault.diagnostics().group_commit_snapshot();
    assert_eq!(
        (
            stats.groups - stats_before.groups,
            stats.writes - stats_before.writes
        ),
        (1, 2),
        "{stats:?}"
    );
}

const CRASH_PATH: &str = "ONEIRON_GROUP_COMMIT_CRASH_PATH";
const CRASH_COMMITTED: usize = 5;
const CRASH_GROUP: usize = 8;

/// Child half of the crash-point test: reports each write it was told is
/// committed, then dies inside a full group, after every member staged its
/// rows and before the shared commit.
#[test]
fn group_commit_crash_child() {
    let Some(path) = std::env::var_os(CRASH_PATH) else {
        return;
    };
    let vault = Arc::new(Vault::open(path, VaultConfig::default()).expect("open vault"));
    let report = |line: String| {
        let mut out = std::io::stdout().lock();
        writeln!(out, "{line}").expect("report");
        out.flush().expect("flush report");
    };
    for write in 0..CRASH_COMMITTED {
        put_rows(vault.batch(), &rows(0, write))
            .commit()
            .expect("sequential write commits");
        report(format!("COMMITTED {write}"));
    }
    vault.store.group_commit.hooks.on_before_commit(move |ran| {
        if ran >= CRASH_GROUP {
            report("STAGED".to_owned());
            std::process::abort();
        }
    });
    vault
        .store
        .group_commit
        .hooks
        .hold_next_group_until(CRASH_GROUP);
    let writers: Vec<_> = (1..=CRASH_GROUP)
        .map(|writer| {
            let vault = Arc::clone(&vault);
            let thread = std::thread::spawn(move || {
                put_rows(vault.batch(), &rows(writer, 0)).commit()?;
                // Never reached: the process dies before the group commits.
                println!("COMMITTED-IN-GROUP {writer}");
                Ok::<(), Error>(())
            });
            if writer == 1 {
                wait_until_leading(&vault);
            }
            thread
        })
        .collect();
    for writer in writers {
        let _ = writer.join();
    }
    panic!("the group committed instead of crashing");
}

/// Crash-point: kill the process mid-group. Every write reported committed
/// survives the reopen whole, and no write of the open group appears at all.
#[test]
fn crash_mid_group_keeps_reported_writes_and_no_part_of_the_open_group() {
    let dir = tempfile::tempdir().expect("tempdir");
    let child = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "store::group_commit::tests::group_commit_crash_child",
            "--nocapture",
        ])
        .env(CRASH_PATH, dir.path())
        .output()
        .expect("run crash child");
    let stdout = String::from_utf8_lossy(&child.stdout);
    assert!(!child.status.success(), "the child must die mid-group");
    assert!(
        stdout.contains("STAGED"),
        "child never reached the crash point:\n{stdout}"
    );
    assert!(!stdout.contains("COMMITTED-IN-GROUP"), "{stdout}");
    let reported: Vec<usize> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("COMMITTED "))
        .map(|write| write.trim().parse().expect("write number"))
        .collect();
    assert_eq!(reported, (0..CRASH_COMMITTED).collect::<Vec<_>>());

    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("reopen after crash");
    for write in reported {
        assert_eq!(
            present(&vault, &rows(0, write)),
            3,
            "reported write {write}"
        );
    }
    for writer in 1..=CRASH_GROUP {
        assert_eq!(
            present(&vault, &rows(writer, 0)),
            0,
            "open-group write {writer}"
        );
    }
}
