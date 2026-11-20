//! FIX row LMDB-TXN-BEGIN-FAILURE-WRONG-FREE (`ONEIRON FORK (begin failure)` in `mdb_txn_begin`):
//! a sealed read transaction that fails to begin frees the chunk table it was given.
//!
//! In a sealed environment (`EnvOpenOptions::page_key`, LMDB's `MDB_REMAP_CHUNKS`) each top-level
//! read transaction gets its own table of the page chunks it holds: 4096 entries, 128 KiB. Upstream
//! ITS#10342 (in our base; `crates/heed/PROVENANCE.md`, "Transaction begin failure") changed
//! `mdb_txn_begin`'s failure exit to free a nested write transaction's dirty list, which
//! `mdb_txn_end` had already freed, in place of that table. So each read begin that failed leaked
//! the table: a full reader table (`MDB_READERS_FULL`), a stale reader slot (`MDB_BAD_RSLOT`), an
//! environment after a fatal error (`MDB_PANIC`), or a map another process grew
//! (`MDB_MAP_RESIZED`).
//!
//! The test gives the environment one reader slot (`MDB_NOTLS`, so a slot belongs to a transaction,
//! not to a thread), holds it with one read transaction, and counts the C heap through glibc's
//! `mallinfo2` over read begins that fail with `MDB_READERS_FULL`. It runs on Linux with glibc only.
//!
//! `cargo test --locked -p oneiron-store --test lmdb_sealed_failed_read_begin` (default features,
//! as `lmdb_sealed_page_buffers.rs`).
#![cfg(all(target_os = "linux", target_env = "gnu"))]

use std::error::Error;
use std::path::Path;

use heed::types::Bytes;
use heed::{Database, Env, EnvFlags, EnvOpenOptions, MdbError};

const PAGE_KEY: [u8; 32] = [0x3c; 32];
/// Failed read begins measured, after one that warms the allocator.
const FAILED_BEGINS: usize = 64;
/// Heap growth allowed over all measured failed begins. The leak is one 128 KiB chunk table per
/// failed begin: 8 MiB over the measured ones.
const GROWTH_BOUND: usize = 1 << 20;

/// glibc's `struct mallinfo2` (glibc 2.33 and later): ten `size_t` fields.
#[repr(C)]
struct MallInfo2([usize; 10]);
/// `hblkhd`: bytes in blocks allocated with `mmap` (glibc maps a 128 KiB block by itself).
const HBLKHD: usize = 4;
/// `uordblks`: bytes in allocated blocks of the heap arenas.
const UORDBLKS: usize = 7;

// SAFETY: glibc 2.33 and later define `mallinfo2` with this signature: no argument, the struct
// returned by value. It only reads the allocator's counters.
unsafe extern "C" {
    safe fn mallinfo2() -> MallInfo2;
}

/// Bytes the C heap has handed out and not taken back.
fn heap_in_use() -> usize {
    let info = mallinfo2();
    info.0[HBLKHD] + info.0[UORDBLKS]
}

fn open_sealed_env_with_one_reader_slot(dir: &Path) -> heed::Result<Env> {
    let mut options = EnvOpenOptions::new();
    options
        .map_size(64 << 20)
        .max_dbs(4)
        .max_readers(1)
        .page_key(&PAGE_KEY);
    // SAFETY: `NO_TLS` only ties each read transaction's reader slot to the transaction instead of
    // its thread; this test keeps every transaction on one thread. `dir` is a temporary directory
    // on a local filesystem that only this test opens, and the map size never changes while the
    // environment is open.
    unsafe {
        options.flags(EnvFlags::NO_TLS);
        options.open(dir)
    }
}

fn read_begin_finds_the_reader_table_full(env: &Env) -> bool {
    matches!(env.read_txn(), Err(heed::Error::Mdb(MdbError::ReadersFull)))
}

#[test]
fn a_sealed_read_transaction_that_fails_to_begin_frees_its_chunk_table()
-> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let env = open_sealed_env_with_one_reader_slot(dir.path())?;
    let mut wtxn = env.write_txn()?;
    let rows: Database<Bytes, Bytes> = env.create_database(&mut wtxn, Some("rows"))?;
    rows.put(&mut wtxn, b"row", b"value")?;
    wtxn.commit()?;

    let holder = env.read_txn()?;
    assert!(
        read_begin_finds_the_reader_table_full(&env),
        "a second read transaction finds the only reader slot taken"
    );
    let before = heap_in_use();
    for _ in 0..FAILED_BEGINS {
        assert!(
            read_begin_finds_the_reader_table_full(&env),
            "a second read transaction finds the only reader slot taken"
        );
    }
    let growth = heap_in_use().saturating_sub(before);
    assert_eq!(
        rows.get(&holder, b"row")?,
        Some(&b"value"[..]),
        "the read transaction that holds the slot still reads"
    );
    drop(holder);
    let after = env.read_txn()?;
    assert_eq!(
        rows.get(&after, b"row")?,
        Some(&b"value"[..]),
        "a read transaction begins once the slot is free again"
    );
    drop(after);
    assert!(
        growth < GROWTH_BOUND,
        "the C heap grew by {growth} bytes over {FAILED_BEGINS} read begins that failed with \
         MDB_READERS_FULL (bound {GROWTH_BOUND} bytes)"
    );
    env.prepare_for_closing().wait();
    Ok(())
}
