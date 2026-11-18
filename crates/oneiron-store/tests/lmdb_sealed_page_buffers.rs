//! FIX row LMDB-MASTER3-UPSTREAM-FIXES-AUDIT (upstream ITS#10520): a sealed environment frees the
//! page buffers it decrypted into, when it closes and when a page fails to open, and unmaps the
//! chunk of a page that failed to open.
//!
//! A sealed environment (`EnvOpenOptions::page_key`) decrypts each chunk of pages it reads into a
//! heap buffer (16 pages: 64 KiB on 4 KiB pages) and keeps the chunk in its page cache until the
//! environment closes. Before upstream ITS#10520 (`crates/heed/PROVENANCE.md`, "Upstream LMDB
//! hardening"), closing unmapped every cached chunk but never freed its buffer, so each close
//! leaked one buffer per chunk read. A chunk whose page failed to open leaked its buffer as well:
//! heed reads one page to check the page key, so each open under a wrong key leaked one. That
//! chunk's mapping stayed too, in no cache that could unmap it; the fork unmaps it (`ONEIRON FORK
//! (LMDB audit)` in `mdb_rpage_get`).
//!
//! The test counts the C heap through glibc's `mallinfo2` and the process's mappings through
//! `/proc/self/maps`, so it runs on Linux with glibc only.
//!
//! `cargo test --locked -p oneiron-store --test lmdb_sealed_page_buffers` (default features, as
//! `lmdb_page_split.rs`).
#![cfg(all(target_os = "linux", target_env = "gnu"))]

use std::error::Error;
use std::path::Path;

use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions};

const PAGE_KEY: [u8; 32] = [0x2c; 32];
const WRONG_PAGE_KEY: [u8; 32] = [0x2d; 32];
/// Rows of `ROW_LEN` bytes: about 2 MB, so a full read caches dozens of chunks.
const ROWS: u16 = 2048;
const ROW_LEN: usize = 1000;
/// Close cycles measured; one more before them warms the allocator.
const CLOSE_CYCLES: usize = 12;
/// Opens under a wrong key measured, after one that warms the allocator.
const WRONG_KEY_OPENS: usize = 64;
/// Heap growth allowed over all measured cycles of one arm. The leak is one 64 KiB buffer per
/// chunk: over 30 per close cycle here, and one per wrong-key open.
const GROWTH_BOUND: usize = 1 << 20;
/// New mappings allowed over all measured wrong-key opens. The leak is one per open.
const MAPPING_GROWTH_BOUND: usize = 16;

/// glibc's `struct mallinfo2` (glibc 2.33 and later): ten `size_t` fields.
#[repr(C)]
struct MallInfo2([usize; 10]);
/// `hblkhd`: bytes in blocks allocated with `mmap`.
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

/// Memory mappings of this process: one line each in `/proc/self/maps`.
fn mappings() -> std::io::Result<usize> {
    Ok(std::fs::read_to_string("/proc/self/maps")?.lines().count())
}

type Rows = Database<Bytes, Bytes>;

fn open_sealed_env(dir: &Path, page_key: &[u8; 32]) -> heed::Result<Env> {
    let mut options = EnvOpenOptions::new();
    options.map_size(64 << 20).max_dbs(4).page_key(page_key);
    // SAFETY: `dir` is a temporary directory on a local filesystem that only this test opens,
    // one environment at a time; the map size never changes while an environment is open.
    unsafe { options.open(dir) }
}

fn write_rows_and_close(dir: &Path) -> heed::Result<()> {
    let env = open_sealed_env(dir, &PAGE_KEY)?;
    let mut wtxn = env.write_txn()?;
    let rows: Rows = env.create_database(&mut wtxn, Some("rows"))?;
    for row in 0..ROWS {
        rows.put(&mut wtxn, &row.to_be_bytes(), &[0x5a; ROW_LEN])?;
    }
    wtxn.commit()?;
    env.prepare_for_closing().wait();
    Ok(())
}

/// Opens the environment, reads every row (so every chunk lands in its page cache), closes it,
/// and returns the bytes read.
fn read_every_row_and_close(dir: &Path) -> Result<usize, Box<dyn Error>> {
    let env = open_sealed_env(dir, &PAGE_KEY)?;
    let rtxn = env.read_txn()?;
    let rows: Rows = env
        .open_database(&rtxn, Some("rows"))?
        .ok_or("the rows database is missing")?;
    let mut read = 0;
    for row in rows.iter(&rtxn)? {
        read += row?.1.len();
    }
    drop(rtxn);
    env.prepare_for_closing().wait();
    Ok(read)
}

/// Heap growth over `CLOSE_CYCLES` full reads, each followed by a close.
fn growth_over_close_cycles(dir: &Path) -> Result<usize, Box<dyn Error>> {
    read_every_row_and_close(dir)?;
    let before = heap_in_use();
    for _ in 0..CLOSE_CYCLES {
        let read = read_every_row_and_close(dir)?;
        assert_eq!(read, usize::from(ROWS) * ROW_LEN, "every row reads back");
    }
    Ok(heap_in_use().saturating_sub(before))
}

/// Heap growth and new mappings over `WRONG_KEY_OPENS` opens under a wrong page key, each of
/// which must refuse.
fn growth_over_wrong_key_opens(dir: &Path) -> std::io::Result<(usize, usize)> {
    let wrong_key_refuses = || open_sealed_env(dir, &WRONG_PAGE_KEY).is_err();
    assert!(wrong_key_refuses(), "a wrong page key refuses");
    let (heap_before, mappings_before) = (heap_in_use(), mappings()?);
    for _ in 0..WRONG_KEY_OPENS {
        assert!(wrong_key_refuses(), "a wrong page key refuses");
    }
    Ok((
        heap_in_use().saturating_sub(heap_before),
        mappings()?.saturating_sub(mappings_before),
    ))
}

#[test]
fn a_sealed_environment_frees_its_page_buffers_on_close_and_on_a_page_that_fails_to_open()
-> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    write_rows_and_close(dir.path())?;
    let close_growth = growth_over_close_cycles(dir.path())?;
    let (wrong_key_growth, wrong_key_mappings) = growth_over_wrong_key_opens(dir.path())?;
    assert!(
        close_growth < GROWTH_BOUND
            && wrong_key_growth < GROWTH_BOUND
            && wrong_key_mappings < MAPPING_GROWTH_BOUND,
        "the C heap grew by {close_growth} bytes over {CLOSE_CYCLES} read-and-close cycles and \
         by {wrong_key_growth} bytes over {WRONG_KEY_OPENS} opens under a wrong page key \
         (bound {GROWTH_BOUND} bytes each); those opens left {wrong_key_mappings} new mappings \
         (bound {MAPPING_GROWTH_BOUND})"
    );
    Ok(())
}
