//! FIX row LMDB-MASTER3-UPSTREAM-FIXES-AUDIT (upstream ITS#9291 and its `ONEIRON FORK (LMDB
//! audit)` hunks): an environment whose data file is damaged refuses to open, and the open never
//! faults the process.
//!
//! A data file that lost its last pages (a torn copy, a partial restore) passes every check of
//! the meta pages. Before upstream ITS#9291 (`crates/heed/PROVENANCE.md`, "Upstream LMDB
//! hardening"), `mdb_env_open2` then opened it, and the first read of a missing page faulted the
//! process (SIGBUS). The check compares the FREE and MAIN roots and their page counts with the
//! file's length: the open answers `MDB_CORRUPTED` (the counts exceed the file) or
//! `MDB_PAGE_NOTFOUND` (a root lies at or past its end). The fork makes a root that starts exactly
//! at the end count as missing, and refuses a meta page size `mdb_env_set_pagesize` would refuse
//! (`MDB_INVALID`) before the check divides by it. It is upstream's quick check, not a walk: a file
//! cut below a named database's page only, with both roots and the counts inside it, still opens.
//!
//! `cargo test --locked -p oneiron-store --test lmdb_open_damaged_file` (default features, as
//! `lmdb_page_split.rs`).

use std::error::Error;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions, MdbError};

/// Write transactions before the file is truncated: each one rewrites the main tree's root.
const COMMITS: u8 = 8;
/// Rows per transaction, each `ROW_LEN` bytes.
const ROWS_PER_COMMIT: u8 = 64;
const ROW_LEN: usize = 256;
/// The meta pages every data file starts with.
const META_PAGES: u64 = 2;
/// Byte offsets in a meta page of a 64-bit build: a 24-byte page header, then `MDB_meta`, whose
/// `mm_magic` comes first and whose `mm_psize` (the FREE record's `md_pad`) sits 24 bytes in.
const META_MAGIC_AT: u64 = 24;
const META_PAGE_SIZE_AT: u64 = 48;
const MDB_MAGIC: u32 = 0xBEEF_C0DE;

type Rows = Database<Bytes, Bytes>;

fn open_env(dir: &Path) -> heed::Result<Env> {
    let mut options = EnvOpenOptions::new();
    options.map_size(64 << 20).max_dbs(4);
    // SAFETY: `dir` is a temporary directory on a local filesystem that only this test opens,
    // one environment at a time; the map size never changes while an environment is open.
    unsafe { options.open(dir) }
}

/// Writes `COMMITS` transactions of rows into a fresh environment, closes it and returns its page
/// size.
fn write_rows_and_close(dir: &Path) -> heed::Result<u64> {
    let env = open_env(dir)?;
    let page_size = u64::from(env.page_size()?);
    let mut wtxn = env.write_txn()?;
    let rows: Rows = env.create_database(&mut wtxn, Some("rows"))?;
    wtxn.commit()?;
    for commit in 0..COMMITS {
        let mut wtxn = env.write_txn()?;
        for row in 0..ROWS_PER_COMMIT {
            rows.put(&mut wtxn, &[commit, row], &[0x5a; ROW_LEN])?;
        }
        wtxn.commit()?;
    }
    env.prepare_for_closing().wait();
    Ok(page_size)
}

/// Puts one row into the main (unnamed) database, overwrites it in a second transaction, closes
/// the environment and returns its page size. The overwrite moves the main tree's leaf to page 3
/// and records the freed page 2 in a new FREE tree leaf at page 4, the file's last page.
fn write_one_row_twice_and_close(dir: &Path) -> heed::Result<u64> {
    let env = open_env(dir)?;
    let page_size = u64::from(env.page_size()?);
    for value in [b"value-one", b"value-two"] {
        let mut wtxn = env.write_txn()?;
        let main: Rows = env.create_database(&mut wtxn, None)?;
        main.put(&mut wtxn, b"row", value)?;
        wtxn.commit()?;
    }
    env.prepare_for_closing().wait();
    Ok(page_size)
}

/// Opens the environment and returns the error the open answered. An open that succeeds is
/// closed at once, without a read (the pages it would read are gone), and fails the test.
fn open_error(dir: &Path) -> Result<heed::Error, Box<dyn Error>> {
    match open_env(dir) {
        Err(error) => Ok(error),
        Ok(env) => {
            env.prepare_for_closing().wait();
            Err("the damaged data file opened".into())
        }
    }
}

fn truncate(data_file: &Path, len: u64) -> std::io::Result<()> {
    OpenOptions::new().write(true).open(data_file)?.set_len(len)
}

#[test]
fn an_environment_whose_data_file_is_truncated_after_its_meta_pages_refuses_to_open()
-> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let page_size = write_rows_and_close(dir.path())?;
    let data_file = dir.path().join("data.mdb");
    let written_len = std::fs::metadata(&data_file)?.len();
    assert!(
        written_len > 4 * META_PAGES * page_size,
        "the rows take pages past the meta pages ({written_len} bytes)"
    );
    truncate(&data_file, META_PAGES * page_size)?;
    let error = open_error(dir.path())?;
    assert!(
        matches!(
            error,
            heed::Error::Mdb(MdbError::Corrupted | MdbError::PageNotFound)
        ),
        "a data file truncated from {written_len} bytes to its meta pages refused with another \
         error: {error}"
    );
    Ok(())
}

#[test]
fn an_environment_whose_free_root_starts_where_its_truncated_data_file_ends_refuses_to_open()
-> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let page_size = write_one_row_twice_and_close(dir.path())?;
    let data_file = dir.path().join("data.mdb");
    let written_len = std::fs::metadata(&data_file)?.len();
    assert_eq!(
        written_len,
        5 * page_size,
        "two meta pages, the first leaf, the moved leaf and the FREE leaf"
    );
    truncate(&data_file, written_len - page_size)?;
    let error = open_error(dir.path())?;
    assert!(
        matches!(error, heed::Error::Mdb(MdbError::PageNotFound)),
        "a data file cut before its FREE root's page refused with another error: {error}"
    );
    Ok(())
}

/// Sets `mm_psize` to zero in both meta pages, after checking that each holds the magic and the
/// page size at the offsets this build lays them out at.
fn zero_the_page_size_of_both_meta_pages(data_file: &Path, page_size: u64) -> std::io::Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(data_file)?;
    let mut word = [0; 4];
    for meta in 0..META_PAGES {
        let base = meta * page_size;
        file.seek(SeekFrom::Start(base + META_MAGIC_AT))?;
        file.read_exact(&mut word)?;
        assert_eq!(
            u32::from_le_bytes(word),
            MDB_MAGIC,
            "meta {meta} starts with the magic"
        );
        file.seek(SeekFrom::Start(base + META_PAGE_SIZE_AT))?;
        file.read_exact(&mut word)?;
        assert_eq!(
            u64::from(u32::from_le_bytes(word)),
            page_size,
            "meta {meta} holds the page size there"
        );
        file.seek(SeekFrom::Start(base + META_PAGE_SIZE_AT))?;
        file.write_all(&[0; 4])?;
    }
    file.sync_all()
}

#[test]
fn an_environment_whose_meta_pages_hold_a_zero_page_size_refuses_to_open()
-> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let page_size = write_one_row_twice_and_close(dir.path())?;
    let data_file = dir.path().join("data.mdb");
    zero_the_page_size_of_both_meta_pages(&data_file, page_size)?;
    let error = open_error(dir.path())?;
    assert!(
        matches!(error, heed::Error::Mdb(MdbError::Invalid)),
        "meta pages with a zero page size refused with another error: {error}"
    );
    Ok(())
}
