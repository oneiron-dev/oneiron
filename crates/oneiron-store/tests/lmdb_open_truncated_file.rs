//! FIX row LMDB-MASTER3-UPSTREAM-FIXES-AUDIT (upstream ITS#9291): an environment whose data file
//! was truncated refuses to open.
//!
//! A data file that keeps its two meta pages but lost the pages after them (a torn copy, a
//! partial restore) passes every check of the meta pages. Before upstream ITS#9291
//! (`crates/heed/PROVENANCE.md`, "Upstream LMDB hardening"), `mdb_env_open2` then opened it: the
//! main tree's root pointed past the end of the file, and the first read of that page faulted the
//! process (SIGBUS). With the check, the open answers `MDB_CORRUPTED` (the page counts exceed the
//! file) or `MDB_PAGE_NOTFOUND` (a root lies past its end), and nothing maps a missing page.
//!
//! `cargo test --locked -p oneiron-store --test lmdb_open_truncated_file` (default features, as
//! `lmdb_page_split.rs`).

use std::error::Error;
use std::fs::OpenOptions;
use std::path::Path;

use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions, MdbError};

/// Write transactions before the file is truncated: each one rewrites the main tree's root.
const COMMITS: u8 = 8;
/// Rows per transaction, each `ROW_LEN` bytes.
const ROWS_PER_COMMIT: u8 = 64;
const ROW_LEN: usize = 256;
/// The meta pages every data file starts with: the truncated file keeps exactly these.
const META_PAGES: u64 = 2;

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
    OpenOptions::new()
        .write(true)
        .open(&data_file)?
        .set_len(META_PAGES * page_size)?;

    match open_env(dir.path()) {
        Err(heed::Error::Mdb(MdbError::Corrupted | MdbError::PageNotFound)) => Ok(()),
        Err(other) => Err(format!("the truncated file refused with another error: {other}").into()),
        Ok(env) => {
            // Close without a read: every page past the meta pages is gone from the file.
            env.prepare_for_closing().wait();
            Err(format!(
                "a data file truncated from {written_len} to {} bytes opened",
                META_PAGES * page_size
            )
            .into())
        }
    }
}
