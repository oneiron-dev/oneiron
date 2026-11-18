//! FIX row TRAP-REGISTER-WAIT-PAGE-FULL: a put that splits a leaf of rows whose key and data are
//! both odd-sized never fails with `MDB_PAGE_FULL`.
//!
//! mdb.master3 pads a leaf node's key and its data to even lengths separately (upstream ITS#8988).
//! Before upstream ITS#10551 (`crates/heed/PROVENANCE.md`, "PAGE-FULL cause"), `mdb_page_split`
//! chose its split point with the older count, 2 bytes short for each such node. The half that
//! took the new row could then pass the page, and the put answered `MDB_PAGE_FULL`.
//! `vault_meta` keys are 33 bytes long, as here.
//!
//! The leaf holds three rows (data 1001, 1001 and 100 bytes); a row with a smaller key splits it.
//! Before the fix, data lengths 1937-1940 of that row failed on a 4 KiB page.
//!
//! `cargo test --locked -p oneiron-store --test lmdb_page_split` (default features: a store-alone
//! `--all-features` build fails on main, FIX STORE-ALONE-NEEDS-BASE-SYNC).

use std::error::Error;
use std::ops::RangeInclusive;
use std::path::Path;

use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions};

/// The key length of the `vault_meta` rows that failed: odd, so its padding counts.
const KEY_LEN: usize = 33;
/// The leaf before the split: the first key byte and the data length of each row, in key order.
const LEAF_ROWS: [(u8, usize); 3] = [(0x10, 1001), (0x20, 1001), (0x30, 100)];
/// The splitting row's key sorts before every leaf row, so the row lands in the left half.
const SPLITTING_KEY_BYTE: u8 = 0x01;
/// Data lengths of the splitting row: a window around the page boundary of a 4 KiB page.
const SPLITTING_DATA_LENS: RangeInclusive<usize> = 1900..=1992;

type Rows = Database<Bytes, Bytes>;

fn open_env(dir: &Path) -> heed::Result<Env> {
    let mut options = EnvOpenOptions::new();
    options.map_size(64 << 20).max_dbs(4);
    // SAFETY: `dir` is a fresh temporary directory on a local filesystem that only this test
    // opens, once; the map size never changes while the environment is open.
    unsafe { options.open(dir) }
}

fn put_row(env: &Env, rows: Rows, key_byte: u8, data_len: usize) -> heed::Result<()> {
    let mut wtxn = env.write_txn()?;
    rows.put(&mut wtxn, &[key_byte; KEY_LEN], &vec![0x5a; data_len])?;
    wtxn.commit()
}

/// Builds the one-leaf tree in a fresh environment, then puts the splitting row and returns
/// that put's result.
fn split_the_leaf(splitting_data_len: usize) -> Result<heed::Result<()>, Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let env = open_env(dir.path())?;
    assert_eq!(
        env.page_size()?,
        4096,
        "the data-length window is for 4 KiB pages"
    );
    let mut wtxn = env.write_txn()?;
    let rows: Rows = env.create_database(&mut wtxn, Some("vault_meta"))?;
    wtxn.commit()?;
    for (key_byte, data_len) in LEAF_ROWS {
        put_row(&env, rows, key_byte, data_len)?;
    }
    let rtxn = env.read_txn()?;
    let stat = rows.stat(&rtxn)?;
    drop(rtxn);
    assert_eq!(
        (stat.depth, stat.leaf_pages),
        (1, 1),
        "the three rows share one leaf before the split"
    );
    Ok(put_row(&env, rows, SPLITTING_KEY_BYTE, splitting_data_len))
}

#[test]
fn a_put_that_splits_a_leaf_of_odd_sized_rows_never_fails_with_page_full()
-> Result<(), Box<dyn Error>> {
    let mut failed = Vec::new();
    for data_len in SPLITTING_DATA_LENS {
        if let Err(error) = split_the_leaf(data_len)? {
            failed.push(format!("{data_len}: {error}"));
        }
    }
    assert!(
        failed.is_empty(),
        "puts that failed (splitting row's data length: error): {failed:?}"
    );
    Ok(())
}
