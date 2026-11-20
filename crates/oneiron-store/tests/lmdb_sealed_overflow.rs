//! FIX row LMDB-MASTER3-UPSTREAM-FIXES-AUDIT (upstream ITS#10519): a sealed environment reads back
//! every value it stored on overflow pages whole, whatever its length.
//!
//! A sealed environment (`EnvOpenOptions::page_key`) keeps a 40-byte authentication area (the
//! nonce and the tag) in the last bytes of each page or overflow run. Before upstream ITS#10519
//! (`crates/heed/PROVENANCE.md`, "ITS#10519: overflow runs count the authentication area"),
//! `OVPAGES` counted an overflow run without that area. When a value's last byte fell into it,
//! the run got one page too few: the seal took the run's last 40 bytes for the tag, so those
//! value bytes were never written, and the commit still succeeded. Each later read returned
//! other bytes in their place. On a 4 KiB page that is every value of 4033-4072 bytes, and the
//! same 40 lengths below each later page end.
//!
//! Two write paths counted the run: a new value (`mdb_node_add`) and a value overwritten in the
//! transaction that wrote it, which reuses its run when the count says it fits (`mdb_cursor_put`).
//!
//! `cargo test --locked -p oneiron-store --test lmdb_sealed_overflow` (default features, as
//! `lmdb_page_split.rs`).

use std::error::Error;
use std::path::Path;

use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions};

/// The page key of the test environment.
const PAGE_KEY: [u8; 32] = [0x2c; 32];
/// Value lengths tried below each page end: more than the 40-byte authentication area plus the
/// page header, so each window also holds lengths that fit on either count.
const BELOW_PAGE_END: usize = 104;
/// Value lengths tried past each page end.
const PAST_PAGE_END: usize = 8;
/// Overflow runs of one and of two pages.
const RUN_PAGES: [usize; 2] = [1, 2];

type Rows = Database<Bytes, Bytes>;

fn open_sealed_env(dir: &Path) -> heed::Result<Env> {
    let mut options = EnvOpenOptions::new();
    options.map_size(64 << 20).max_dbs(4).page_key(&PAGE_KEY);
    // SAFETY: `dir` is a fresh temporary directory on a local filesystem that only this test
    // opens, once; the map size never changes while the environment is open.
    unsafe { options.open(dir) }
}

/// The value lengths of every window: from `BELOW_PAGE_END` bytes under the end of an overflow
/// run of `RUN_PAGES` pages to `PAST_PAGE_END` bytes past it.
fn value_lens(page_size: usize) -> Vec<usize> {
    RUN_PAGES
        .iter()
        .flat_map(|pages| {
            let run_end = pages * page_size;
            run_end - BELOW_PAGE_END..=run_end + PAST_PAGE_END
        })
        .collect()
}

/// A value whose bytes differ along its length and from one length to the next, none of them
/// zero, so a byte read from anywhere else shows.
fn value(len: usize) -> Vec<u8> {
    (0..len)
        .map(|at| u8::try_from((at * 7 + len) % 251 + 1).unwrap_or(1))
        .collect()
}

fn key(path: &str, len: usize) -> Vec<u8> {
    format!("{path}-{len:06}").into_bytes()
}

/// Reads each value back in a fresh read transaction and names every length whose value came
/// back different, with the first offset that differs.
fn misread_lens(env: &Env, rows: Rows, path: &str, lens: &[usize]) -> heed::Result<Vec<String>> {
    let rtxn = env.read_txn()?;
    let mut misread = Vec::new();
    for &len in lens {
        let want = value(len);
        match rows.get(&rtxn, &key(path, len))? {
            Some(got) if got == want.as_slice() => {}
            Some(got) => {
                let at = got.iter().zip(&want).position(|(g, w)| g != w);
                misread.push(format!(
                    "{len} (read {} bytes, first wrong byte at {at:?})",
                    got.len()
                ));
            }
            None => misread.push(format!("{len} (missing)")),
        }
    }
    Ok(misread)
}

#[test]
fn a_sealed_value_on_overflow_pages_reads_back_whole_at_every_length_near_a_page_end()
-> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let env = open_sealed_env(dir.path())?;
    let page_size = usize::try_from(env.page_size()?)?;
    let lens = value_lens(page_size);
    let mut wtxn = env.write_txn()?;
    let rows: Rows = env.create_database(&mut wtxn, Some("rows"))?;
    for &len in &lens {
        rows.put(&mut wtxn, &key("new", len), &value(len))?;
    }
    wtxn.commit()?;

    // Overwrite in the writing transaction: each first value takes an overflow run of the same
    // page count as the window's lengths (more than half a page, so it never fits in a leaf),
    // and the second put reuses that run whenever the count says the new value fits.
    let mut wtxn = env.write_txn()?;
    for &len in &lens {
        let first_len = (len / page_size) * page_size + page_size / 2 + 64;
        rows.put(&mut wtxn, &key("overwritten", len), &value(first_len))?;
        rows.put(&mut wtxn, &key("overwritten", len), &value(len))?;
    }
    wtxn.commit()?;

    let new = misread_lens(&env, rows, "new", &lens)?;
    let overwritten = misread_lens(&env, rows, "overwritten", &lens)?;
    assert!(
        new.is_empty() && overwritten.is_empty(),
        "sealed values read back wrong on a {page_size}-byte page \
         (new values: {new:?}; values overwritten in their transaction: {overwritten:?})"
    );
    Ok(())
}
