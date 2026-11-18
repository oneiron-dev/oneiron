//! FIX rows LMDB-MASTER3-UPSTREAM-FIXES-AUDIT (upstream ITS#9291 and its `ONEIRON FORK (LMDB
//! audit)` hunks), LMDB-TRUNCATED-NAMED-DB-PAGE-SIGBUS (`ONEIRON FORK (page bound)`) and
//! LMDB-IGNORED-PAGE-FETCH-RC (`ONEIRON FORK (fetch rc)`): an environment whose data file is
//! damaged refuses to open or answers the damage's own error (`MDB_CORRUPTED`, or
//! `MDB_CRYPTO_FAIL` for an altered sealed page) on the call that reaches it, and never faults the
//! process.
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
//! The page bound (`crates/heed/PROVENANCE.md`, "Page bound") covers that file: `mdb_page_get`
//! checks each page against the file's length before it reads the page through the map, so the
//! read of a named database's leaf or of an overflow run the cut removed answers `MDB_CORRUPTED`.
//! Before it, that read faulted the process (SIGBUS), plain and sealed alike: a sealed
//! environment maps its chunks from the same file.
//!
//! The fetch rc fork (`crates/heed/PROVENANCE.md`, "Fetch rc") covers the calls of a later
//! transaction. Each transaction starts with a named database's record marked stale, and its
//! first call on the database fetches the root while it sets its cursor up. Upstream dropped that
//! fetch's error and marked the transaction failed, so a get, a cursor, a put or a delete
//! answered `MDB_BAD_TXN` and a count answered the record's count with success. Each now answers
//! the fetch's own error.
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
/// The page key of the sealed test environments.
const PAGE_KEY: [u8; 32] = [0x2c; 32];
/// The named database the page-bound tests write their one row into.
const NAMED: &str = "rows";
const NAMED_KEY: &[u8] = b"row";
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

fn open_sealed_env(dir: &Path) -> heed::Result<Env> {
    let mut options = EnvOpenOptions::new();
    options.map_size(64 << 20).max_dbs(4).page_key(&PAGE_KEY);
    // SAFETY: as `open_env`.
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

/// The value of the page-bound tests' one row: `len` bytes that differ along its length.
fn named_value(len: usize) -> Vec<u8> {
    (0..len)
        .map(|at| u8::try_from(at % 251 + 1).unwrap_or(1))
        .collect()
}

/// In one transaction of a fresh environment, creates the named database and puts its one row,
/// then closes the environment and returns the data file's length and its page size. Creating
/// the database puts its record into the main tree's leaf (page 2); the row goes into the named
/// database's leaf (page 3) and, when it is larger than a page, into an overflow run after it.
/// The commit allocates no later page: the main leaf is already dirty and nothing was freed.
fn write_one_named_row_and_close(
    dir: &Path,
    open: fn(&Path) -> heed::Result<Env>,
    value: &[u8],
) -> heed::Result<(u64, u64)> {
    let env = open(dir)?;
    let page_size = u64::from(env.page_size()?);
    let mut wtxn = env.write_txn()?;
    let rows: Rows = env.create_database(&mut wtxn, Some(NAMED))?;
    rows.put(&mut wtxn, NAMED_KEY, value)?;
    wtxn.commit()?;
    env.prepare_for_closing().wait();
    let written_len = std::fs::metadata(dir.join("data.mdb"))?.len();
    Ok((written_len, page_size))
}

/// Writes the one named row, cuts the data file's last page, reopens the environment (upstream's
/// quick check passes the file) and reads the row back. Returns what the read answered: `Ok`
/// with whether the value came back whole, or the read's error. Before the page bound, the read
/// faulted the process instead.
fn read_named_row_after_cutting_the_last_page(
    open: fn(&Path) -> heed::Result<Env>,
    value_len: usize,
    file_pages: u64,
) -> Result<heed::Result<bool>, Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let value = named_value(value_len);
    let (written_len, page_size) = write_one_named_row_and_close(dir.path(), open, &value)?;
    assert_eq!(
        written_len,
        file_pages * page_size,
        "two meta pages, the main leaf, the named leaf and the value's overflow pages"
    );
    truncate(&dir.path().join("data.mdb"), written_len - page_size)?;
    let env = open(dir.path())?;
    let rtxn = env.read_txn()?;
    let rows: Rows = env
        .open_database(&rtxn, Some(NAMED))?
        .ok_or("the named database's record is in the main leaf, inside the cut file")?;
    let read = rows
        .get(&rtxn, NAMED_KEY)
        .map(|got| got.is_some_and(|got| got == value.as_slice()));
    drop(rtxn);
    env.prepare_for_closing().wait();
    Ok(read)
}

fn assert_corrupted(read: heed::Result<bool>, what: &str) {
    assert!(
        matches!(read, Err(heed::Error::Mdb(MdbError::Corrupted))),
        "the read of {what} the cut removed answered {read:?}, not MDB_CORRUPTED"
    );
}

/// A row small enough to stay on its leaf.
const LEAF_ROW_LEN: usize = 9;
/// A row of three pages' bytes: with the overflow page header (and a sealed page's
/// authentication area) its run takes four pages.
const RUN_ROW_PAGES: usize = 3;
/// Two meta pages, the main leaf and the named leaf; plus a four-page overflow run.
const LEAF_FILE_PAGES: u64 = 4;
const RUN_FILE_PAGES: u64 = 8;

#[test]
fn a_read_of_a_named_database_leaf_its_truncated_data_file_lost_answers_corrupted()
-> Result<(), Box<dyn Error>> {
    let read = read_named_row_after_cutting_the_last_page(open_env, LEAF_ROW_LEN, LEAF_FILE_PAGES)?;
    assert_corrupted(read, "a named database's leaf");
    Ok(())
}

#[test]
fn a_read_of_a_value_whose_overflow_run_its_truncated_data_file_cut_answers_corrupted()
-> Result<(), Box<dyn Error>> {
    let page_size = usize::try_from(page_size_of(open_env)?)?;
    let read = read_named_row_after_cutting_the_last_page(
        open_env,
        RUN_ROW_PAGES * page_size,
        RUN_FILE_PAGES,
    )?;
    assert_corrupted(read, "an overflow run's last page");
    Ok(())
}

#[test]
fn a_sealed_read_of_a_named_database_leaf_its_truncated_data_file_lost_answers_corrupted()
-> Result<(), Box<dyn Error>> {
    let read =
        read_named_row_after_cutting_the_last_page(open_sealed_env, LEAF_ROW_LEN, LEAF_FILE_PAGES)?;
    assert_corrupted(read, "a sealed named database's leaf");
    Ok(())
}

#[test]
fn a_sealed_read_of_a_value_whose_overflow_run_its_truncated_data_file_cut_answers_corrupted()
-> Result<(), Box<dyn Error>> {
    let page_size = usize::try_from(page_size_of(open_sealed_env)?)?;
    let read = read_named_row_after_cutting_the_last_page(
        open_sealed_env,
        RUN_ROW_PAGES * page_size,
        RUN_FILE_PAGES,
    )?;
    assert_corrupted(read, "a sealed overflow run's last page");
    Ok(())
}

/// The page size an environment opened by `open` gets, read from a fresh one.
fn page_size_of(open: fn(&Path) -> heed::Result<Env>) -> Result<u64, Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let env = open(dir.path())?;
    let page_size = u64::from(env.page_size()?);
    env.prepare_for_closing().wait();
    Ok(page_size)
}

/// LMDB's code for a sealed page that fails its authentication, which heed hands over as a raw
/// OS error.
const MDB_CRYPTO_FAIL: i32 = -30777;
/// The named database's leaf in the page-bound tests' file: the page after the main leaf.
const NAMED_LEAF_PAGE: u64 = 3;

/// Cuts the named database's leaf, the data file's last page, off.
fn cut_the_named_leaf(data_file: &Path, page_size: u64) -> std::io::Result<()> {
    truncate(data_file, NAMED_LEAF_PAGE * page_size)
}

/// Flips one byte in the middle of the named database's leaf, inside the sealed page's body.
fn flip_a_byte_of_the_named_leaf(data_file: &Path, page_size: u64) -> std::io::Result<()> {
    let at = NAMED_LEAF_PAGE * page_size + page_size / 2;
    let mut file = OpenOptions::new().read(true).write(true).open(data_file)?;
    let mut byte = [0_u8; 1];
    file.seek(SeekFrom::Start(at))?;
    file.read_exact(&mut byte)?;
    byte[0] ^= 0xff;
    file.seek(SeekFrom::Start(at))?;
    file.write_all(&byte)?;
    file.sync_all()
}

/// Writes the one named row, damages the named database's leaf with `damage`, reopens the
/// environment and opens the named database in a read transaction that commits, so the handle
/// outlives it. The open reads the database's record from the main leaf, which the damage spared,
/// and never fetches the leaf. Every later transaction starts with that record marked stale
/// (`DB_STALE`): its first call on the database reads the record again and fetches the
/// database's root, the damaged leaf. Returns the directory that holds the files, the
/// environment and the handle.
fn reopen_with_a_damaged_named_leaf(
    open: fn(&Path) -> heed::Result<Env>,
    damage: fn(&Path, u64) -> std::io::Result<()>,
) -> Result<(tempfile::TempDir, Env, Rows), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let (written_len, page_size) =
        write_one_named_row_and_close(dir.path(), open, &named_value(LEAF_ROW_LEN))?;
    assert_eq!(
        written_len,
        LEAF_FILE_PAGES * page_size,
        "two meta pages, the main leaf and the named leaf"
    );
    damage(&dir.path().join("data.mdb"), page_size)?;
    let env = open(dir.path())?;
    let rtxn = env.read_txn()?;
    let rows: Rows = env
        .open_database(&rtxn, Some(NAMED))?
        .ok_or("the named database's record is in the main leaf, which the damage spared")?;
    rtxn.commit()?;
    Ok((dir, env, rows))
}

/// Before the fetch rc fork, the root fetch's error was dropped and the transaction marked
/// failed, so the call answered `MDB_BAD_TXN` (or, for a count, the record's count with success).
fn assert_later_call_corrupted<T: std::fmt::Debug>(answer: heed::Result<T>, call: &str) {
    assert!(
        matches!(answer, Err(heed::Error::Mdb(MdbError::Corrupted))),
        "{call} in a later transaction answered {answer:?}, not MDB_CORRUPTED (the root fetch's \
         own error)"
    );
}

#[test]
fn a_get_in_a_later_transaction_of_a_named_database_whose_leaf_the_cut_lost_answers_corrupted()
-> Result<(), Box<dyn Error>> {
    let (_dir, env, rows) = reopen_with_a_damaged_named_leaf(open_env, cut_the_named_leaf)?;
    let rtxn = env.read_txn()?;
    let answer = rows.get(&rtxn, NAMED_KEY).map(|got| got.map(<[u8]>::len));
    drop(rtxn);
    env.prepare_for_closing().wait();
    assert_later_call_corrupted(answer, "a get");
    Ok(())
}

#[test]
fn a_cursor_in_a_later_transaction_on_a_named_database_whose_leaf_the_cut_lost_answers_corrupted()
-> Result<(), Box<dyn Error>> {
    let (_dir, env, rows) = reopen_with_a_damaged_named_leaf(open_env, cut_the_named_leaf)?;
    let rtxn = env.read_txn()?;
    // The cursor opens through `mdb_cursor_open`; its first step is what upstream answered with.
    let answer = rows
        .iter(&rtxn)
        .map(|mut iter| iter.next().map(|row| row.map(|(key, _)| key.len())));
    drop(rtxn);
    env.prepare_for_closing().wait();
    assert_later_call_corrupted(answer, "a cursor open");
    Ok(())
}

#[test]
fn a_count_in_a_later_transaction_of_a_named_database_whose_leaf_the_cut_lost_answers_corrupted()
-> Result<(), Box<dyn Error>> {
    let (_dir, env, rows) = reopen_with_a_damaged_named_leaf(open_env, cut_the_named_leaf)?;
    let rtxn = env.read_txn()?;
    // `len` reads `mdb_stat`, which counted from the record and left the transaction failed.
    let answer = rows.len(&rtxn);
    drop(rtxn);
    env.prepare_for_closing().wait();
    assert_later_call_corrupted(answer, "a count");
    Ok(())
}

#[test]
fn a_put_in_a_later_transaction_into_a_named_database_whose_leaf_the_cut_lost_answers_corrupted()
-> Result<(), Box<dyn Error>> {
    let (_dir, env, rows) = reopen_with_a_damaged_named_leaf(open_env, cut_the_named_leaf)?;
    let mut wtxn = env.write_txn()?;
    let answer = rows.put(&mut wtxn, b"another row", b"another value");
    wtxn.abort();
    env.prepare_for_closing().wait();
    assert_later_call_corrupted(answer, "a put");
    Ok(())
}

#[test]
fn a_delete_in_a_later_transaction_from_a_named_database_whose_leaf_the_cut_lost_answers_corrupted()
-> Result<(), Box<dyn Error>> {
    let (_dir, env, rows) = reopen_with_a_damaged_named_leaf(open_env, cut_the_named_leaf)?;
    let mut wtxn = env.write_txn()?;
    let answer = rows.delete(&mut wtxn, NAMED_KEY);
    wtxn.abort();
    env.prepare_for_closing().wait();
    assert_later_call_corrupted(answer, "a delete");
    Ok(())
}

#[test]
fn a_sealed_get_in_a_later_transaction_of_an_altered_named_leaf_answers_the_seal_failure()
-> Result<(), Box<dyn Error>> {
    let (_dir, env, rows) =
        reopen_with_a_damaged_named_leaf(open_sealed_env, flip_a_byte_of_the_named_leaf)?;
    let rtxn = env.read_txn()?;
    let answer = rows.get(&rtxn, NAMED_KEY).map(|got| got.map(<[u8]>::len));
    drop(rtxn);
    env.prepare_for_closing().wait();
    let code = match &answer {
        Err(heed::Error::Io(error)) => error.raw_os_error(),
        _ => None,
    };
    assert!(
        code == Some(MDB_CRYPTO_FAIL),
        "a sealed get in a later transaction answered {answer:?}, not MDB_CRYPTO_FAIL (the altered \
         leaf's own error)"
    );
    Ok(())
}
