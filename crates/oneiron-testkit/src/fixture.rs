//! Fixture vaults: seed a vault once, copy it for every test.
//!
//! [`FixtureVault::build`] opens a fresh vault under a [`FakeClock`] at
//! [`crate::clock::FAKE_EPOCH`], runs the seed (public calls only: verbs,
//! owner doors, the attempt queue), closes the vault and keeps its directory
//! in a [`FixtureCache`]. The cache is keyed by the fixture's name and by the
//! test binary itself (its size and modification time), so a rebuilt engine or
//! an edited seed builds a new fixture, and every test process of one binary
//! (nextest runs one process per test) reuses the first one's. Two processes
//! that build the same fixture at once each build it in a private directory
//! and the first rename wins.
//!
//! [`FixtureVault::copy`] copies the closed directory into a fresh temp dir:
//! one vault per test, never shared. The copy's clock starts where the seed's
//! ended, so the vault's recorded time never runs backwards.
//!
//! What a copy guarantees: a fixture is a bare, unsealed vault with no key
//! custody bound. Key custody lives beside a vault and its row names the
//! vault's absolute path, so a byte copy of a custody-bound vault would read
//! the original's keys. The build refuses a seed that leaves anything beside
//! the vault directory. A test that needs custody binds it on its own copy.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use oneiron::{Vault, VaultConfig};

use crate::clock::{FAKE_EPOCH, FakeClock};

/// The directory inside a fixture or a copy that holds the vault.
const VAULT_DIR: &str = "vault";
/// The file beside it that records how the fixture ended.
const RECORD_FILE: &str = "fixture.json";
/// The block a copy compares against zero to keep holes.
const COPY_BLOCK: usize = 64 << 10;

/// What went wrong building or copying a fixture.
#[derive(Debug)]
pub enum FixtureError {
    Io(io::Error),
    /// Opening the vault failed.
    Engine(oneiron::Error),
    /// The seed failed.
    Seed(Box<dyn std::error::Error + Send + Sync>),
    /// The cached fixture's record is unreadable.
    Record(String),
}

impl fmt::Display for FixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "fixture I/O: {error}"),
            Self::Engine(error) => write!(f, "fixture vault: {error}"),
            Self::Seed(error) => write!(f, "fixture seed: {error}"),
            Self::Record(error) => write!(f, "fixture record: {error}"),
        }
    }
}

impl std::error::Error for FixtureError {}

impl From<io::Error> for FixtureError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<oneiron::Error> for FixtureError {
    fn from(error: oneiron::Error) -> Self {
        Self::Engine(error)
    }
}

/// The error a seed returns.
pub type SeedError = Box<dyn std::error::Error + Send + Sync>;

/// Where built fixtures are kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureCache {
    root: PathBuf,
}

/// The cache an integration test should use: under the target directory's
/// per-package temp dir (`CARGO_TARGET_TMPDIR`), so `cargo clean` clears it.
/// Expands in the calling test crate.
#[macro_export]
macro_rules! fixture_cache {
    () => {
        $crate::fixture::FixtureCache::new(::std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("oneiron-testkit-fixtures"))
    };
}

impl FixtureCache {
    /// A cache rooted at `root` (created on first build).
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The cache root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// A built, closed fixture vault in the cache. Never opened in place: copy
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureVault {
    dir: PathBuf,
    ended_at: u64,
}

/// The test binary's identity: a rebuilt binary is a new one.
fn binary_identity() -> String {
    std::env::current_exe()
        .and_then(|exe| {
            let meta = fs::metadata(&exe)?;
            let modified = meta
                .modified()?
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_nanos());
            Ok(format!("{}|{}|{modified}", exe.display(), meta.len()))
        })
        // Unknown: key by process, so nothing is reused across processes.
        .unwrap_or_else(|_| format!("pid {}", std::process::id()))
}

fn fixture_key(name: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron-testkit/fixture/v1\0");
    hasher.update(name.as_bytes());
    hasher.update(b"\0");
    hasher.update(binary_identity().as_bytes());
    hasher.finalize().to_hex()[..16].to_owned()
}

fn safe_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

static BUILD_COUNTER: AtomicU64 = AtomicU64::new(0);

impl FixtureVault {
    /// The fixture `name`, built by `seed` on a `VaultConfig::device()` vault
    /// unless the cache already holds it for this test binary. `name` keys
    /// the cache: one name, one seed.
    ///
    /// # Errors
    /// The vault cannot be opened, the seed fails, or the cache cannot be
    /// written.
    pub fn build<F>(cache: &FixtureCache, name: &str, seed: F) -> Result<Self, FixtureError>
    where
        F: FnOnce(&Vault, &FakeClock) -> Result<(), SeedError>,
    {
        Self::build_with(cache, name, FakeClock::vault_config, seed)
    }

    /// [`Self::build`] with the vault config `config` makes from the seed's
    /// clock (a server preset, an embedding model). Copies are opened with
    /// the same config by [`VaultCopy::open_with`].
    ///
    /// # Errors
    /// As [`Self::build`].
    pub fn build_with<C, F>(
        cache: &FixtureCache,
        name: &str,
        config: C,
        seed: F,
    ) -> Result<Self, FixtureError>
    where
        C: FnOnce(&FakeClock) -> VaultConfig,
        F: FnOnce(&Vault, &FakeClock) -> Result<(), SeedError>,
    {
        let dir = cache
            .root
            .join(format!("{}-{}", safe_name(name), fixture_key(name)));
        if let Some(fixture) = Self::read(&dir)? {
            return Ok(fixture);
        }
        fs::create_dir_all(&cache.root)?;
        let staging = cache.root.join(format!(
            ".{}.build-{}-{}",
            safe_name(name),
            std::process::id(),
            BUILD_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        if staging.exists() {
            fs::remove_dir_all(&staging)?;
        }
        if let Err(error) = seed_into(&staging, name, config, seed) {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
        match fs::rename(&staging, &dir) {
            Ok(()) => {}
            // Another process won the race: use its fixture, drop ours.
            Err(_) if dir.join(RECORD_FILE).is_file() => {
                fs::remove_dir_all(&staging)?;
            }
            Err(error) => return Err(error.into()),
        }
        Self::read(&dir)?.ok_or_else(|| FixtureError::Record(format!("{} vanished", dir.display())))
    }

    /// The fixture a seeding run wrote into `dir` ([`seed_into`], or the
    /// `oneiron-testkit-seed` binary); `None` when `dir` holds none.
    ///
    /// # Errors
    /// The record is unreadable.
    pub fn at(dir: &Path) -> Result<Option<Self>, FixtureError> {
        Self::read(dir)
    }

    /// An empty vault: opened once, nothing seeded.
    ///
    /// # Errors
    /// As [`Self::build`].
    pub fn empty(cache: &FixtureCache) -> Result<Self, FixtureError> {
        Self::build(cache, "empty", |_, _| Ok(()))
    }

    fn read(dir: &Path) -> Result<Option<Self>, FixtureError> {
        let record = match fs::read_to_string(dir.join(RECORD_FILE)) {
            Ok(record) => record,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let record: serde_json::Value = serde_json::from_str(&record)
            .map_err(|error| FixtureError::Record(error.to_string()))?;
        let ended_at = record
            .get("ended_at")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| FixtureError::Record(format!("{}: no ended_at", dir.display())))?;
        Ok(Some(Self {
            dir: dir.to_path_buf(),
            ended_at,
        }))
    }

    /// The fake time the seed ended at.
    #[must_use]
    pub fn ended_at(&self) -> u64 {
        self.ended_at
    }

    /// A private copy of the fixture for one test.
    ///
    /// # Errors
    /// The copy cannot be written.
    pub fn copy(&self) -> Result<VaultCopy, FixtureError> {
        let temp = tempfile::Builder::new()
            .prefix("oneiron-testkit-vault-")
            .tempdir()?;
        copy_tree(&self.dir.join(VAULT_DIR), &temp.path().join(VAULT_DIR))?;
        Ok(VaultCopy {
            path: temp.path().join(VAULT_DIR),
            temp,
            clock: FakeClock::at(self.ended_at),
        })
    }
}

/// Seeds a fixture into `dir`, which must be absent or empty: the vault at
/// `dir/vault`, opened process-owned (so owner verbs run) on a fake clock at
/// [`FAKE_EPOCH`] with the config `config` makes, seeded by `seed`, closed,
/// and recorded in `dir/fixture.json`. Returns the fake time the seed ended
/// at.
///
/// # Errors
/// `dir` holds something, the vault cannot be opened, the seed fails, or the
/// seed left anything beside the vault directory (key custody or a page
/// seal: their rows name this vault's absolute path, so a byte copy would
/// share the original's keys instead of owning its own).
pub fn seed_into<C, F>(dir: &Path, name: &str, config: C, seed: F) -> Result<u64, FixtureError>
where
    C: FnOnce(&FakeClock) -> VaultConfig,
    F: FnOnce(&Vault, &FakeClock) -> Result<(), SeedError>,
{
    if dir.exists() && fs::read_dir(dir)?.next().is_some() {
        return Err(FixtureError::Record(format!("{} is not empty", dir.display())));
    }
    fs::create_dir_all(dir.join(VAULT_DIR))?;
    let clock = FakeClock::at(FAKE_EPOCH);
    {
        let vault = Vault::open_owned(dir.join(VAULT_DIR), config(&clock))?;
        seed(&vault, &clock).map_err(FixtureError::Seed)?;
    }
    let mut beside: Vec<String> = fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|entry| entry != VAULT_DIR)
        .collect();
    if !beside.is_empty() {
        beside.sort();
        return Err(FixtureError::Record(format!(
            "the seed of {name:?} left {beside:?} beside the vault (key custody or a page seal); a copy of it \
             would share those keys. Seed without protected publication, or build per test."
        )));
    }
    let ended_at = clock.now();
    fs::write(
        dir.join(RECORD_FILE),
        serde_json::json!({"name": name, "ended_at": ended_at}).to_string(),
    )?;
    Ok(ended_at)
}

/// A seed read from JSONL, as fixture seeds under `tests/fixtures/` are
/// written: one JSON object per line, run in order as the vault's embedded
/// owner through the public verb door. Blank lines and lines starting with
/// `#` are skipped.
///
/// - `{"verb": "<dotted verb name>", "input": {...}}` runs that verb;
/// - `{"advance_secs": <n>}` moves the fake clock forward.
///
/// A line that fails stops the seed with its line number.
pub fn jsonl_seed(text: &str) -> impl FnOnce(&Vault, &FakeClock) -> Result<(), SeedError> + '_ {
    move |vault, clock| {
        let owner = crate::door::owner(vault).map_err(|error| format!("the owner: {error}"))?;
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let at = index + 1;
            let step: serde_json::Value =
                serde_json::from_str(line).map_err(|error| format!("seed line {at}: {error}"))?;
            if let Some(secs) = step.get("advance_secs").and_then(serde_json::Value::as_u64) {
                clock.advance(secs);
            } else if let Some(verb) = step.get("verb").and_then(serde_json::Value::as_str) {
                let input = step.get("input").cloned().unwrap_or_else(|| serde_json::json!({}));
                crate::door::invoke(&owner, verb, input)
                    .map_err(|error| format!("seed line {at} ({verb}): {error}"))?;
            } else {
                return Err(format!("seed line {at}: neither `verb` nor `advance_secs`").into());
            }
        }
        Ok(())
    }
}

fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = to.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            copy_file_keeping_holes(&entry.path(), &target)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: a vault holds only files and directories", entry.path().display()),
            ));
        }
    }
    Ok(())
}

/// Copies a file block by block, seeking over all-zero blocks, so a sparse
/// LMDB map stays sparse in the copy.
fn copy_file_keeping_holes(from: &Path, to: &Path) -> io::Result<()> {
    let mut input = File::open(from)?;
    let length = input.metadata()?.len();
    let mut output = File::create(to)?;
    let mut block = vec![0_u8; COPY_BLOCK];
    loop {
        let read = input.read(&mut block)?;
        if read == 0 {
            break;
        }
        if block[..read].iter().all(|&byte| byte == 0) {
            output.seek(SeekFrom::Current(i64::try_from(read).unwrap_or(i64::MAX)))?;
        } else {
            output.write_all(&block[..read])?;
        }
    }
    output.set_len(length)?;
    output.sync_all()?;
    fs::set_permissions(to, fs::metadata(from)?.permissions())
}

/// One test's private copy of a fixture vault. The directory is deleted
/// when the copy drops.
#[derive(Debug)]
pub struct VaultCopy {
    temp: tempfile::TempDir,
    path: PathBuf,
    clock: FakeClock,
}

impl VaultCopy {
    /// The vault directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The temp dir around the vault, for the test's other files.
    #[must_use]
    pub fn temp_dir(&self) -> &Path {
        self.temp.path()
    }

    /// The copy's clock, starting where the fixture's seed ended.
    #[must_use]
    pub fn clock(&self) -> &FakeClock {
        &self.clock
    }

    /// `VaultConfig::device()` on the copy's clock.
    #[must_use]
    pub fn config(&self) -> VaultConfig {
        self.clock.vault_config()
    }

    /// Opens the copy with [`Self::config`].
    ///
    /// # Errors
    /// The engine refuses the open.
    pub fn open(&self) -> oneiron::Result<Vault> {
        Vault::open(&self.path, self.config())
    }

    /// Opens the copy with the config `config` makes from the copy's clock
    /// (the one the fixture was built with, for a fixture made by
    /// [`FixtureVault::build_with`]).
    ///
    /// # Errors
    /// The engine refuses the open.
    pub fn open_with(&self, config: impl FnOnce(&FakeClock) -> VaultConfig) -> oneiron::Result<Vault> {
        Vault::open(&self.path, config(&self.clock))
    }

    /// Opens the copy as a process-owned vault (it holds the writer lease),
    /// as a server or an embedded SDK host does. Owner-only verbs need it.
    ///
    /// # Errors
    /// The engine refuses the open.
    pub fn open_owned(&self) -> oneiron::Result<Vault> {
        Vault::open_owned(&self.path, self.config())
    }

    /// Opens the copy through the existing-only door, which never creates.
    ///
    /// # Errors
    /// The engine refuses the open.
    pub fn open_existing(&self) -> oneiron::Result<Vault> {
        Vault::open_existing(&self.path, self.config())
    }
}
