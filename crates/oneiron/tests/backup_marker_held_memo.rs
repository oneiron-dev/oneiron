//! Pre-idle backup reuse asks `BackupMarker::held`, the strong check that the
//! file a marker names is still the backup it recorded, and it read the
//! whole artifact every time, which on a large vault outlasts the pre-idle
//! preparation window (FIX 6729). Once this process has read a backup whole,
//! it now answers from the file's identity (device, inode, size,
//! modification and status-change times) while that stays the same; any
//! change takes the whole read again.
//!
//! The test backs up a vault holding `BODIES` x `BODY_BYTES` of text, lands
//! the artifact under a label's file name, records its marker, waits until
//! the file has settled (a read seeds the memo only from a file unchanged
//! for a minute), and times held reads: twice on the landed file (the first
//! reads it whole), once after a same-size rewrite of one byte in place (not
//! held), and twice after the byte is put back (held again; both read whole,
//! as the file changed under a minute before). It prints each time and the
//! artifact's size: the measurement main and the fix are compared by.
//!
//! A second test changes a byte through a page already mapped writable,
//! which moves no time: device, inode, size, mtime and ctime all stay (Astra
//! review of #8317). The held read before that change must not seed the
//! memo (the file changed under a minute before it), so the held read after
//! it reads the changed bytes whole and refuses them. It prints whether the
//! identity really stayed (`FIX6729-KEPT`).
//!
//! Markers are read only on unix; the memory keystore needs `test-support`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test backup_marker_held_memo`
#![cfg(all(unix, feature = "test-support"))]

use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::recovery::checkpoint::{BackupMarker, backup_marker};
use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const LABEL: &str = "heldmemo";
const BODIES: u64 = 1_024;
/// The second test's label and vault size: small, as it times nothing.
const KEPT_LABEL: &str = "keptidentity";
const KEPT_BODIES: u64 = 64;
const BODY_BYTES: usize = 32 * 1024;

/// Text no compressor shrinks much: letters and digits from a xorshift.
fn body(seed: u64) -> Vec<u8> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..BODY_BYTES)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            ALPHABET[usize::try_from(state % 36).expect("an index")]
        })
        .collect()
}

fn timed_held(marker: &BackupMarker, dir: &Path) -> (f64, bool) {
    let started = Instant::now();
    let held = marker.held(dir);
    (started.elapsed().as_secs_f64() * 1000.0, held)
}

/// Turns the artifact's byte at `at` into its complement, in place.
fn flip_byte(path: &Path, at: u64) {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("the artifact opens for writing");
    let mut byte = [0_u8; 1];
    file.seek(SeekFrom::Start(at)).expect("seek");
    file.read_exact(&mut byte).expect("read the byte");
    byte[0] = !byte[0];
    file.seek(SeekFrom::Start(at)).expect("seek back");
    file.write_all(&byte).expect("write the byte");
    file.sync_all().expect("sync");
}

/// One backup landed under `label` with its marker; the directories live as
/// long as it does.
struct Landed {
    _vault_dir: tempfile::TempDir,
    backups: tempfile::TempDir,
    marker: BackupMarker,
    path: PathBuf,
    size: u64,
}

/// The file's identity as the memo keys it.
fn identity_of(path: &Path) -> (u64, u64, u64, i64, i64, i64, i64) {
    let metadata = std::fs::metadata(path).expect("artifact metadata");
    (
        metadata.dev(),
        metadata.ino(),
        metadata.size(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn land(label: &str, bodies: u64) -> Landed {
    let vault_dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(vault_dir.path(), VaultConfig::device()).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    for seed in 0..bodies {
        vault
            .put_entity(
                &EntityId::now(),
                ENTITY_TYPE_ASSET,
                TimeRange { start: 7, end: 7 },
                9,
                &body(seed),
            )
            .expect("a text asset");
    }
    vault.ensure_vault_key().expect("the vault key");

    let backups = tempfile::tempdir().expect("backup dir");
    let partial = backups.path().join(".partial");
    let receipt = vault
        .snapshot_backup(&partial, vault.now_recorded_at(), None, None)
        .expect("a backup");
    let id8 = receipt.image_digest.get(..8).expect("a hex digest");
    let file = format!("{label}-1-20261115T201500.000Z-{id8}.oneiron-backup");
    let path = backups.path().join(&file);
    std::fs::rename(&partial, &path).expect("the artifact lands");
    receipt
        .persist_marker(backups.path(), label, &file)
        .expect("the marker lands");
    let marker = backup_marker(backups.path(), label).expect("the marker names the backup");
    let size = std::fs::metadata(&path).expect("artifact metadata").len();
    Landed {
        _vault_dir: vault_dir,
        backups,
        marker,
        path,
        size,
    }
}

#[test]
fn a_recorded_backup_is_held_without_a_whole_read_until_it_changes() {
    let Landed {
        backups,
        marker,
        path,
        size,
        ..
    } = land(LABEL, BODIES);
    // Past the memo's settle time since the artifact's rename.
    std::thread::sleep(Duration::from_secs(61));

    let (first_ms, first) = timed_held(&marker, backups.path());
    let (second_ms, second) = timed_held(&marker, backups.path());
    assert!(first && second, "the landed backup is held");

    flip_byte(&path, size / 2);
    let (changed_ms, changed) = timed_held(&marker, backups.path());
    assert!(!changed, "a backup rewritten in place is not held");

    flip_byte(&path, size / 2);
    let (restored_ms, restored) = timed_held(&marker, backups.path());
    let (again_ms, again) = timed_held(&marker, backups.path());
    assert!(
        restored && again,
        "its bytes put back, the whole read finds the backup again"
    );

    let mebibytes = f64::from(u32::try_from(size / 1024).expect("artifact size")) / 1024.0;
    println!(
        "FIX6729-HELD artifact_mib={mebibytes:.1} landed_first_ms={first_ms:.2} \
         landed_second_ms={second_ms:.2} rewritten_ms={changed_ms:.2} \
         restored_first_ms={restored_ms:.2} restored_second_ms={again_ms:.2}"
    );
}

#[test]
fn a_change_that_keeps_the_identity_is_not_held() {
    let landed = land(KEPT_LABEL, KEPT_BODIES);
    let dir = landed.backups.path();
    let at = usize::try_from(landed.size / 2).expect("an offset");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&landed.path)
        .expect("the artifact opens for writing");
    // SAFETY: the test owns the artifact; nothing truncates it while mapped.
    let mut map = unsafe { memmap2::MmapMut::map_mut(&file) }.expect("a shared writable map");
    let byte = map.as_mut_ptr().wrapping_add(at);
    // SAFETY: `at` is inside the mapping, which lives to the end of the test.
    let original = unsafe { std::ptr::read_volatile(byte) };
    // The first store faults the page writable and moves the file's times.
    // SAFETY: as above.
    unsafe { std::ptr::write_volatile(byte, original) };
    let before = identity_of(&landed.path);
    assert!(landed.marker.held(dir), "the landed backup is held");
    // A later store through the writable page moves no time.
    // SAFETY: as above.
    unsafe { std::ptr::write_volatile(byte, !original) };
    let after = identity_of(&landed.path);
    let changed = landed.marker.held(dir);
    // SAFETY: as above.
    unsafe { std::ptr::write_volatile(byte, original) };
    drop(map);
    println!("FIX6729-KEPT identity_unchanged={}", before == after);
    assert!(
        !changed,
        "a backup changed through a writable mapping is not held"
    );
}
