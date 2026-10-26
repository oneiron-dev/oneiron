//! The strict read of a label's backup marker (FIX 6777): what every public
//! reader of the marker ([`super::last_backed_up`], [`super::backup_marker`])
//! takes it through, so a stale or forged marker never reads as a backup
//! that covers the vault.
//!
//! A marker reads only when it is a private file of this user, no longer
//! than any marker this engine writes, of the schema it writes, naming its
//! backup by the current file name (`<label>-<sequence>-<stamp>-<id8>
//! .oneiron-backup`, the id the image digest's first eight hex digits), with
//! full hex digests and a size; and when that file, opened without following
//! a link and never blocking, is a regular file of exactly that size whose
//! clear head and tail ([`inspect_backup_tail`]) carry the commitment the
//! marker records, signed by the signer it names. Anything else reads as no
//! marker: the backup is due. The tail is no proof of the bytes between
//! head and root nor of what is sealed; [`super::BackupMarker::held`] stays
//! the strong check, which reads the whole artifact.

use std::io::Read;
use std::path::Path;

use oneiron_crypto::backup::{CheckpointSigner, inspect_backup_tail, verify_tail_with_pins};

use super::{MARKER_SCHEMA_VERSION, WatermarkMarker, marker_name};

/// The suffix of a backup's file name, as its host names it.
const BACKUP_FILE_SUFFIX: &str = ".oneiron-backup";

/// The most bytes a marker this engine writes takes: its schema, a file name
/// within one path component, a watermark and three hex digests. A longer
/// file is no marker of ours, and reads as none.
const MARKER_MAX_BYTES: u64 = 4096;

/// The marker of `label`'s newest backup in `dir`, when it reads strictly.
pub(super) fn read_bound_marker(dir: &Path, label: &str) -> Option<WatermarkMarker> {
    read_bound_marker_with_pins(dir, label, None)
}

/// [`read_bound_marker`], and when `pins` are given, the commitment the
/// backup's tail carries signed by one of them (FIX 10712).
pub(super) fn read_bound_marker_with_pins(
    dir: &Path,
    label: &str,
    pins: Option<&[CheckpointSigner]>,
) -> Option<WatermarkMarker> {
    let bytes = read_private_marker(&dir.join(marker_name(label)))?;
    let marker: WatermarkMarker = serde_json::from_slice(&bytes).ok()?;
    let named = marker.schema_version == MARKER_SCHEMA_VERSION
        && hex64(&marker.image_digest)
        && hex64(&marker.commitment_digest)
        && hex64(&marker.outer_blake3)
        && marker.size > 0
        && names_backup(&marker.file, label, &marker.image_digest);
    (named && tail_holds(dir, &marker, pins)).then_some(marker)
}

/// The marker file at `path`, read whole, when it is a private regular file
/// of this user (one name, mode 0600, no link followed) no longer than
/// [`MARKER_MAX_BYTES`].
#[cfg(unix)]
fn read_private_marker(path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    // SAFETY: `geteuid` takes no argument and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_file()
        || metadata.uid() != euid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MARKER_MAX_BYTES
    {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MARKER_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= MARKER_MAX_BYTES).then_some(bytes)
}

/// No private marker reads off unix.
#[cfg(not(unix))]
fn read_private_marker(_path: &Path) -> Option<Vec<u8>> {
    None
}

/// Whether `text` is 64 lower-case hex digits: a full digest.
fn hex64(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether `file` is the current name of a backup of `label` whose image is
/// `image_digest`: `<label>-<sequence>-<stamp>-<id8>.oneiron-backup`, the
/// sequence ASCII digits, the stamp `YYYYMMDDTHHMMSS.mmmZ` and the id the
/// digest's first eight hex digits. The label is the one asked for, so a
/// hyphen in it never shifts the fields.
fn names_backup(file: &str, label: &str, image_digest: &str) -> bool {
    let Some(rest) = file
        .strip_prefix(label)
        .and_then(|rest| rest.strip_prefix('-'))
        .and_then(|rest| rest.strip_suffix(BACKUP_FILE_SUFFIX))
    else {
        return false;
    };
    let mut fields = rest.splitn(3, '-');
    let (Some(sequence), Some(stamp), Some(id8)) = (fields.next(), fields.next(), fields.next())
    else {
        return false;
    };
    !sequence.is_empty()
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
        && stamp_shape(stamp)
        && image_digest.get(..8) == Some(id8)
}

/// Whether `stamp` has the shape of a backup file's stamp,
/// `YYYYMMDDTHHMMSS.mmmZ`.
fn stamp_shape(stamp: &str) -> bool {
    let bytes = stamp.as_bytes();
    bytes.len() == 20
        && bytes.iter().enumerate().all(|(at, byte)| match at {
            8 => *byte == b'T',
            15 => *byte == b'.',
            19 => *byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
}

/// Whether the backup `marker` names in `dir` is a regular file of exactly
/// its size, opened without following a link and never blocking, whose
/// head and tail carry the commitment it records, signed by one of `pins`
/// when they are given.
fn tail_holds(dir: &Path, marker: &WatermarkMarker, pins: Option<&[CheckpointSigner]>) -> bool {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut options,
        libc::O_NOFOLLOW | libc::O_NONBLOCK,
    );
    let Ok(file) = options.open(dir.join(&marker.file)) else {
        return false;
    };
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if !metadata.is_file() || metadata.len() != marker.size {
        return false;
    }
    inspect_backup_tail(std::io::BufReader::new(&file)).is_ok_and(|tail| {
        tail.size == marker.size
            && oneiron_vault_contract::hex(&tail.commitment_digest) == marker.commitment_digest
            && pins.is_none_or(|pins| verify_tail_with_pins(&tail, pins).is_ok())
    })
}
