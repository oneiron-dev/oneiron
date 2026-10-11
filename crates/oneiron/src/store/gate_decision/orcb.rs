//! ORCB v1: schema-only dictionary, per-claim hot-value AEAD and exterior key custody.
//!
//! `[ORCB | 1 | claim_id:16 | decision_id:16 | nonce:12 | AES-256-GCM(
//! zstd-dict(MessagePack(record)), AAD=header)]`. The dictionary consists only
//! of fixed field markers and closed enum tokens; no live value can train it.
//! Keys sit beside the restorable vault root, never in the LMDB image. A host
//! must exclude this custody directory from every restorable snapshot.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

use super::ledger::{decode_gate_decision, encode_gate_decision};
use super::types::{GateDecisionId, GateDecisionRecord};

const MAGIC: &[u8; 4] = b"ORCB";
const VERSION: u8 = 1;
const ROTATED_VERSION: u8 = 2;
const HEADER_LEN: usize = 4 + 1 + 16 + 16 + 12;
const ROTATED_HEADER_LEN: usize = HEADER_LEN + 8;
const MAX_PLAINTEXT: usize = 16 * 1024 * 1024;

// RAW-CONTENT zstd dictionary (no live training or adaptive state). Every
// token is a schema field name or a closed vocabulary value. Do not add a
// sample taken from a vault, even in a test fixture or build script.
const SYNTHETIC_DICTIONARY: &[u8] = b"version decision_id created_at outcome reason_codes receipt_reasons system_notices actor_class actor_ref content_kind policy_manifest_version claim_id grant_ref diff_handle read_frontier_hash redacted_at notice_type channel voice audience body row_ref setting_change_offer policy_plane policy_version docs_url allow deny hold owner_policy hosted_legal gate.allow gate.deny gate.hold";

pub(super) fn corrupt() -> Error {
    Error::CorruptedIndex("gate decision ORCB")
}

/// Exterior to the restorable vault directory. Custody is intentionally NOT a
/// child of the LMDB root: restoring its data.mdb cannot restore shredded keys.
fn key_directory(root: &Path) -> Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::ffi::OsString;
        let mut name = OsString::from(".");
        name.push(root.file_name().ok_or_else(corrupt)?);
        name.push(".gate-decision-keys");
        Ok(root.with_file_name(name))
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Err(Error::InvalidConfig(
            "claim-key custody requires a supported Unix filesystem".into(),
        ))
    }
}

/// This marker is checkpointed; it contains a native absolute PATH, never key
/// material. A restore binds to, or a side restore forks, the current exterior
/// custody at that path, so replacing an LMDB image cannot bring back a key
/// already destroyed there.
pub(in crate::store) const CUSTODY_ROOT_KEY: &[u8] = b"gate_decision:custody_root:v1";

pub(in crate::store) fn encode_custody_root(root: &Path) -> Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        if !root.is_absolute() {
            return Err(corrupt());
        }
        Ok(root.as_os_str().as_bytes().to_vec())
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Err(corrupt())
    }
}

pub(in crate::store) fn decode_custody_root(raw: &[u8]) -> Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(raw));
        if raw.is_empty() || raw.len() > 4096 || !path.is_absolute() {
            return Err(corrupt());
        }
        Ok(path.to_path_buf())
    }
    #[cfg(not(unix))]
    {
        let _ = raw;
        Err(corrupt())
    }
}

fn claim_key_path(root: &Path, claim_id: &[u8; 16], generation: u64) -> Result<PathBuf> {
    let hex = crate::entity_id::bytes_to_hex_lower(claim_id);
    let name = if generation == 0 {
        hex
    } else {
        format!("{hex}.g{generation:016x}")
    };
    Ok(key_directory(root)?.join(name))
}

fn retired_marker(dir: &Path, claim_id: &[u8; 16], generation: u64) -> PathBuf {
    let hex = crate::entity_id::bytes_to_hex_lower(claim_id);
    let name = if generation == 0 {
        format!(".retired-{hex}")
    } else {
        format!(".retired-{hex}.g{generation:016x}")
    };
    dir.join(name)
}

fn is_retired(dir: &Path, claim_id: &[u8; 16], generation: u64) -> Result<bool> {
    let path = retired_marker(dir, claim_id, generation);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            safe_open(&path, false, false)?;
            Ok(true)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

fn current_generation(dir: &Path, claim_id: &[u8; 16]) -> Result<u64> {
    let mut generation = 0_u64;
    while is_retired(dir, claim_id, generation)? {
        generation = generation
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("gate decision key generation"))?;
    }
    Ok(generation)
}

pub(super) fn key_generation(root: &Path, claim_id: &[u8; 16]) -> Result<u64> {
    current_generation(&key_directory(root)?, claim_id)
}

pub(super) fn generation_retired(
    root: &Path,
    claim_id: &[u8; 16],
    generation: u64,
) -> Result<bool> {
    is_retired(&key_directory(root)?, claim_id, generation)
}

/// Whether a key file was ever published for this generation and still
/// exists. A missing custody directory means no claim key exists at all.
pub(super) fn key_published(root: &Path, claim_id: &[u8; 16], generation: u64) -> Result<bool> {
    match fs::symlink_metadata(claim_key_path(root, claim_id, generation)?) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

#[cfg(unix)]
fn verify_permissions(file: &File, is_directory: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    // SAFETY: geteuid has no arguments or pointers and only reads the caller's
    // effective uid; the result is used to reject another owner's key file.
    if meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || (!is_directory && meta.nlink() != 1)
        || (is_directory && !meta.is_dir())
        || (!is_directory && !meta.is_file())
    {
        return Err(corrupt());
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_permissions(file: &File, is_directory: bool) -> Result<()> {
    let meta = file.metadata()?;
    if (is_directory && !meta.is_dir()) || (!is_directory && !meta.is_file()) {
        return Err(corrupt());
    }
    Ok(())
}

fn safe_open(path: &Path, write_new: bool, directory: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    if write_new {
        options.write(true).create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        options.mode(0o600);
    }
    let file = options.open(path)?;
    verify_permissions(&file, directory)?;
    Ok(file)
}

#[cfg(test)]
thread_local! {
    static AFTER_KEY_MARKER_CHECK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(in crate::store) fn arm_after_key_marker_check(callback: impl FnOnce() + 'static) {
    AFTER_KEY_MARKER_CHECK.with(|slot| *slot.borrow_mut() = Some(Box::new(callback)));
}

fn read_key(root: &Path, claim_id: &[u8; 16], generation: u64) -> Result<Zeroizing<[u8; 32]>> {
    let dir = key_directory(root)?;
    let _ = safe_open(&dir, false, true)?;
    if is_retired(&dir, claim_id, generation)? {
        return Err(corrupt());
    }
    #[cfg(test)]
    AFTER_KEY_MARKER_CHECK.with(|slot| {
        if let Some(callback) = slot.borrow_mut().take() {
            callback();
        }
    });
    let mut file = safe_open(&claim_key_path(root, claim_id, generation)?, false, false)?;
    let mut key = Zeroizing::new([0; 32]);
    file.read_exact(&mut *key).map_err(|_| corrupt())?;
    let mut extra = [0];
    if file.read(&mut extra)? != 0 {
        return Err(corrupt());
    }
    Ok(key)
}

/// Remove interrupted, unpublished temporary keys for this claim. A crash
/// after hard-link publication but before unlink leaves a complete final key
/// with link count two; removing its pending sibling makes it readable again.
fn clean_pending(dir: &Path, claim_id: &[u8; 16]) -> Result<()> {
    let prefix = format!(".{}-", crate::entity_id::bytes_to_hex_lower(claim_id));
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(".pending"))
        {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

/// Opens the custody directory beside `root`, creating it when absent, or
/// only creating it when `create_new`. A new directory's parent is synced
/// before any key is written inside it.
fn open_key_directory(root: &Path, create_new: bool) -> Result<(PathBuf, File)> {
    let dir = key_directory(root)?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(&dir) {
        Ok(()) => {
            // Without this parent fsync, a synced key in a new directory can
            // still disappear after power loss while LMDB keeps its ciphertext.
            File::open(dir.parent().ok_or_else(corrupt)?)?.sync_all()?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists && !create_new => {}
        Err(err) => return Err(err.into()),
    }
    let directory = safe_open(&dir, false, true)?;
    Ok((dir, directory))
}

/// Publishes `key` at `path` through a synced temporary hard link, so a crash
/// never leaves a short final key. False when `path` already exists.
fn publish_key(dir: &Path, path: &Path, claim_id: &[u8; 16], key: &[u8; 32]) -> Result<bool> {
    let suffix = rand::rngs::OsRng.next_u64();
    let temp = dir.join(format!(
        ".{}-{suffix:016x}.pending",
        crate::entity_id::bytes_to_hex_lower(claim_id)
    ));
    let published = (|| -> Result<bool> {
        let mut file = safe_open(&temp, true, false)?;
        file.write_all(key)?;
        file.sync_all()?;
        match fs::hard_link(&temp, path) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(err) => Err(err.into()),
        }
    })();
    // Cleanup is unconditional, including I/O failure before publication.
    fs::remove_file(&temp)?;
    published
}

/// First claim-bound append syncs the exterior directory entry before LMDB
/// may commit ciphertext. A short/zero final key is NEVER treated as absent.
/// Only an unpublished temporary file may be discarded on retry.
fn first_append_key(
    root: &Path,
    claim_id: &[u8; 16],
    generation: u64,
) -> Result<Zeroizing<[u8; 32]>> {
    let (dir, directory) = open_key_directory(root, false)?;
    clean_pending(&dir, claim_id)?;
    directory.sync_all()?;
    if is_retired(&dir, claim_id, generation)? {
        return Err(corrupt());
    }
    let path = claim_key_path(root, claim_id, generation)?;
    if path.exists() {
        return read_key(root, claim_id, generation);
    }
    let mut key = Zeroizing::new([0; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *key);
    let published = publish_key(&dir, &path, claim_id, &key)?;
    directory.sync_all()?;
    if published {
        Ok(key)
    } else {
        read_key(root, claim_id, generation)
    }
}

pub(super) fn encode_hot(root: &Path, record: &GateDecisionRecord) -> Result<Vec<u8>> {
    let claim_id = record.claim_id.ok_or_else(corrupt)?;
    encode_hot_at(root, record, key_generation(root, &claim_id)?)
}

/// Encrypts under one named generation. An erase uses this to move a receipt
/// it must keep readable onto the generation after the one it retires.
pub(super) fn encode_hot_at(
    root: &Path,
    record: &GateDecisionRecord,
    generation: u64,
) -> Result<Vec<u8>> {
    let claim_id = record.claim_id.ok_or_else(corrupt)?;
    let key = first_append_key(root, &claim_id, generation)?;
    let plain = encode_gate_decision(record)?;
    if plain.len() > MAX_PLAINTEXT {
        return Err(Error::InvariantViolation("gate decision ORCB size"));
    }
    let mut compressor = zstd::bulk::Compressor::with_dictionary(3, SYNTHETIC_DICTIONARY)
        .map_err(|_| Error::InvariantViolation("gate decision ORCB compress"))?;
    let compressed = compressor
        .compress(&plain)
        .map_err(|_| Error::InvariantViolation("gate decision ORCB compress"))?;
    let mut header = Vec::with_capacity(ROTATED_HEADER_LEN + compressed.len() + 16);
    header.extend_from_slice(MAGIC);
    header.push(if generation == 0 {
        VERSION
    } else {
        ROTATED_VERSION
    });
    header.extend_from_slice(&claim_id);
    header.extend_from_slice(&record.decision_id.as_bytes());
    let mut nonce = [0; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    header.extend_from_slice(&nonce);
    if generation != 0 {
        header.extend_from_slice(&generation.to_be_bytes());
    }
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| corrupt())?;
    let encrypted = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &compressed,
                aad: &header,
            },
        )
        .map_err(|_| corrupt())?;
    header.extend_from_slice(&encrypted);
    Ok(header)
}

pub(super) fn decode_hot(
    root: &Path,
    decision_id: GateDecisionId,
    raw: &[u8],
) -> Result<GateDecisionRecord> {
    if !raw.starts_with(MAGIC) || raw.len() < HEADER_LEN + 16 {
        return Err(corrupt());
    }
    let (generation, header_len) = match raw[4] {
        VERSION => (0, HEADER_LEN),
        ROTATED_VERSION if raw.len() >= ROTATED_HEADER_LEN + 16 => {
            let generation = u64::from_be_bytes(
                raw[HEADER_LEN..ROTATED_HEADER_LEN]
                    .try_into()
                    .map_err(|_| corrupt())?,
            );
            if generation == 0 {
                return Err(corrupt());
            }
            (generation, ROTATED_HEADER_LEN)
        }
        _ => return Err(corrupt()),
    };
    let claim_id: [u8; 16] = raw[5..21].try_into().map_err(|_| corrupt())?;
    if raw[21..37] != decision_id.as_bytes() {
        return Err(corrupt());
    }
    let key = read_key(root, &claim_id, generation)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| corrupt())?;
    let nonce: [u8; 12] = raw[37..49].try_into().map_err(|_| corrupt())?;
    let compressed = cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &raw[header_len..],
                aad: &raw[..header_len],
            },
        )
        .map_err(|_| corrupt())?;
    let mut decompressor =
        zstd::bulk::Decompressor::with_dictionary(SYNTHETIC_DICTIONARY).map_err(|_| corrupt())?;
    let plain = decompressor
        .decompress(&compressed, MAX_PLAINTEXT)
        .map_err(|_| corrupt())?;
    let record = decode_gate_decision(&plain)?;
    if record.claim_id != Some(claim_id) || record.decision_id != decision_id {
        return Err(corrupt());
    }
    Ok(record)
}

/// Retire precisely the committed intent's generation. Later receipts use
/// a new generation, and neither an old snapshot nor a delayed finisher can
/// revive or destroy a different generation's key.
pub(super) fn retire_claim_key(root: &Path, claim_id: &[u8; 16], generation: u64) -> Result<()> {
    let dir = key_directory(root)?;
    let directory = safe_open(&dir, false, true)?;
    mark_retired(&dir, claim_id, generation)?;
    directory.sync_all()?;
    let path = claim_key_path(root, claim_id, generation)?;
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    directory.sync_all()?;
    Ok(())
}

fn mark_retired(dir: &Path, claim_id: &[u8; 16], generation: u64) -> Result<()> {
    match safe_open(&retired_marker(dir, claim_id, generation), true, false) {
        Ok(file) => file.sync_all()?,
        Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            if !is_retired(dir, claim_id, generation)? {
                return Err(corrupt());
            }
        }
        Err(err) => return Err(err),
    }
    Ok(())
}

/// Whether a custody directory exists beside `root`.
pub(super) fn custody_present(root: &Path) -> Result<bool> {
    match fs::symlink_metadata(key_directory(root)?) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// A custody directory a side restore's fork created, named by device and
/// inode so its cleanup never removes a directory that replaced it. The
/// directory stays open for the fork's life, so no other directory can take
/// its inode number while the cleanup may still compare against it.
pub(crate) struct ForkedCustodyDir {
    path: PathBuf,
    identity: (u64, u64),
    directory: File,
}

impl ForkedCustodyDir {
    /// Removes the fork's keys and markers, for a restore that failed or was
    /// refused after it; best effort, and only while the path still names the
    /// directory the fork created.
    pub(crate) fn remove(self) {
        if fs::symlink_metadata(&self.path)
            .ok()
            .and_then(|meta| directory_identity(&meta))
            == Some(self.identity)
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(unix)]
fn directory_identity(meta: &fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    meta.is_dir().then(|| (meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn directory_identity(_: &fs::Metadata) -> Option<(u64, u64)> {
    None
}

/// Every claim generation a retirement marker in `dir` names. A name the
/// engine would not write is not a marker it reads either, so it is skipped.
fn retired_generations(dir: &Path) -> Result<Vec<([u8; 16], u64)>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let mut retired = Vec::new();
    for entry in entries {
        let name = entry?.file_name();
        let Some(marker) = name
            .to_str()
            .and_then(|name| name.strip_prefix(".retired-"))
        else {
            continue;
        };
        let (hex, generation) = marker.split_once(".g").unwrap_or((marker, "0"));
        let (Ok(claim), Ok(generation)) = (
            u128::from_str_radix(hex, 16),
            u64::from_str_radix(generation, 16),
        ) else {
            continue;
        };
        let claim = claim.to_be_bytes();
        if retired_marker(dir, &claim, generation).file_name() == Some(name.as_os_str()) {
            retired.push((claim, generation));
        }
    }
    Ok(retired)
}

/// Forks the custody beside `source` into a new custody directory beside
/// `destination`. Every generation the source destroyed stays destroyed: its
/// retirement marker is copied, whatever the claim. For each claim a restore
/// needs, through its newest generation, one that a committed retirement
/// destroys (`committed`, its newest) is marked destroyed as well, and every
/// other key still live in the source is copied. The copy thus counts
/// generations as the source does, so its own erase reaches every key it
/// holds. A fork that fails removes what it created.
pub(super) fn fork_custody(
    source: &Path,
    destination: &Path,
    claims: &[([u8; 16], u64, Option<u64>)],
) -> Result<Option<ForkedCustodyDir>> {
    let source_dir = key_directory(source)?;
    let retired = retired_generations(&source_dir)?;
    if retired.is_empty() && claims.is_empty() {
        return Ok(None);
    }
    let (dir, directory) = open_key_directory(destination, true)?;
    let forked = ForkedCustodyDir {
        identity: directory_identity(&directory.metadata()?).ok_or_else(corrupt)?,
        path: dir.clone(),
        directory,
    };
    // The directory is synced once at the end; a marker carries no bytes.
    let mark = |claim_id: &[u8; 16], generation| match safe_open(
        &retired_marker(&dir, claim_id, generation),
        true,
        false,
    ) {
        Ok(_) => Ok(()),
        Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(err),
    };
    let copied = (|| -> Result<()> {
        for (claim_id, generation) in &retired {
            if is_retired(&source_dir, claim_id, *generation)? {
                mark(claim_id, *generation)?;
            }
        }
        for (claim_id, through, committed) in claims {
            for generation in 0..=*through {
                if committed.is_some_and(|newest| generation <= newest) {
                    mark(claim_id, generation)?;
                } else if !is_retired(&source_dir, claim_id, generation)?
                    && key_published(source, claim_id, generation)?
                {
                    let key = read_key(source, claim_id, generation)?;
                    let path = claim_key_path(destination, claim_id, generation)?;
                    if !publish_key(&dir, &path, claim_id, &key)? {
                        return Err(corrupt());
                    }
                }
            }
        }
        forked.directory.sync_all()?;
        Ok(())
    })();
    match copied {
        Ok(()) => Ok(Some(forked)),
        Err(err) => {
            forked.remove();
            Err(err)
        }
    }
}

pub(super) fn raw_key_retired(root: &Path, raw: &[u8]) -> Result<bool> {
    match raw_claim_generation(raw) {
        Some((claim, generation)) => generation_retired(root, &claim, generation),
        None => Ok(false),
    }
}

/// The claim and key generation an ORCB header names, read without a key.
pub(super) fn raw_claim_generation(raw: &[u8]) -> Option<([u8; 16], u64)> {
    if !is_orcb(raw) || raw.len() < HEADER_LEN + 16 {
        return None;
    }
    let claim: [u8; 16] = raw[5..21].try_into().ok()?;
    let generation = match raw[4] {
        VERSION => 0,
        ROTATED_VERSION if raw.len() >= ROTATED_HEADER_LEN + 16 => {
            u64::from_be_bytes(raw[HEADER_LEN..ROTATED_HEADER_LEN].try_into().ok()?)
        }
        _ => return None,
    };
    Some((claim, generation))
}

pub(super) fn is_orcb(raw: &[u8]) -> bool {
    raw.starts_with(MAGIC)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::SYNTHETIC_DICTIONARY;

    #[test]
    fn orcb_v1_dictionary_is_pinned_to_schema_only_tokens() {
        // Changing these bytes without changing the ORCB version silently
        // strands encrypted rows. This fingerprint pins the audited synthetic
        // field/enum corpus; it is not a live-record training fixture.
        let digest = Sha256::digest(SYNTHETIC_DICTIONARY);
        assert_eq!(
            format!("{digest:x}"),
            "0a4fd8b6e54aa65fca3f3ef2a50042e291ee3b00dd7a5bfe9d4faad824b68582"
        );
    }
}
