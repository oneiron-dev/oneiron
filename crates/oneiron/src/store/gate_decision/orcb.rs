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

fn corrupt() -> Error {
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
/// material. A restore binds to the current exterior custody at that path, so
/// replacing an LMDB image cannot bring back a key already destroyed there.
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

/// First claim-bound append syncs the exterior directory entry before LMDB
/// may commit ciphertext. A short/zero final key is NEVER treated as absent.
/// Only an unpublished temporary file may be discarded on retry.
fn first_append_key(
    root: &Path,
    claim_id: &[u8; 16],
    generation: u64,
) -> Result<Zeroizing<[u8; 32]>> {
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
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err.into()),
    }
    let directory = safe_open(&dir, false, true)?;
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
    let suffix = rand::rngs::OsRng.next_u64();
    let temp = dir.join(format!(
        ".{}-{suffix:016x}.pending",
        crate::entity_id::bytes_to_hex_lower(claim_id)
    ));
    let published = (|| -> Result<bool> {
        let mut file = safe_open(&temp, true, false)?;
        file.write_all(&*key)?;
        file.sync_all()?;
        match fs::hard_link(&temp, &path) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(err) => Err(err.into()),
        }
    })();
    // Cleanup is unconditional, including I/O failure before publication.
    fs::remove_file(&temp)?;
    let published = published?;
    directory.sync_all()?;
    if published {
        Ok(key)
    } else {
        read_key(root, claim_id, generation)
    }
}

pub(super) fn encode_hot(root: &Path, record: &GateDecisionRecord) -> Result<Vec<u8>> {
    let claim_id = record.claim_id.ok_or_else(corrupt)?;
    let generation = key_generation(root, &claim_id)?;
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

/// Authenticate encrypted canonical rows against CURRENT exterior keys before
/// restore creates its destination. The image supplies a pointer, not a key;
/// deleted keys remain absent when an old checkpoint is replayed.
pub(crate) fn preflight_checkpoint_rows(rows: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
    use super::keys::GATE_DECISION_KEY_PREFIX;
    use crate::side_table::SideKey;
    let bound = rows
        .iter()
        .find(|(key, _)| key == CUSTODY_ROOT_KEY)
        .map(|(_, value)| decode_custody_root(value))
        .transpose()?;
    for (key, value) in rows {
        if key.starts_with(GATE_DECISION_KEY_PREFIX) && is_orcb(value) {
            let root = bound.as_deref().ok_or_else(corrupt)?;
            let id = key
                .strip_prefix(GATE_DECISION_KEY_PREFIX)
                .and_then(GateDecisionId::decode_key)
                .ok_or(Error::CorruptedIndex("gate decision ledger key"))?;
            decode_hot(root, id, value)?;
        }
    }
    Ok(())
}

/// Retire precisely the committed intent's generation. Later receipts use
/// a new generation, and neither an old snapshot nor a delayed finisher can
/// revive or destroy a different generation's key.
pub(super) fn retire_claim_key(root: &Path, claim_id: &[u8; 16], generation: u64) -> Result<()> {
    let dir = key_directory(root)?;
    let directory = safe_open(&dir, false, true)?;
    let marker = retired_marker(&dir, claim_id, generation);
    match safe_open(&marker, true, false) {
        Ok(file) => file.sync_all()?,
        Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            if !is_retired(&dir, claim_id, generation)? {
                return Err(corrupt());
            }
        }
        Err(err) => return Err(err),
    }
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

pub(super) fn raw_key_retired(root: &Path, raw: &[u8]) -> Result<bool> {
    if !is_orcb(raw) || raw.len() < HEADER_LEN + 16 {
        return Ok(false);
    }
    let claim: [u8; 16] = raw[5..21].try_into().map_err(|_| corrupt())?;
    let generation = match raw[4] {
        VERSION => 0,
        ROTATED_VERSION if raw.len() >= ROTATED_HEADER_LEN + 16 => u64::from_be_bytes(
            raw[HEADER_LEN..ROTATED_HEADER_LEN]
                .try_into()
                .map_err(|_| corrupt())?,
        ),
        _ => return Ok(false),
    };
    generation_retired(root, &claim, generation)
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
