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
const HEADER_LEN: usize = 4 + 1 + 16 + 16 + 12;
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
    let name = root.file_name().ok_or_else(corrupt)?.to_string_lossy();
    Ok(root.with_file_name(format!(".{name}.gate-decision-keys")))
}

fn claim_key_path(root: &Path, claim_id: &[u8; 16]) -> Result<PathBuf> {
    Ok(key_directory(root)?.join(crate::entity_id::bytes_to_hex_lower(claim_id)))
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

fn read_key(root: &Path, claim_id: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let dir = key_directory(root)?;
    let _ = safe_open(&dir, false, true)?;
    let mut file = safe_open(&claim_key_path(root, claim_id)?, false, false)?;
    let mut key = Zeroizing::new([0; 32]);
    file.read_exact(&mut *key).map_err(|_| corrupt())?;
    let mut extra = [0];
    if file.read(&mut extra)? != 0 {
        return Err(corrupt());
    }
    Ok(key)
}

/// First claim-bound append creates and syncs the key before LMDB commits the
/// ciphertext. An aborted transaction may leave an unused key, never a row
/// without its key. Existing keys must not be silently replaced after erasure.
fn first_append_key(root: &Path, claim_id: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let dir = key_directory(root)?;
    match fs::create_dir(&dir) {
        Ok(()) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err.into()),
    }
    let directory = safe_open(&dir, false, true)?;
    let path = claim_key_path(root, claim_id)?;
    let mut key = Zeroizing::new([0; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *key);
    match safe_open(&path, true, false) {
        Ok(mut file) => {
            file.write_all(&*key)?;
            file.sync_all()?;
            directory.sync_all()?;
            Ok(key)
        }
        Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            read_key(root, claim_id)
        }
        Err(err) => Err(err),
    }
}

pub(super) fn encode_hot(root: &Path, record: &GateDecisionRecord) -> Result<Vec<u8>> {
    let claim_id = record.claim_id.ok_or_else(corrupt)?;
    let key = first_append_key(root, &claim_id)?;
    let plain = encode_gate_decision(record)?;
    if plain.len() > MAX_PLAINTEXT {
        return Err(Error::InvariantViolation("gate decision ORCB size"));
    }
    let mut compressor = zstd::bulk::Compressor::with_dictionary(3, SYNTHETIC_DICTIONARY)
        .map_err(|_| Error::InvariantViolation("gate decision ORCB compress"))?;
    let compressed = compressor
        .compress(&plain)
        .map_err(|_| Error::InvariantViolation("gate decision ORCB compress"))?;
    let mut header = Vec::with_capacity(HEADER_LEN + compressed.len() + 16);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&claim_id);
    header.extend_from_slice(&record.decision_id.as_bytes());
    let mut nonce = [0; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    header.extend_from_slice(&nonce);
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
    if !raw.starts_with(MAGIC) || raw.len() < HEADER_LEN + 16 || raw[4] != VERSION {
        return Err(corrupt());
    }
    let claim_id: [u8; 16] = raw[5..21].try_into().map_err(|_| corrupt())?;
    if raw[21..37] != decision_id.as_bytes() {
        return Err(corrupt());
    }
    let key = read_key(root, &claim_id)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| corrupt())?;
    let nonce: [u8; 12] = raw[37..49].try_into().map_err(|_| corrupt())?;
    let compressed = cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &raw[HEADER_LEN..],
                aad: &raw[..HEADER_LEN],
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
