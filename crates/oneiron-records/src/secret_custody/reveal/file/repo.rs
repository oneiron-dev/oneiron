//! Moved from `crates/oneiron/src/secret_custody/reveal/file/repo.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Domain of a repo file read's identity digests and its fingerprint.
pub const REPO_FILE_DOMAIN: &[u8] = b"oneiron.secret_reveal.repo_file.v1";

/// The BLAKE3 of `fields` under [`REPO_FILE_DOMAIN`], each length-prefixed.
pub fn digest(fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REPO_FILE_DOMAIN);
    for field in fields {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    *hasher.finalize().as_bytes()
}

pub fn hex(bytes: &[u8; 32]) -> String {
    oneiron_contracts::entity_id::bytes_to_hex_lower(bytes)
}
