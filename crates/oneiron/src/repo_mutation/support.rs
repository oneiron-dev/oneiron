use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

use super::types::RepoForkHash;

const MAX_REPO_MUTATION_FAILURE_BYTES: usize = 4096;

pub(super) fn truncate_failure(message: &str) -> String {
    if message.len() <= MAX_REPO_MUTATION_FAILURE_BYTES {
        return message.to_owned();
    }
    let mut end = MAX_REPO_MUTATION_FAILURE_BYTES;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = message[..end].to_owned();
    out.push_str("...");
    out
}

pub(super) fn path_arg(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(Error::InvalidRepoMutationRecord("path must be UTF-8"))
}

pub(super) fn utf8_trimmed(bytes: Vec<u8>, context: &'static str) -> Result<String> {
    let text = String::from_utf8(bytes).map_err(|_| Error::InvalidRepoMutationRecord(context))?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

pub(super) fn sha256_bytes(bytes: &[u8]) -> RepoForkHash {
    let digest = Sha256::digest(bytes);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(super) fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

pub(super) fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

pub(super) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
