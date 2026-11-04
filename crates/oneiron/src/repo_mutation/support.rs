//! Path, digest, time and actor-name helpers for repository mutations.
//! The digest entry is `sha256_bytes`.
//! `deletion` owns the forwarded actor predicate; the other helpers are local.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

use super::types::RepoForkHash;
use crate::error::CodeError;


pub(super) use crate::git_wire::mutation_commands::truncate_failure;

pub(super) use crate::git_wire::mutation_commands::path_arg;

pub(super) use crate::git_wire::mutation_commands::utf8_trimmed;

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

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the mutation log or the proposals (FIX 3520).
pub(super) use crate::deletion::names_no_actor;

pub(super) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
