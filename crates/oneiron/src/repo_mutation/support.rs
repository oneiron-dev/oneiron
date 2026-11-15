//! Path, digest, time and actor-name helpers for repository mutations.
//! The digest entry is `sha256_bytes`.
//! `deletion` owns the forwarded actor predicate; the other helpers are local.

use std::path::Path;

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
    oneiron_hex::encode(bytes)
}

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the mutation log or the proposals (FIX 3520).
pub(super) use crate::deletion::names_no_actor;
