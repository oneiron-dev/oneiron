//! Linked parts for a window carrier too large for one map value (Rule 5).
//!
//! A carrier over [`PART_BYTES`] rides as its parts, each under `part/` and
//! the digest of its bytes in the same root map, and a manifest that lists
//! them in order. No size is skipped: any carrier splits into as many parts
//! as it needs, and a receiver joins them once all have landed.

use std::collections::BTreeSet;

use loro::{LoroMap, LoroValue, ValueOrContainer};
use serde::{Deserialize, Serialize};

use super::loro_support::{map_contains_binary, map_get_bytes, map_insert_bytes};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};

/// The largest part a window carries, and so the largest carrier that rides
/// whole.
pub(crate) const PART_BYTES: usize = 1 << 20;

/// The key prefix of a part.
const PART: &str = "part/";

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("carrier part refused: {reason}"))
}

/// The parts of one carrier, in order, by the digest of each.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Parts {
    /// The carrier's length in bytes.
    pub(crate) len: u64,
    /// The blake3 digest of each part.
    pub(crate) parts: Vec<[u8; 32]>,
}

impl Parts {
    /// Whether this is the one split of a carrier of its length: every part
    /// but the last full, and the last nonempty.
    pub(crate) fn well_formed(&self) -> bool {
        let Ok(len) = usize::try_from(self.len) else {
            return false;
        };
        len > 0 && self.parts.len() == len.div_ceil(PART_BYTES)
    }

    /// The map key of each part.
    pub(crate) fn keys(&self) -> impl Iterator<Item = String> + '_ {
        self.parts.iter().map(part_key)
    }
}

/// The map key of the part whose digest is `digest`.
pub(crate) fn part_key(digest: &[u8; 32]) -> String {
    format!("{PART}{}", bytes_to_hex_lower(digest))
}

/// Whether `map_key` names a part.
pub(crate) fn is_part_key(map_key: &str) -> bool {
    map_key.starts_with(PART)
}

/// Splits `bytes` into its parts: the manifest, and each part under its key.
pub(crate) fn split_parts(bytes: &[u8]) -> Result<(Parts, Vec<(String, &[u8])>)> {
    let mut digests = Vec::new();
    let mut pieces = Vec::new();
    for part in bytes.chunks(PART_BYTES) {
        let digest = *blake3::hash(part).as_bytes();
        pieces.push((part_key(&digest), part));
        digests.push(digest);
    }
    let len = u64::try_from(bytes.len()).map_err(|_| refused("too long"))?;
    Ok((
        Parts {
            len,
            parts: digests,
        },
        pieces,
    ))
}

/// Writes each of `pieces` that `map` lacks. The caller writes the manifest
/// first, so a scrub never finds the parts with no manifest that lists them;
/// it commits.
pub(crate) fn write_parts(map: &LoroMap, pieces: &[(String, &[u8])]) -> Result<()> {
    for (key, part) in pieces {
        if !map_contains_binary(map, key) {
            map_insert_bytes(map, key, part)?;
        }
    }
    Ok(())
}

/// The carrier `parts` lists, joined from `map`; `None` while a part has not
/// landed.
pub(crate) fn join_parts(map: &LoroMap, parts: &Parts) -> Option<Vec<u8>> {
    if !parts.well_formed() {
        return None;
    }
    let mut bytes = Vec::with_capacity(usize::try_from(parts.len).ok()?);
    for digest in &parts.parts {
        let part = map_get_bytes(map, &part_key(digest))?;
        if blake3::hash(&part).as_bytes() != digest {
            return None;
        }
        bytes.extend_from_slice(&part);
    }
    (bytes.len() == usize::try_from(parts.len).ok()?).then_some(bytes)
}

/// Admits one part insert: nonempty, no larger than a part, and filed under
/// its own digest.
pub(crate) fn admit_part(map_key: &str, value: &LoroValue) -> Result<()> {
    let LoroValue::Binary(bytes) = value else {
        return Err(refused("not bytes"));
    };
    if bytes.is_empty() || bytes.len() > PART_BYTES {
        return Err(refused("not a part's length"));
    }
    if part_key(blake3::hash(bytes).as_bytes()) != map_key {
        return Err(refused("filed under another key"));
    }
    Ok(())
}

/// The key of each part `map` holds that no carrier in `referenced` lists.
pub(crate) fn unreferenced_parts(map: &LoroMap, referenced: &BTreeSet<String>) -> Vec<String> {
    let mut gone = Vec::new();
    map.for_each(|map_key, value| {
        if is_part_key(map_key)
            && matches!(value, ValueOrContainer::Value(LoroValue::Binary(_)))
            && !referenced.contains(map_key)
        {
            gone.push(map_key.to_owned());
        }
    });
    gone
}
