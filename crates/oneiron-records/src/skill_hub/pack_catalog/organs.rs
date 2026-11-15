//! Moved from `crates/oneiron/src/skill_hub/pack_catalog/organs.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;

pub const MAX_ORGAN_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// The calls at once an organ runs with when its facet names no `threads`,
/// as the organ host's first-party spec sets it.
pub const DEFAULT_ORGAN_THREADS: u16 = 2;

/// The memory an organ runs with when its facet names no `memory_bytes`,
/// as the organ host's first-party spec sets it.
pub const DEFAULT_ORGAN_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

pub fn is_name(value: &str) -> bool {
    value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

pub fn is_media_type(value: &str) -> bool {
    value.split_once('/').is_some_and(|(kind, sub)| {
        !kind.is_empty()
            && !sub.is_empty()
            && value
                .bytes()
                .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\\'))
    })
}

pub fn is_platform(value: &str) -> bool {
    value.len() <= 64
        && (2..=4).contains(&value.split('-').count())
        && value.split('-').all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.')
                })
        })
}
