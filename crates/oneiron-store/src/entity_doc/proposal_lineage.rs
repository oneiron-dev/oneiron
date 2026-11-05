//! The lineage that opened a text proposal, frozen in its review bundle
//! (DEC-0006 "Proposals, settlements and the review bundle"; FIX 5064,
//! 10931): the verified credential chains an owner's opening proof was
//! carried under. An explicit verdict a proof answers from that lineage, or
//! from a fork of it, never settles the proposal. An opening no owner proof
//! carried (a standing grant, a propose-only writer) freezes none, so it
//! excludes no one; an automatic grant landing is no verdict and is never
//! judged here.

use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::bytes_to_hex_lower;

/// A slip id spelled as 64 lowercase hex digits.
pub fn slip_id(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut id = [0u8; 32];
    for (byte, pair) in id.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    (bytes_to_hex_lower(&id) == text).then_some(id)
}
