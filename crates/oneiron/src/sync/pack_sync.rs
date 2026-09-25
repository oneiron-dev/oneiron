//! PackByteMap sync seams: canonical wire form, echo mapping, and remote validation.
//!
//! Runtime kinds `128..247` resolve by namespaced [`PackKindIdentity`](crate::registry::pack_byte_map::PackKindIdentity)
//! plus exact source/schema hashes and local generation. The local u8 handle is
//! only an interning value; the wire byte is a lineage hint, never identity or
//! admission. [`PackInstanceEnvelope::canonical_wire_form`](crate::registry::pack_byte_map::PackInstanceEnvelope::canonical_wire_form)
//! restores the retained origin handle/generation while keeping exact
//! identity/payload. Reverse rematerialization must serialize that wire
//! header/body, not the receiver-local materialization, or differing local
//! handles create a rematerialization/byte-equality echo.
//!
//! Inbound rematerialization accepts a correctly registered name and remaps
//! source-local bytes before static schema rejection (the batch replay door
//! already maps by name). Echo comparisons use this module's canonical/local
//! mapping and never mutate. Foreign `ASSET` map snapshots are ordinary data:
//! they never authorize a local install (only an explicit local
//! `install_pack_kinds_in_txn` moves the head pin).
//!
//! Missing pack registration fails closed through the existing
//! quarantine/pending machinery ([`PackKindNotInstalled`](crate::error::ErrorKind::PackKindNotInstalled)
//! is quarantine-and-continue with a pending retry marker, so a later local
//! install heals via forward rematerialization). There is no generic allow.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, ErrorKind, Result};
use crate::registry::pack_byte_map::PackInstanceEnvelope;
use crate::registry::{TypeByteZone, zone_of};

/// Whether the type byte is a runtime-pack local handle.
#[must_use]
pub(crate) fn is_pack_handle(entity_type: u8) -> bool {
    zone_of(entity_type) == TypeByteZone::PackHandle
}

/// Canonical outbound bytes for one local row, or `None` when the row is not a pack instance.
///
/// For pack rows this decodes the local envelope and rebuilds the full blob
/// with the origin handle in the header and the canonical wire body
/// (`canonical_wire_form`: origin handle/generation, exact identity/payload).
/// The `occurred`/`learned_at` stamps are preserved from the local row.
///
/// A pack row that fails to decode is LOCAL corruption (our own LMDB wrote
/// it): the error propagates fail-closed and must never be quarantined as a
/// remote rejection. Callers use [`remote_pack_envelope_error`] for the raw
/// remote validation half.
pub(crate) fn canonical_outbound_blob(raw: &[u8]) -> Result<Option<Vec<u8>>> {
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Ok(None);
    };
    if !is_pack_handle(header.entity_type) {
        return Ok(None);
    }
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    let envelope = PackInstanceEnvelope::from_bytes(body)?;
    let (wire_handle, wire_body) = envelope.canonical_wire_form()?;
    let mut out = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + wire_body.len());
    out.push(wire_handle);
    out.extend_from_slice(&header.occurred_start.to_be_bytes());
    out.extend_from_slice(&header.occurred_end.to_be_bytes());
    out.extend_from_slice(&header.learned_at.to_be_bytes());
    out.extend_from_slice(&wire_body);
    Ok(Some(out))
}

/// Canonical echo comparison for one local row against one CRDT carrier.
///
/// `true` only when both blobs are pack rows with equal `occurred`/`learned_at`
/// stamps and equal kind identity, payload, and retained origin. The header
/// handle byte and the envelope's receiver-local `generation` are ignored:
/// they differ by construction after a name-based remap. Shared-handle (247)
/// subtypes stay distinct through the name plus allocation-generation
/// discriminator inside the compared identity/generation fields.
///
/// Decode failures return `false` (not echo): the caller proceeds to the
/// normal replay door, which quarantines a malformed REMOTE body via
/// [`remote_pack_envelope_error`] and fails closed on LOCAL corruption.
#[must_use]
pub(crate) fn pack_echo_equal(local: &[u8], remote: &[u8]) -> bool {
    let (Some(local_header), Some(remote_header)) = (
        EntityMetadataHeader::parse(local),
        EntityMetadataHeader::parse(remote),
    ) else {
        return false;
    };
    if !is_pack_handle(local_header.entity_type) || !is_pack_handle(remote_header.entity_type) {
        return false;
    }
    if local_header.occurred_start != remote_header.occurred_start
        || local_header.occurred_end != remote_header.occurred_end
        || local_header.learned_at != remote_header.learned_at
    {
        return false;
    }
    let (Ok(local_envelope), Ok(remote_envelope)) = (
        PackInstanceEnvelope::from_bytes(&local[ENTITY_METADATA_HEADER_LEN..]),
        PackInstanceEnvelope::from_bytes(&remote[ENTITY_METADATA_HEADER_LEN..]),
    ) else {
        return false;
    };
    local_envelope.kind == remote_envelope.kind
        && local_envelope.payload == remote_envelope.payload
        && local_envelope.origin == remote_envelope.origin
}

/// Stateless validation of a REMOTE pack body, before any local map read.
///
/// Returns `Some(InvalidPackByteMap)` only when the remote bytes themselves
/// are malformed. `None` means the remote shape is well-formed and the caller
/// must proceed to the name-based remap; a later `InvalidPackByteMap` from
/// that remap is then LOCAL state corruption (carrier drift, missing head)
/// and must fail closed, never quarantine. This split is what keeps the
/// quarantine classifier from blindly remote-classifying a corrupt local map.
#[must_use]
pub(crate) fn remote_pack_envelope_error(body: &[u8]) -> Option<Error> {
    PackInstanceEnvelope::from_bytes(body).err()
}

/// Whether a pack replay failure keeps its `rm:` retry marker pending.
///
/// Only [`ErrorKind::PackKindNotInstalled`] retries: the remote bytes are
/// well-formed data for a kind this vault has not installed yet, so the
/// quarantined carrier stays in the CRDT map and a later local install heals
/// it via forward rematerialization (lease-mirror OD-10 parity). Forged
/// identity ([`ErrorKind::PackKindNameCollision`]) and malformed bodies are
/// terminal: no local install can heal them.
#[must_use]
pub(crate) fn pack_rejection_keeps_retry_marker(error: &Error) -> bool {
    matches!(error.kind(), ErrorKind::PackKindNotInstalled)
}

#[cfg(test)]
mod tests;
