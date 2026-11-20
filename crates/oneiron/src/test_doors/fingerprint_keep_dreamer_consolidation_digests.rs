//! K-proof door for dreamer-consolidation digests that existing records store or compare.
//! Compiled only under `oneiron_test_support`; never part of the engine API.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;

use oneiron_model::llm::{ModelId, ModelLocality};

use crate::EntityId;
use crate::dreamer_consolidation::{self as consolidation, WorkingSetTurn, root_evidence};

/// The call-labels digest a request carries: each kind's ids under its prefix
/// letter (`P`, `C`, `T`, `N`, `V`, `S`, `R`, `Q`) in assignment order, and
/// each choice question's options as shown.
#[must_use]
pub fn call_labels(
    mint: Option<&[u8]>,
    ids: &[(char, Vec<EntityId>)],
    choices: &BTreeMap<EntityId, Vec<String>>,
) -> [u8; 32] {
    consolidation::labels_digest_for_test(mint, ids, choices)
}

/// The follower's reported-cache pin, over the cache identity's JSON bytes.
#[must_use]
pub fn follower_reported_cache(identity_json: &[u8]) -> [u8; 32] {
    consolidation::cache_identity_digest_for_test(identity_json)
}

/// The follower's route pin.
#[must_use]
pub fn follower_route(model: &ModelId, locality: ModelLocality) -> [u8; 32] {
    consolidation::route_digest_for_test(model, locality)
}

/// A NOTE's text fingerprint, over its read mode and text.
#[must_use]
pub fn note_text(mode: &str, text: &str) -> [u8; 32] {
    consolidation::note_text_fingerprint_for_test(mode, text)
}

/// A round's partition-round hash over its TURNs at their own keys.
#[must_use]
pub fn partition_round(turns: &[WorkingSetTurn]) -> [u8; 32] {
    consolidation::partition_round_hash(turns)
}

/// A round's partition-round hash with carried TURNs at their carriers' ids.
#[must_use]
pub fn keyed_partition_round(
    turns: &[WorkingSetTurn],
    carried: &BTreeMap<EntityId, EntityId>,
) -> [u8; 32] {
    consolidation::keyed_partition_round_hash_for_test(turns, carried)
}

/// A child receipt's judgement hash, over the judgement's JSON bytes.
#[must_use]
pub fn child_judgement(encoded: &[u8]) -> [u8; 32] {
    root_evidence::judgement_digest_for_test(encoded)
}

/// An Arc composed in parts: its params hash, over the params JSON bytes.
#[must_use]
pub fn arc_parts_params(params: &[u8]) -> [u8; 32] {
    consolidation::arc_parts_params_hash_for_test(params)
}

/// An Arc composed in one call: its params hash, over the params JSON bytes.
#[must_use]
pub fn arc_composition_params(params: &[u8]) -> [u8; 32] {
    consolidation::arc_composition_params_hash_for_test(params)
}

/// A sitting composed in pages: its params hash, over the params JSON bytes.
#[must_use]
pub fn session_pages_params(params: &[u8]) -> [u8; 32] {
    consolidation::session_pages_params_hash_for_test(params)
}

/// A MESSAGE slice's attribution pin.
#[must_use]
pub fn message_attribution(
    imported: bool,
    authors: &[EntityId],
    speaker: Option<EntityId>,
) -> Option<[u8; 32]> {
    consolidation::attribution_hash_for_test(imported, authors, speaker)
}
