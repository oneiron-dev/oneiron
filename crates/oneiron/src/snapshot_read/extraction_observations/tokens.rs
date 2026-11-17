//! Domain-separated equality tokens over the native routing keys.

use crate::dreamer_consolidation::routing::CandidateKeys;
use crate::memory::{MemoryError, MemoryResult};

/// The word-free equality tokens of one native key triple and its slice.
pub(super) struct ObservationKeyTokens {
    /// The full conflict identity token.
    pub(super) identity: String,
    /// The question key token.
    pub(super) topic: String,
    /// The normalized value key token.
    pub(super) value: String,
    /// The same-slice tuple token.
    pub(super) slice: String,
}

/// Encodes the native identity fields in fixed-position canonical JSON arrays.
pub(super) fn observation_key_tokens(keys: &CandidateKeys) -> MemoryResult<ObservationKeyTokens> {
    let identity = &keys.identity;
    let subject = identity.subject.to_hex();
    let world = identity.world.map(|id| id.to_hex());
    let facet = identity.facet.map(|id| id.to_hex());
    let relationships = identity
        .rel
        .as_ref()
        .map(|ids| ids.iter().map(|id| id.to_hex()).collect::<Vec<_>>());
    let project = identity.project.to_hex();
    let encoded_identity = serde_json::to_vec(&(
        &subject,
        &identity.predicate,
        &world,
        &facet,
        &relationships,
        &project,
        &identity.topic,
    ))
    .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    let encoded_slice = serde_json::to_vec(&(&subject, &world, &facet, &relationships, &project))
        .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    Ok(ObservationKeyTokens {
        identity: equality_token(b"oneiron:extraction:identity-token:v1", &encoded_identity),
        topic: equality_token(b"oneiron:extraction:topic-token:v1", &keys.topic_key),
        value: equality_token(b"oneiron:extraction:value-token:v1", &keys.value_key),
        slice: equality_token(b"oneiron:extraction:slice-token:v1", &encoded_slice),
    })
}

/// Hashes native key bytes after one token-kind domain and a NUL separator.
fn equality_token(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(domain);
    hash.update(&[0]);
    hash.update(bytes);
    hash.finalize().to_hex().to_string()
}
