//! Domain-separated equality tokens over the native routing keys.

use crate::dreamer_consolidation::routing::CandidateKeys;
use crate::memory::{MemoryError, MemoryResult};
use oneiron_contracts::fingerprint::{LegacyDigest, LegacyPurpose, purposes};

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
        identity: equality_token(
            purposes::dreamer::EXTRACTION_IDENTITY_TOKEN,
            &encoded_identity,
        ),
        topic: equality_token(purposes::dreamer::EXTRACTION_TOPIC_TOKEN, &keys.topic_key),
        value: equality_token(purposes::dreamer::EXTRACTION_VALUE_TOKEN, &keys.value_key),
        slice: equality_token(purposes::dreamer::EXTRACTION_SLICE_TOKEN, &encoded_slice),
    })
}

/// Hashes native key bytes after one token kind's tag and a NUL separator. Each tag is a
/// legacy purpose: an observations page already sends these bytes, so they are kept (K,
/// PLAN-UC-04).
fn equality_token(purpose: LegacyPurpose, bytes: &[u8]) -> String {
    oneiron_hex::encode(&LegacyDigest::new(purpose).raw(&[0]).raw(bytes).finish())
}

/// [`observation_key_tokens`] as the identity, topic, value and slice tokens in that
/// order, for the K door (`test_doors::fingerprint_keep_extraction_read_digests`). Not API.
#[cfg(oneiron_test_support)]
pub(crate) fn observation_key_tokens_for_test(keys: &CandidateKeys) -> MemoryResult<[String; 4]> {
    let tokens = observation_key_tokens(keys)?;
    Ok([tokens.identity, tokens.topic, tokens.value, tokens.slice])
}
