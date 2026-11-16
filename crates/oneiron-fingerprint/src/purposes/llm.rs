//! Purposes of model calls (`oneiron-model`'s `llm`).
//!
//! A call's request key and a media call's request hash are the plain BLAKE3 of the call's
//! sorted JSON (`llm::canonical_json_bytes`): steps memoize on the first, and receipts,
//! replies, decisions and replay keys name both. A session's binding crosses the native
//! channel to a model worker, which refuses an op on a handle bound to another, and a
//! segment manifest's digest is its admitted turn's identity. So each keeps its bytes (K,
//! PLAN-UC-04 stage 6.4b).

purposes! {}

legacy_purposes! {
    /// A model call's request key (`LlmRequest::canonical_hash`, and its hex form): plain
    /// BLAKE3 of the request's sorted JSON, with no tag or length.
    REQUEST = (Blake3, NotHashed, "oneiron.llm.request.v1");

    /// A media call's request hash (`MediaRequest::canonical_hash_hex`), the request half of
    /// its replay key (`MediaReplayKey`): plain BLAKE3 of the request's sorted JSON, with no
    /// tag or length, written as 64 lowercase hex digits.
    MEDIA_REQUEST = (Blake3, NotHashed, "oneiron.llm.media_request.v1");

    /// A segment manifest's digest (`SegmentManifest::digest`): BLAKE3, the tag's bytes (with
    /// its final NUL), then the sorted JSON of the segments, the anchor and the message
    /// stamps (nothing more when that JSON fails), with no lengths.
    SEGMENTS_MANIFEST = (Blake3, HashedFirst, "oneiron.llm.segments.manifest.v1\0");

    /// A session's binding (`SessionKey::binding`): BLAKE3, the tag's bytes (with its final
    /// NUL), then the sorted JSON of the key less its HEAD (the vault, read scope,
    /// conversation, fold epoch, identity and conditioning; nothing more when that JSON
    /// fails), with no lengths.
    SESSION_BINDING = (Blake3, HashedFirst, "oneiron.llm.session.binding.v1\0");
}
