//! Purposes of model calls (`oneiron-model`'s `llm`, and the engine's `llm` steps and
//! trials).
//!
//! A call's request key and a media call's request hash are the plain BLAKE3 of the call's
//! sorted JSON (`llm::canonical_json_bytes`): steps memoize on the first, and receipts,
//! replies, decisions and replay keys name both. A session's binding crosses the native
//! channel to a model worker, which refuses an op on a handle bound to another, and a
//! segment manifest's digest is its admitted turn's identity. So each keeps its bytes (K,
//! PLAN-UC-04 stage 6.4b). A durable step's params identity, a public step's call hash
//! and a trial's measurements hash are the plain BLAKE3 of their values' sorted JSON too,
//! and keep their bytes (stage 6.4d).

purposes! {}

legacy_purposes! {
    /// A model call's request key (`LlmRequest::canonical_hash`, and its hex form): plain
    /// BLAKE3 of the request's sorted JSON, with no tag or length.
    REQUEST = (Blake3, NotHashed, "oneiron.llm.request.v1");

    /// A media call's request hash (`MediaRequest::canonical_hash`, and its hex form), the
    /// request half of its replay key (`MediaReplayKey`) and a durable media step's step
    /// hash (`call_media_as_step`): plain BLAKE3 of the request's sorted JSON, with no tag
    /// or length.
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

    /// A durable model step's params identity (`request_params_hash`), which a terminal
    /// `dreamer.step` claim stores and a memo hit compares: plain BLAKE3 of the request's
    /// params as sorted JSON, with no tag or length, written as 64 lowercase hex digits.
    STEP_PARAMS = (Blake3, NotHashed, "oneiron.llm.step.params.v1");

    /// A public model step's call hash, which its invocation claim holds
    /// (`model_step`'s submit): plain BLAKE3 of the submit's sorted JSON (step key, request,
    /// retry policy), with no tag or length.
    STEP_SUBMIT = (Blake3, NotHashed, "oneiron.llm.step.submit.v1");

    /// A model trial's measurements hash (`TrialEvidence::measurements_hash`), which an
    /// assessment must name: plain BLAKE3 of the sorted JSON of the trial's set pin, its
    /// frozen cases and its measurements, with no tag or length.
    TRIAL_MEASUREMENTS = (Blake3, NotHashed, "oneiron.llm.model_trials.measurements.v1");
}
