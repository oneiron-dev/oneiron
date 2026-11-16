//! Purposes of code runs (`crates/oneiron/src/code_run`).
//!
//! A model call's evidence record (`ModelCallRecord`, through `ModelCallKind::{Generate,
//! LabelRead, SeatDecision}`) stores a model call's messages, system and tools digests and a
//! native read's request hash. Each is the plain BLAKE3 of a value's sorted JSON
//! (`llm::canonical_json_bytes`), so each keeps its bytes (K, PLAN-UC-04 stage 6.4d).

purposes! {}

legacy_purposes! {
    /// A model call's messages digest (`ModelCallDigests::messages_digest`): plain BLAKE3 of
    /// the request's messages as sorted JSON, with no tag or length.
    MODEL_CALL_MESSAGES = (Blake3, NotHashed, "oneiron.code_run.model_call.messages.v1");

    /// A model call's system digest (`ModelCallDigests::system_digest`): plain BLAKE3 of the
    /// request's system messages, in order, as sorted JSON, with no tag or length.
    MODEL_CALL_SYSTEM = (Blake3, NotHashed, "oneiron.code_run.model_call.system.v1");

    /// A model call's tools digest (`ModelCallDigests::tools_digest`): plain BLAKE3 of the
    /// request's tools as sorted JSON, with no tag or length.
    MODEL_CALL_TOOLS = (Blake3, NotHashed, "oneiron.code_run.model_call.tools.v1");

    /// A native read's request hash (`NativeReadDigests::request_hash`): plain BLAKE3 of the
    /// sorted JSON of the label-read pack (`native_read_digests`: the state and each question's
    /// text, labels and paired question) or of the built native-seat body
    /// (`native_seat_read_digests`), with no tag or length.
    NATIVE_READ_REQUEST = (Blake3, NotHashed, "oneiron.code_run.native_read.request.v1");
}
