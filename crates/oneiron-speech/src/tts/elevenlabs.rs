//! ElevenLabs Flash's speech wire, `POST /v1/text-to-speech/{voice}`: one
//! call speaks one text in a provider voice and answers raw PCM16 at
//! [`PCM_RATE`]. The request rules both hosted wires share are
//! [`super::hosted::build`]'s.
use serde_json::{Value as JsonValue, json};

use super::hosted::PCM_RATE;

/// The path and body that speak `text` in the provider voice `voice` on the
/// provider's model `wire_model`. `voice` goes into the path, so
/// [`super::hosted::build`] checks it first.
pub(crate) fn speech_request(wire_model: String, text: &str, voice: &str) -> (String, JsonValue) {
    (
        format!("/v1/text-to-speech/{voice}?output_format=pcm_{PCM_RATE}"),
        json!({"model_id": wire_model, "text": text}),
    )
}
