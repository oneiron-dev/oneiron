//! Cartesia Sonic's speech wire, `POST /tts/bytes`: one call speaks one text
//! in a provider voice and answers raw PCM16 at [`PCM_RATE`]. The request
//! rules both hosted wires share are [`super::hosted::build`]'s.
use serde_json::{Value as JsonValue, json};

use super::hosted::PCM_RATE;

/// The API version every Cartesia call names, its clone calls too.
pub const CARTESIA_VERSION: &str = "2026-08-14";

/// The path and body that speak `text` in the provider voice `voice` on the
/// provider's model `wire_model`. `voice` is checked by
/// [`super::hosted::build`] first.
pub(crate) fn speech_request(wire_model: String, text: &str, voice: &str) -> (String, JsonValue) {
    (
        "/tts/bytes".to_owned(),
        json!({
            "model_id": wire_model,
            "transcript": text,
            "voice": {"mode": "id", "id": voice},
            "output_format": {
                "container": "raw",
                "encoding": "pcm_s16le",
                "sample_rate": PCM_RATE,
            },
        }),
    )
}
