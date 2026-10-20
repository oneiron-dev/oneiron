//! Solo admission (INF 1): a call an own server runs alone, with nothing
//! batched beside it. The house EXL3 server runs up to four calls at once,
//! and batch invariance does not hold there for a long or multi-turn
//! request, so a call whose answer is compared with another's (an exact
//! replay, a shadow arm, a matched contribution fork, a bench identity row)
//! asks to run alone.
//!
//! The marker rides the host's own provider-options namespace
//! ([`HOST_PROVIDER_OPTIONS`]), which no adapter reads as its own. The
//! OpenAI-compatible wire sends it as a top-level `"oneiron_solo": true` to
//! a `local-openai-compat` provider alone; no other provider sees it.

use serde_json::{Map, Value};

use crate::LlmRequest;
use crate::code_run::HOST_PROVIDER_OPTIONS;

/// The solo marker's key in [`HOST_PROVIDER_OPTIONS`].
const SOLO_KEY: &str = "solo";

/// Marks `request` to run alone on an own server that admits calls so, and
/// keeps every other entry the host's namespace holds (its cache boundaries
/// among them). A namespace that is not an object holds no entry to keep: it
/// becomes one holding the marker.
pub fn mark_solo(request: &mut LlmRequest) {
    let options = request
        .provider_options
        .entry(HOST_PROVIDER_OPTIONS.to_owned())
        .or_insert(Value::Null);
    if !options.is_object() {
        *options = Value::Object(Map::new());
    }
    if let Value::Object(options) = options {
        options.insert(SOLO_KEY.to_owned(), Value::Bool(true));
    }
}

/// Whether `request` carries the solo marker.
#[must_use]
pub fn is_solo(request: &LlmRequest) -> bool {
    let solo = request
        .provider_options
        .get(HOST_PROVIDER_OPTIONS)
        .and_then(|options| options.get(SOLO_KEY));
    matches!(solo, Some(Value::Bool(true)))
}
