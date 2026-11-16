//! `ai.ask_image`'s input, answer and receipt (OF-329, FIX 679): one
//! question about an image's pixels to the host's Local-vision seat, by the
//! view handle the image was served with. `POST /v1/ai/ask_image` and the
//! verb's host door share these shapes and one answering path; an embedded
//! handle has no seat and refuses it.
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::host::ask_image::AskImageRequest;

#[doc(hidden)]
pub use oneiron_records::verbs::host::ask_image::{AskImageAnswer, AskImageReceipt};
