//! PERSON substitution only in the typed text of a model reply's evidence copy.

use serde::Deserialize;
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use crate::code_run::ExecutorStorage;
use crate::{ContentPart, EntityId, Error, LlmMessage, Result};

/// Sweeps the original encoding once, with PERSON spans restricted to typed
/// Text parts. Without PERSON prints, skips encoding and leaves the ordinary
/// custody-sweeping JSON sink in place.
pub(super) fn for_run_bytes(
    storage: &ExecutorStorage<'_>,
    exec_run: EntityId,
    reply: &LlmMessage,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let source = storage.code_run_known_source(exec_run)?;
    source.replace_reply_person_texts(|| {
        // Borrowed RawValues locate typed fields only when PERSON prints exist.
        let mut encoded = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *encoded, reply).map_err(encoding_error)?;
        let positions: EncodedReply<'_> =
            serde_json::from_slice(&encoded).map_err(encoding_error)?;
        let mut texts = Vec::with_capacity(reply.content.len());
        for (part, encoded_part) in reply.content.iter().zip(positions.content) {
            let ContentPart::Text { text, .. } = part else {
                continue;
            };
            let position: EncodedText<'_> =
                serde_json::from_str(encoded_part.get()).map_err(encoding_error)?;
            let scalar = position.text.get();
            let start = scalar.as_ptr() as usize - encoded.as_ptr() as usize;
            texts.push((text.as_str(), start..start + scalar.len()));
        }
        Ok((encoded, texts))
    })
}

#[derive(Deserialize)]
struct EncodedReply<'a> {
    #[serde(borrow)]
    content: Vec<&'a RawValue>,
}

#[derive(Deserialize)]
struct EncodedText<'a> {
    #[serde(borrow)]
    text: &'a RawValue,
}

fn encoding_error(error: serde_json::Error) -> Error {
    Error::InvalidConfig(format!("result body encoding failed: {error}"))
}
