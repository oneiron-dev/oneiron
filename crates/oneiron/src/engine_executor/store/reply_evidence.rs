//! PERSON substitution only in the typed text of a model reply's evidence copy.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use zeroize::{Zeroize, Zeroizing};

use crate::code_run::ExecutorStorage;
use crate::{ContentPart, EntityId, Error, LlmMessage, LlmMessageRole, Result};

#[derive(Serialize)]
pub(super) struct ReplyEvidence<'a> {
    role: &'a LlmMessageRole,
    content: Vec<Cow<'a, ContentPart>>,
}

impl Drop for ReplyEvidence<'_> {
    fn drop(&mut self) {
        for part in &mut self.content {
            if let Cow::Owned(ContentPart::Text { text }) = part {
                text.zeroize();
            }
        }
    }
}

pub(super) fn for_run<'a>(
    storage: &ExecutorStorage<'_>,
    exec_run: EntityId,
    reply: &'a LlmMessage,
) -> Result<ReplyEvidence<'a>> {
    let source = storage.code_run_known_source(exec_run)?;
    let mut evidence = ReplyEvidence {
        role: &reply.role,
        content: Vec::with_capacity(reply.content.len()),
    };
    // Borrowed RawValues locate native typed fields in the exact full encoding;
    // no field-name search or independent scalar encoding chooses custody hits.
    let mut encoded = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *encoded, reply).map_err(encoding_error)?;
    let positions: EncodedReply<'_> = serde_json::from_slice(&encoded).map_err(encoding_error)?;
    for (part, encoded_part) in reply.content.iter().zip(positions.content) {
        let part = match part {
            ContentPart::Text { text } => {
                let position: EncodedText<'_> =
                    serde_json::from_str(encoded_part.get()).map_err(encoding_error)?;
                let scalar = position.text.get();
                let start = scalar.as_ptr() as usize - encoded.as_ptr() as usize;
                match source.replace_person_text(text, &encoded, start..start + scalar.len())? {
                    Some(text) => Cow::Owned(ContentPart::Text { text }),
                    None => Cow::Borrowed(part),
                }
            }
            _ => Cow::Borrowed(part),
        };
        evidence.content.push(part);
    }
    Ok(evidence)
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
