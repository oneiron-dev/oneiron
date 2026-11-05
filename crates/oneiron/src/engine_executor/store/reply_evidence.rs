//! PERSON substitution only in the typed text of a model reply's evidence copy.

use std::borrow::Cow;

use serde::Serialize;
use zeroize::Zeroize;

use crate::code_run::ExecutorStorage;
use crate::{ContentPart, EntityId, LlmMessage, LlmMessageRole, Result};

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
    for part in &reply.content {
        let part = match part {
            ContentPart::Text { text } => match source.replace_person_text(text)? {
                Some(text) => Cow::Owned(ContentPart::Text { text }),
                None => Cow::Borrowed(part),
            },
            _ => Cow::Borrowed(part),
        };
        evidence.content.push(part);
    }
    Ok(evidence)
}
