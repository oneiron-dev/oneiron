//! The typed result a MESSAGE carries in place of an answer too large to say
//! (FIX 365): a bounded preview of the body, the run and occurrence that
//! produced it, and the facets that read the rest. The MESSAGE body keeps it
//! under one reserved metadata key; a transcript shows it as its own `result`
//! field. It names a body and grants nothing: every read of the body behind
//! it is admitted again for its reader, under the taint it has now.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::code_run::{
    CodeRunOutputKind, CodeRunOutputPreview, CodeRunRawOutput, ResultFacet, ResultOccurrence,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// The metadata key a MESSAGE's result attachment sits under. Only the
/// executor door writes it.
pub const MESSAGE_RESULT_METADATA_KEY: &str = "result";

/// Where a MESSAGE's result came from: the run that produced its body, that
/// run's occurrence of it, and its path in the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageResultSource {
    pub run_id: EntityId,
    /// The producer's occurrence: where the body's authority and taint came
    /// from. Never the MESSAGE's own hold on it.
    pub occurrence: EntityId,
    pub path: String,
}

/// One result attachment: what a MESSAGE says of a body it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageResultAttachment {
    pub source: MessageResultSource,
    /// The body's content handle (`code-run-output:blake3:<hex>`).
    pub handle: String,
    pub bytes: u64,
    /// `text` or `binary`.
    pub kind: String,
    pub lines: u64,
    /// Whether the producer finished the body.
    pub complete: bool,
    /// A bounded preview of the body's head, withheld while it is not clean.
    pub preview: String,
    pub preview_truncated: bool,
    /// The facets that read the rest of the body.
    pub more: Vec<ResultFacet>,
}

impl MessageResultAttachment {
    /// The attachment of `output`, run `run_id`'s occurrence of its body,
    /// with the preview its card shows now.
    pub(crate) fn of(
        run_id: EntityId,
        output: &CodeRunRawOutput,
        preview: String,
        preview_truncated: bool,
    ) -> Result<Self> {
        Ok(Self {
            source: MessageResultSource {
                run_id,
                occurrence: ResultOccurrence::owned(run_id, &output.path)?.id(),
                path: output.path.clone(),
            },
            handle: output.handle.clone(),
            bytes: output.raw_len,
            kind: match output.kind {
                CodeRunOutputKind::Text => "text",
                CodeRunOutputKind::Binary => "binary",
            }
            .to_owned(),
            lines: output.lines,
            complete: output.complete,
            preview,
            preview_truncated,
            more: ResultFacet::ALL.to_vec(),
        })
    }

    /// Why this attachment is not one the executor could have written, if
    /// it is not.
    pub fn invalid_reason(&self) -> Option<&'static str> {
        if handle_digest(&self.handle).is_none() {
            return Some("result handle is not a code-run output handle");
        }
        if !matches!(self.kind.as_str(), "text" | "binary") {
            return Some("result kind is neither text nor binary");
        }
        if self.more != ResultFacet::ALL {
            return Some("result facets differ from the result read facets");
        }
        if self.preview.chars().count() > crate::serialize::CODE_RUN_OUTPUT_PREVIEW_MAX_CHARS {
            return Some("result preview exceeds the preview bound");
        }
        match ResultOccurrence::owned(self.source.run_id, &self.source.path) {
            Ok(occurrence) if occurrence.id() == self.source.occurrence => None,
            _ => Some("result occurrence is not its run's occurrence of its path"),
        }
    }

    /// The manifest of the body this attachment names, at its producer's
    /// path: what a read of it resolves without the producer's replay.
    pub(crate) fn output(&self) -> Result<CodeRunRawOutput> {
        let corrupt = || Error::CorruptedIndex("message result attachment");
        if self.invalid_reason().is_some() {
            return Err(corrupt());
        }
        Ok(CodeRunRawOutput {
            handle: self.handle.clone(),
            path: self.source.path.clone(),
            raw_blake3: handle_digest(&self.handle).ok_or_else(corrupt)?,
            raw_len: self.bytes,
            kind: if self.kind == "text" {
                CodeRunOutputKind::Text
            } else {
                CodeRunOutputKind::Binary
            },
            lines: self.lines,
            complete: self.complete,
            input_rows: None,
            preview: CodeRunOutputPreview {
                codec: crate::serialize::CODE_RUN_OUTPUT_PREVIEW_CODEC.to_owned(),
                text: self.preview.clone(),
                truncated: self.preview_truncated,
            },
        })
    }

    /// The occurrence `message` holds of this body: its own, beside the
    /// producer's, so a hold adds a holder and never takes the run's place.
    pub(crate) fn message_occurrence(&self, message: EntityId) -> Result<EntityId> {
        Ok(ResultOccurrence::owned(message, &self.source.path)?.id())
    }

    /// MESSAGE metadata carrying this attachment and nothing else.
    pub(crate) fn to_metadata(&self) -> Result<Value> {
        let attachment = serde_json::to_value(self)
            .map_err(|_| Error::InvariantViolation("message result attachment encodes"))?;
        Ok(serde_json::json!({ MESSAGE_RESULT_METADATA_KEY: attachment }))
    }

    /// The attachment a MESSAGE's metadata carries, if any. `Err` names why
    /// a reserved value is not one.
    pub fn from_metadata(
        metadata: Option<&Value>,
    ) -> std::result::Result<Option<Self>, &'static str> {
        let Some(value) = metadata.and_then(|metadata| metadata.get(MESSAGE_RESULT_METADATA_KEY))
        else {
            return Ok(None);
        };
        let attachment: Self = serde_json::from_value(value.clone())
            .map_err(|_| "message result attachment does not decode")?;
        match attachment.invalid_reason() {
            Some(reason) => Err(reason),
            None => Ok(Some(attachment)),
        }
    }

    /// `metadata` less its reserved result key; `None` when nothing else is
    /// left.
    #[must_use]
    pub fn strip_metadata(metadata: Option<Value>) -> Option<Value> {
        match metadata {
            Some(Value::Object(mut fields)) => {
                fields.remove(MESSAGE_RESULT_METADATA_KEY);
                (!fields.is_empty()).then_some(Value::Object(fields))
            }
            other => other,
        }
    }
}

/// The digest a body's handle names.
fn handle_digest(handle: &str) -> Option<[u8; 32]> {
    let hex = handle.strip_prefix("code-run-output:blake3:")?;
    if hex.len() != 64 {
        return None;
    }
    let mut digest = [0; 32];
    for (byte, pair) in digest.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(digest)
}
