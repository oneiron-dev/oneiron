//! The NOTE review's classification request and reply (ARCH-0032 stage 2,
//! OF-073). The request is the extraction request over one NOTE; the reply
//! is an extraction reply whose candidates the review promotes, and beside
//! them the NOTE's own fields: its `importance`, and the `topic_key` the
//! model names for its topic (FIX 907). A missing or malformed NOTE field
//! reads as absent: it never refuses a reply the extraction contract takes.

use super::executor::ConsolidationExecutor;
use super::executor::extraction::{ExtractionReply, contract_reply, reply_json};
use super::roles::RoleCall;
use crate::entity_id::bytes_to_hex_lower;
use crate::llm::{LlmRequest, LlmResponse};
use crate::{EntityId, Result};

/// How a sealed scratchpad's review asks for its `keep` lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PadAsk {
    /// The first read: scratch lines blanked; `keep` when a line is marked
    /// `keep`.
    First { keep: bool },
    /// The one re-ask (FIX 2240): only the `keep` lines the last review
    /// grounded no belief in are left; every other line is blank.
    Missed,
}

/// A NOTE review's reply: the extraction contract's candidates and the
/// NOTE's own fields.
pub(super) struct NoteClassificationReply {
    /// The candidates, each the review's to write or skip.
    pub(super) candidates: Vec<serde_json::Value>,
    /// How much the note itself matters to keep, when the model gave a
    /// number from 0 to 1.
    pub(super) importance: Option<f64>,
    /// The topic the model named for the note, trimmed, when it named one
    /// as a string that is not blank.
    pub(super) topic_key: Option<String>,
}

impl ConsolidationExecutor<'_> {
    /// The extraction request over one NOTE (OF-073): the same prompt and
    /// reply contract, with the NOTE's markdown as the only source. Its
    /// byte ranges count over that markdown, so the review can check each
    /// one against the exact text it read. It also asks the note's
    /// importance and its topic.
    /// `sealed_pad` is a sealed scratchpad's review and how it asks for
    /// the pad's `keep` lines (ARCH-0032 #scratchpad-marks).
    pub(super) fn note_request(
        call: &RoleCall<'_>,
        note: EntityId,
        markdown: &str,
        sealed_pad: Option<PadAsk>,
        scope: &crate::llm::Scope,
    ) -> Result<LlmRequest> {
        let id = bytes_to_hex_lower(note.as_bytes());
        let mut rule = format!(
            "The source is one note, not a conversation. Cite it as \
             {{\"source_id\": \"{id}\", \"byte_range\": [start, end]}}, a range of \
             UTF-8 bytes of the note's markdown, which starts on the line after its \
             header. Also give the object a key \"importance\": a number from 0 to 1 \
             for how much the note itself matters to keep, and a key \"topic_key\": \
             a short name for the one topic the note is about, worded so that notes \
             on the same topic get the same name."
        );
        match sealed_pad {
            Some(PadAsk::First { keep }) => {
                rule.push_str(
                    " The note is a sealed scratchpad. Blank lines held text its writer \
                     marked scratch: cite none of them.",
                );
                if keep {
                    rule.push_str(
                        " A line headed [keep] or [pin keep] states a fact its writer \
                         asked to keep: extract each one.",
                    );
                }
                rule.push_str(" Decide each other line on its own.");
            }
            Some(PadAsk::Missed) => rule.push_str(
                " The note is a sealed scratchpad, asked again. Blank lines were read \
                 before or marked scratch: cite none of them. Each line left is headed \
                 [keep] or [pin keep]: a fact its writer asked to keep that the last \
                 review grounded no belief in. Extract each one.",
            ),
            None => {}
        }
        Self::request_over(call, Some(rule), format!("note {id}\n{markdown}"), scope)
    }
}

/// `response` as a NOTE review reads it. It is refused exactly when the
/// extraction reply is; the NOTE's own fields never refuse it.
pub(super) fn note_classification_reply(response: &LlmResponse) -> Result<NoteClassificationReply> {
    let reply = reply_json(response)?;
    let importance = reply
        .get("importance")
        .and_then(serde_json::Value::as_f64)
        .filter(|importance| (0.0..=1.0).contains(importance));
    let topic_key = reply
        .get("topic_key")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|topic| !topic.is_empty())
        .map(str::to_owned);
    let ExtractionReply { candidates, .. } = contract_reply(reply)?;
    Ok(NoteClassificationReply {
        candidates,
        importance,
        topic_key,
    })
}
