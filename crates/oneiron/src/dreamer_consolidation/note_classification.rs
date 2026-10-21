//! The NOTE review's classification request and reply (ARCH-0032 stage 2,
//! OF-073). The request is the extraction request over one NOTE; the reply
//! is an extraction reply whose candidates the review promotes, and beside
//! them the NOTE's own fields: its `importance`, and the `topic_key` the
//! model names for its topic (FIX 907). A missing or malformed NOTE field
//! reads as absent: it never refuses a reply the extraction contract takes.

use super::call_labels::{CallLabelMap, LabelKind};
use super::executor::ConsolidationExecutor;
use super::executor::extraction::{ExtractedPerson, ExtractionReply, contract_reply, reply_json};
use super::extracted_people::MintNamespace;
use super::neighbourhood::Neighbourhood;
use super::roles::RoleCall;
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

/// A NOTE review's reply: the extraction contract's candidates and
/// persons, and the NOTE's own fields.
pub(super) struct NoteClassificationReply {
    /// The candidates, each the review's to write or skip.
    pub(super) candidates: Vec<serde_json::Value>,
    /// The people the reply declares, each `new:P<n>` its own (FIX 7506).
    pub(super) persons: Vec<ExtractedPerson>,
    /// How much the note itself matters to keep, when the model gave a
    /// number from 0 to 1.
    pub(super) importance: Option<f64>,
    /// The topic the model named for the note, trimmed, when it named one
    /// as a string that is not blank.
    pub(super) topic_key: Option<String>,
}

impl ConsolidationExecutor<'_> {
    /// The extraction request over one NOTE (OF-073): the same prompt and
    /// reply contract, with the NOTE's markdown as the only source, after
    /// the entities `listed` it names. The call names each by a label
    /// (FIX 7506): the note is `N1`, each listed entity `P<n>`. A citation
    /// quotes the note's words, and the review binds each quote to the exact
    /// text it read. It also asks the note's importance and its topic.
    /// `sealed_pad` is a sealed scratchpad's review and how it asks for
    /// the pad's `keep` lines (ARCH-0032 #scratchpad-marks). Returns the
    /// request and the label map its reply is read through, bound into the
    /// request's identity with the person-mint `namespace`.
    pub(super) fn note_request(
        call: &RoleCall<'_>,
        note: EntityId,
        listed: &Neighbourhood,
        markdown: &str,
        sealed_pad: Option<PadAsk>,
        scope: &crate::llm::Scope,
        namespace: &MintNamespace,
    ) -> Result<(LlmRequest, CallLabelMap)> {
        let mut labels = CallLabelMap::default();
        // The review holds no prior head: its listing shows entities only.
        let listing = listed.render(&mut labels, |_| false);
        let id = labels.assign(LabelKind::Note, note);
        let mut rule = format!(
            "The source is one note, not a conversation. Cite it as \
             {{\"source\": \"{id}\", \"quote\": \"<a short run of words copied \
             exactly from the note>\"}}: quote enough words that they occur only once \
             in the note. A person the note names, added under \"persons\", has \
             \"evidence_turn_refs\": [\"{id}\"]. Also give the object a key \
             \"importance\": a number from 0 to 1 for how much the note itself matters \
             to keep, and a key \"topic_key\": a short name for the one topic the note \
             is about, worded so that notes on the same topic get the same name."
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
        let mut request = Self::request_over(
            call,
            Some(rule),
            format!("{listing}note {id}\n{markdown}"),
            scope,
        )?;
        labels.bind_request(&mut request, Some(&namespace.identity()));
        Ok((request, labels))
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
    let ExtractionReply {
        candidates,
        persons,
    } = contract_reply(reply)?;
    Ok(NoteClassificationReply {
        candidates,
        persons,
        importance,
        topic_key,
    })
}
