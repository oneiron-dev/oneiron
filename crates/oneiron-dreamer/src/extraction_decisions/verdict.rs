//! Calls bound verdicts, consuming only one typed layout refusal per read.

use oneiron_remote::OneironClient;
use serde_json::{Value, json};

use crate::conflict_decisions::{
    self, AnsweredPack, ConflictDecision, Correction, ExtractionLayout, ExtractionPack,
    ExtractionRead, Input, ResolutionInput, Step,
};

use super::Error;

const VERB: &str = "ai.verdict";

fn request(pack: &ExtractionPack) -> Result<Value, Error> {
    let question = match pack.read {
        ExtractionRead::Correction | ExtractionRead::CorrectionFinal => "correction",
        ExtractionRead::Resolution | ExtractionRead::ResolutionFinal => "resolution",
        ExtractionRead::IdentityFinal => "identity",
    };
    let first = pack
        .questions
        .first()
        .ok_or_else(|| Error::InvalidObservations("a verdict pack has no first question".into()))?;
    let state = serde_json::to_value(pack).map_err(|error| Error::Decode {
        verb: VERB,
        message: error.to_string(),
    })?;
    Ok(json!({
        "question": question,
        "contract": {"kind": "choice", "options": first.options},
        "evidence": [],
        "state": state,
        "ceiling": "big",
        "reversibility": "reversible_read",
        "routine": false,
        "misses": 0,
    }))
}

fn drive<T>(
    client: &OneironClient,
    mut step: impl FnMut(
        Option<&ExtractionLayout>,
        &[AnsweredPack],
    ) -> Result<Step<T>, conflict_decisions::Error>,
) -> Result<T, Error> {
    let mut layout = None;
    let mut history = Vec::new();
    loop {
        let pack = match step(layout.as_ref(), &history).map_err(Error::Decisions)? {
            Step::Finished(result) => return Ok(result),
            Step::Ask(pack) => pack,
        };
        match client.agent_verb(VERB, request(&pack)?) {
            Ok(answer) => history
                .push(conflict_decisions::read_answers(&pack, answer).map_err(Error::Decisions)?),
            Err(error) => {
                let encoded = serde_json::to_value(&error).map_err(|error| Error::Decode {
                    verb: VERB,
                    message: error.to_string(),
                })?;
                if encoded
                    .get("extraction_layout")
                    .is_some_and(|field| !field.is_null())
                {
                    if layout.is_some() {
                        return Err(Error::RepeatedLayout {
                            code: error.code,
                            message: error.message,
                        });
                    }
                    layout = Some(conflict_decisions::read_layout(&error).map_err(|failure| {
                        Error::Layout {
                            code: error.code,
                            message: error.message,
                            error: failure,
                        }
                    })?);
                    history.clear();
                } else {
                    return Err(Error::Client {
                        verb: VERB,
                        code: error.code,
                        message: error.message,
                    });
                }
            }
        }
    }
}

/// Drives the pure correction fold over successful bound answers.
pub(super) fn corrections(
    client: &OneironClient,
    input: Input<'_>,
) -> Result<Vec<Correction>, Error> {
    drive(client, |layout, history| {
        conflict_decisions::correction_step(input, layout, history)
    })
}

/// Drives one set's pure resolution fold over successful bound answers.
pub(super) fn resolution(
    client: &OneironClient,
    input: ResolutionInput<'_>,
) -> Result<ConflictDecision, Error> {
    drive(client, |layout, history| {
        conflict_decisions::resolution_step(input, layout, history)
    })
}
