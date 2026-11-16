//! Pages TURN locators and retains source versions as unchanged JSON values.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::extraction_selection::ExtractionSelectionConfig;

use super::{Error, Input, wire};
use crate::extraction_reply::BoundExtractionReply;

/// Names the attempt's inputs page.
const INPUTS: &str = "vault.consolidation.extraction.inputs.page";

/// Holds a TURN locator and its version exactly as the page served it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Turn {
    /// Names the served TURN in lowercase hexadecimal.
    pub turn: String,
    /// Preserves the whole served source version without reconstructing fields.
    pub version: Value,
}

/// Holds the complete served inputs under one policy.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Inputs {
    /// Retains every TURN in served order.
    pub(super) turns: Vec<Turn>,
    /// Caps each proposed extraction step's evidence count.
    pub(super) per_step: usize,
    /// Holds phase two's selection config.
    pub(super) config: ExtractionSelectionConfig,
    /// Pins the complete served extraction policy.
    pub(super) policy_pin: String,
}

/// Mirrors the page's scoped-read envelope.
#[derive(Deserialize)]
struct Envelope {
    /// Holds the served page, not the scoped-read metadata.
    value: Page,
}

/// Mirrors the inputs page without reconstructing selection fields.
#[derive(Deserialize)]
struct Page {
    /// Echoes the admitted attempt.
    attempt: String,
    /// Holds the page's effective policy.
    policy: Policy,
    /// Pins the whole extraction policy.
    policy_pin: String,
    /// Holds the served TURN locators in queue order.
    turns: Vec<Turn>,
    /// Names a cursor only when a later TURN can be served.
    next: Option<String>,
}

/// Retains the selection row verbatim for cross-page equality.
#[derive(Deserialize)]
struct Policy {
    /// Holds the selection policy JSON exactly as served.
    selection: Value,
}

/// Collects all pages, refusing moved policy or a stationary cursor.
pub(super) fn collect(input: Input<'_>) -> Result<Inputs, Error> {
    let mut cursor: Option<String> = None;
    let mut first: Option<(String, Value)> = None;
    let mut turns = Vec::new();
    loop {
        let answer = wire::call(
            input.client,
            INPUTS,
            json!({"attempt": input.attempt, "cursor": cursor, "limit": null}),
        )?;
        let page: Envelope = wire::decode(INPUTS, answer)?;
        let page = page.value;
        if page.attempt != input.attempt {
            return Err(Error::Decode {
                verb: INPUTS,
                message: "the page echoes another attempt".to_owned(),
            });
        }
        if let Some((pin, selection)) = &first {
            if pin != &page.policy_pin {
                return Err(Error::InputsChanged {
                    field: "policy_pin",
                });
            }
            if selection != &page.policy.selection {
                return Err(Error::InputsChanged {
                    field: "policy.selection",
                });
            }
        } else {
            first = Some((page.policy_pin, page.policy.selection));
        }
        turns.extend(page.turns);
        match page.next {
            None => break,
            Some(next) if cursor.as_ref() == Some(&next) => {
                return Err(Error::CursorDidNotAdvance);
            }
            Some(next) => cursor = Some(next),
        }
    }
    let (policy_pin, selection) = first.ok_or_else(|| Error::Decode {
        verb: INPUTS,
        message: "the inputs read served no policy".to_owned(),
    })?;
    let per_step = selection
        .get("extraction_turns_per_child")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .filter(|count| *count > 0)
        .ok_or_else(|| Error::Decode {
            verb: INPUTS,
            message: "extraction_turns_per_child must be a positive integer".to_owned(),
        })?;
    let config =
        ExtractionSelectionConfig::from_selection(selection, &policy_pin).map_err(|error| {
            Error::Decode {
                verb: INPUTS,
                message: error.to_string(),
            }
        })?;
    Ok(Inputs {
        turns,
        per_step,
        config,
        policy_pin,
    })
}

/// Rejects every reply TURN absent from the complete served inputs before any mint.
pub(super) fn check_reply_turns(
    replies: &[BoundExtractionReply],
    turns: &[Turn],
) -> Result<(), Error> {
    for reply in replies {
        for cited in reply
            .candidates
            .iter()
            .flat_map(|candidate| &candidate.evidence)
        {
            require_turn(&cited.turn, turns)?;
        }
        for person in &reply.persons {
            for turn in &person.turns {
                require_turn(turn, turns)?;
            }
        }
    }
    Ok(())
}

/// Requires membership without changing the served source version.
pub(super) fn require_turn(turn: &str, turns: &[Turn]) -> Result<(), Error> {
    if turns.iter().any(|served| served.turn == turn) {
        Ok(())
    } else {
        Err(Error::ReplyTurnNotServed {
            turn: turn.to_owned(),
        })
    }
}
