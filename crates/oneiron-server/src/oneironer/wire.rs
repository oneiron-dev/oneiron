//! The qualify case input as JSON writes it, shared by qualification and calibration.
//!
//! `oneiron oneironer qualify` reads it as each case's `input`, and the
//! bundle's `parity.json` as each reference case's: an [`EncoderInput`]
//! without its `following` and `register`, as contract version 2 sends it.
//! One type, so the two never drift.

use oneiron::memory::extraction::{
    EncoderInput, EncoderMessage, EncoderRegister, EncoderTurn, SpeakerRole,
};
use serde::Deserialize;

/// An [`EncoderInput`] as JSON writes it: a qualify case's input and a
/// reference case's.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireInput {
    turn: String,
    messages: Vec<WireMessage>,
    #[serde(default)]
    context: Vec<WireTurn>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    speaker: Option<SpeakerRole>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireMessage {
    id: String,
    text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireTurn {
    turn: String,
    messages: Vec<WireMessage>,
    #[serde(default)]
    speaker: Option<SpeakerRole>,
}

fn messages(wire: Vec<WireMessage>) -> Vec<EncoderMessage> {
    wire.into_iter()
        .map(|message| EncoderMessage {
            id: message.id,
            text: message.text,
        })
        .collect()
}

impl From<WireInput> for EncoderInput {
    fn from(wire: WireInput) -> Self {
        Self {
            turn: wire.turn,
            messages: messages(wire.messages),
            context: wire
                .context
                .into_iter()
                .map(|turn| EncoderTurn {
                    turn: turn.turn,
                    messages: messages(turn.messages),
                    speaker: turn.speaker,
                })
                .collect(),
            following: Vec::new(),
            register: EncoderRegister::Live,
            language: wire.language,
            speaker: wire.speaker,
        }
    }
}
