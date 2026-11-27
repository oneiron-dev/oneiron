use oneiron_contracts::msgpack::Entries;

use crate::code_run::{CodeRunBridgeCall, SelfCall, SelfEffect};
use crate::task_verb::sdk::{AgentVerb, RunVerb};

/// Refusal when a bound door cannot identify the call that produced an answer.
pub const RECORDED_ANSWER_UNIDENTIFIED: &str = "recorded_answer_unidentified";

/// The call a bound door must admit before releasing its recorded answer
/// (FIX CODE-MODE-LENDING-W11).
pub(crate) enum RecordedProducer {
    Bridge {
        effect: SelfEffect,
        row: Option<&'static str>,
        outer_skill_call: bool,
    },
    Verb(AgentVerb),
    Descriptor,
    Unidentified,
}

impl RecordedProducer {
    /// The offered call only after it has matched its stored row.
    pub(crate) fn of_call(call: &SelfCall, outer_skill_call: bool) -> Self {
        match call {
            SelfCall::Context(_) => Self::Descriptor,
            SelfCall::AgentVerb(call) => Self::Verb(call.verb),
            _ => Self::Bridge {
                effect: call.effect(),
                row: call.shared_effect_row(),
                outer_skill_call: outer_skill_call && matches!(call, SelfCall::SkillsCall(_)),
            },
        }
    }

    /// The original producer, even when the offered retry names another call.
    pub(crate) fn of_row(row: &CodeRunBridgeCall, outer_skill_call: bool) -> Self {
        let effect = row.effect;
        let row = match effect {
            SelfEffect::AgentVerb => {
                return row
                    .recorded_verb()
                    .and_then(AgentVerb::from_name)
                    .map_or(Self::Unidentified, Self::Verb);
            }
            SelfEffect::Context => return Self::Descriptor,
            SelfEffect::Fold | SelfEffect::Team | SelfEffect::Leader => {
                let Some(row) = shared_row(row) else {
                    return Self::Unidentified;
                };
                Some(row)
            }
            _ => None,
        };
        Self::Bridge {
            effect,
            row,
            outer_skill_call,
        }
    }
}

fn shared_row(row: &CodeRunBridgeCall) -> Option<&'static str> {
    let request = Entries::of(&row.request).ok()?;
    let verb = match row.effect {
        SelfEffect::Fold => {
            let call = serde_json::from_str(request.require("call").ok()?.as_str()?).ok()?;
            return SelfCall::Fold(call).shared_effect_row();
        }
        SelfEffect::Team => match request.get("verb").ok()? {
            Some(verb) if verb.as_str() == Some("submit") => RunVerb::SelfTeamSubmit,
            Some(_) => return None,
            None => {
                #[derive(serde::Deserialize)]
                struct TeamCallTag {
                    verb: String,
                }
                let call: TeamCallTag =
                    serde_json::from_str(request.require("call").ok()?.as_str()?).ok()?;
                match call.verb.as_str() {
                    "start" => RunVerb::SelfTeamStart,
                    "record" => RunVerb::SelfTeamRecord,
                    "vote" => RunVerb::SelfTeamVote,
                    _ => return None,
                }
            }
        },
        SelfEffect::Leader => match request.require("verb").ok()?.as_str()? {
            "advice" => RunVerb::SelfLeaderAdvice,
            "pattern" => RunVerb::SelfLeaderPattern,
            _ => return None,
        },
        _ => return None,
    };
    Some(verb.as_str())
}
