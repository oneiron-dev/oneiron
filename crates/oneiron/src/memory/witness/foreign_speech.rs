//! Foreign speech (FIX 15412): a TURN brought in from outside this vault,
//! whose words neither this vault's own person nor its own companion spoke,
//! speaks as a counterparty. A federation guest's TURN and a foreign
//! archive's TURN come here. The original speaker and the source's `actor`
//! byline ride inert beside the new speaker; a system notice, a tool or
//! injected row, and a TURN-shaped row with no speaker stay as they are.

use rmpv::Value;

use crate::dreamer_runner::{DreamerTurnRole, dreamer_turn_role};

/// A TURN's speaker aliases: the witness door's `speaker` and the scanner's
/// `spkr`, which the Dreamer reads first-wins (`decode_turn_body`).
const TURN_SPEAKER_ALIASES: [&str; 2] = ["speaker", "spkr"];

/// A native TURN's PERSON byline, and the inert key an import keeps it under.
pub(super) const TURN_KEY_ACTOR: &str = "actor";
pub(super) const TURN_KEY_IMPORT_ACTOR: &str = "import_actor";

/// The inert key a foreign TURN keeps its original speaker under.
const TURN_KEY_IMPORT_SPEAKER: &str = "import_speaker";

/// What [`speak_as_counterparty`] found in a TURN body's entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForeignTurn {
    /// No speaker alias reads as a person, an assistant or a counterparty: a
    /// system notice, a tool or injected row, an unknown speaker, or a
    /// TURN-shaped row with no speaker (a task artifact). Left as it is.
    NotSpeech,
    /// The TURN speaks as a counterparty, and its entries already said so.
    Unchanged,
    /// The TURN speaks as a counterparty now: a speaker alias or its byline
    /// changed.
    Relabelled,
}

/// Makes the entries of a TURN body brought in from outside this vault speak
/// as a counterparty. Each speaker alias (`speaker`, `spkr`) that this vault
/// reads as its own user or assistant (`dreamer_turn_role`, with the host's
/// `assistant_display_names`) becomes `counterparty`; the first original is
/// kept inert as `import_speaker`, unless the body already keeps one. A
/// speaking TURN's `actor` byline is kept inert as `import_actor`: the
/// source's writer is no local author. Idempotent: a TURN this already made
/// a counterparty's comes back [`ForeignTurn::Unchanged`].
pub(crate) fn speak_as_counterparty(
    entries: &mut Vec<(Value, Value)>,
    assistant_display_names: &[String],
) -> ForeignTurn {
    let counterparty = DreamerTurnRole::Counterparty.as_str();
    let mut original = None;
    let mut speaks = false;
    for (name, value) in &mut *entries {
        if !name
            .as_str()
            .is_some_and(|name| TURN_SPEAKER_ALIASES.contains(&name))
        {
            continue;
        }
        let Some(speaker) = value.as_str() else {
            continue;
        };
        match dreamer_turn_role(Some(speaker), assistant_display_names) {
            DreamerTurnRole::User | DreamerTurnRole::Assistant => {
                if original.is_none() {
                    original = Some(speaker.to_owned());
                }
                *value = Value::from(counterparty);
                speaks = true;
            }
            DreamerTurnRole::Counterparty => speaks = true,
            _ => {}
        }
    }
    if !speaks {
        return ForeignTurn::NotSpeech;
    }
    let mut changed = false;
    for (name, _) in &mut *entries {
        if name.as_str() == Some(TURN_KEY_ACTOR) {
            *name = Value::from(TURN_KEY_IMPORT_ACTOR);
            changed = true;
        }
    }
    if let Some(original) = original {
        changed = true;
        if !entries
            .iter()
            .any(|(name, _)| name.as_str() == Some(TURN_KEY_IMPORT_SPEAKER))
        {
            entries.push((Value::from(TURN_KEY_IMPORT_SPEAKER), Value::from(original)));
        }
    }
    if changed {
        ForeignTurn::Relabelled
    } else {
        ForeignTurn::Unchanged
    }
}
