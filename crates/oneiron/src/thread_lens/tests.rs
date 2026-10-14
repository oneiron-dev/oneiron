//! H131: the send card a person approves shows what its action dispatches.

use super::*;
use crate::outbound::{OutboundIntentDraft, OutboundIntentTrigger};

fn intent(channel: &str, target: &str) -> OutboundIntent {
    OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "send_dm", channel, target),
        OutboundIntentTrigger::agent_immediate("session:thread-lens"),
    )
}

fn instrument() -> ThreadLensInstrument {
    let entry = ThreadLensEntry::new("linkedin", "Jane Doe", "Thanks for reaching out.")
        .expect("thread entry");
    let send_box = ThreadLensSendBox::new(
        "intent:thread-lens",
        intent("linkedin", "linkedin:member:jane-doe"),
        "Happy to share more details.",
    )
    .expect("send box");
    ThreadLensInstrument::new(
        "thread-lens-jane",
        "Jane Doe",
        "linkedin",
        "2-jane-doe-abc",
        vec![entry],
        send_box,
    )
    .expect("instrument")
}

/// Every string value under `label: <label>` objects in the rendered card.
fn labelled_values(card: &GeneratedUiCard, label: &str) -> Vec<String> {
    fn walk(value: &serde_json::Value, label: &str, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                if map.get("label").and_then(serde_json::Value::as_str) == Some(label)
                    && let Some(found) = map.get("value").and_then(serde_json::Value::as_str)
                {
                    out.push(found.to_owned());
                }
                map.values().for_each(|child| walk(child, label, out));
            }
            serde_json::Value::Array(items) => {
                items.iter().for_each(|child| walk(child, label, out))
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(
        &serde_json::to_value(card).expect("card serializes"),
        label,
        &mut out,
    );
    out
}

#[test]
fn a_send_intent_swapped_after_validation_never_renders() {
    let mut swapped = instrument();
    swapped.send_box.intent = intent("email", "someone-else@example.com");
    assert!(
        swapped.card().is_err(),
        "a send on another channel renders no card"
    );

    let mut moved_entry = instrument();
    moved_entry.entries[0].channel = "email".to_owned();
    assert!(
        moved_entry.card().is_err(),
        "an entry from another channel renders no card"
    );

    assert!(
        instrument().card().is_ok(),
        "the instrument as built still renders"
    );
}

#[test]
fn the_send_card_names_the_target_its_action_dispatches_to() {
    let card = instrument().card().expect("card");
    assert_eq!(
        labelled_values(&card, "send to"),
        vec!["linkedin:member:jane-doe".to_owned()]
    );
}
