//! Contract v2 through the shipped serve path: a pronoun takes an earlier
//! turn's name through a context link, a speaker link names the turn's
//! author or the one other party of a 1:1 room, the request carries each
//! turn's side from its stored authors, and the served stack binds every
//! answer and every saved tag set. Every text here is fixture text written
//! for these tests.

use std::collections::BTreeSet;

use oneiron::EntityId;
use oneiron::attempt_queue::AttemptState;
use oneiron::edge::EdgeActorClass;
use oneiron::memory::WitnessAuthor;
use oneiron::memory::extraction::SpeakerTarget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::tagging::{
    MentionLink, MentionReference, OutputRefusal, TaggingFailure, TaggingOutcome, TurnTags,
};
use serde_json::{Value, json};

use super::support::{
    Answer, NOW, STACK, StubTagger, endpoint_config, make_room, markers, open_clocked_vault,
    open_saving_vault, open_vault_for, person, said, say, server, speaker, stack_card,
};
use super::worker::{Running, content_digests, outcomes, wait_until_long};
use crate::config::{OneironerConfig, OneironerMode};

const FIRST: &str = "Mira booked the flights";
const SECOND: &str = "I can drive her there";
const THIRD: &str = "She said thanks to you";
const FOURTH: &str = "Mira wrote back";
const OTHER_STACK: &str = "0f0f0f0f0f0f0f0f";

fn saving(stub: &StubTagger) -> OneironerConfig {
    OneironerConfig {
        mode: OneironerMode::Save,
        ..endpoint_config(&stub.base)
    }
}

fn pronoun(start: usize, end: usize) -> Value {
    json!({"message": 0, "start": start, "end": end, "label": "MENTION/PRONOUN", "confidence": 0.8})
}

/// The context turn and message of `body` whose text is `text`.
fn context_of(body: &Value, text: &str) -> Option<(String, String)> {
    body["context"].as_array()?.iter().find_map(|turn| {
        let message = turn["messages"]
            .as_array()?
            .iter()
            .find(|message| message["text"] == text)?;
        Some((
            turn["turn"].as_str()?.to_owned(),
            message["id"].as_str()?.to_owned(),
        ))
    })
}

/// A context link from `span` to "Mira" in the first turn, when the window
/// holds it.
fn to_mira(body: &Value, span: usize, confidence: f64) -> Value {
    let (turn, message) = context_of(body, FIRST).expect("the first turn is in the window");
    json!({"span": span, "turn": turn, "message": message, "start": 0, "end": 4, "confidence": confidence})
}

/// What a v2 tagger answers for the three fixture turns.
fn script(body: &Value) -> Value {
    let vad = json!({"valence": 0.2, "arousal": 0.4, "dominance": 0.6});
    match body["messages"][0]["text"].as_str().unwrap_or_default() {
        FIRST => json!({
            "spans": [{"message": 0, "start": 0, "end": 4, "label": "PERSON", "confidence": 0.97}],
            "links": [],
            "vad": vad,
        }),
        SECOND => json!({
            "spans": [pronoun(0, 1), pronoun(12, 15)],
            "links": [],
            "vad": vad,
            "context_links": [to_mira(body, 1, 0.9)],
            "speaker_links": [{"span": 0, "target": "speaker", "confidence": 0.98}],
        }),
        THIRD => json!({
            "spans": [pronoun(0, 3), pronoun(19, 22)],
            "links": [],
            "vad": vad,
            "context_links": [to_mira(body, 0, 0.93)],
            "speaker_links": [{"span": 1, "target": "addressee", "confidence": 0.95}],
        }),
        _ => json!({"spans": [], "links": []}),
    }
}

/// Whether a tagging marker still waits: queued, scheduled for a retry, or
/// leased by the stopped worker.
fn owes_a_pass(vault: &oneiron::Vault) -> bool {
    markers(vault).iter().any(|marker| {
        matches!(
            marker.state,
            AttemptState::Queued | AttemptState::Scheduled | AttemptState::Leased
        )
    })
}

fn tags(vault: &oneiron::Vault, turn: &EntityId) -> TurnTags {
    vault.turn_tags(turn).expect("tags read").expect("tagged")
}

fn person_link(entity: EntityId) -> MentionLink {
    MentionLink::Candidates {
        kind: ENTITY_TYPE_PERSON,
        entities: vec![entity],
    }
}

/// A context link whose earlier span the vault never saved keeps no
/// antecedent and is counted. A context link to a turn the request did not
/// send refuses the whole answer, and so do two spans at one place, which a
/// later context link could not tell apart; their markers wait.
#[test]
fn a_context_link_to_an_unsaved_span_is_counted_and_an_answer_off_the_contract_is_refused() {
    let stub = StubTagger::start(Answer::Good);
    stub.set_script(|body: &Value| {
        let text = body["messages"][0]["text"].as_str().unwrap_or_default();
        match text {
            FIRST => json!({"spans": [], "links": []}),
            // "booked" holds no saved span.
            SECOND => {
                let mut link = to_mira(body, 0, 0.7);
                link["start"] = json!(5);
                link["end"] = json!(11);
                json!({"spans": [pronoun(12, 15)], "links": [], "context_links": [link]})
            }
            FOURTH => json!({
                "spans": [{"message": 0, "start": 0, "end": 4, "label": "PERSON", "confidence": 0.9},
                          {"message": 0, "start": 0, "end": 4, "label": "ORG", "confidence": 0.6}],
                "links": [],
            }),
            _ => {
                let elsewhere = EntityId::from_bytes([0x5a; 16]).expect("id").to_hex();
                json!({
                    "spans": [pronoun(0, 3)],
                    "links": [],
                    "context_links": [{"span": 0, "turn": elsewhere, "message": elsewhere,
                                       "start": 0, "end": 3, "confidence": 0.7}],
                })
            }
        }
    });
    let dir = tempfile::tempdir().expect("dir");
    let (vault, clock) = open_clocked_vault(dir.path(), &saving(&stub));
    let owner = speaker(&vault);
    let room = make_room(
        &vault,
        0x73,
        &[owner, person(&vault, 0x23, "fixture friend")],
    );
    let user = |text, at| {
        clock.set(at);
        say(
            &vault,
            owner,
            room,
            None,
            said(WitnessAuthor::User, text, 0, None),
            at,
        )
    };
    let first = user(FIRST, NOW + 1);
    let second = user(SECOND, NOW + 2);
    let third = user(THIRD, NOW + 3);
    let fourth = user(FOURTH, NOW + 4);

    let tagged = server(&vault, Some(&saving(&stub)));
    let running = Running::start(&tagged);
    let refused = |why: OutputRefusal| {
        outcomes(&tagged).iter().any(|outcome| {
            matches!(
                outcome,
                TaggingOutcome::Failed {
                    failure: TaggingFailure::Refused { refusal },
                    ..
                } if *refusal == why
            )
        })
    };
    assert!(wait_until_long(|| {
        vault.turn_tags(&second).expect("read").is_some()
            && refused(OutputRefusal::UnknownContext)
            && refused(OutputRefusal::SpanOrder)
    }));
    running.stop();

    assert!(tags(&vault, &first).mentions.is_empty());
    let unsaved = &tags(&vault, &second).mentions[0];
    assert_eq!(unsaved.link, MentionLink::Tag);
    assert_eq!((unsaved.reference, unsaved.link_confidence), (None, None));
    assert!(outcomes(&tagged).iter().any(|outcome| matches!(
        outcome,
        TaggingOutcome::Saved {
            context_links: 1,
            unresolved_context_links: 1,
            ..
        }
    )));
    assert_eq!(vault.turn_tags(&third).expect("read"), None);
    assert_eq!(vault.turn_tags(&fourth).expect("read"), None);
    assert!(owes_a_pass(&vault), "the refused turns still owe a pass");
}

/// The served stack binds the answer: one naming another stack than the
/// card fails the call, saves nothing, and the marker waits.
#[test]
fn an_answer_naming_another_stack_than_its_card_fails_and_the_marker_waits() {
    let stub = StubTagger::start(Answer::Good);
    stub.set_answer_stack(OTHER_STACK);
    let dir = tempfile::tempdir().expect("dir");
    let vault = open_saving_vault(dir.path());
    let turn = super::support::witness(&vault, FIRST);
    let tagged = server(&vault, Some(&saving(&stub)));
    let running = Running::start(&tagged);
    assert!(wait_until_long(|| outcomes(&tagged).iter().any(
        |outcome| matches!(
            outcome,
            TaggingOutcome::Failed { failure: TaggingFailure::Call { code }, .. }
                if code == "tagger answer names another stack than its model card"
        )
    )));
    running.stop();
    assert_eq!(vault.turn_tags(&turn).expect("read"), None);
    assert!(owes_a_pass(&vault), "the turn still owes a pass");
}
