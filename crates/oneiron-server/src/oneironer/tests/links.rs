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

/// The gate-2 acceptance on invented text: three turns of a 1:1 room are
/// witnessed, the worker settles them through the HTTP tagger, and the saved
/// tags read back. The third turn's pronoun takes the first turn's PERSON
/// through a context link; a speaker link names the turn's author, and the
/// addressee the one other party of the room; the mood is saved; and the save
/// writes no claim, edge, entity or merge.
#[test]
fn a_pronoun_takes_an_earlier_turns_name_and_a_speaker_link_names_its_person() {
    let stub = StubTagger::start(Answer::Good);
    stub.set_script(script);
    let dir = tempfile::tempdir().expect("dir");
    let (vault, clock) = open_clocked_vault(dir.path(), &saving(&stub));
    let owner = speaker(&vault);
    let companion = person(&vault, 0x22, "fixture companion");
    let room = make_room(&vault, 0x72, &[owner, companion]);
    let turn = |writer, author, text, at| {
        clock.set(at);
        say(&vault, writer, room, None, said(author, text, 0, None), at)
    };
    let first = turn(owner, WitnessAuthor::User, FIRST, NOW + 1);
    let second = turn(companion, WitnessAuthor::Companion, SECOND, NOW + 2);
    let third = turn(owner, WitnessAuthor::User, THIRD, NOW + 3);

    let tagged = server(&vault, Some(&saving(&stub)));
    let before = content_digests(&vault);
    let running = Running::start(&tagged);
    assert!(
        wait_until_long(|| vault.turn_tags(&third).expect("read").is_some()),
        "the third turn is tagged"
    );
    running.stop();

    let first_tags = tags(&vault, &first);
    let MentionLink::Minted { entity: mira, .. } = first_tags.mentions[0].link.clone() else {
        panic!("a name the vault does not know mints a provisional entity");
    };
    let second_tags = tags(&vault, &second);
    assert_eq!(second_tags.mentions[0].link, person_link(companion));
    assert_eq!(
        second_tags.mentions[0].reference,
        Some(MentionReference::Speaker {
            target: SpeakerTarget::Speaker,
            resolved: true,
        })
    );
    assert_eq!(second_tags.mentions[1].link, person_link(mira));
    assert_eq!(
        second_tags.mentions[1].reference,
        Some(MentionReference::Context)
    );
    assert_eq!(second_tags.mentions[1].link_confidence, Some(0.9));

    let third_tags = tags(&vault, &third);
    assert_eq!(third_tags.mentions[0].link, person_link(mira));
    assert_eq!(
        third_tags.mentions[0].reference,
        Some(MentionReference::Context)
    );
    assert_eq!(third_tags.mentions[0].antecedent, None);
    assert_eq!(third_tags.mentions[1].link, person_link(companion));
    assert_eq!(
        third_tags.mentions[1].reference,
        Some(MentionReference::Speaker {
            target: SpeakerTarget::Addressee,
            resolved: true,
        })
    );
    for saved in [&first_tags, &second_tags, &third_tags] {
        assert!(saved.mood.is_some(), "the mood is saved");
        assert_eq!(saved.envelope.stack.as_deref(), Some(STACK));
        assert!(saved.merge_evidence.is_empty());
    }
    let hits: BTreeSet<EntityId> = vault
        .tagged_mentions(&mira)
        .expect("search")
        .into_iter()
        .map(|hit| hit.turn)
        .collect();
    assert_eq!(
        hits,
        BTreeSet::from([first, second, third]),
        "every turn names her"
    );
    for outcome in outcomes(&tagged) {
        let TaggingOutcome::Saved {
            unresolved_context_links,
            unresolved_speaker_links,
            ..
        } = outcome
        else {
            panic!("every turn is saved: {outcome:?}");
        };
        assert_eq!((unresolved_context_links, unresolved_speaker_links), (0, 0));
    }
    // Saved tags are local derived rows: no entity, edge, claim or text
    // index changed, only the side tables and the job ledger.
    let changed: Vec<&str> = before
        .iter()
        .zip(content_digests(&vault))
        .filter(|(was, now)| **was != *now)
        .map(|(was, _)| was.0)
        .collect();
    assert!(
        changed.iter().all(|name| *name == "vault_meta"),
        "the save wrote outside its side tables: {changed:?}"
    );

    // The request names each turn's side from its stored author, never its
    // place in the room, and no language, which nothing stored names.
    let extracts = stub.extracts();
    let request = |turn: &EntityId| {
        extracts
            .iter()
            .find(|body| body["turn"] == turn.to_hex())
            .expect("tagged")
            .clone()
    };
    let third_request = request(&third);
    assert_eq!(third_request["speaker"], "A");
    assert_eq!(
        third_request["context"]
            .as_array()
            .expect("context")
            .iter()
            .map(|turn| turn["speaker"].clone())
            .collect::<Vec<_>>(),
        vec![json!("A"), json!("B")]
    );
    assert_eq!(request(&second)["speaker"], "B");
    assert!(extracts.iter().all(|body| body.get("language").is_none()));
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

/// A turn said in a room of three keeps its addressee unresolved after one
/// of the others leaves: the one other party left now may not have been the
/// only one there when the turn was said, so a room that has ever held a
/// third person is no pair.
#[test]
fn an_addressee_in_a_room_someone_has_left_since_stays_unresolved() {
    let stub = StubTagger::start(Answer::Good);
    stub.set_script(|_: &Value| {
        json!({
            "spans": [pronoun(10, 13)],
            "links": [],
            "speaker_links": [{"span": 0, "target": "addressee", "confidence": 0.95}],
        })
    });
    let dir = tempfile::tempdir().expect("dir");
    let (vault, clock) = open_clocked_vault(dir.path(), &saving(&stub));
    let owner = speaker(&vault);
    let friend = person(&vault, 0x25, "fixture friend");
    let neighbour = person(&vault, 0x26, "fixture neighbour");
    let room = make_room(&vault, 0x75, &[owner, friend, neighbour]);
    clock.set(NOW + 1);
    let turn = say(
        &vault,
        owner,
        room,
        None,
        said(WitnessAuthor::User, "Thanks to you", 0, None),
        NOW + 1,
    );
    clock.set(NOW + 2);
    vault
        .leave_member(
            room,
            neighbour,
            oneiron::WriteActor::new(owner, EdgeActorClass::Human),
            NOW + 2,
        )
        .expect("the neighbour leaves");

    let tagged = server(&vault, Some(&saving(&stub)));
    let running = Running::start(&tagged);
    assert!(wait_until_long(|| vault
        .turn_tags(&turn)
        .expect("read")
        .is_some()));
    running.stop();
    let you = &tags(&vault, &turn).mentions[0];
    assert_eq!(you.link, MentionLink::Tag, "nobody is picked");
    assert_eq!(
        you.reference,
        Some(MentionReference::Speaker {
            target: SpeakerTarget::Addressee,
            resolved: false,
        })
    );
    assert!(outcomes(&tagged).iter().any(|outcome| matches!(
        outcome,
        TaggingOutcome::Saved {
            unresolved_speaker_links: 1,
            ..
        }
    )));
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

/// A head swap at a fixed checkpoint owes every turn a new pass, as a trunk
/// swap does. A marker committed under the old stack is moved onto the new
/// one; and a turn the old stack tagged is tagged again under the new one,
/// although its text never changed, because the stack is part of its tags'
/// derivation.
#[test]
fn a_head_swap_at_a_fixed_checkpoint_owes_every_turn_a_new_pass() {
    let stub = StubTagger::start(Answer::Good);
    let dir = tempfile::tempdir().expect("dir");
    let pinned = |stack: &str| OneironerConfig {
        stack_sha16: Some(stack.to_owned()),
        ..saving(&stub)
    };
    let (owner, room, tagged_turn, waiting_turn);
    {
        let vault = open_vault_for(dir.path(), &pinned(STACK));
        owner = speaker(&vault);
        room = make_room(
            &vault,
            0x74,
            &[owner, person(&vault, 0x24, "fixture friend")],
        );
        tagged_turn = say(
            &vault,
            owner,
            room,
            None,
            said(WitnessAuthor::User, FIRST, 0, None),
            NOW,
        );
        let tagged = server(&vault, Some(&pinned(STACK)));
        let running = Running::start(&tagged);
        assert!(wait_until_long(|| vault
            .turn_tags(&tagged_turn)
            .expect("read")
            .is_some()));
        running.stop();
        drop(tagged);
        waiting_turn = say(
            &vault,
            owner,
            room,
            None,
            said(WitnessAuthor::User, THIRD, 0, None),
            NOW + 1,
        );
        assert_eq!(
            tags(&vault, &tagged_turn).envelope.stack.as_deref(),
            Some(STACK)
        );
    }

    // The new head reads moods another way; the trunk is the same.
    stub.set_card(stack_card(super::support::CHECKPOINT, OTHER_STACK));
    stub.set_script(|_: &Value| {
        json!({
            "spans": [{"message": 0, "start": 0, "end": 3, "label": "PERSON", "confidence": 0.9}],
            "links": [],
            "vad": {"valence": -0.5, "arousal": 0.5, "dominance": 0.5},
        })
    });
    let vault = open_vault_for(dir.path(), &pinned(OTHER_STACK));
    // An empty message owes the turn a pass and changes none of its text.
    say(
        &vault,
        owner,
        room,
        Some(tagged_turn),
        said(WitnessAuthor::User, "", 1, None),
        NOW + 2,
    );
    let tagged = server(&vault, Some(&pinned(OTHER_STACK)));
    let running = Running::start(&tagged);
    let under_new_head = |turn: &EntityId| {
        vault
            .turn_tags(turn)
            .expect("read")
            .is_some_and(|tags| tags.envelope.stack.as_deref() == Some(OTHER_STACK))
    };
    assert!(wait_until_long(
        || under_new_head(&tagged_turn) && under_new_head(&waiting_turn)
    ));
    running.stop();
    assert!(
        outcomes(&tagged)
            .iter()
            .any(|outcome| matches!(outcome, TaggingOutcome::Rekeyed)),
        "the marker committed under the old stack moved onto the new one"
    );
    let retagged = tags(&vault, &tagged_turn);
    assert_eq!(retagged.mood.map(|mood| mood.valence), Some(-0.5));
    assert_eq!(retagged.mentions[0].end, 3);
}
