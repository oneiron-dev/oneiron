//! The served stack's goldens replayed through the adapter and the save
//! path. The model lane recorded `turns-v1.sidecar-v2.json` from the real
//! served stack (NER, coreference and VAD heads; contract v2) on the 200
//! invented turns of `turns-v1.jsonl`, which carry no real conversation. The
//! stub serves the recorded card and answers; the engine must send each turn
//! exactly as the fixture holds it, and save what the stack answered.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::memory::WitnessAuthor;
use oneiron::memory::extraction::EncoderGolden;
use oneiron::tagging::{MentionReference, TaggingOutcome};
use serde_json::{Value, json};

use super::support::{
    Answer, NOW, StubTagger, endpoint_config, open_clocked_vault, said, say, server, speaker,
};
use super::worker::{Running, outcomes};
use crate::config::{OneironerConfig, OneironerMode};

const FIXTURE: &str = include_str!("golden/turns-v1.jsonl");
const GOLDENS: &str = include_str!("golden/turns-v1.sidecar-v2.json");

/// The fixture's turns: each record's earlier turns are its conversation's.
fn records() -> Vec<Value> {
    FIXTURE
        .lines()
        .map(|line| serde_json::from_str(line).expect("fixture record"))
        .collect()
}

/// A request as the fixture holds it: the turn, its messages and its window,
/// each message an id and a text.
fn as_sent(body: &Value) -> Value {
    let messages = |turn: &Value| -> Value {
        turn["messages"]
            .as_array()
            .expect("messages")
            .iter()
            .map(|message| json!({"id": message["id"], "text": message["text"]}))
            .collect()
    };
    json!({
        "turn": body["turn"],
        "messages": messages(body),
        "context": body["context"]
            .as_array()
            .expect("context")
            .iter()
            .map(|turn| json!({"turn": turn["turn"], "messages": messages(turn)}))
            .collect::<Vec<_>>(),
    })
}

#[test]
fn the_served_stacks_goldens_replay_through_the_adapter_and_the_save() {
    let goldens: Value = serde_json::from_str(GOLDENS).expect("goldens");
    let card = goldens["runtime_detail"]["card"].clone();
    let stack = card["stack_sha16"].as_str().expect("stack").to_owned();
    let answers: BTreeMap<String, Value> = records()
        .iter()
        .zip(goldens["records"].as_array().expect("records"))
        .map(|(record, golden)| {
            assert_eq!(record["turn"], golden["turn"], "one golden per record, in order");
            (
                record["turn"].as_str().expect("turn").to_owned(),
                golden["golden"]["output"].clone(),
            )
        })
        .collect();
    // Each recorded answer is an `EncoderGolden` of the served model.
    for golden in goldens["records"].as_array().expect("records") {
        let golden: EncoderGolden =
            serde_json::from_value(golden["golden"].clone()).expect("an encoder golden");
        assert_eq!(golden.model, "oneironer/endpoint@eeeaf8bea4e8d166");
        assert_eq!(golden.output.stack_sha16.as_deref(), Some(stack.as_str()));
    }

    let stub = StubTagger::start(Answer::Good);
    stub.set_card(card.clone());
    stub.set_script(move |body: &Value| {
        answers
            .get(body["turn"].as_str().unwrap_or_default())
            .cloned()
            .unwrap_or_else(|| json!({"spans": [], "links": []}))
    });
    let section = OneironerConfig {
        mode: OneironerMode::Save,
        checkpoint_sha16: card["checkpoint_sha16"].as_str().map(str::to_owned),
        stack_sha16: Some(stack.clone()),
        label_count: card["label_count"]
            .as_u64()
            .and_then(|count| u32::try_from(count).ok()),
        labels: ["PERSON", "ORG", "PLACE"]
            .map(|label| (label.to_owned(), label.to_owned()))
            .into(),
        // Every fixture window is its turn's whole conversation, at most 15
        // turns and 4,399 characters: a window this wide sends it whole.
        live_window_tokens: 300,
        ..endpoint_config(&stub.base)
    };
    section.validate().expect("the profile's section");
    let dir = tempfile::tempdir().expect("dir");
    let (vault, clock) = open_clocked_vault(dir.path(), &section);
    let owner = speaker(&vault);

    // Each conversation is a room; its turns are a second apart, in order,
    // and so are their markers, so each turn is tagged after the turns
    // before it.
    let records = records();
    let mut room_of: BTreeMap<String, EntityId> = BTreeMap::new();
    for (at, record) in (NOW + 1..).zip(&records) {
        clock.set(at);
        let context = record["context"].as_array().expect("context");
        let room = match context.first() {
            None => EntityId::from_bytes([0x80 + u8::try_from(room_of.len() % 64).expect("u8"); 16])
                .expect("room id"),
            Some(earlier) => room_of[earlier["turn"].as_str().expect("turn")],
        };
        let turn = record["turn"].as_str().expect("turn");
        room_of.insert(turn.to_owned(), room);
        let turn = EntityId::from_hex(turn).expect("turn id");
        for (order, message) in (0_u32..).zip(record["messages"].as_array().expect("messages")) {
            // The goldens read every turn as the user's side.
            let message = said(
                WitnessAuthor::User,
                message["text"].as_str().expect("text"),
                order,
                message["id"].as_str(),
            );
            say(&vault, owner, room, Some(turn), message, at);
        }
    }
    assert_eq!(room_of.values().collect::<BTreeSet<_>>().len(), 35);

    let tagged = server(&vault, Some(&section));
    let running = Running::start(&tagged);
    let deadline = Instant::now() + Duration::from_secs(300);
    while outcomes(&tagged).len() < records.len() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    running.stop();

    // The engine sent each turn as the fixture holds it, its window whole,
    // every turn on the user's side and no language.
    let extracts = stub.extracts();
    assert_eq!(extracts.len(), records.len(), "one call per turn");
    for record in &records {
        let body = extracts
            .iter()
            .find(|body| body["turn"] == record["turn"])
            .expect("the turn was tagged");
        assert_eq!(as_sent(body), as_sent(record), "turn {}", record["turn"]);
        assert_eq!(body["speaker"], "A");
        assert!(
            body["context"]
                .as_array()
                .expect("context")
                .iter()
                .all(|turn| turn["speaker"] == "A")
        );
        assert!(body.get("language").is_none());
    }

    let (mut links, mut context_links, mut unresolved) = (0, 0, 0);
    for outcome in outcomes(&tagged) {
        let TaggingOutcome::Saved {
            links: these,
            mood,
            context_links: carried,
            unresolved_context_links,
            ..
        } = outcome
        else {
            panic!("every turn is saved: {outcome:?}");
        };
        assert!(mood, "every turn has its mood");
        links += these;
        context_links += carried;
        unresolved += unresolved_context_links;
    }
    assert_eq!((links, context_links), (114, 50));
    let mut resolved = 0;
    for record in &records {
        let turn = EntityId::from_hex(record["turn"].as_str().expect("turn")).expect("turn id");
        let tags = vault.turn_tags(&turn).expect("read").expect("tagged");
        assert!(tags.mood.is_some());
        assert_eq!(tags.envelope.stack.as_deref(), Some(stack.as_str()));
        resolved += tags
            .mentions
            .iter()
            .filter(|mention| mention.reference == Some(MentionReference::Context))
            .count();
    }
    assert_eq!(resolved + unresolved, context_links);
    assert!(resolved > 0, "context links find their earlier spans");
    eprintln!("golden replay: {links} links, {context_links} context links, {resolved} resolved");
}
