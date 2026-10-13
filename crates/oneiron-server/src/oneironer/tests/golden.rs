//! The served stack's goldens replayed through the adapter and the save
//! path. The model lane recorded `turns-v1.sidecar-v2.json` from the real
//! served stack (NER, coreference and VAD heads; contract v2) on the 200
//! invented turns of `turns-v1.jsonl`, which carry no real conversation. The
//! stub serves the recorded card and answers; the engine must send each turn
//! exactly as the fixture holds it, and save what the stack answered.
//!
//! The fixture names no side, so the goldens were recorded on requests with
//! no role; the engine sends each turn's stored side, the user's here. The
//! sidecar reads a request with no roles as every turn on the user's side,
//! so the stack reads the same turns either way; only its speaker links,
//! which a request with no roles drops, and the pronoun spans that exist
//! for them alone, could differ. So this replay binds each answer to the
//! turn, messages and window the engine sent (the model lane's input digest,
//! roles aside) and proves spans, links, context links and moods; the speaker
//! links are proven against the fake endpoint in `links.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::memory::WitnessAuthor;
use oneiron::memory::extraction::EncoderGolden;
use oneiron::tagging::{MentionReference, TaggingOutcome};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

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

fn fold_messages(hash: &mut Sha256, turn: &Value) {
    for message in turn["messages"].as_array().expect("messages") {
        let text = message["text"].as_str().expect("text");
        hash.update(message["id"].as_str().expect("id").as_bytes());
        hash.update((text.len() as u64).to_le_bytes());
        hash.update(text.as_bytes());
    }
}

/// The goldens' `input_hash` of a request: the engine's input digest, as
/// the goldens' `engine` block spells it out, over the turn, its messages
/// and its window. It folds in no role: the goldens were recorded without.
fn digest(body: &Value) -> String {
    let mut hash = Sha256::new();
    hash.update(body["turn"].as_str().expect("turn").as_bytes());
    fold_messages(&mut hash, body);
    let context = body["context"].as_array().expect("context");
    if !context.is_empty() {
        hash.update(b"\0context");
        hash.update((context.len() as u64).to_le_bytes());
        for turn in context {
            let messages = turn["messages"].as_array().expect("messages");
            hash.update(turn["turn"].as_str().expect("turn").as_bytes());
            hash.update((messages.len() as u64).to_le_bytes());
            fold_messages(&mut hash, turn);
        }
    }
    format!("{:x}", hash.finalize())
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
            assert_eq!(
                record["turn"], golden["turn"],
                "one golden per record, in order"
            );
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
        // A profile `serve` accepts: a retry waits at least a second.
        retry_backoff_secs: 1,
        max_retry_backoff_secs: 1,
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
        let turn = EntityId::from_hex(record["turn"].as_str().expect("turn")).expect("turn id");
        let room = match context.first() {
            // A turn with no window opens its conversation's own room, named
            // by its id reversed: one per conversation, and none of the ids
            // the vault seeds for itself.
            None => {
                let mut room = *turn.as_bytes();
                room.reverse();
                EntityId::from_bytes(room).expect("room id")
            }
            Some(earlier) => room_of[earlier["turn"].as_str().expect("turn")],
        };
        room_of.insert(turn.to_hex(), room);
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
    // every turn on the user's side and no language; and each answer
    // replayed is the stack's answer to those very bytes.
    let extracts = stub.extracts();
    assert_eq!(extracts.len(), records.len(), "one call per turn");
    for (record, golden) in records
        .iter()
        .zip(goldens["records"].as_array().expect("records"))
    {
        let body = extracts
            .iter()
            .find(|body| body["turn"] == record["turn"])
            .expect("the turn was tagged");
        assert_eq!(as_sent(body), as_sent(record), "turn {}", record["turn"]);
        assert_eq!(
            Some(digest(body).as_str()),
            golden["golden"]["input_hash"].as_str(),
            "turn {}",
            record["turn"]
        );
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
    // Two context links point where the earlier turn saved no span at those
    // coordinates: a Korean name its answer never sent as a span, and a
    // Ukrainian word its answer split in two. Neither is guessed from its
    // surface; each keeps no antecedent and is counted.
    assert_eq!((resolved, unresolved), (48, 2));
    eprintln!("golden replay: {links} links, {context_links} context links, {resolved} resolved");
}
