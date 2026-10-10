// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! What a saved tag set and a provisional entity do across two devices of
//! one vault (ARCH-0036, serving the tagger; owner ruling 2026-10-08, card
//! 3 = A).
//!
//! A mention is saved unconfirmed: derived, rebuilt locally, never synced.
//! A provisional entity stays local like the tags, and the Dreamer's or an
//! actor's confirmation makes the real, synced entity. Every row here crosses
//! the real Loro delta path between two `Vault`s (`reverse_rematerialize` →
//! `sync_harness::exchange` → Observer B), in the window the store clock
//! writes the turn into.

#![cfg(feature = "sync")]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::edge::EdgeActorClass;
use oneiron::memory::extraction::{EncoderInput, EncoderOutput, ExtractionEncoder, NerSpan};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::reverse_rematerialize;
use oneiron::tagging::{MentionLink, TaggingMarkerConfig, TaggingReconciler};
use oneiron::{EntityId, ModelId};

use crate::sync_harness::{TestNode, exchange, test_config, time_range};

/// Tags the first word of the turn's first message as a `PERSON`.
struct FirstWord(ModelId);

impl ExtractionEncoder for FirstWord {
    fn model_id(&self) -> &ModelId {
        &self.0
    }
    fn locality(&self) -> oneiron::embed::EmbedderLocality {
        oneiron::embed::EmbedderLocality::OnDevice
    }
    fn infer(&self, input: &EncoderInput) -> oneiron::Result<EncoderOutput> {
        let text = &input.messages[0].text;
        Ok(EncoderOutput {
            spans: vec![NerSpan {
                message: 0,
                start: 0,
                end: text.find(' ').unwrap_or(text.len()),
                label: "PERSON".to_owned(),
                confidence: 0.9,
            }],
            links: Vec::new(),
            vad: None,
        })
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn converge(a: &TestNode, b: &TestNode, window: &WindowKey) {
    for node in [a, b] {
        reverse_rematerialize(&node.vault, node.doc(window.as_str()), window)
            .expect("mirror local rows into the window doc");
    }
    exchange(a, b, window.as_str());
}

/// Device B never sees device A's unconfirmed entity, nor A's tags of a turn
/// both devices hold; once A confirms the entity, B receives the real one.
#[test]
fn a_provisional_entity_stays_on_its_device_until_it_is_confirmed() {
    let now = now_seconds();
    let window = WindowKey::from_timestamp(now);
    let mut config = test_config();
    config.tagging = Some(
        TaggingMarkerConfig::new("0123456789abcdef")
            .unwrap()
            .with_labels(BTreeMap::from([("PERSON".to_owned(), ENTITY_TYPE_PERSON)])),
    );
    let mut a = TestNode::with_config("node-a", 1, config.clone());
    let mut b = TestNode::with_config("node-b", 2, config);
    a.open_window(window.as_str());
    b.open_window(window.as_str());
    let owner = EntityId::from_bytes([0xE1; 16]).unwrap();
    a.vault
        .put_entity(&owner, ENTITY_TYPE_PERSON, time_range(now), now, b"owner")
        .unwrap();
    let memory = a.vault.memory(owner, EdgeActorClass::Human);
    let turn_ref = "78787878787878787878787878787878";
    memory
        .witness(&WitnessTurn {
            conversation_ref: "79797979797979797979797979797979".into(),
            turn_ref: Some(turn_ref.into()),
            occurred_at: now,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "Mirela called".into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
        })
        .expect("witness on device A");
    let turn = EntityId::from_hex(turn_ref).unwrap();
    TaggingReconciler::new(
        Arc::clone(&a.vault),
        Arc::new(FirstWord("fixture/first-word@v1".parse().unwrap())),
    )
    .unwrap()
    .drain_once()
    .expect("device A tags the turn");
    let tags = a.vault.turn_tags(&turn).unwrap().expect("A saved its tags");
    let MentionLink::Minted { entity: mirela, .. } = tags.mentions[0].link.clone() else {
        panic!("a name the vault does not know mints a provisional entity");
    };
    assert!(a.vault.provisional_entity(&mirela).unwrap().is_some());

    converge(&a, &b, &window);

    assert!(
        b.vault.get(&turn).unwrap().is_some(),
        "the turn itself crosses"
    );
    assert_eq!(b.vault.get(&mirela).unwrap(), None);
    assert_eq!(b.vault.provisional_entity(&mirela).unwrap(), None);
    assert_eq!(b.vault.turn_tags(&turn).unwrap(), None);

    memory
        .confirm_provisional_entity(&mirela)
        .expect("device A confirms Mirela");
    assert_eq!(a.vault.provisional_entity(&mirela).unwrap(), None);
    converge(&a, &b, &window);

    assert!(
        b.vault.get(&mirela).unwrap().is_some(),
        "the confirmed entity crosses"
    );
    assert_eq!(
        b.vault
            .lookup_identity_key(ENTITY_TYPE_PERSON, "Mirela")
            .unwrap(),
        vec![mirela]
    );
}
