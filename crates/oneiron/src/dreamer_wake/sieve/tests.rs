//! The sieve against the packet's checks (gate 3, ARCH-0026 Continuous): a
//! turn chunk with a date and a name gets both flags and queues them by
//! score; a restart keeps the queue and the cursor and reads nothing twice;
//! saved oneiroNER tags stand in for the rule names, and a save that lands
//! after the sieve read the turn owes it a new read.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::*;
use crate::edge::EdgeActorClass;
use crate::memory::extraction::{EncoderInput, EncoderOutput, ExtractionEncoder, NerSpan};
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::ports::ManualClock;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::tagging::{TaggingMarkerConfig, TaggingMode, TaggingReconciler};
use crate::temporal::TimeRange;
use crate::{ModelId, VaultConfig};

const NOW: u64 = 1_790_000_000;
const ROOM: &str = "52525252525252525252525252525252";

fn witness(vault: &Vault, turn_ref: &str, text: &str) -> EntityId {
    let speaker = EntityId::from_bytes([0x21; 16]).expect("speaker id");
    if vault.get(&speaker).expect("speaker read").is_none() {
        vault
            .put_entity(
                &speaker,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&serde_json::json!({ "name": "speaker" }))
                    .expect("body"),
            )
            .expect("speaker");
    }
    let turn = WitnessTurn {
        conversation_ref: ROOM.into(),
        turn_ref: Some(turn_ref.to_owned()),
        occurred_at: NOW,
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: text.into(),
            metadata: None,
            is_visible: true,
            order: 0,
        }],
    };
    vault
        .memory(speaker, EdgeActorClass::Human)
        .witness(&turn)
        .expect("witness");
    EntityId::from_hex(turn_ref).expect("turn id")
}

/// A fake oneiroNER tagger: each word it knows is a `PERSON`.
struct Names {
    model: ModelId,
    known: Vec<&'static str>,
}

impl ExtractionEncoder for Names {
    fn model_id(&self) -> &ModelId {
        &self.model
    }
    fn locality(&self) -> crate::embed::EmbedderLocality {
        crate::embed::EmbedderLocality::OnDevice
    }
    fn infer(&self, input: &EncoderInput) -> crate::Result<EncoderOutput> {
        let mut spans = Vec::new();
        for (message, each) in input.messages.iter().enumerate() {
            for name in &self.known {
                if let Some(start) = each.text.find(name) {
                    spans.push(NerSpan {
                        message,
                        start,
                        end: start + name.len(),
                        label: "PERSON".to_owned(),
                        confidence: 0.9,
                    });
                }
            }
        }
        Ok(EncoderOutput {
            spans,
            links: Vec::new(),
            vad: None,
        })
    }
}

fn open(path: &std::path::Path, tagging: bool) -> Arc<Vault> {
    let mut config = VaultConfig::device();
    config.store_clock = ManualClock::new(NOW).bundle();
    if tagging {
        config.tagging = Some(
            TaggingMarkerConfig::new("0123456789abcdef")
                .expect("checkpoint")
                .with_labels(BTreeMap::from([("PERSON".to_owned(), ENTITY_TYPE_PERSON)]))
                .with_mode(TaggingMode::Save),
        );
    }
    Arc::new(Vault::open(path, config).expect("open vault"))
}

/// Every queued span of `turn` as (kind, its words, its origin's tag),
/// in text order.
fn flags(vault: &Vault, turn: &EntityId, text: &str) -> Vec<(SpanKind, String, &'static str)> {
    let mut spans: Vec<_> = vault
        .sieve_queue(usize::MAX)
        .expect("queue")
        .into_iter()
        .filter(|span| span.turn == *turn)
        .collect();
    spans.sort_by_key(|span| span.start);
    spans
        .iter()
        .map(|span| {
            let origin = match span.origin {
                SpanOrigin::Rule { .. } => "rule",
                SpanOrigin::SavedTag { .. } => "tag",
            };
            (
                span.kind,
                text[span.start as usize..span.end as usize].to_owned(),
                origin,
            )
        })
        .collect()
}

#[test]
fn a_turn_with_a_date_and_a_name_queues_both_by_score_and_a_restart_reads_nothing_twice() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), false);
    let text = "We met Alice Smith on October 12, 2026.";
    let turn = witness(&vault, "71717171717171717171717171717171", text);

    let pass = vault.sieve_pass(NOW).expect("pass");
    assert_eq!((pass.turns_read, pass.spans_queued), (1, 2));
    assert_eq!(
        flags(&vault, &turn, text),
        vec![
            (SpanKind::Name, "Alice Smith".to_owned(), "rule"),
            (SpanKind::Date, "October 12, 2026".to_owned(), "rule"),
        ]
    );
    let queue = vault.sieve_queue(usize::MAX).expect("queue");
    assert_eq!(queue[0].kind, SpanKind::Date, "the surer date leads");
    assert!(queue.windows(2).all(|pair| pair[0].score >= pair[1].score));
    // No model rung has run: every span waits on the novelty question.
    assert!(queue.iter().all(|span| span.owed.contains(&SieveRung::Novelty)));

    drop(vault);
    let vault = open(dir.path(), false);
    assert_eq!(vault.sieve_queue(usize::MAX).expect("queue"), queue);
    assert_eq!(vault.sieve_pass(NOW + 1).expect("pass"), SievePass::default());
    assert_eq!(vault.sieve_queue(usize::MAX).expect("queue"), queue);

    // The cursor stood: a new turn is the only thing the next pass reads.
    let next = "Ken joins next week.";
    let later = witness(&vault, "72727272727272727272727272727272", next);
    let pass = vault.sieve_pass(NOW + 2).expect("pass");
    assert_eq!(pass.turns_read, 1);
    assert_eq!(
        flags(&vault, &later, next),
        vec![
            (SpanKind::Name, "Ken".to_owned(), "rule"),
            (SpanKind::Date, "next week".to_owned(), "rule"),
        ]
    );
    let uncertain = vault
        .sieve_queue(usize::MAX)
        .expect("queue")
        .into_iter()
        .find(|span| span.turn == later && span.kind == SpanKind::Name)
        .expect("the opening name");
    assert_eq!(uncertain.band, SpanBand::Uncertain);
    assert_eq!(uncertain.owed, vec![SieveRung::Novelty, SieveRung::Typing]);
    assert_eq!(vault.sieve_queue(usize::MAX).expect("queue").len(), 4);
}

#[test]
fn saved_tags_stand_in_for_the_rule_names_once_the_tagger_saves_them() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let text = "Ada met Mirela on 2026-10-12.";
    let turn = witness(&vault, "73737373737373737373737373737373", text);

    // No tags yet: the rules name both.
    vault.sieve_pass(NOW).expect("pass");
    assert_eq!(
        flags(&vault, &turn, text),
        vec![
            (SpanKind::Name, "Ada".to_owned(), "rule"),
            (SpanKind::Name, "Mirela".to_owned(), "rule"),
            (SpanKind::Date, "2026-10-12".to_owned(), "rule"),
        ]
    );

    // The tagger saves its tags after the sieve read the turn: the save owes
    // the turn a read, and its names now come from the tag set alone.
    let tagger: Arc<dyn ExtractionEncoder> = Arc::new(Names {
        model: "fixture/names@v1".parse().expect("model id"),
        known: vec!["Mirela"],
    });
    TaggingReconciler::new(Arc::clone(&vault), tagger)
        .expect("reconciler")
        .drain_once()
        .expect("drain");
    assert!(vault.turn_tags(&turn).expect("tags").is_some());
    let pass = vault.sieve_pass(NOW + 1).expect("pass");
    assert_eq!((pass.turns_read, pass.spans_retired), (1, 3));
    assert_eq!(
        flags(&vault, &turn, text),
        vec![
            (SpanKind::Name, "Mirela".to_owned(), "tag"),
            (SpanKind::Date, "2026-10-12".to_owned(), "rule"),
        ]
    );
    // Read once: the next pass finds nothing owed.
    assert_eq!(vault.sieve_pass(NOW + 2).expect("pass"), SievePass::default());
}
