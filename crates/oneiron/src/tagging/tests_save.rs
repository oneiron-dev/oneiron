//! Save mode end to end, observed through the read doors (ARCH-0036, serving
//! the tagger): a tagged turn's mentions are saved unconfirmed and found by
//! name, a re-tag replaces them, a deletion takes them with it, and an
//! import that holds its tags makes no tagger call.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::*;
use crate::affect::{Vad, VadAnnotationSource};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::memory::extraction::{
    CorefLink, EncoderInput, EncoderOutput, ExtractionEncoder, NerSpan,
};
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::ports::ManualClock;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;
use crate::{EntityId, ModelId, Vault, VaultConfig};

const CHECKPOINT: &str = "0123456789abcdef";
const NOW: u64 = 1_790_000_000;
const ROOM: &str = "52525252525252525252525252525252";
const MOOD: Vad = Vad {
    valence: 0.3,
    arousal: 0.4,
    dominance: 0.5,
};

/// A tagger that tags each name it knows as `PERSON`, and links each "she"
/// or "he" to the nearest name before it. Every answer carries a mood.
struct Names {
    model: ModelId,
    known: Mutex<Vec<&'static str>>,
    calls: AtomicUsize,
}

impl Names {
    fn new(known: &[&'static str]) -> Arc<Self> {
        Arc::new(Self {
            model: "fixture/names@v1".parse().expect("model id"),
            known: Mutex::new(known.to_vec()),
            calls: AtomicUsize::new(0),
        })
    }
    /// The names a later call knows, as a tagger that reads the text
    /// differently would.
    fn know(&self, known: &[&'static str]) {
        *self.known.lock().expect("known lock") = known.to_vec();
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ExtractionEncoder for Names {
    fn model_id(&self) -> &ModelId {
        &self.model
    }
    fn locality(&self) -> crate::embed::EmbedderLocality {
        crate::embed::EmbedderLocality::OnDevice
    }
    fn infer(&self, input: &EncoderInput) -> crate::Result<EncoderOutput> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(names_in(input, &self.known.lock().expect("known lock")))
    }
}

/// The answer [`Names`] gives: spans over the turn's own messages only.
fn names_in(input: &EncoderInput, known: &[&str]) -> EncoderOutput {
    let mut spans = Vec::new();
    let mut links = Vec::new();
    let mut last_name = None;
    for (message, each) in input.messages.iter().enumerate() {
        let text = each.text.as_str();
        for word in text.split_whitespace() {
            let bare = word.trim_matches(|c: char| !c.is_alphanumeric());
            if bare.is_empty() {
                continue;
            }
            let start = bare.as_ptr() as usize - text.as_ptr() as usize;
            let span = NerSpan {
                message,
                start,
                end: start + bare.len(),
                label: "PERSON".to_owned(),
                confidence: 0.9,
            };
            if known.contains(&bare) {
                last_name = Some(spans.len());
                spans.push(span);
            } else if matches!(bare.to_lowercase().as_str(), "she" | "he")
                && let Some(antecedent) = last_name
            {
                links.push(CorefLink {
                    span: spans.len(),
                    antecedent,
                });
                spans.push(span);
            }
        }
    }
    EncoderOutput {
        spans,
        links,
        vad: Some(MOOD),
    }
}

/// A vault whose tagger saves its tags, mapping the `PERSON` label.
fn open(path: &std::path::Path) -> Arc<Vault> {
    let mut config = VaultConfig::device();
    config.store_clock = ManualClock::new(NOW).bundle();
    config.tagging = Some(
        TaggingMarkerConfig::new(CHECKPOINT)
            .expect("checkpoint")
            .with_labels(BTreeMap::from([("PERSON".to_owned(), ENTITY_TYPE_PERSON)])),
    );
    Arc::new(Vault::open(path, config).expect("open vault"))
}

fn person(vault: &Vault, byte: u8, name: &str) -> EntityId {
    let id = EntityId::from_bytes([byte; 16]).expect("person id");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).expect("body"),
        )
        .expect("person");
    id
}

fn speaker(vault: &Vault) -> EntityId {
    let id = EntityId::from_bytes([0x21; 16]).expect("speaker id");
    if vault.get(&id).expect("speaker read").is_none() {
        person(vault, 0x21, "fixture speaker");
    }
    id
}

fn turn(turn_ref: &str, messages: &[(u32, &str)]) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: ROOM.into(),
        turn_ref: Some(turn_ref.to_owned()),
        occurred_at: NOW,
        messages: messages
            .iter()
            .map(|(order, content)| WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: (*content).into(),
                metadata: None,
                is_visible: true,
                order: *order,
            })
            .collect(),
    }
}

/// Witnesses `messages` into the turn `turn_ref` and returns the turn's id.
fn witness(vault: &Vault, turn_ref: &str, messages: &[(u32, &str)]) -> EntityId {
    vault
        .memory(speaker(vault), EdgeActorClass::Human)
        .witness(&turn(turn_ref, messages))
        .expect("witness");
    EntityId::from_hex(turn_ref).expect("turn id")
}

fn reconciler(vault: &Arc<Vault>, tagger: &Arc<Names>) -> TaggingReconciler {
    TaggingReconciler::new(
        Arc::clone(vault),
        Arc::clone(tagger) as Arc<dyn ExtractionEncoder>,
    )
    .expect("reconciler")
}

fn tags(vault: &Vault, turn: &EntityId) -> TurnTags {
    vault
        .turn_tags(turn)
        .expect("tags read")
        .expect("the turn's tags are saved")
}

/// The (turn, place) of every saved mention of a name.
fn found(vault: &Vault, name: &str) -> Vec<(EntityId, usize)> {
    vault
        .tagged_mentions_of_name(ENTITY_TYPE_PERSON, name)
        .expect("search")
        .into_iter()
        .map(|hit| (hit.turn, hit.index))
        .collect()
}

fn minted(link: &MentionLink) -> EntityId {
    match link {
        MentionLink::Minted { entity, .. } => *entity,
        other => panic!("expected a minted provisional entity, got {other:?}"),
    }
}

/// ARCH-0036 "what the engine saves", end to end through the worker: a
/// name the identity key knows is a soft link to it even with one hit; a
/// name it misses mints one provisional entity, local, which the next turn
/// naming it finds instead of minting a twin; a pronoun takes its
/// antecedent's entity; the mood lands on the turn and the turn-VAD read
/// door sees it; and every mention, the pronoun's included, is found by the
/// name it is linked through. No edge and no entity row is written.
#[test]
fn a_tagged_turns_mentions_are_saved_unconfirmed_and_found_by_name() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path());
    let ada = person(&vault, 0x22, "Ada");
    let tagger = Names::new(&["Ada", "Mirela"]);
    let first = witness(
        &vault,
        "71717171717171717171717171717171",
        &[(0, "Ada met Mirela. She smiled.")],
    );
    let entities_before = vault
        .count_entities_by_type(ENTITY_TYPE_PERSON)
        .expect("count");

    let pass = reconciler(&vault, &tagger).drain_once().expect("drain");

    assert!(matches!(
        pass.traces.as_slice(),
        [TaggingTrace {
            outcome: TaggingOutcome::Saved {
                spans: 3,
                linked: 3,
                minted: 1,
                ..
            },
            ..
        }]
    ));
    let saved = tags(&vault, &first);
    assert_eq!(
        saved.mentions[0].link,
        MentionLink::Candidates {
            kind: ENTITY_TYPE_PERSON,
            entities: vec![ada],
        }
    );
    let mirela = minted(&saved.mentions[1].link);
    assert_eq!(saved.mentions[2].link, saved.mentions[1].link);
    assert_eq!(saved.mentions[2].antecedent, Some(1));
    assert_eq!(
        saved.envelope.model_id,
        format!("fixture/names@v1@{CHECKPOINT}")
    );
    let provisional = vault
        .provisional_entity(&mirela)
        .expect("read")
        .expect("Mirela is provisional");
    assert_eq!(
        (
            provisional.kind,
            provisional.name.as_str(),
            provisional.origin
        ),
        (ENTITY_TYPE_PERSON, "Mirela", first)
    );
    assert!(provisional.facet.is_some());
    assert_eq!(vault.get(&mirela).expect("read"), None);
    assert_eq!(
        vault
            .count_entities_by_type(ENTITY_TYPE_PERSON)
            .expect("count"),
        entities_before
    );
    assert!(saved.mentions.iter().all(|mention| {
        vault
            .edges_out(&mention.message)
            .expect("edges")
            .iter()
            .all(|edge| edge.kind != EdgeKind::Mentions)
    }));
    let mood = vault
        .get_turn_vad_annotation(&first)
        .expect("mood read")
        .expect("the turn's mood");
    assert_eq!(
        (mood.vad, mood.source),
        (MOOD, VadAnnotationSource::ModelInference)
    );

    let second = witness(
        &vault,
        "72727272727272727272727272727272",
        &[(0, "Mirela called back.")],
    );
    let pass = reconciler(&vault, &tagger).drain_once().expect("drain");
    assert!(matches!(
        pass.traces[0].outcome,
        TaggingOutcome::Saved { minted: 0, .. }
    ));
    assert_eq!(
        tags(&vault, &second).mentions[0].link,
        MentionLink::Candidates {
            kind: ENTITY_TYPE_PERSON,
            entities: vec![mirela],
        }
    );
    assert_eq!(
        found(&vault, "mirela"),
        vec![(first, 1), (first, 2), (second, 0)]
    );
    assert_eq!(found(&vault, "Ada"), vec![(first, 0)]);
}

/// "A new tagger re-tags by that key", and the #1285 review item: a re-tag
/// replaces the turn's tags, and a provisional entity no tag set names any
/// more is retired, so the name no longer finds anything.
#[test]
fn a_re_tag_replaces_a_turns_tags_and_retires_a_name_no_turn_holds() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path());
    let tagger = Names::new(&["Mirela"]);
    let turn_ref = "73737373737373737373737373737373";
    let turn = witness(&vault, turn_ref, &[(0, "Mirela called")]);
    reconciler(&vault, &tagger).drain_once().expect("drain");
    let mirela = minted(&tags(&vault, &turn).mentions[0].link);

    // New text owes the turn a new pass, and this tagger reads the turn
    // differently.
    tagger.know(&["Ottilie"]);
    witness(&vault, turn_ref, &[(1, "then Ottilie answered")]);
    reconciler(&vault, &tagger).drain_once().expect("drain");

    let retagged = tags(&vault, &turn);
    assert_eq!(retagged.mentions.len(), 1);
    let ottilie = minted(&retagged.mentions[0].link);
    assert_ne!(ottilie, mirela);
    assert_eq!(vault.provisional_entity(&mirela).expect("read"), None);
    assert!(found(&vault, "Mirela").is_empty());
    assert!(vault.tagged_mentions(&mirela).expect("search").is_empty());
    assert_eq!(found(&vault, "Ottilie"), vec![(turn, 0)]);
}

/// The #1285 review item: erasing a turn's text takes its tags, and leaves
/// no origin naming the erased text. A provisional entity another turn still
/// names moves there and takes its text; one no turn names is retired. Both
/// erase tiers: a GDPR purge of one message, a user delete of the other.
#[test]
fn erasing_a_message_takes_its_turns_tags_and_moves_or_retires_what_they_minted() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path());
    let tagger = Names::new(&["Mirela"]);
    let first = witness(
        &vault,
        "74747474747474747474747474747474",
        &[(0, "Mirela called")],
    );
    reconciler(&vault, &tagger).drain_once().expect("drain");
    let second = witness(
        &vault,
        "75757575757575757575757575757575",
        &[(0, "Mirela, again.")],
    );
    reconciler(&vault, &tagger).drain_once().expect("drain");
    let first_tags = tags(&vault, &first);
    let mirela = minted(&first_tags.mentions[0].link);
    let second_message = tags(&vault, &second).mentions[0].message;

    vault
        .delete_entity_with_reason(
            &first_tags.mentions[0].message,
            crate::DeleteReason::GdprDelete,
        )
        .expect("purge the first turn's message");

    assert_eq!(vault.turn_tags(&first).expect("read"), None);
    let moved = vault
        .provisional_entity(&mirela)
        .expect("read")
        .expect("still provisional");
    assert_eq!((moved.origin, moved.name.as_str()), (second, "Mirela"));
    assert_eq!(found(&vault, "Mirela"), vec![(second, 0)]);

    // The first turn was owed a pass over the text it kept: none.
    reconciler(&vault, &tagger).drain_once().expect("drain");
    assert_eq!(vault.turn_tags(&first).expect("read"), None);

    vault
        .delete_entity(&second_message)
        .expect("delete the second turn's message");

    assert_eq!(vault.turn_tags(&second).expect("read"), None);
    assert_eq!(vault.provisional_entity(&mirela).expect("read"), None);
    assert!(found(&vault, "Mirela").is_empty());
}

/// ARCH-0036: "an import that already holds tags completes its markers
/// without a tagger call", and the #1303 deferral: held tags are checked,
/// saved and the marker settled inside the turn's own write, so a running
/// worker never calls the tagger for that turn. Tags that break the
/// contract leave the turn to the tagger.
#[test]
fn an_import_that_holds_its_tags_makes_no_tagger_call() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path());
    let tagger = Names::new(&["Mirela"]);
    let worker = reconciler(&vault, &tagger);
    let memory = vault.memory(speaker(&vault), EdgeActorClass::Human);
    let landed = turn(
        "76767676767676767676767676767676",
        &[(0, "Mirela wrote back")],
    );
    let held = EncoderOutput {
        spans: vec![NerSpan {
            message: 0,
            start: 0,
            end: 6,
            label: "PERSON".to_owned(),
            confidence: 1.0,
        }],
        links: Vec::new(),
        vad: None,
    };

    let (_, outcome) = memory
        .witness_with_held_tags(&landed, &held)
        .expect("import");

    assert!(matches!(
        outcome,
        HeldTagsOutcome::Completed(TaggingTrace {
            outcome: TaggingOutcome::Imported { spans: 1, .. },
            ..
        })
    ));
    let turn = EntityId::from_hex("76767676767676767676767676767676").expect("turn id");
    let saved = tags(&vault, &turn);
    assert_eq!(saved.envelope.model_id, format!("held@{CHECKPOINT}"));
    assert_eq!(saved.mood, None);
    assert_eq!(found(&vault, "Mirela"), vec![(turn, 0)]);
    let pass = worker.drain_once().expect("drain");
    assert!(pass.traces.is_empty());
    assert_eq!(tagger.calls(), 0);

    let broken = EncoderOutput {
        spans: vec![NerSpan {
            end: 99,
            ..held.spans[0].clone()
        }],
        ..held
    };
    let (_, outcome) = memory
        .witness_with_held_tags(
            &self::turn("77777777777777777777777777777777", &[(0, "Mirela again")]),
            &broken,
        )
        .expect("import");
    assert_eq!(outcome, HeldTagsOutcome::Refused(OutputRefusal::BadOffsets));
    worker.drain_once().expect("drain");
    assert_eq!(tagger.calls(), 1);
}
