//! Save mode end to end, observed through the read doors (ARCH-0036, serving
//! the tagger): a tagged turn's mentions are saved unconfirmed and found by
//! name, a re-tag replaces them, a deletion takes them with it, and an
//! import that holds its tags makes no tagger call. The rest repro the Sol
//! review of the save path (2026-10-10), each named for what it holds.

use std::collections::{BTreeMap, BTreeSet};
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

/// A tagger that tags each name it knows as `PERSON`, and each "she" or "he"
/// as a `PRONOUN` linked to the nearest name before it, as a tagger with a
/// mention head labels a reference. Every answer carries a mood.
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
            let span = |label: &str| NerSpan {
                message,
                start,
                end: start + bare.len(),
                label: label.to_owned(),
                confidence: 0.9,
            };
            if known.contains(&bare) {
                last_name = Some(spans.len());
                spans.push(span("PERSON"));
            } else if matches!(bare.to_lowercase().as_str(), "she" | "he")
                && let Some(antecedent) = last_name
            {
                links.push(CorefLink {
                    span: spans.len(),
                    antecedent,
                });
                spans.push(span("PRONOUN"));
            }
        }
    }
    EncoderOutput {
        spans,
        links,
        vad: Some(MOOD),
    }
}

/// A vault whose tagger saves its tags, mapping the `PERSON` label and
/// leaving `PRONOUN` out. Its id source starts over at every open, as a new
/// manual clock's does.
fn open(path: &std::path::Path) -> Arc<Vault> {
    open_in(path, TaggingMode::Save)
}

/// [`open`] with the tagger in `mode`.
fn open_in(path: &std::path::Path, mode: TaggingMode) -> Arc<Vault> {
    let mut config = VaultConfig::device();
    config.store_clock = ManualClock::new(NOW).bundle();
    config.tagging = Some(
        TaggingMarkerConfig::new(CHECKPOINT)
            .expect("checkpoint")
            .with_labels(BTreeMap::from([("PERSON".to_owned(), ENTITY_TYPE_PERSON)]))
            .with_mode(mode),
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
/// antecedent's entity, even when someone in the vault is named as it is
/// spelled; the mood lands on the turn and the turn-VAD read door sees it;
/// and every mention, the pronoun's included, is found by the name it is
/// linked through. No edge and no entity row is written.
#[test]
fn a_tagged_turns_mentions_are_saved_unconfirmed_and_found_by_name() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path());
    let ada = person(&vault, 0x22, "Ada");
    let she = person(&vault, 0x23, "She");
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
    assert!(saved.merge_evidence.is_empty());
    assert!(vault.tagged_mentions(&she).expect("search").is_empty());
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
/// erase tiers, each through the room door as the message's author: a hard
/// delete of one message, a user delete of the other.
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
        .delete_own_room_record(
            first_tags.mentions[0].message,
            crate::DeleteReason::UserHardDelete,
        )
        .expect("hard-delete the first turn's message");

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
        .delete_own_room_record(second_message, crate::DeleteReason::UserDelete)
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

/// A span an importer holds for a name, labelled as the label table maps it.
fn name_span(message: usize, start: usize, end: usize) -> NerSpan {
    NerSpan {
        message,
        start,
        end,
        label: "PERSON".to_owned(),
        confidence: 1.0,
    }
}

/// Greptile on #1356: held tags index the messages as the importer sent
/// them, not the text the turn shows. In a turn whose text skips a hidden
/// message and an empty one, each span is saved on the message it was read
/// from, never on the one at its index in the turn's text. A span on the
/// hidden message, which the turn does not show, is refused, and the turn is
/// left to the tagger.
#[test]
fn held_tags_are_saved_on_the_messages_they_were_read_from() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path());
    let memory = vault.memory(speaker(&vault), EdgeActorClass::Human);
    let message = |byte: u8| EntityId::from_bytes([byte; 16]).expect("message id");
    // The companion's turn, as sent: a user row is never hidden.
    let sent = |turn_ref: &str, messages: &[(u8, bool, &str)]| WitnessTurn {
        messages: messages
            .iter()
            .zip(0..)
            .map(|((id, visible, content), order)| WitnessMessage {
                id: Some(message(*id).to_hex()),
                author: WitnessAuthor::Companion,
                message_type: "text".into(),
                content: (*content).into(),
                metadata: None,
                is_visible: *visible,
                order,
            })
            .collect(),
        ..turn(turn_ref, &[])
    };
    let landed = sent(
        "7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d",
        &[
            (0xc1, true, "Ada called"),
            (0xc2, false, "about Mirela"),
            (0xc3, true, ""),
            (0xc4, true, "Mirela wrote back"),
            (0xc5, true, "Ottilie answered"),
            (0xc6, true, "Bruno too"),
        ],
    );
    let held = EncoderOutput {
        spans: vec![name_span(0, 0, 3), name_span(3, 0, 6)],
        links: Vec::new(),
        vad: None,
    };

    let (_, outcome) = memory
        .witness_with_held_tags(&landed, &held)
        .expect("import");

    assert!(matches!(outcome, HeldTagsOutcome::Completed(_)));
    let turn = EntityId::from_hex("7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d").expect("turn id");
    let saved = tags(&vault, &turn);
    assert_eq!(
        saved
            .mentions
            .iter()
            .map(|mention| (mention.message, mention.start, mention.end))
            .collect::<Vec<_>>(),
        vec![(message(0xc1), 0, 3), (message(0xc4), 0, 6)]
    );
    assert_eq!(found(&vault, "Ada"), vec![(turn, 0)]);
    assert_eq!(found(&vault, "Mirela"), vec![(turn, 1)]);
    assert!(found(&vault, "Bruno").is_empty());

    let (_, outcome) = memory
        .witness_with_held_tags(
            &sent(
                "7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e",
                &[(0xb1, true, "Ada called"), (0xb2, false, "about Mirela")],
            ),
            &EncoderOutput {
                spans: vec![name_span(1, 6, 12)],
                ..held
            },
        )
        .expect("import");
    assert_eq!(outcome, HeldTagsOutcome::Unread(UnreadText::UnshownMessage));
    let hidden = EntityId::from_hex("7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e").expect("turn id");
    assert_eq!(vault.turn_tags(&hidden).expect("read"), None);
}

/// Greptile on #1356: held tags that never read a turn's earlier text do
/// not settle it. An append whose tags index only the message it sends is
/// refused; the tag set read from the turn stays until the tagger reads the
/// turn whole.
#[test]
fn held_tags_for_an_append_leave_the_turn_to_the_tagger() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path());
    let tagger = Names::new(&["Ada", "Mirela"]);
    let worker = reconciler(&vault, &tagger);
    let memory = vault.memory(speaker(&vault), EdgeActorClass::Human);
    let turn_ref = "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f";
    let held = |spans| EncoderOutput {
        spans,
        links: Vec::new(),
        vad: None,
    };
    let (_, outcome) = memory
        .witness_with_held_tags(
            &turn(turn_ref, &[(0, "Ada called")]),
            &held(vec![name_span(0, 0, 3)]),
        )
        .expect("import");
    assert!(matches!(outcome, HeldTagsOutcome::Completed(_)));

    let (_, outcome) = memory
        .witness_with_held_tags(
            &turn(turn_ref, &[(1, "Mirela wrote back")]),
            &held(vec![name_span(0, 0, 6)]),
        )
        .expect("append");

    assert_eq!(outcome, HeldTagsOutcome::Unread(UnreadText::UnsentMessage));
    let turn = EntityId::from_hex(turn_ref).expect("turn id");
    assert_eq!(found(&vault, "Ada"), vec![(turn, 0)]);
    worker.drain_once().expect("drain");
    assert_eq!(tagger.calls(), 1);
    assert_eq!(found(&vault, "Ada"), vec![(turn, 0)]);
    assert_eq!(found(&vault, "Mirela"), vec![(turn, 1)]);
}

/// Greptile on #1356: merge evidence names two spans linked to different
/// entities, and goes when they stop being so. "Mira", a name the key
/// misses, mints; "Mirela", which the tagger says is the same one, keys to
/// the vault's Mirela: evidence the two may be one. Resolving the
/// provisional name into Mirela leaves no suggestion to merge her with
/// herself, and deleting either entity leaves no evidence whose span names
/// nothing.
#[test]
fn merge_evidence_goes_when_its_spans_stop_naming_different_entities() {
    let turn_ref = "70707070707070707070707070707070";
    let coreferent = || {
        let dir = tempfile::tempdir().expect("dir");
        let vault = open(dir.path());
        let mirela = person(&vault, 0x22, "Mirela");
        let (_, outcome) = vault
            .memory(speaker(&vault), EdgeActorClass::Human)
            .witness_with_held_tags(
                &turn(turn_ref, &[(0, "Mira wrote. Mirela agreed.")]),
                &EncoderOutput {
                    spans: vec![name_span(0, 0, 4), name_span(0, 12, 18)],
                    links: vec![CorefLink {
                        span: 1,
                        antecedent: 0,
                    }],
                    vad: None,
                },
            )
            .expect("import");
        assert!(matches!(outcome, HeldTagsOutcome::Completed(_)));
        let turn = EntityId::from_hex(turn_ref).expect("turn id");
        let saved = tags(&vault, &turn);
        assert_eq!(saved.merge_evidence.len(), 1);
        let mira = minted(&saved.mentions[0].link);
        (dir, vault, turn, mira, mirela)
    };

    let (_dir, vault, turn, mira, mirela) = coreferent();
    vault
        .memory(speaker(&vault), EdgeActorClass::Human)
        .resolve_provisional_entity(&mira, &mirela)
        .expect("resolve Mira into Mirela");
    let resolved = tags(&vault, &turn);
    assert_eq!(resolved.entities(), BTreeSet::from([mirela]));
    assert!(resolved.merge_evidence.is_empty());

    let (_dir, vault, turn, _, mirela) = coreferent();
    vault
        .batch()
        .delete(&mirela)
        .commit()
        .expect("delete Mirela");
    assert_eq!(tags(&vault, &turn).mentions[1].link, MentionLink::Tag);
    assert!(tags(&vault, &turn).merge_evidence.is_empty());

    let (_dir, vault, turn, mira, _) = coreferent();
    vault
        .batch()
        .delete(&mira)
        .commit()
        .expect("delete the provisional id");
    assert_eq!(tags(&vault, &turn).mentions[0].link, MentionLink::Tag);
    assert!(tags(&vault, &turn).merge_evidence.is_empty());
}

/// A provisional entity's id is never allocated again: its row is no entity
/// write, so the save keeps the id floor itself. Both turns are owed before
/// the first pass; after a reopen whose id source starts over, the second
/// name takes a new id and the first keeps its own.
#[test]
fn a_minted_id_is_never_allocated_again_after_a_reopen() {
    let dir = tempfile::tempdir().expect("dir");
    let tagger = Names::new(&["Mirela", "Ottilie"]);
    let (first, second) = {
        let vault = open(dir.path());
        let first = witness(
            &vault,
            "78787878787878787878787878787878",
            &[(0, "Mirela called")],
        );
        let second = witness(
            &vault,
            "79797979797979797979797979797979",
            &[(0, "Ottilie wrote")],
        );
        let pass = reconciler(&vault, &tagger)
            .with_batch_size(1)
            .drain_once()
            .expect("drain one");
        assert_eq!(pass.traces.len(), 1);
        (first, second)
    };

    let vault = open(dir.path());
    reconciler(&vault, &tagger)
        .drain_once()
        .expect("drain the other");

    let mirela = minted(&tags(&vault, &first).mentions[0].link);
    let ottilie = minted(&tags(&vault, &second).mentions[0].link);
    assert_ne!(mirela, ottilie);
    let name = |id: &EntityId| {
        vault
            .provisional_entity(id)
            .expect("read")
            .map(|entity| entity.name)
    };
    assert_eq!(name(&mirela).as_deref(), Some("Mirela"));
    assert_eq!(name(&ottilie).as_deref(), Some("Ottilie"));
    assert_eq!(found(&vault, "Mirela"), vec![(first, 0)]);
}

/// A turn whose text is erased loses its tags. An edit that empties its only
/// message owes the turn a pass; with no text left, that pass drops the tag
/// set, retires the name it minted and takes the mood with it.
#[cfg(feature = "sync")]
#[test]
fn a_turn_whose_text_is_erased_loses_its_tags() {
    let erased = erase_a_saved_turns_text(TaggingMode::Save);

    assert_eq!(erased.vault.turn_tags(&erased.turn).expect("read"), None);
    assert_eq!(
        erased
            .vault
            .provisional_entity(&erased.mirela)
            .expect("read"),
        None
    );
    assert!(found(&erased.vault, "Mirela").is_empty());
    assert!(
        erased
            .vault
            .get_turn_vad_annotation(&erased.turn)
            .expect("mood read")
            .is_none()
    );
}

/// Shadow writes nothing but job state: the same pass, run by a vault
/// reopened in shadow, settles its marker and leaves the saved tags as they
/// were.
#[cfg(feature = "sync")]
#[test]
fn a_shadow_pass_over_an_erased_turn_leaves_its_saved_tags() {
    let erased = erase_a_saved_turns_text(TaggingMode::Shadow);

    assert_eq!(
        erased.vault.turn_tags(&erased.turn).expect("read"),
        Some(erased.saved)
    );
    assert!(
        erased
            .vault
            .provisional_entity(&erased.mirela)
            .expect("read")
            .is_some()
    );
}

/// What [`erase_a_saved_turns_text`] leaves.
#[cfg(feature = "sync")]
struct Erased {
    vault: Arc<Vault>,
    turn: EntityId,
    mirela: EntityId,
    saved: TurnTags,
    _dir: tempfile::TempDir,
}

/// Saves a turn naming Mirela, reopens the vault in `mode`, empties the
/// turn's only message through the entity-document edit door, and drains
/// the pass that owes the turn, which skips it for having no text.
#[cfg(feature = "sync")]
fn erase_a_saved_turns_text(mode: TaggingMode) -> Erased {
    use crate::entity_doc::{AnchoredEdit, DocAuthorization, EditVerb, TextField};
    use crate::write_envelope::WriteActor;

    let dir = tempfile::tempdir().expect("dir");
    let tagger = Names::new(&["Mirela"]);
    let (turn, saved) = {
        let vault = open(dir.path());
        let turn = witness(
            &vault,
            "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a",
            &[(0, "Mirela called")],
        );
        reconciler(&vault, &tagger).drain_once().expect("drain");
        (turn, tags(&vault, &turn))
    };
    let vault = open_in(dir.path(), mode);
    let mirela = minted(&saved.mentions[0].link);
    let message = saved.mentions[0].message;
    let writer = speaker(&vault);
    let actor = WriteActor::new(writer, EdgeActorClass::Human);
    let owner = vault
        .authenticate_owner(
            writer,
            "principal:tagging-test",
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner");
    let authorization = DocAuthorization::Owner(&owner);
    vault
        .migrate_entity_text(
            &message,
            &TextField::MapField("content".into()),
            actor,
            &authorization,
        )
        .expect("migrate");
    let end = vault.entity_text(&message).expect("text").chars().count();
    let erase = AnchoredEdit {
        actor: Some(actor),
        verb: EditVerb::ReplaceQuotedSpan {
            span: vault.entity_text_anchor(&message, 0, end).expect("anchor"),
            text: String::new(),
        },
    };
    vault
        .edit_entity_text(&message, &[erase], &authorization, NOW)
        .expect("erase the text");

    let pass = reconciler(&vault, &tagger).drain_once().expect("drain");

    assert!(matches!(
        pass.traces.as_slice(),
        [TaggingTrace {
            outcome: TaggingOutcome::Skipped {
                reason: SkipReason::NoText
            },
            ..
        }]
    ));
    Erased {
        vault,
        turn,
        mirela,
        saved,
        _dir: dir,
    }
}

/// A batch delete tears an entity down as the erase doors do: a deleted
/// entity leaves the tags that named it, and a provisional id deleted there
/// is retired.
#[test]
fn a_batch_delete_takes_an_entity_out_of_the_tags_that_named_it() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path());
    let ada = person(&vault, 0x22, "Ada");
    let tagger = Names::new(&["Ada", "Mirela"]);
    let turn = witness(
        &vault,
        "7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b",
        &[(0, "Ada met Mirela")],
    );
    reconciler(&vault, &tagger).drain_once().expect("drain");
    let mirela = minted(&tags(&vault, &turn).mentions[1].link);

    vault.batch().delete(&ada).commit().expect("delete Ada");
    vault
        .batch()
        .delete(&mirela)
        .commit()
        .expect("delete the provisional id");

    assert!(
        tags(&vault, &turn)
            .mentions
            .iter()
            .all(|mention| mention.link == MentionLink::Tag)
    );
    assert!(vault.tagged_mentions(&ada).expect("search").is_empty());
    assert!(vault.tagged_mentions(&mirela).expect("search").is_empty());
    assert_eq!(vault.provisional_entity(&mirela).expect("read"), None);
}

/// A hard delete publishes before it purges, and its source reads deleted
/// from the publication on. Until the purge lands, no read door returns the
/// tags read from that source, the turn's mood or the name it minted, and
/// confirming the name is refused: a copy of deleted text never becomes a
/// real, synced entity.
#[cfg(feature = "sync")]
#[test]
fn a_published_deletion_hides_what_was_read_from_it_before_the_purge() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path());
    let tagger = Names::new(&["Mirela"]);
    let turn = witness(
        &vault,
        "7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c",
        &[(0, "Mirela called")],
    );
    reconciler(&vault, &tagger).drain_once().expect("drain");
    let saved = tags(&vault, &turn);
    let mirela = minted(&saved.mentions[0].link);

    crate::deletion::arm_fail_after_tombstone_before_purge();
    vault
        .delete_own_room_record(
            saved.mentions[0].message,
            crate::DeleteReason::UserHardDelete,
        )
        .expect_err("the purge is cut off after the publication");

    assert_eq!(vault.turn_tags(&turn).expect("read"), None);
    assert!(
        vault
            .get_turn_vad_annotation(&turn)
            .expect("mood read")
            .is_none()
    );
    assert_eq!(vault.provisional_entity(&mirela).expect("read"), None);
    assert!(
        vault
            .provisional_entities(None, 16)
            .expect("worklist")
            .is_empty()
    );
    assert!(found(&vault, "Mirela").is_empty());
    assert!(
        vault
            .memory(speaker(&vault), EdgeActorClass::Human)
            .confirm_provisional_entity(&mirela)
            .is_err()
    );
    assert_eq!(vault.get(&mirela).expect("read"), None);
}

/// ARCH-0055 §10, resolution sees the archive: a name the key finds on an
/// archived entity is a candidate for it, and no provisional twin is minted.
#[test]
fn an_archived_entity_is_a_candidate_and_mints_no_twin() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path());
    let ada = person(&vault, 0x22, "Ada");
    archive(&vault, &ada);
    let tagger = Names::new(&["Ada"]);
    let turn = witness(
        &vault,
        "7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d",
        &[(0, "Ada called")],
    );

    let pass = reconciler(&vault, &tagger).drain_once().expect("drain");

    assert!(matches!(
        pass.traces[0].outcome,
        TaggingOutcome::Saved { minted: 0, .. }
    ));
    assert_eq!(
        tags(&vault, &turn).mentions[0].link,
        MentionLink::Candidates {
            kind: ENTITY_TYPE_PERSON,
            entities: vec![ada],
        }
    );
}

/// The archive the cleanup door leaves: a local visibility marker over a row
/// and identity index kept whole.
fn archive(vault: &Vault, id: &EntityId) {
    use crate::side_table::{HexId, Raw, SideTable};
    const ARCHIVE_MARKER: SideTable<HexId, Vec<u8>, Raw> =
        SideTable::new(&crate::side_table::DELETION_ARCHIVE_MARKER);
    let marker = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::ArchivedByCleanup,
        deleted_at: NOW,
        request_id: [0x5a; 16],
    };
    vault
        .with_write_txn(|txn| {
            ARCHIVE_MARKER.put(&vault.store, txn, &HexId(*id), &marker.encode().to_vec())
        })
        .expect("archive");
    let txn = vault.store.env.read_txn().expect("read txn");
    let state = crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, &txn, id)
        .expect("visibility");
    assert!(state.archived && state.deleted);
}

/// A substrate invariant of deletion: an erase reads every `PartOf` edge it
/// needs and never refuses for a degree a query would cap, so in a vault
/// with no tagger an entity with more such edges than a query returns is
/// still deleted.
#[test]
fn an_entity_with_more_part_of_edges_than_a_query_returns_is_deleted() {
    let dir = tempfile::tempdir().expect("dir");
    let mut config = VaultConfig::device();
    config.store_clock = ManualClock::new(NOW).bundle();
    let vault = Vault::open(dir.path(), config).expect("open vault");
    let hub = person(&vault, 0x24, "Hub");
    let mut value = [0u8; 12];
    value[0..4].copy_from_slice(&1.0_f32.to_le_bytes());
    value[4..12].copy_from_slice(&1_u64.to_le_bytes());
    vault
        .with_write_txn(|txn| {
            for index in 0..=crate::vault::MAX_EDGE_QUERY_RESULTS {
                let mut bytes = [0u8; 16];
                bytes[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
                bytes[15] = 0xC9;
                let part = EntityId::from_bytes(bytes).expect("seeded id is never reserved");
                let key = crate::store::Store::encode_edge_key(&hub, EdgeKind::PartOf, &part);
                vault.store.edges_out.put(txn, &key, &value)?;
            }
            Ok(())
        })
        .expect("seed a high-degree entity");

    vault
        .delete_entity_with_reason(&hub, crate::DeleteReason::UserDelete)
        .expect("delete");
}

/// A provisional id is held until it is confirmed, resolved or retired, at
/// every door that names an entity's id: a witness that names it as a new
/// turn, a session witness that names it as a message (refused before it is
/// staged, so promote never meets it), and a claim candidate written under
/// it are all refused. The provisional entity, the tags that name it and the
/// entity rows are as they were.
#[test]
fn an_entity_write_never_lands_under_a_provisional_id() {
    use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
    use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path());
    let ada = person(&vault, 0x22, "Ada");
    let bea = person(&vault, 0x25, "Bea");
    let tagger = Names::new(&["Mirela"]);
    let tagged = witness(
        &vault,
        "7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e",
        &[(0, "Mirela called")],
    );
    reconciler(&vault, &tagger).drain_once().expect("drain");
    let mirela = minted(&tags(&vault, &tagged).mentions[0].link);
    let memory = vault.memory(speaker(&vault), EdgeActorClass::Human);

    let as_turn = memory.witness(&turn(&mirela.to_hex(), &[(0, "a turn under that id")]));

    let session = vault
        .off_record_session_vault()
        .enter(
            "tagging-held-id",
            crate::off_record::OffRecordBackendClass::Local,
        )
        .expect("enter session");
    let mut message = turn(
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        &[(0, "a message under that id")],
    );
    message.conversation_ref = String::new();
    message.turn_ref = None;
    message.messages[0].id = Some(mirela.to_hex());
    let as_message = memory.witness_into_session(&session, &message, None);
    session.close().expect("close session");

    let envelope = WriteEnvelope::new(
        WriteActor::new(speaker(&vault), EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(rmpv::Value::from("tagging-held-id")).expect("provenance"),
        ClaimApprovalStatus::Approved,
    );
    let claim = |subject: EntityId, name: &str| {
        ClaimCandidate::new(
            "profile.name",
            ClaimSubject::Entity(subject),
            rmpv::Value::from(name),
            1.0,
        )
    };
    let at = TimeRange {
        start: NOW,
        end: NOW,
    };
    let free = EntityId::from_bytes([0x26; 16]).expect("free id");
    vault
        .batch()
        .claim_candidate(&free, claim(ada, "Ada"), &envelope, at, NOW)
        .commit()
        .expect("the claim lands at a free id");
    let as_claim = vault
        .batch()
        .claim_candidate(&mirela, claim(bea, "Bea"), &envelope, at, NOW)
        .commit();

    assert!(as_turn.is_err());
    assert!(as_message.is_err());
    assert!(as_claim.is_err());
    assert_eq!(vault.get(&mirela).expect("read"), None);
    assert_eq!(
        vault
            .provisional_entity(&mirela)
            .expect("read")
            .map(|entity| entity.name),
        Some("Mirela".to_owned())
    );
    assert_eq!(found(&vault, "Mirela"), vec![(tagged, 0)]);
}

/// CodeRabbit on #1356, a substrate invariant of the sync door: a peer's row
/// takes a provisional id only when it lands. One the time-range gate
/// refuses is quarantined, and the provisional entity and the tags that name
/// it are as they were; one that lands stands, and the provisional entity
/// leaves the tags and is retired. Both cross the real Observer-B path.
#[cfg(feature = "sync")]
#[test]
fn a_peers_row_takes_a_provisional_id_only_when_it_lands() {
    use crate::sync::bridge::{Materializer, register_observer_b};

    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path());
    let tagger = Names::new(&["Mirela"]);
    let tagged = witness(
        &vault,
        "7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e",
        &[(0, "Mirela called")],
    );
    reconciler(&vault, &tagger).drain_once().expect("drain");
    let mirela = minted(&tags(&vault, &tagged).mentions[0].link);
    let doc = loro::LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _observers = register_observer_b(&doc, &vault, &materializer, "2026-03");
    let peer_row = |start: u64, end: u64| {
        let mut blob = vec![crate::registry::ENTITY_TYPE_TASK];
        for stamp in [start, end, end] {
            blob.extend_from_slice(&stamp.to_be_bytes());
        }
        blob.extend(crate::habit::task_body_for_test(
            crate::habit::TaskRole::Task,
        ));
        blob
    };

    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("entities"),
        &mirela.to_hex(),
        &peer_row(9, 3),
    )
    .expect("a peer's row with an inverted range");
    doc.commit();

    assert!(
        crate::sync::quarantine::quarantined_records(&vault)
            .expect("quarantine")
            .iter()
            .any(|(_, record)| record.reason_code == "InvalidTimeRange")
    );
    assert_eq!(vault.get(&mirela).expect("read"), None);
    assert_eq!(
        vault
            .provisional_entity(&mirela)
            .expect("read")
            .map(|entity| entity.name),
        Some("Mirela".to_owned())
    );
    assert_eq!(found(&vault, "Mirela"), vec![(tagged, 0)]);

    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("entities"),
        &mirela.to_hex(),
        &peer_row(9, 9),
    )
    .expect("the peer's row again, well formed");
    doc.commit();

    assert!(vault.get(&mirela).expect("read").is_some());
    assert_eq!(vault.provisional_entity(&mirela).expect("read"), None);
    assert_eq!(tags(&vault, &tagged).mentions[0].link, MentionLink::Tag);
}
