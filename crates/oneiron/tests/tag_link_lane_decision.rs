//! A saved mention's link is served to a lane as the lane would decide it
//! over the persons it reads (FIX TAG-LINK-DECIDED-OVER-UNREADABLE-PERSONS;
//! the lead's ruling A of 21 Nov, which applies the Engine's rule of
//! 2026-10-15: a contact the reader cannot read counts as absent).
//!
//! A save decides a mention's link over every person in a world the turn is
//! in, readable or not. Kathryn Smith is a PERSON confirmed from a name only a
//! relationship R's MESSAGE holds, so only R's members read her. The outsider
//! is a member of a relationship S, outside R; the insider is a member of
//! both. The TURN under test holds one S MESSAGE, which both read.
//! - Candidates shrink: beside a readable Katherine Smith, "Katharine Smyth"
//!   sounds like both and is saved as candidates naming both. Narrowed, the
//!   outsider would be served Katherine Smith alone, where its own decision
//!   finds one person who sounds like the name and mints. It is served as
//!   unmatched, and its mentions of Katherine Smith leave that mention out.
//! - Hidden exact name: "Kathryn Smith" keys to her alone and is saved as
//!   candidates naming her. Narrowed, the outsider would be served a tag. It
//!   is served as unmatched, and beside two readable persons who sound like
//!   the name, as candidates naming those two.
//! - Control: the insider reads every person the saved link names and is
//!   served the saved link.
//!
//! The served link is compared as its JSON, so the test builds on main too.
//! Each `FIXTURE:` assertion checks the setup, never the fix.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test tag_link_lane_decision`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::edge::EdgeActorClass;
use oneiron::embed::EmbedderLocality;
use oneiron::memory::extraction::{
    EncoderAttempt, EncoderInput, EncoderOutput, ExtractionEncoder, ExtractionWork, NerSpan,
};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::tagging::{
    MentionLink, MentionLinkView, TaggingMarkerConfig, TaggingMentionsRequest, TaggingMode,
    TaggingReconciler, TaggingTurnRequest,
};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::open_member_vault;
use oneiron::{EntityId, ModelId, Vault, VaultConfig};
use oneiron_authority::federation::scope_codec::read_preset;
use serde_json::json;

const CHECKPOINT: &str = "0123456789abcdef";
/// Her name. Before the TURN under test it is said only in R's MESSAGE.
const HIDDEN_NAME: &str = "Kathryn Smith";
/// A name that sounds like hers and like Katherine Smith's (Soundex K365
/// S530 for every one of them), and is no name of either.
const SOUND_ALIKE: &str = "Katharine Smyth";

/// A tagger that tags each name it knows as a `PERSON`, in every MESSAGE it
/// is given.
struct Names {
    model: ModelId,
}

impl ExtractionEncoder for Names {
    fn model_id(&self) -> &ModelId {
        &self.model
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn infer(&self, input: &EncoderInput, _work: ExtractionWork) -> EncoderAttempt {
        let mut spans = Vec::new();
        for (message, each) in input.messages.iter().enumerate() {
            for name in [HIDDEN_NAME, SOUND_ALIKE] {
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
        spans.sort_by_key(|span| (span.message, span.start));
        EncoderAttempt {
            execution: None,
            panicked: false,
            result: Ok(EncoderOutput {
                spans,
                links: Vec::new(),
                vad: None,
                context_links: Vec::new(),
                speaker_links: Vec::new(),
                mood_parts: Vec::new(),
                relations: None,
                stack_sha16: None,
            }),
        }
    }
}

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// An entity of `kind` with `body`.
fn put(vault: &Vault, kind: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(&id, kind, at(1), 1, body)
        .expect("an entity");
    id
}

/// A PERSON named `name`, read as any entity row is; its birth writes its
/// identity hints and its phonetic postings.
fn person(vault: &Vault, name: &str) -> EntityId {
    let body = rmp_serde::to_vec_named(&json!({ "name": name })).expect("body");
    put(vault, ENTITY_TYPE_PERSON, &body)
}

/// A live grant for `member` to read the MESSAGEs of `space`.
fn grant(vault: &Vault, member: EntityId, space: EntityId) {
    vault
        .create_access_grant(
            &EntityId::now(),
            &AccessGrant {
                principal_ref: member,
                scope: AccessGrantScope::Messages { space_ref: space },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: 1,
                revoked_at: None,
                expires_at: None,
                authority_scope: read_preset(),
                companion_bounds: None,
            },
        )
        .expect("a member's grant");
}

/// One tagging pass over every TURN owed one.
fn tag(vault: &Arc<Vault>) {
    TaggingReconciler::new(
        Arc::clone(vault),
        Arc::new(Names {
            model: "fixture/names@v1".parse().expect("model id"),
        }),
    )
    .expect("reconciler")
    .drain_once()
    .expect("one tagging pass");
}

/// A served link's shape: its kind of link, its entity kind, and the refs it
/// names.
fn shape(link: &MentionLinkView) -> (String, Option<u64>, BTreeSet<String>) {
    let value = serde_json::to_value(link).expect("a link's JSON");
    let refs = match (&value["entity_refs"], &value["entity_ref"]) {
        (serde_json::Value::Array(refs), _) => refs
            .iter()
            .filter_map(|each| each.as_str().map(str::to_owned))
            .collect(),
        (_, serde_json::Value::String(one)) => BTreeSet::from([one.clone()]),
        _ => BTreeSet::new(),
    };
    (
        value["link"].as_str().unwrap_or_default().to_owned(),
        value["kind"].as_u64(),
        refs,
    )
}

/// The shape of a link naming `entities` as candidates.
fn candidates(entities: &[EntityId]) -> (String, Option<u64>, BTreeSet<String>) {
    (
        "candidates".to_owned(),
        Some(u64::from(ENTITY_TYPE_PERSON)),
        entities.iter().map(EntityId::to_hex).collect(),
    )
}

/// The shape of a person mention the reader matches to no one it reads.
fn unmatched() -> (String, Option<u64>, BTreeSet<String>) {
    (
        "unmatched".to_owned(),
        Some(u64::from(ENTITY_TYPE_PERSON)),
        BTreeSet::new(),
    )
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    /// A member of S, outside R.
    outsider: EntityId,
    /// A member of R and S.
    insider: EntityId,
    /// The speaker of every MESSAGE.
    speaker: EntityId,
    shared: EntityId,
    /// Kathryn Smith, whom only R's members read.
    hidden: EntityId,
}

/// A vault whose tagger saves its tags, with Kathryn Smith confirmed from
/// the one R MESSAGE that names her.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let (outsider, insider) = (EntityId::now(), EntityId::now());
    let mut config = VaultConfig::device();
    config.tagging = Some(
        TaggingMarkerConfig::new(CHECKPOINT)
            .expect("checkpoint")
            .with_labels(BTreeMap::from([("PERSON".to_owned(), ENTITY_TYPE_PERSON)]))
            .with_mode(TaggingMode::Save),
    );
    let members = [outsider.to_hex(), insider.to_hex()];
    let vault = Arc::new(open_member_vault(dir.path(), config, &members).expect("fixture vault"));
    let relationship = put(&vault, ENTITY_TYPE_RELATIONSHIP, b"relationship R");
    let shared = put(&vault, ENTITY_TYPE_RELATIONSHIP, b"relationship S");
    for member in [outsider, insider] {
        vault
            .put_entity(&member, ENTITY_TYPE_PERSON, at(1), 1, b"member")
            .expect("a member");
        grant(&vault, member, shared);
    }
    grant(&vault, insider, relationship);
    let speaker = person(&vault, "speaker");
    let mut fixture = Fixture {
        _dir: dir,
        vault,
        outsider,
        insider,
        speaker,
        shared,
        hidden: speaker,
    };

    let (turn, link) = fixture.said(&format!("{HIDDEN_NAME} called."), relationship, 10);
    let MentionLink::Minted { entity, .. } = link else {
        panic!("FIXTURE: R's MESSAGE mints a provisional entity for her name: {link:?}");
    };
    fixture
        .vault
        .memory(speaker, EdgeActorClass::Human)
        .confirm_provisional_entity(&entity)
        .expect("the speaker confirms her");
    fixture.hidden = entity;
    assert!(
        fixture.vault.turn_tags(&turn).expect("tags read").is_some(),
        "FIXTURE: R's TURN keeps its tags"
    );
    assert!(
        fixture
            .vault
            .lookup_identity_key(ENTITY_TYPE_PERSON, HIDDEN_NAME)
            .expect("key lookup")
            .contains(&entity),
        "FIXTURE: her name keys to her"
    );
    assert!(
        !fixture.reads(outsider, &entity),
        "FIXTURE: the outsider does not read her"
    );
    assert!(
        fixture.reads(insider, &entity),
        "FIXTURE: the insider reads her"
    );
    fixture
}

impl Fixture {
    fn reads(&self, reader: EntityId, id: &EntityId) -> bool {
        self.vault
            .memory(reader, EdgeActorClass::Human)
            .get_entity(&id.to_hex())
            .expect("a member's read")
            .value
            .is_some()
    }

    /// Witnesses `words` as a TURN of one MESSAGE of `space` at `time`,
    /// tags it, and returns the TURN and its one saved link.
    fn said(&self, words: &str, space: EntityId, time: u64) -> (EntityId, MentionLink) {
        let turn = EntityId::now();
        self.vault
            .memory(self.speaker, EdgeActorClass::Human)
            .witness(&WitnessTurn {
                conversation_ref: EntityId::now().to_hex(),
                turn_ref: Some(turn.to_hex()),
                thread_audience: None,
                project: None,
                messages: vec![WitnessMessage {
                    id: Some(EntityId::now().to_hex()),
                    author: WitnessAuthor::User,
                    message_type: "dialogue".to_owned(),
                    content: words.to_owned(),
                    parts: None,
                    metadata: Some(json!({"rel": space.to_hex()})),
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at: time,
                assertions: WitnessAssertions::default(),
            })
            .expect("witness");
        tag(&self.vault);
        let tags = self
            .vault
            .turn_tags(&turn)
            .expect("tags read")
            .expect("FIXTURE: the TURN's tags are saved");
        assert_eq!(tags.mentions.len(), 1, "FIXTURE: one name is tagged");
        (turn, tags.mentions[0].link.clone())
    }

    /// [`Self::said`] in S, after Kathryn Smith was confirmed.
    fn said_in_s(&self, words: &str) -> (EntityId, MentionLink) {
        self.said(words, self.shared, 20)
    }

    /// The shape of the one mention's link `reader` is served for `turn`.
    fn served(&self, reader: EntityId, turn: EntityId) -> (String, Option<u64>, BTreeSet<String>) {
        let tags = self
            .vault
            .memory(reader, EdgeActorClass::Human)
            .tagging_tags(&TaggingTurnRequest {
                turn_ref: turn.to_hex(),
            })
            .expect("FIXTURE: the reader reads the TURN's tags")
            .value
            .tags
            .expect("FIXTURE: the TURN has tags");
        assert_eq!(
            tags.mentions.len(),
            1,
            "FIXTURE: the reader sees the S MESSAGE's mention"
        );
        shape(&tags.mentions[0].link)
    }

    /// How many mentions of `entity` `reader` is served.
    fn mentions_of(&self, reader: EntityId, entity: EntityId) -> usize {
        self.vault
            .memory(reader, EdgeActorClass::Human)
            .tagging_mentions(&TaggingMentionsRequest {
                entity_ref: entity.to_hex(),
                limit: 16,
            })
            .expect("the reader's mentions")
            .value
            .mentions
            .len()
    }
}

/// "Katharine Smyth" sounds like Katherine Smith, whom the outsider reads,
/// and like Kathryn Smith, whom it does not: the save names both. The
/// outsider alone finds one person who sounds like the name, which mints: it
/// is served the name as unmatched, and no mention of Katherine Smith.
#[test]
fn a_hidden_sound_alike_leaves_the_outsider_an_unmatched_name_not_one_candidate() {
    let fixture = fixture();
    let katherine = person(&fixture.vault, "Katherine Smith");
    assert!(
        fixture.reads(fixture.outsider, &katherine),
        "FIXTURE: the outsider reads Katherine Smith"
    );
    let (turn, saved) = fixture.said_in_s(&format!("{SOUND_ALIKE} called."));
    let saved_names: BTreeSet<_> = saved.entities().iter().copied().collect();
    assert_eq!(
        (saved.kind(), saved_names),
        (
            Some(ENTITY_TYPE_PERSON),
            BTreeSet::from([katherine, fixture.hidden])
        ),
        "FIXTURE: the save names both persons who sound like the name"
    );
    assert_eq!(
        fixture.served(fixture.insider, turn),
        candidates(&[katherine, fixture.hidden]),
        "the insider, who reads both, is served the saved link"
    );
    assert_eq!(
        (
            fixture.served(fixture.outsider, turn),
            fixture.mentions_of(fixture.outsider, katherine)
        ),
        (unmatched(), 0),
        "LEAK: a person the outsider cannot read turned its lone sound match into candidates"
    );
}

/// "Kathryn Smith" keys to her alone: the save names her. The outsider alone
/// finds no one, which mints: it is served the name as unmatched, not as a
/// tag.
#[test]
fn a_hidden_exact_name_leaves_the_outsider_an_unmatched_name_not_a_tag() {
    let fixture = fixture();
    let (turn, saved) = fixture.said_in_s(&format!("{HIDDEN_NAME} called."));
    assert_eq!(
        saved,
        MentionLink::Candidates {
            kind: ENTITY_TYPE_PERSON,
            entities: vec![fixture.hidden],
        },
        "FIXTURE: her exact name keys to her alone"
    );
    assert_eq!(
        fixture.served(fixture.insider, turn),
        candidates(&[fixture.hidden]),
        "the insider, who reads her, is served the saved link"
    );
    assert_eq!(
        fixture.served(fixture.outsider, turn),
        unmatched(),
        "LEAK: a person the outsider cannot read, holding the name, turned its mint into a tag"
    );
}

/// "Kathryn Smith" keys to her alone, so the save never asks who sounds like
/// the name. The outsider alone finds Katherine Smith and Kathrin Smith, who
/// both sound like it: it is served them as candidates.
#[test]
fn a_hidden_exact_name_leaves_the_outsider_the_sound_alikes_it_reads() {
    let fixture = fixture();
    let katherine = person(&fixture.vault, "Katherine Smith");
    let kathrin = person(&fixture.vault, "Kathrin Smith");
    let (turn, saved) = fixture.said_in_s(&format!("{HIDDEN_NAME} called."));
    assert_eq!(
        saved,
        MentionLink::Candidates {
            kind: ENTITY_TYPE_PERSON,
            entities: vec![fixture.hidden],
        },
        "FIXTURE: her exact name keys to her alone"
    );
    assert!(
        fixture.reads(fixture.outsider, &katherine) && fixture.reads(fixture.outsider, &kathrin),
        "FIXTURE: the outsider reads both sound-alikes"
    );
    assert_eq!(
        fixture.served(fixture.outsider, turn),
        candidates(&[katherine, kathrin]),
        "LEAK: a person the outsider cannot read, holding the name, hid the persons it reads"
    );
}
