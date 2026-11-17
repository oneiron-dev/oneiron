//! A role phrase names a person by their relation to its possessor, the one
//! author of the message it is said in (ARCH-0024 #walks, #resgrid;
//! `tagging/role.rs`). FIX LINKER-ROLE-PROVISIONAL-PER-SPEAKER.
//!
//! "My manager" said by two people names two people until each is settled.
//! On main a provisional person was keyed by the mention's words alone: the
//! second speaker's "my manager" linked to the provisional person minted for
//! the first's, and answering the first speaker's ask re-pointed both
//! mentions to the first speaker's manager. Each speaker's role phrase now
//! mints, and finds, only its own possessor's provisional person.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test entity_linker_role_possessor`.

#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::edge::EdgeActorClass;
use oneiron::memory::extraction::{CorefLink, EncoderOutput, NerSpan};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};
use oneiron::tagging::{HeldTagsOutcome, MentionLink, TaggingMarkerConfig, TaggingMode};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::identity_recheck::{run_identity_recheck, settle_identity_asks_of_turn};
use oneiron::test_doors::label_writers::{embedded_owner, open_member_vault};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, Vault,
    VaultConfig,
};
use serde_json::json;

const CHECKPOINT: &str = "0123456789abcdef";
const SHIPPED_POLICY_PACK: &str = "oneiron-default-policy";
const ROOM: &str = "52525252525252525252525252525252";
const FIRST_TURN: &str = "76767676767676767676767676767676";
const SECOND_TURN: &str = "77777777777777777777777777777777";
const SAID: &str = "my manager called.";
const ROLE_PHRASE: &str = "my manager";

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

/// A device config whose tagger saves its tags, mapping the `PERSON` label.
fn tagging_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.tagging = Some(
        TaggingMarkerConfig::new(CHECKPOINT)
            .expect("checkpoint")
            .with_labels(BTreeMap::from([("PERSON".to_owned(), ENTITY_TYPE_PERSON)]))
            .with_mode(TaggingMode::Save),
    );
    config
}

/// A vault with the shipped policy whose tagger saves its tags, and its
/// embedded owner.
fn open_with_owner(dir: &tempfile::TempDir) -> (Arc<Vault>, EntityId) {
    let vault =
        Arc::new(open_member_vault(dir.path(), tagging_config(), &[]).expect("fixture vault"));
    let (owner, _proof) = embedded_owner(&vault).expect("the owner");
    (vault, owner)
}

/// A PERSON named `name`.
fn person(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&json!({ "name": name })).expect("body"),
        )
        .expect("a person");
    id
}

/// Witnesses "my manager called." as the turn `turn` of `author` in one
/// room, its held tags naming "my manager" as a `PERSON`; returns the turn
/// and the saved link of that one mention.
fn says_my_manager(vault: &Vault, author: EntityId, turn: &str) -> (EntityId, MentionLink) {
    let start = SAID.find(ROLE_PHRASE).expect("the phrase is in the text");
    let witnessed = WitnessTurn {
        conversation_ref: ROOM.into(),
        turn_ref: Some(turn.to_owned()),
        thread_audience: None,
        occurred_at: now_seconds(),
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: SAID.into(),
            parts: None,
            metadata: None,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        assertions: WitnessAssertions::default(),
    };
    let tags = EncoderOutput {
        spans: vec![NerSpan {
            message: 0,
            start,
            end: start + ROLE_PHRASE.len(),
            label: "PERSON".to_owned(),
            confidence: 1.0,
        }],
        links: Vec::new(),
        vad: None,
        context_links: Vec::new(),
        speaker_links: Vec::new(),
        stack_sha16: None,
        mood_parts: Vec::new(),
        relations: None,
    };
    let (_, outcome) = vault
        .memory(author, EdgeActorClass::Human)
        .witness_with_held_tags(&witnessed, &tags)
        .expect("witness with held tags");
    assert!(
        matches!(outcome, HeldTagsOutcome::Completed(_)),
        "FIXTURE: the held tags are saved in the witness write: {outcome:?}"
    );
    let turn = EntityId::from_hex(turn).expect("turn id");
    (turn, saved_link(vault, &turn))
}

/// The saved link of the one mention in `turn`.
fn saved_link(vault: &Vault, turn: &EntityId) -> MentionLink {
    let saved = vault
        .turn_tags(turn)
        .expect("tags read")
        .expect("the turn has saved tags");
    assert_eq!(saved.mentions.len(), 1, "FIXTURE: one mention");
    saved.mentions[0].link.clone()
}

/// The provisional person `link` minted; panics on any other link.
fn minted(vault: &Vault, link: &MentionLink, who: &str) -> EntityId {
    let MentionLink::Minted { kind, entity } = link else {
        panic!("{who}'s \"my manager\" mints its own provisional person, got {link:?}");
    };
    assert_eq!(*kind, ENTITY_TYPE_PERSON);
    assert!(
        vault
            .provisional_entity(entity)
            .expect("provisional read")
            .is_some(),
        "{who}'s mention names a provisional person"
    );
    *entity
}

/// Declares the exact `predicate` normal in the stored shipped policy, as
/// an owner's policy rule would, so a role edge write lands.
fn declare_predicate_normal(vault: &Vault, predicate: &str) {
    let axes = json!({ "criticality": "normal", "sensitivity": "normal" });
    for id in vault
        .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
        .expect("policy manifests")
    {
        let Some(bytes) = vault.get(&id).expect("policy manifest read") else {
            continue;
        };
        let mut manifest: serde_json::Value =
            rmp_serde::from_slice(&bytes).expect("policy manifest body");
        if manifest["pack_id"] != SHIPPED_POLICY_PACK {
            continue;
        }
        let rules = manifest
            .as_object_mut()
            .expect("policy manifest map")
            .entry("rules")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("policy rules list");
        let index = match rules.iter().position(|rule| rule["prefix"] == predicate) {
            Some(index) => index,
            None => {
                rules.push(json!({ "prefix": predicate }));
                rules.len() - 1
            }
        };
        rules[index]["axes"] = axes;
        rules[index]["exact"] = json!(true);
        oneiron::test_support::put_policy_manifest_bytes(
            vault,
            id,
            &rmp_serde::to_vec_named(&manifest).expect("policy manifest encode"),
        )
        .expect("policy manifest put");
        return;
    }
    panic!("the vault holds no shipped policy manifest");
}

/// An Auto `relationship.manager` edge on `possessor` valued with
/// `manager`'s id: an unsure role edge, so the mention mints and the
/// nightly re-check asks about it.
fn auto_manager_edge(vault: &Vault, possessor: EntityId, manager: EntityId) {
    let predicate = "relationship.manager";
    declare_predicate_normal(vault, predicate);
    let claim = EntityId::now();
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(possessor),
        rmpv::Value::from(manager.to_hex()),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("role edge body");
    body.scope_facet = oneiron::claim::substrate_facet_id(possessor).expect("substrate facet");
    vault
        .put_claim(&claim, &body, TimeRange { start: 1, end: 1 }, 1)
        .expect("role edge put");
    let stored = vault
        .get_claim(&claim)
        .expect("claim read")
        .expect("FIXTURE: the role edge is stored");
    assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
    assert_eq!(stored.lifecycle, ClaimLifecycleStatus::Active);
}

/// Xavier, then Yumi, says "my manager called." in one room. Neither has a
/// manager edge, so each mention mints a provisional person, and the two
/// differ: each names its own speaker's manager. On main Yumi's mention
/// linked to the provisional person Xavier's minted.
#[test]
fn two_speakers_my_manager_mint_two_provisional_persons() {
    let dir = tempfile::tempdir().expect("dir");
    let (vault, _owner) = open_with_owner(&dir);
    let xavier = person(&vault, "Xavier Ito");
    let yumi = person(&vault, "Yumi Sato");

    let (_, xaviers) = says_my_manager(&vault, xavier, FIRST_TURN);
    let (_, yumis) = says_my_manager(&vault, yumi, SECOND_TURN);

    let xaviers = minted(&vault, &xaviers, "Xavier");
    let yumis = minted(&vault, &yumis, "Yumi");
    assert_ne!(
        xaviers, yumis,
        "two speakers' \"my manager\" are two provisional persons"
    );
}

/// The owner holds an Auto manager edge naming Owen, so the owner's "my
/// manager" mints and the nightly re-check asks whether it is Owen. Yumi,
/// who holds no manager edge, says it too. Settling the owner's ask as Owen
/// leaves Yumi's mention on her own provisional person. On main both
/// mentions named the owner's provisional person, and settling the owner's
/// ask re-pointed Yumi's mention to Owen.
#[test]
fn answering_one_speakers_manager_leaves_the_others_mention() {
    let dir = tempfile::tempdir().expect("dir");
    let (vault, owner) = open_with_owner(&dir);
    let owen = person(&vault, "Owen Smith");
    let yumi = person(&vault, "Yumi Sato");
    auto_manager_edge(&vault, owner, owen);

    let (owners_turn, owners) = says_my_manager(&vault, owner, FIRST_TURN);
    let (yumis_turn, _) = says_my_manager(&vault, yumi, SECOND_TURN);
    minted(&vault, &owners, "the owner");

    let asks = run_identity_recheck(&vault, now_seconds()).expect("recheck");
    assert!(
        asks.iter()
            .any(|ask| ask.turn == owners_turn && ask.candidates.contains(&owen)),
        "FIXTURE: the re-check asks whether the owner's manager is Owen: {asks:?}"
    );
    let settled = settle_identity_asks_of_turn(&vault, &owners_turn, owen, now_seconds())
        .expect("the owner's ask settles");
    assert_eq!(settled, 1, "FIXTURE: the owner's one ask is settled");

    let after = saved_link(&vault, &yumis_turn);
    assert!(
        !after.entities().contains(&owen),
        "Yumi's \"my manager\" is not the owner's manager: {after:?}"
    );
    minted(&vault, &after, "Yumi");
}

/// "Bob, my manager, called.": the tagger links "my manager" to "Bob", an
/// ordinary name the key misses, so the role phrase takes Bob's link, as on
/// main. Only another speaker's role person is never inherited (FIX
/// LINKER-ROLE-PROVISIONAL-PER-SPEAKER, Opus second review P1).
#[test]
fn a_role_phrase_takes_its_antecedents_ordinary_name() {
    let dir = tempfile::tempdir().expect("dir");
    let (vault, _owner) = open_with_owner(&dir);
    let xavier = person(&vault, "Xavier Ito");
    let text = "Bob, my manager, called.";
    let span = |name: &str| {
        let start = text.find(name).expect("the name is in the text");
        NerSpan {
            message: 0,
            start,
            end: start + name.len(),
            label: "PERSON".to_owned(),
            confidence: 1.0,
        }
    };
    let witnessed = WitnessTurn {
        conversation_ref: ROOM.into(),
        turn_ref: Some(FIRST_TURN.to_owned()),
        thread_audience: None,
        occurred_at: now_seconds(),
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: text.into(),
            parts: None,
            metadata: None,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        assertions: WitnessAssertions::default(),
    };
    let tags = EncoderOutput {
        spans: vec![span("Bob"), span(ROLE_PHRASE)],
        links: vec![CorefLink {
            span: 1,
            antecedent: 0,
            confidence: Some(0.9),
        }],
        vad: None,
        context_links: Vec::new(),
        speaker_links: Vec::new(),
        stack_sha16: None,
        mood_parts: Vec::new(),
        relations: None,
    };
    let (_, outcome) = vault
        .memory(xavier, EdgeActorClass::Human)
        .witness_with_held_tags(&witnessed, &tags)
        .expect("witness with held tags");
    assert!(
        matches!(outcome, HeldTagsOutcome::Completed(_)),
        "FIXTURE: the held tags are saved in the witness write: {outcome:?}"
    );
    let turn = EntityId::from_hex(FIRST_TURN).expect("turn id");
    let saved = vault
        .turn_tags(&turn)
        .expect("tags read")
        .expect("the turn has saved tags");
    assert_eq!(saved.mentions.len(), 2, "FIXTURE: two mentions");
    let bob = minted(&vault, &saved.mentions[0].link, "Bob");
    assert_eq!(
        saved.mentions[1].link.entities(),
        [bob].as_slice(),
        "\"my manager\" takes Bob's link: {:?}",
        saved.mentions[1].link
    );
}
