//! A confirmed role person is its possessor's alone (FIX
//! LINKER-ROLE-CONFIRMED-PERSON-KEY-ACROSS-SPEAKERS; Engine ruling
//! LINKER-ROLE-CONFIRM-ASSERTS-ROLE-EDGE = A, 20 Nov 19:31).
//!
//! "My manager" said by Xavier mints a provisional person whose possessor
//! is Xavier. On main, confirming it made a real person whose identity name
//! was the role words, so every other speaker's "my manager" found that
//! person by the identity key as a lone real candidate: Yumi's manager was
//! Xavier's, with no ask, and the act-now guard settled on him. Confirming
//! a possessed role person now labels it with the role words as its
//! `display_name` only, and asserts the relationship as the role edge
//! `relationship.<word>` on the possessor, valued with the person's id:
//! Approved when the owner's someone-new answer confirms it, Auto when
//! another actor does. Another speaker's phrase finds no key and mints its
//! own provisional person; the possessor's phrase reads the edge.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test entity_linker_confirmed_role_possessor`.

#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::maintenance::identity::{
    IdentityActNow, IdentityActNowRequest, IdentityAnswerRequest, IdentityEffect,
};
use oneiron::edge::EdgeActorClass;
use oneiron::memory::extraction::{EncoderOutput, NerSpan};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::tagging::{HeldTagsOutcome, MentionLink, TaggingMarkerConfig, TaggingMode};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::identity_recheck::run_identity_recheck;
use oneiron::test_doors::label_writers::{embedded_owner, open_member_vault};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, Vault,
    VaultConfig,
};
use serde_json::json;

const CHECKPOINT: &str = "0123456789abcdef";
const ROOM: &str = "53535353535353535353535353535353";
const FIRST_TURN: &str = "78787878787878787878787878787878";
const SECOND_TURN: &str = "79797979797979797979797979797979";
const THIRD_TURN: &str = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a";
const SAID: &str = "my manager called.";
const ROLE_PHRASE: &str = "my manager";
const ROLE_EDGE: &str = "relationship.manager";

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

/// A vault with the shipped policy whose tagger saves its tags, its
/// embedded owner and the owner's proof. The install's machine keys come
/// from its device keystore, as a host's, so an identity answer's signed
/// topology event has a carrier.
fn open_with_owner(dir: &tempfile::TempDir) -> (Arc<Vault>, EntityId, AuthenticatedOwner) {
    let vault =
        Arc::new(open_member_vault(dir.path(), tagging_config(), &[]).expect("fixture vault"));
    let (owner, proof) = embedded_owner(&vault).expect("the owner");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .ensure_serving_install_profile(
            &oneiron::test_support::test_host_issuer(),
            oneiron::authority::MachineRole::Unanswered,
        )
        .expect("this install's machine profile");
    (vault, owner, proof)
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
        project: None,
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

/// The `relationship.manager` edges on `possessor` valued with `person`'s
/// id, as stored.
fn manager_edges(vault: &Vault, possessor: EntityId, person: EntityId) -> Vec<ClaimBody> {
    vault
        .claims_for_subject(&possessor)
        .expect("claims of the possessor")
        .iter()
        .filter_map(|claim| vault.get_claim(claim).expect("claim read"))
        .filter(|body| {
            body.predicate == ROLE_EDGE
                && body.subject == ClaimSubject::Entity(possessor)
                && body.value.as_str() == Some(person.to_hex().as_str())
        })
        .collect()
}

/// The confirmed person's stored body, as a JSON map.
fn person_body(vault: &Vault, person: EntityId) -> serde_json::Value {
    let bytes = vault
        .get(&person)
        .expect("person read")
        .expect("the confirmed person is stored");
    rmp_serde::from_slice(&bytes).expect("person body")
}

/// The confirmed person carries the role words as its label only: no
/// identity name, so the identity key never finds it by the words.
fn assert_labelled_by_the_words_only(vault: &Vault, person: EntityId) {
    let body = person_body(vault, person);
    assert_eq!(
        body["display_name"],
        json!(ROLE_PHRASE),
        "the confirmed person is labelled by the words said: {body}"
    );
    assert!(
        body.get("name").is_none(),
        "the role words are no identity name: {body}"
    );
    assert!(
        !vault
            .lookup_identity_key(ENTITY_TYPE_PERSON, ROLE_PHRASE)
            .expect("identity key lookup")
            .contains(&person),
        "the identity key finds no person by the role words"
    );
}

/// A Proposed `relationship.manager` edge on `possessor` valued with
/// `manager`'s id: an unsure role edge, which lands under the shipped
/// policy, where the predicate is critical. The possessor's "my manager"
/// mints, and the act-now guard asks whether it is that person.
fn proposed_manager_edge(vault: &Vault, possessor: EntityId, manager: EntityId) {
    let claim = EntityId::now();
    let mut body = ClaimBody::new(
        ROLE_EDGE,
        ClaimSubject::Entity(possessor),
        rmpv::Value::from(manager.to_hex()),
        1.0,
        ClaimApprovalStatus::Proposed,
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
    assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
}

/// Xavier says "my manager", and a session of the owner's without the
/// owner's proof confirms the person it minted: the actor alone never
/// authenticates the owner. Yumi then says "my manager": her mention mints
/// her own provisional person and no ask offers her Xavier's manager.
/// Xavier holds an unsure manager edge naming the confirmed person, so his
/// own repeat is an unsure match the re-check asks about. On main the
/// confirm wrote the role words as an identity name and Yumi's mention
/// linked to Xavier's manager as a lone real candidate.
#[test]
fn a_confirmed_role_person_is_not_another_speakers_manager() {
    let dir = tempfile::tempdir().expect("dir");
    let (vault, owner, _proof) = open_with_owner(&dir);
    let xavier = person(&vault, "Xavier Ito");
    let yumi = person(&vault, "Yumi Sato");

    let (_, xaviers) = says_my_manager(&vault, xavier, FIRST_TURN);
    let manager = minted(&vault, &xaviers, "Xavier");
    vault
        .memory(owner, EdgeActorClass::Human)
        .confirm_provisional_entity(&manager)
        .expect("the confirm lands");

    let (yumis_turn, yumis) = says_my_manager(&vault, yumi, SECOND_TURN);
    assert!(
        !yumis.entities().contains(&manager),
        "FAILBEFORE LINKER-ROLE-CONFIRMED-PERSON-KEY-ACROSS-SPEAKERS: Yumi's \"my manager\" \
         is not Xavier's confirmed manager: {yumis:?}"
    );
    minted(&vault, &yumis, "Yumi");
    assert_labelled_by_the_words_only(&vault, manager);

    let edges = manager_edges(&vault, xavier, manager);
    let [edge] = edges.as_slice() else {
        panic!("one manager edge on Xavier names the confirmed person: {edges:?}");
    };
    assert!(
        matches!(
            edge.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Proposed
        ) && edge.lifecycle == ClaimLifecycleStatus::Active,
        "a confirm without the owner's proof asserts the edge unsure: {edge:?}"
    );
    assert!(
        manager_edges(&vault, yumi, manager).is_empty(),
        "Yumi holds no edge naming Xavier's manager"
    );

    let (xaviers_again, again) = says_my_manager(&vault, xavier, THIRD_TURN);
    minted(&vault, &again, "Xavier's repeat");
    let asks = run_identity_recheck(&vault, now_seconds()).expect("recheck");
    assert!(
        asks.iter()
            .any(|ask| ask.turn == xaviers_again && ask.candidates.contains(&manager)),
        "the re-check asks whether Xavier's repeat is the person his edge names: {asks:?}"
    );
    assert!(
        !asks
            .iter()
            .any(|ask| ask.turn == yumis_turn && ask.candidates.contains(&manager)),
        "no ask offers Yumi Xavier's manager: {asks:?}"
    );
}

/// The owner holds a Proposed manager edge naming Owen, so the owner's "my
/// manager" mints and the act-now guard asks whether it is Owen. The owner,
/// under the owner's proof, answers someone new. The person born is
/// labelled by the words only, the owner holds an Approved manager edge
/// naming it, and the owner's repeat reads it; Yumi's "my manager" does
/// not. On main the answer wrote the role words as an identity name and no
/// edge, and Yumi's mention linked to the owner's manager.
#[test]
fn an_owner_someone_new_answer_asserts_the_owners_manager() {
    let dir = tempfile::tempdir().expect("dir");
    let (vault, owner, proof) = open_with_owner(&dir);
    let owen = person(&vault, "Owen Smith");
    let yumi = person(&vault, "Yumi Sato");
    proposed_manager_edge(&vault, owner, owen);

    let (_, owners) = says_my_manager(&vault, owner, FIRST_TURN);
    let own = minted(&vault, &owners, "the owner");
    let owner_memory = vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(&proof);
    let opened = owner_memory
        .identity_act_now(&IdentityActNowRequest {
            name: ROLE_PHRASE.to_owned(),
            conversation: None,
            effect: IdentityEffect::Send,
            prompt: "Which manager?".to_owned(),
            someone_new: "Someone new".to_owned(),
            provisional: None,
        })
        .expect("the act-now ask");
    let IdentityActNow::Deciding { ask } = opened else {
        panic!("FIXTURE: the unsure manager opens an ask, got {opened:?}");
    };
    let settled = owner_memory
        .identity_answer(&IdentityAnswerRequest {
            ask,
            choice: "someone_new".to_owned(),
        })
        .expect("the owner answers someone new");
    let manager = EntityId::from_hex(&settled.entity).expect("entity id");
    assert_eq!(
        manager, own,
        "FIXTURE: someone new confirms the mention's own person"
    );

    let edges = manager_edges(&vault, owner, manager);
    let [edge] = edges.as_slice() else {
        panic!(
            "FAILBEFORE LINKER-ROLE-CONFIRMED-PERSON-KEY-ACROSS-SPEAKERS: one manager edge on \
             the owner names the person someone new confirmed: {edges:?}"
        );
    };
    assert_eq!(
        (edge.approval, edge.lifecycle),
        (ClaimApprovalStatus::Approved, ClaimLifecycleStatus::Active),
        "the owner's own answer asserts the edge"
    );
    assert_labelled_by_the_words_only(&vault, manager);

    let (_, yumis) = says_my_manager(&vault, yumi, SECOND_TURN);
    assert!(
        !yumis.entities().contains(&manager),
        "Yumi's \"my manager\" is not the owner's: {yumis:?}"
    );
    minted(&vault, &yumis, "Yumi");

    let (_, again) = says_my_manager(&vault, owner, THIRD_TURN);
    assert!(
        again.entities().contains(&manager),
        "the owner's repeat reads the owner's edge: {again:?}"
    );
}
