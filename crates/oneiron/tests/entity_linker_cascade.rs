//! The entity linker's phonetic and role rungs (census item 12; ARCH-0024
//! signals 2 and 3).
//!
//! A person's name of two or more parts that the identity key misses is
//! looked up next over the phonetic postings every PERSON birth writes: a
//! person sounds like it who holds its whole romaji or kana code, or the
//! Soundex code of every one of its parts. Two or more people who sound like
//! the name stay candidates together: the nightly identity re-check asks
//! which one it is (IDENTITY_SETTLE), and nothing is merged. One person alone
//! is an unsure match (OF-123): the mention mints its own provisional person,
//! as on main, the re-check asks whether it is that person or someone new,
//! and an agent about to act on the name asks first. A first name alone
//! mints with no ask, as on main, and so does a name whose parts sound unlike
//! every person's.
//!
//! A person mention that names someone by their relationship to the
//! speaker, `my manager`, is looked up through the speaker's role edges: an
//! Active `relationship.<word>` claim on the speaker valued with the related
//! person's id. One person an Approved edge names is the mention's link, as
//! a known role edge hard-links; two or more stay candidates for the nightly
//! IDENTITY_SETTLE ask and are never merged; one only an unsure edge names
//! (Auto, or Approved but held for its owner's answer) is an unsure match,
//! asked about as a lone sound match is, and persons who only sound like the
//! role words never take its place. The `relationship`
//! root is multi-valued, so a second edge of one word stands beside the
//! first. A stored id follows a merge to its one surviving head; a deleted
//! person, no edge for the word, or an edge of someone other than the
//! speaker, mints as on main.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test entity_linker_cascade`.

#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::batch::generate_phonetic_codes;
use oneiron::dreamer_runner::maintenance::identity::{
    IdentityActNow, IdentityActNowRequest, IdentityAskReason, IdentityEffect,
};
use oneiron::edge::EdgeActorClass;
use oneiron::identity_topology::{
    IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp,
    SurvivorshipPlan,
};
use oneiron::memory::extraction::{EncoderOutput, NerSpan};
use oneiron::memory::{
    ClaimInput, MEMORY_CODE_IDENTITY_UNSETTLED, MessagePersonRequest, WitnessAssertions,
    WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::outbound::MentionProvenance;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};
use oneiron::tagging::{HeldTagsOutcome, MentionLink, TaggingMarkerConfig, TaggingMode};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::identity_recheck::run_identity_recheck;
use oneiron::test_doors::label_writers::{embedded_owner, open_member_vault};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    Vault, VaultConfig,
};
use serde_json::json;

const CHECKPOINT: &str = "0123456789abcdef";
const SHIPPED_POLICY_PACK: &str = "oneiron-default-policy";
const ROOM: &str = "52525252525252525252525252525252";
const TURN: &str = "76767676767676767676767676767676";

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

/// A vault whose tagger saves its tags.
fn open(dir: &tempfile::TempDir) -> Arc<Vault> {
    Arc::new(Vault::open(dir.path(), tagging_config()).expect("open vault"))
}

/// A PERSON named `name`; its birth writes its identity hints and its
/// phonetic postings.
fn person(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).expect("body"),
        )
        .expect("a person");
    id
}

/// [`save_as`], said by a fresh PERSON.
fn save(vault: &Vault, text: &str, name: &str) -> (EntityId, MentionLink) {
    let speaker = person(vault, "fixture speaker");
    save_as(vault, speaker, text, name)
}

/// Witnesses `text` as one turn of `author` whose held tags name `name` in
/// it as a `PERSON`, saved in the witness write; returns the turn and the
/// saved link of that one mention.
fn save_as(vault: &Vault, author: EntityId, text: &str, name: &str) -> (EntityId, MentionLink) {
    let start = text.find(name).expect("the name is in the text");
    let turn = WitnessTurn {
        conversation_ref: ROOM.into(),
        turn_ref: Some(TURN.to_owned()),
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
        spans: vec![NerSpan {
            message: 0,
            start,
            end: start + name.len(),
            label: "PERSON".to_owned(),
            confidence: 1.0,
        }],
        links: Vec::new(),
        vad: None,
        context_links: Vec::new(),
        speaker_links: Vec::new(),
        stack_sha16: None,
        mood_parts: Vec::new(),
    };
    let (_, outcome) = vault
        .memory(author, EdgeActorClass::Human)
        .witness_with_held_tags(&turn, &tags)
        .expect("witness with held tags");
    assert!(
        matches!(outcome, HeldTagsOutcome::Completed(_)),
        "the held tags are saved in the witness write: {outcome:?}"
    );
    let turn = EntityId::from_hex(TURN).expect("turn id");
    let saved = vault
        .turn_tags(&turn)
        .expect("tags read")
        .expect("the turn has saved tags");
    assert_eq!(saved.mentions.len(), 1);
    (turn, saved.mentions[0].link.clone())
}

/// "Owan Smyth" is no name or alias of Owen Smith, so the identity key
/// misses it. He is the one person it sounds like, which is an unsure
/// match: the mention mints its own provisional person, and the nightly
/// re-check opens one IDENTITY_SETTLE ask, Owen Smith or someone new. Main
/// mints and asks nothing.
#[test]
fn a_lone_sound_match_mints_and_the_recheck_asks_about_it() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(&dir);
    let owen = person(&vault, "Owen Smith");
    assert!(
        vault
            .lookup_identity_key(ENTITY_TYPE_PERSON, "Owan Smyth")
            .expect("key lookup")
            .is_empty(),
        "the identity key misses the spelling"
    );

    let (turn, link) = save(&vault, "Owan Smyth called.", "Owan Smyth");

    assert_asks_whether_it_is(&vault, (turn, link), "Owan Smyth", owen);
}

/// Two people sound like "Owan Smyth". The mention keeps both as candidates,
/// the nightly re-check opens one IDENTITY_SETTLE ask that names both, and
/// both stay their own entity. Main mints a provisional entity and asks
/// nothing.
#[test]
fn two_people_who_sound_alike_raise_a_settle_ask_and_stay_two() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(&dir);
    let smith = person(&vault, "Owen Smith");
    let smyth = person(&vault, "Owen Smyth");
    let both = BTreeSet::from([smith, smyth]);

    let (turn, link) = save(&vault, "Owan Smyth called.", "Owan Smyth");

    let MentionLink::Candidates { kind, entities } = &link else {
        panic!("two people who sound alike are both candidates, not a mint: {link:?}");
    };
    assert_eq!(*kind, ENTITY_TYPE_PERSON);
    assert_eq!(entities.iter().copied().collect::<BTreeSet<_>>(), both);

    let asks = run_identity_recheck(&vault, now_seconds()).expect("recheck");
    assert_eq!(asks.len(), 1, "one ask for the one mention: {asks:?}");
    let ask = &asks[0];
    assert_eq!(ask.kind, ENTITY_TYPE_PERSON);
    assert_eq!(ask.name, "Owan Smyth");
    assert_eq!(ask.turn, turn);
    assert_eq!(ask.reason, IdentityAskReason::Unsettled);
    assert_eq!(ask.provisional, None);
    assert_eq!(
        ask.candidates.iter().copied().collect::<BTreeSet<_>>(),
        both
    );

    assert_eq!(vault.resolve_entity(&smith).expect("resolve"), vec![smith]);
    assert_eq!(vault.resolve_entity(&smyth).expect("resolve"), vec![smyth]);
}

/// A kana spelling of a name shares its romaji key with the Latin one, so
/// "もり ゆき" sounds like Mori Yuki alone: it mints, and the nightly
/// re-check asks whether it is Mori Yuki. Main mints and asks nothing.
#[test]
fn a_kana_spelling_is_asked_about_the_romaji_name() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(&dir);
    let yuki = person(&vault, "Mori Yuki");

    let (turn, link) = save(&vault, "もり ゆきが来た。", "もり ゆき");

    assert_asks_whether_it_is(&vault, (turn, link), "もり ゆき", yuki);
}

/// An agent about to act on a lone sound match asks first (OF-123). With
/// only John Smith in the vault, "Jon Smyth" mints. A message that names
/// that mention as its source is refused IDENTITY_UNSETTLED, and
/// `self.identity.settle` opens the act-now ask, John Smith or someone new.
/// The guard runs before the recipient lookup, so the request's `pr` is
/// John's id, not a roster handle. On main the mention's own provisional
/// settles it at once: the guard lets the message through, and it fails
/// later on that lookup (NOT_FOUND), not IDENTITY_UNSETTLED.
#[test]
fn an_effect_on_a_lone_sound_match_asks_first() {
    let dir = tempfile::tempdir().expect("dir");
    let vault =
        Arc::new(open_member_vault(dir.path(), tagging_config(), &[]).expect("fixture vault"));
    let (owner, _proof) = embedded_owner(&vault).expect("the owner");
    let john = person(&vault, "John Smith");

    let (turn, link) = save_as(&vault, owner, "Jon Smyth called.", "Jon Smyth");
    let provisional = assert_mints(&vault, link);
    let tags = vault
        .turn_tags(&turn)
        .expect("tags read")
        .expect("the turn has saved tags");
    let mention = &tags.mentions[0];
    let memory = vault.memory(owner, EdgeActorClass::Human);

    let refused = memory
        .message_person(&MessagePersonRequest {
            pr: john.to_hex(),
            text: "The meeting moved to noon.".to_owned(),
            mention: Some(MentionProvenance {
                turn: turn.to_hex(),
                message: mention.message.to_hex(),
                start: u64::try_from(mention.start).expect("span start"),
                end: u64::try_from(mention.end).expect("span end"),
            }),
            from_project: None,
            to_project: None,
        })
        .expect_err("a message to a lone sound match waits for its ask");
    assert_eq!(refused.code, MEMORY_CODE_IDENTITY_UNSETTLED, "{refused:?}");

    let opened = memory
        .identity_act_now(&IdentityActNowRequest {
            name: "Jon Smyth".to_owned(),
            conversation: None,
            effect: IdentityEffect::Send,
            prompt: "Which Jon Smyth?".to_owned(),
            someone_new: "Someone new".to_owned(),
            provisional: None,
        })
        .expect("the act-now ask");
    assert!(
        matches!(opened, IdentityActNow::Deciding { .. }),
        "a lone sound match opens the act-now ask: {opened:?}"
    );
    let asks = run_identity_recheck(&vault, now_seconds()).expect("recheck");
    assert_eq!(asks.len(), 1, "one ask for the one mention: {asks:?}");
    let ask = &asks[0];
    assert_eq!(ask.name, "Jon Smyth");
    assert_eq!(
        ask.reason,
        IdentityAskReason::ActNow {
            effect: IdentityEffect::Send
        }
    );
    assert_eq!(ask.provisional, Some(provisional));
    assert_eq!(
        ask.candidates.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([john, provisional])
    );
}

/// A first name alone is too common to name one person by its sound:
/// "Owan" mints and is not asked about Owen Smith, as on main.
#[test]
fn a_first_name_alone_takes_no_phonetic_link() {
    assert_no_phonetic_link("Owen Smith", "Owan");
}

/// "Robert Jones" and Robert Smith share the Soundex code of the whole
/// name, R163, because the first name's consonants fill all four of its
/// characters. The last names' own codes, J520 and S530, differ, so the
/// mention mints and is not asked about Robert Smith, as on main.
#[test]
fn a_shared_first_name_takes_no_phonetic_link() {
    assert_no_phonetic_link("Robert Smith", "Robert Jones");
}

/// "Owen Snow" and Owen Smith share the Soundex code of the whole name,
/// O525, which stops inside the last name. The last names' own codes, S500
/// and S530, differ, so the mention mints with no ask, as on main.
#[test]
fn a_last_name_that_sounds_different_takes_no_phonetic_link() {
    assert_no_phonetic_link("Owen Smith", "Owen Snow");
}

/// A family name written first fills the whole name's Soundex code alone:
/// "Morimoto Owen" and Morimoto Yuki are both M653. The given names' codes,
/// O500 and Y200, differ, so the mention mints with no ask, as on main.
#[test]
fn a_shared_family_name_written_first_takes_no_phonetic_link() {
    assert_no_phonetic_link("Morimoto Yuki", "Morimoto Owen");
}

/// A part of combining marks alone is no part once the marks are stripped:
/// "Owan \u{301}" is a first name alone, so it mints and is not asked about
/// Owen Smith, as on main.
#[test]
fn a_part_of_marks_alone_takes_no_phonetic_link() {
    assert_no_phonetic_link("Owen Smith", "Owan \u{301}");
}

/// With only `person_name` in the vault, a mention of `mention` is not
/// matched to them: it mints a provisional person, and the nightly
/// re-check opens no ask.
fn assert_no_phonetic_link(person_name: &str, mention: &str) {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(&dir);
    person(&vault, person_name);

    let (_, link) = save(&vault, &format!("{mention} called."), mention);

    assert_mints(&vault, link);
    let asks = run_identity_recheck(&vault, now_seconds()).expect("recheck");
    assert!(asks.is_empty(), "no ask follows: {asks:?}");
}

/// The mention `name` in `turn` minted its own provisional person, and the
/// nightly re-check opened one IDENTITY_SETTLE ask: is it `real`, or
/// someone new?
fn assert_asks_whether_it_is(
    vault: &Vault,
    (turn, link): (EntityId, MentionLink),
    name: &str,
    real: EntityId,
) {
    let provisional = assert_mints(vault, link);
    let asks = run_identity_recheck(vault, now_seconds()).expect("recheck");
    assert_eq!(asks.len(), 1, "one ask for the one mention: {asks:?}");
    let ask = &asks[0];
    assert_eq!(ask.kind, ENTITY_TYPE_PERSON);
    assert_eq!(ask.name, name);
    assert_eq!(ask.turn, turn);
    assert_eq!(ask.reason, IdentityAskReason::Unsettled);
    assert_eq!(ask.provisional, Some(provisional));
    assert_eq!(
        ask.candidates.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([real, provisional])
    );
}

/// The mention minted a provisional person, which is returned: it is no
/// one's candidate.
fn assert_mints(vault: &Vault, link: MentionLink) -> EntityId {
    let MentionLink::Minted { kind, entity } = link else {
        panic!("the mention mints: {link:?}");
    };
    assert_eq!(kind, ENTITY_TYPE_PERSON);
    assert!(
        vault
            .provisional_entity(&entity)
            .expect("provisional read")
            .is_some()
    );
    entity
}

/// A vault with the shipped policy whose tagger saves its tags, and its
/// embedded owner.
fn open_with_owner(dir: &tempfile::TempDir) -> (Arc<Vault>, EntityId) {
    let vault =
        Arc::new(open_member_vault(dir.path(), tagging_config(), &[]).expect("fixture vault"));
    let (owner, _proof) = embedded_owner(&vault).expect("the owner");
    (vault, owner)
}

/// Writes the role edge `relationship.<word>` on `possessor`, valued with
/// `person`'s id, at `approval`, and checks that it reads back Active at
/// that approval. The predicate is declared normal first, as an owner's
/// policy rule would: a predicate no rule names takes the criticality
/// floor, so its write pends instead of landing.
fn role_edge(
    vault: &Vault,
    possessor: EntityId,
    word: &str,
    person: EntityId,
    approval: ClaimApprovalStatus,
) -> EntityId {
    role_edge_valid_from(vault, possessor, word, person, approval, None)
}

/// A role edge as [`role_edge`] writes it, whose valid time starts at
/// `valid_from` (Unix seconds).
fn role_edge_valid_from(
    vault: &Vault,
    possessor: EntityId,
    word: &str,
    person: EntityId,
    approval: ClaimApprovalStatus,
    valid_from: Option<u64>,
) -> EntityId {
    let predicate = format!("relationship.{word}");
    declare_predicate_normal(vault, &predicate);
    let claim = EntityId::now();
    let mut body = ClaimBody::new(
        predicate.as_str(),
        ClaimSubject::Entity(possessor),
        rmpv::Value::from(person.to_hex()),
        1.0,
        approval,
        ClaimLifecycleStatus::Active,
    )
    .expect("role edge body");
    body.scope_facet = oneiron::claim::substrate_facet_id(possessor).expect("substrate facet");
    body.valid_from = valid_from;
    vault
        .put_claim(&claim, &body, TimeRange { start: 1, end: 1 }, 1)
        .expect("role edge put");
    let stored = vault
        .get_claim(&claim)
        .expect("claim read")
        .expect("the role edge is stored");
    assert_eq!(stored.predicate, predicate);
    assert_eq!(stored.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(stored.approval, approval, "the role edge lands as written");
    claim
}

/// Declares the exact `predicate` normal in the stored shipped policy.
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

/// The owner's own statement that `person` is their `word`, through the
/// public claim facade (`Memory::claim_upsert`), as an owner records it;
/// the facade decides its approval.
fn stated_role_edge(vault: &Vault, owner: EntityId, word: &str, person: EntityId) -> EntityId {
    let id = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .claim_upsert(&ClaimInput {
            id: Some(id.to_hex()),
            predicate: format!("relationship.{word}"),
            subject_ref: owner.to_hex(),
            value: json!(person.to_hex()),
            confidence: 0.9,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
            confidence_details: None,
        })
        .expect("the owner's role edge");
    id
}

/// Installs this device's keystore and loads the install's signing keys, as
/// a host does after each open: a merge's seal and a delete need them.
fn install_signing(vault: &Vault) {
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
}

/// The owner says "my manager", and an Approved role edge on the owner
/// names Owen Smith: the mention links to Owen, as a known role edge
/// hard-links, mints nothing, and the nightly re-check asks nothing. Main
/// and the phonetic rung alone never read the edge: the mention mints a
/// provisional person named "my manager".
#[test]
fn my_manager_links_through_the_owners_role_edge() {
    let dir = tempfile::tempdir().expect("dir");
    let (vault, owner) = open_with_owner(&dir);
    let owen = person(&vault, "Owen Smith");
    role_edge(
        &vault,
        owner,
        "manager",
        owen,
        ClaimApprovalStatus::Approved,
    );
    assert!(
        vault
            .lookup_identity_key(ENTITY_TYPE_PERSON, "my manager")
            .expect("key lookup")
            .is_empty(),
        "the identity key misses the role"
    );

    let (_, link) = save_as(&vault, owner, "my manager called.", "my manager");

    assert_eq!(
        link,
        MentionLink::Candidates {
            kind: ENTITY_TYPE_PERSON,
            entities: vec![owen],
        },
        "the owner's manager edge links the mention to Owen"
    );
    let asks = run_identity_recheck(&vault, now_seconds()).expect("recheck");
    assert!(
        asks.is_empty(),
        "a known role edge is a sure link: {asks:?}"
    );
    assert_eq!(vault.resolve_entity(&owen).expect("resolve"), vec![owen]);
}

/// The owner states two managers through the claim facade, Owen Smith and
/// Mori Yuki. The `relationship` root is multi-valued, so the second edge
/// stands beside the first instead of superseding it. The mention keeps
/// both as candidates, the nightly re-check opens one IDENTITY_SETTLE ask
/// that names both, and both stay their own entity. Main supersedes the
/// first edge and mints a provisional person.
#[test]
fn two_managers_stay_candidates_and_raise_a_settle_ask() {
    let dir = tempfile::tempdir().expect("dir");
    let (vault, owner) = open_with_owner(&dir);
    let owen = person(&vault, "Owen Smith");
    let yuki = person(&vault, "Mori Yuki");
    declare_predicate_normal(&vault, "relationship.manager");
    let edges = [owen, yuki].map(|manager| stated_role_edge(&vault, owner, "manager", manager));
    for edge in edges {
        let stored = vault
            .get_claim(&edge)
            .expect("claim read")
            .expect("the role edge is stored");
        assert_eq!(
            stored.lifecycle,
            ClaimLifecycleStatus::Active,
            "a second manager edge stands beside the first"
        );
    }
    let both = BTreeSet::from([owen, yuki]);

    let (turn, link) = save_as(&vault, owner, "my manager called.", "my manager");

    let MentionLink::Candidates { kind, entities } = &link else {
        panic!("two managers are both candidates, not a mint: {link:?}");
    };
    assert_eq!(*kind, ENTITY_TYPE_PERSON);
    assert_eq!(entities.iter().copied().collect::<BTreeSet<_>>(), both);

    let asks = run_identity_recheck(&vault, now_seconds()).expect("recheck");
    assert_eq!(asks.len(), 1, "one ask for the one mention: {asks:?}");
    let ask = &asks[0];
    assert_eq!(ask.kind, ENTITY_TYPE_PERSON);
    assert_eq!(ask.name, "my manager");
    assert_eq!(ask.turn, turn);
    assert_eq!(ask.reason, IdentityAskReason::Unsettled);
    assert_eq!(ask.provisional, None);
    assert_eq!(
        ask.candidates.iter().copied().collect::<BTreeSet<_>>(),
        both
    );

    assert_eq!(vault.resolve_entity(&owen).expect("resolve"), vec![owen]);
    assert_eq!(vault.resolve_entity(&yuki).expect("resolve"), vec![yuki]);
}

/// Owen Smith was merged into Owen R. Smith after the owner's Approved
/// manager edge named him. The stored id follows the merge to its one
/// surviving head, so "my manager" links to Owen R. Smith. Main mints a
/// provisional person.
#[test]
fn a_merged_manager_links_to_the_surviving_head() {
    let dir = tempfile::tempdir().expect("dir");
    let (vault, owner) = open_with_owner(&dir);
    install_signing(&vault);
    let owen = person(&vault, "Owen Smith");
    let survivor = person(&vault, "Owen R. Smith");
    role_edge(
        &vault,
        owner,
        "manager",
        owen,
        ClaimApprovalStatus::Approved,
    );
    let merged = vault
        .apply_identity_topology_op(
            &IdentityTopologyOp::Merge(MergeOp {
                sources: vec![owen],
                survivor,
                evidence: IdentityOpEvidence {
                    refs: Vec::new(),
                    rationale: "one person under two records".to_owned(),
                },
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            }),
            &IdentityOpWrite::auto(ClaimSource::UserStated),
            now_seconds(),
        )
        .expect("merge");
    assert!(
        matches!(merged, IdentityOpOutcome::Applied { .. }),
        "the merge applies: {merged:?}"
    );
    assert_eq!(
        vault.resolve_entity(&owen).expect("resolve"),
        vec![survivor]
    );

    let (_, link) = save_as(&vault, owner, "my manager called.", "my manager");

    assert_eq!(
        link,
        MentionLink::Candidates {
            kind: ENTITY_TYPE_PERSON,
            entities: vec![survivor],
        },
        "the edge's stored id follows the merge to its surviving head"
    );
}

/// The owner's Approved manager edge names Owen Smith, who is deleted. A
/// deleted person names no one: "my manager" mints with no ask, as on
/// main.
#[test]
fn a_deleted_manager_gives_no_link() {
    let dir = tempfile::tempdir().expect("dir");
    let (vault, owner) = open_with_owner(&dir);
    install_signing(&vault);
    let owen = person(&vault, "Owen Smith");
    role_edge(
        &vault,
        owner,
        "manager",
        owen,
        ClaimApprovalStatus::Approved,
    );
    assert!(vault.delete_entity(&owen).expect("delete Owen"));

    let (_, link) = save_as(&vault, owner, "my manager called.", "my manager");

    assert_mints(&vault, link);
    let asks = run_identity_recheck(&vault, now_seconds()).expect("recheck");
    assert!(asks.is_empty(), "no ask follows: {asks:?}");
}

/// The owner said "my manager" before any edge named Owen Smith, so the
/// mention minted. Once an Approved manager edge names him, the nightly
/// re-check asks whether the mention is Owen or someone new. Main never
/// reads the edge and asks nothing.
#[test]
fn a_mention_minted_before_its_role_edge_is_asked_about() {
    let dir = tempfile::tempdir().expect("dir");
    let (vault, owner) = open_with_owner(&dir);
    let owen = person(&vault, "Owen Smith");
    let (turn, link) = save_as(&vault, owner, "my manager called.", "my manager");

    role_edge(
        &vault,
        owner,
        "manager",
        owen,
        ClaimApprovalStatus::Approved,
    );

    assert_asks_whether_it_is(&vault, (turn, link), "my manager", owen);
}

/// An Auto manager edge, which no owner approved, is an unsure match
/// (OF-123): the mention mints its own provisional person, and an agent
/// about to act on it asks first. A message that names the mention as its
/// source is refused IDENTITY_UNSETTLED, and `self.identity.settle` opens
/// the act-now ask, Owen Smith or someone new. On main the mention's own
/// provisional settles it at once: the guard lets the message through, and
/// it fails later on the recipient lookup (NOT_FOUND), not
/// IDENTITY_UNSETTLED. The edge's valid time starts at 1 s: the guard
/// reads it at the vault's clock, as the save and the recheck do, not at 0.
#[test]
fn an_effect_on_an_inferred_role_edge_asks_first() {
    let dir = tempfile::tempdir().expect("dir");
    let (vault, owner) = open_with_owner(&dir);
    let owen = person(&vault, "Owen Smith");
    role_edge_valid_from(
        &vault,
        owner,
        "manager",
        owen,
        ClaimApprovalStatus::Auto,
        Some(1),
    );

    let (turn, link) = save_as(&vault, owner, "my manager called.", "my manager");
    let provisional = assert_mints(&vault, link);
    let tags = vault
        .turn_tags(&turn)
        .expect("tags read")
        .expect("the turn has saved tags");
    let mention = &tags.mentions[0];
    let memory = vault.memory(owner, EdgeActorClass::Human);

    let refused = memory
        .message_person(&MessagePersonRequest {
            pr: owen.to_hex(),
            text: "The meeting moved to noon.".to_owned(),
            mention: Some(MentionProvenance {
                turn: turn.to_hex(),
                message: mention.message.to_hex(),
                start: u64::try_from(mention.start).expect("span start"),
                end: u64::try_from(mention.end).expect("span end"),
            }),
            from_project: None,
            to_project: None,
        })
        .expect_err("a message to an inferred manager waits for its ask");
    assert_eq!(refused.code, MEMORY_CODE_IDENTITY_UNSETTLED, "{refused:?}");

    let opened = memory
        .identity_act_now(&IdentityActNowRequest {
            name: "my manager".to_owned(),
            conversation: None,
            effect: IdentityEffect::Send,
            prompt: "Which manager?".to_owned(),
            someone_new: "Someone new".to_owned(),
            provisional: None,
        })
        .expect("the act-now ask");
    assert!(
        matches!(opened, IdentityActNow::Deciding { .. }),
        "an inferred role edge opens the act-now ask: {opened:?}"
    );
    let asks = run_identity_recheck(&vault, now_seconds()).expect("recheck");
    assert_eq!(asks.len(), 1, "one ask for the one mention: {asks:?}");
    let ask = &asks[0];
    assert_eq!(ask.name, "my manager");
    assert_eq!(
        ask.reason,
        IdentityAskReason::ActNow {
            effect: IdentityEffect::Send
        }
    );
    assert_eq!(ask.provisional, Some(provisional));
    assert_eq!(
        ask.candidates.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([owen, provisional])
    );
}

/// The role words are the fixed relationship labels with no synonym: an
/// Approved `relationship.boss` edge is not read for "my manager", which
/// mints with no ask, as on main.
#[test]
fn a_role_with_no_edge_for_its_word_mints_as_today() {
    let dir = tempfile::tempdir().expect("dir");
    let (vault, owner) = open_with_owner(&dir);
    let owen = person(&vault, "Owen Smith");
    role_edge(&vault, owner, "boss", owen, ClaimApprovalStatus::Approved);

    let (_, link) = save_as(&vault, owner, "my manager called.", "my manager");

    assert_mints(&vault, link);
    let asks = run_identity_recheck(&vault, now_seconds()).expect("recheck");
    assert!(asks.is_empty(), "no ask follows: {asks:?}");
}

/// "my" names the speaker: Mori Yuki's manager edge naming Owen Smith is not
/// read when the owner says "my manager", which mints with no ask, as on
/// main.
#[test]
fn another_persons_role_edge_is_not_the_speakers() {
    let dir = tempfile::tempdir().expect("dir");
    let (vault, owner) = open_with_owner(&dir);
    let owen = person(&vault, "Owen Smith");
    let yuki = person(&vault, "Mori Yuki");
    role_edge(&vault, yuki, "manager", owen, ClaimApprovalStatus::Approved);

    let (_, link) = save_as(&vault, owner, "my manager called.", "my manager");

    assert_mints(&vault, link);
    let asks = run_identity_recheck(&vault, now_seconds()).expect("recheck");
    assert!(asks.is_empty(), "no ask follows: {asks:?}");
}

/// The owner's Approved manager edge naming Owen Smith is held for its
/// owner's answer (ARCH-0026 §G3), as a replica's Approved revision of a
/// held critical claim leaves it. A held claim lends no authority, so the
/// edge is an unsure match: "my manager" mints its own provisional person,
/// and the nightly re-check asks whether it is Owen or someone new. #7387's
/// first head read the stored approval alone and linked Owen with no ask.
#[test]
fn a_held_approved_role_edge_is_an_unsure_match() {
    let dir = tempfile::tempdir().expect("dir");
    let (vault, owner) = open_with_owner(&dir);
    let owen = person(&vault, "Owen Smith");
    let edge = role_edge(
        &vault,
        owner,
        "manager",
        owen,
        ClaimApprovalStatus::Approved,
    );
    oneiron::test_doors::identity_recheck::open_owner_answer_obligation(&vault, &edge)
        .expect("the edge is held for its owner's answer");

    let (turn, link) = save_as(&vault, owner, "my manager called.", "my manager");

    assert_asks_whether_it_is(&vault, (turn, link), "my manager", owen);
}

/// An Auto manager edge names Owen Smith, and May Manager and Moe Manager
/// both sound like "my manager" (the Soundex code of every part: M000,
/// M526). The lone unsure role hit is the mention's unsure match: it mints
/// its own provisional person, and the nightly re-check asks about Owen
/// beside the two who sound like it, or someone new. #7387's first head
/// fell through to the phonetic rung and saved May and Moe as the
/// candidates, with Owen in no ask.
#[test]
fn a_lone_unsure_role_edge_is_not_replaced_by_sound_matches() {
    let dir = tempfile::tempdir().expect("dir");
    let (vault, owner) = open_with_owner(&dir);
    let owen = person(&vault, "Owen Smith");
    let may = person(&vault, "May Manager");
    let moe = person(&vault, "Moe Manager");
    role_edge(&vault, owner, "manager", owen, ClaimApprovalStatus::Auto);

    let (turn, link) = save_as(&vault, owner, "my manager called.", "my manager");

    let provisional = assert_mints(&vault, link);
    let asks = run_identity_recheck(&vault, now_seconds()).expect("recheck");
    assert_eq!(asks.len(), 1, "one ask for the one mention: {asks:?}");
    let ask = &asks[0];
    assert_eq!(ask.name, "my manager");
    assert_eq!(ask.turn, turn);
    assert_eq!(ask.reason, IdentityAskReason::Unsettled);
    assert_eq!(ask.provisional, Some(provisional));
    assert_eq!(
        ask.candidates.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([owen, may, moe, provisional])
    );
}

/// The codes a write posts are the ones main posts: the linker's whole-name
/// codes come out of the same generator without changing it.
#[test]
fn the_write_codes_are_unchanged() {
    assert_eq!(
        generate_phonetic_codes("Owen Smith"),
        [
            "en:soundex:O500",
            "en:soundex:O525",
            "en:soundex:S530",
            "romaji:owen",
            "romaji:owensmith",
            "romaji:smith",
        ]
    );
    assert_eq!(
        generate_phonetic_codes("Mori Yuki"),
        [
            "en:soundex:M600",
            "en:soundex:M620",
            "en:soundex:Y200",
            "romaji:mori",
            "romaji:moriyuki",
            "romaji:yuki",
        ]
    );
    assert_eq!(
        generate_phonetic_codes("もり ゆき"),
        ["kana:もりゆき", "romaji:moriyuki"]
    );
}
