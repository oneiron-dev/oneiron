//! The entity linker's phonetic rung (census item 12; ARCH-0024 signal 2).
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
use oneiron::memory::extraction::{EncoderOutput, NerSpan};
use oneiron::memory::{
    MEMORY_CODE_IDENTITY_UNSETTLED, MessagePersonRequest, WitnessAssertions, WitnessAuthor,
    WitnessMessage, WitnessTurn,
};
use oneiron::outbound::MentionProvenance;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::tagging::{HeldTagsOutcome, MentionLink, TaggingMarkerConfig, TaggingMode};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::identity_recheck::run_identity_recheck;
use oneiron::test_doors::label_writers::{embedded_owner, open_member_vault};
use oneiron::{EntityId, Vault, VaultConfig};

const CHECKPOINT: &str = "0123456789abcdef";
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
