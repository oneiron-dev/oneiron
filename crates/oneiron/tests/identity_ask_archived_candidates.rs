//! FIX [IDENTITY-ASK-ARCHIVED-CANDIDATE-OPTIONS]: an archived person the
//! nightly identity re-check names is an option on the owner's card.
//!
//! ARCH-0055 section 10 (archive-visible): "The archive stays visible to the
//! resolver. A later mention of an archived entity restores it and mints no
//! duplicate." The phonetic rung finds a person the vault cleanup archived,
//! and the re-check stores the ask with that person among its candidates.
//! The doors that list, render, decide and answer the ask read each
//! candidate through the caller's lane (FIX 8711), and that read now judges
//! a stored candidate through its cleanup archive: only the archive is
//! lifted, for that one row, and every other gate of the lane still judges
//! it.
//!
//! Red without the fix (the first two tests): the scoped read refuses a
//! cleanup-archived row on every lane, the owner's included, so the owner's
//! card offers only the mention's own provisional person and someone new,
//! and the owner's answer naming the archived person is "not one of the
//! ask's options".
//!
//! The settle restores the person it picks on every path: the third test's
//! ask has no provisional person of its own, so nothing is absorbed. Red
//! without the fix (the answer is no option) and with the candidate read
//! alone (the answer settles, and the person stays archived).
//!
//! Guards that hold with and without the fix (the last two tests): the
//! lift reaches only the candidate read; the owner's plain read of the
//! archived person still finds none, and listing the ask restores no one.
//! An act-now on a name whose one saved person is archived answers unknown,
//! as it did before the fix, since that answer restores no one (red with
//! the candidate read used there too).
//!
//! The Dreamer's settle that picks the archived person restores him too,
//! and the owner's revert of that settle puts the archive back, by the
//! cleanup's own rule (REVIEW-9779 round 2): his plain read finds no one
//! again. Red without the fix (the revert leaves the person restored). A
//! later mention of the person keeps the restore through the revert, and
//! the revert lists him as left alone (red without the fix: it lists
//! nothing).
//!
//! Each `FIXTURE:` assertion checks the setup, never the fix.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test identity_ask_archived_candidates`.

#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::claim::{ClaimSource, ScopedRead, ScopedReadActorKey};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::maintenance::MaintenanceTarget;
use oneiron::dreamer_runner::maintenance::identity::{
    IdentityActNow, IdentityActNowRequest, IdentityAskReason, IdentityAskView, IdentityEffect,
};
use oneiron::edge::EdgeActorClass;
use oneiron::memory::extraction::{EncoderOutput, NerSpan};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::tagging::{HeldTagsOutcome, MentionLink, TaggingMarkerConfig, TaggingMode};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::cleanup_archive::archive_as_cleanup;
use oneiron::test_doors::identity_recheck::{
    run_identity_recheck, settle_identity_asks_of_turn_as_dreamer,
};
use oneiron::test_doors::label_writers::{embedded_owner, open_member_vault};
use oneiron::test_support::test_host_issuer;
use oneiron::{EntityId, Vault, VaultConfig};

const CHECKPOINT: &str = "0123456789abcdef";
const ROOM: &str = "52525252525252525252525252525252";
const TURN: &str = "76767676767676767676767676767676";
/// A later turn of the same room.
const LATER_TURN: &str = "74747474747474747474747474747474";

/// The person the cleanup archived.
const ARCHIVED: &str = "Owen Smith";
/// The mention: no name or alias of [`ARCHIVED`], so the identity key misses
/// it, but every part sounds like his (Soundex O500 and S530).
const MENTION: &str = "Owan Smyth";

/// The pass's clock, in seconds. The re-check, the due list and the answer
/// compare `now` only with the ask's own stamps (it opens with `retry_at` 0
/// and `opened_at` at `now`), never with a row the vault stamps by its own
/// clock, so a fixed instant stands in for the wall clock.
const NOW: u64 = 1_763_600_000;

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

/// The vault, its embedded owner and his proof, with this install's signing
/// keys loaded, as a host loads them after each open.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    owner: EntityId,
    proof: AuthenticatedOwner,
}

fn open() -> Fixture {
    let dir = tempfile::tempdir().expect("dir");
    let vault =
        Arc::new(open_member_vault(dir.path(), tagging_config(), &[]).expect("fixture vault"));
    let (owner, proof) = embedded_owner(&vault).expect("the owner");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    Fixture {
        _dir: dir,
        vault,
        owner,
        proof,
    }
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

/// A PERSON named `name` that an extraction minted, with the mint evidence
/// the cleanup's rule reads; its birth writes what [`person`]'s does.
fn extraction_person(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    assert!(
        vault
            .put_extraction_minted_person(
                &id,
                ClaimSource::Generated,
                TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).expect("body"),
            )
            .expect("an extraction mint"),
        "FIXTURE: the extraction mints {name}"
    );
    id
}

/// Witnesses `text` as one turn of `author` whose held tags name `name` in
/// it as a `PERSON`, saved in the witness write; returns the turn and the
/// saved link of that one mention.
fn save_as(vault: &Vault, author: EntityId, text: &str, name: &str) -> (EntityId, MentionLink) {
    save_in(vault, author, TURN, text, name)
}

/// [`save_as`] in the turn `turn_ref`.
fn save_in(
    vault: &Vault,
    author: EntityId,
    turn_ref: &str,
    text: &str,
    name: &str,
) -> (EntityId, MentionLink) {
    let start = text.find(name).expect("the name is in the text");
    let turn = WitnessTurn {
        conversation_ref: ROOM.into(),
        turn_ref: Some(turn_ref.to_owned()),
        thread_audience: None,
        project: None,
        occurred_at: NOW,
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
        relations: None,
        stack_sha16: None,
        mood_parts: Vec::new(),
    };
    let (_, outcome) = vault
        .memory(author, EdgeActorClass::Human)
        .witness_with_held_tags(&turn, &tags)
        .expect("witness with held tags");
    assert!(
        matches!(outcome, HeldTagsOutcome::Completed(_)),
        "FIXTURE: the held tags are saved in the witness write: {outcome:?}"
    );
    let turn = EntityId::from_hex(turn_ref).expect("turn id");
    (turn, saved_link(vault, &turn))
}

/// The saved link of the one mention in `turn`.
fn saved_link(vault: &Vault, turn: &EntityId) -> MentionLink {
    let saved = vault
        .turn_tags(turn)
        .expect("tags read")
        .expect("the turn has saved tags");
    assert_eq!(saved.mentions.len(), 1, "FIXTURE: one mention is saved");
    saved.mentions[0].link.clone()
}

/// The owner's own read lane: a human slip cut from the test host root for
/// him and verified on its binding, as his request presents it.
fn owner_read<'v>(vault: &'v Vault, owner: EntityId) -> ScopedRead<'v> {
    let issuer = test_host_issuer();
    let root = vault
        .ensure_host_root_slip(&issuer)
        .expect("the host root slip");
    let issued_at = vault.capability_slip_now().expect("the slip clock");
    let mut claims = root.claims;
    claims.slip_id = [0x51; 32];
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.issued_at = issued_at;
    claims.expires_at = issued_at + 3_600;
    claims.ttl_secs = 3_600;
    let slip = vault
        .mint_capability_slip(&issuer, claims)
        .expect("the owner's slip");
    let challenge = b"identity-ask-archived-candidates";
    let binding = issuer
        .binding_proof(&slip, challenge)
        .expect("the binding proof");
    let verified = vault
        .verify_capability_slip(&issuer.public_key(), &slip, challenge, &binding)
        .expect("the slip verifies");
    let key = ScopedReadActorKey::from_verified_slip(&verified).expect("the slip carries read");
    vault.scoped_read(key)
}

/// Owen Smith, archived by the vault cleanup; then the owner says
/// "Owan Smyth called.", which mints its own provisional person (a lone sound
/// match is unsure, OF-123), and the nightly re-check opens one ask: is it
/// Owen or someone new? Returns Owen, the turn and the provisional person.
fn archived_owen_is_asked_about(fixture: &Fixture) -> (EntityId, EntityId, EntityId) {
    let vault = &fixture.vault;
    let owen = person(vault, ARCHIVED);
    archive_as_cleanup(vault, &owen).expect("the cleanup archives Owen");
    assert!(
        vault.archived_entity(&owen).expect("read").is_some(),
        "FIXTURE: Owen is archived"
    );
    assert!(
        vault
            .lookup_identity_key(ENTITY_TYPE_PERSON, MENTION)
            .expect("key lookup")
            .is_empty(),
        "FIXTURE: the identity key misses the spelling"
    );

    let (turn, link) = save_as(vault, fixture.owner, &format!("{MENTION} called."), MENTION);
    let MentionLink::Minted { kind, entity } = link else {
        panic!("FIXTURE: a lone sound match mints: {link:?}");
    };
    assert_eq!(kind, ENTITY_TYPE_PERSON);
    let provisional = entity;

    let asks = run_identity_recheck(vault, NOW).expect("recheck");
    assert_eq!(
        asks.len(),
        1,
        "FIXTURE: one ask for the one mention: {asks:?}"
    );
    let ask = &asks[0];
    assert_eq!(ask.turn, turn);
    assert_eq!(ask.name, MENTION);
    assert_eq!(ask.reason, IdentityAskReason::Unsettled);
    assert_eq!(ask.provisional, Some(provisional));
    assert_eq!(
        ask.candidates.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([owen, provisional]),
        "FIXTURE: the stored ask names the archived Owen, as the resolver sees the archive"
    );
    (owen, turn, provisional)
}

/// The one open ask the owner's lane lists.
fn the_owners_ask(vault: &Vault, read: &ScopedRead<'_>) -> IdentityAskView {
    let views = vault.identity_asks(read).expect("the owner's asks");
    assert_eq!(
        views.len(),
        1,
        "FIXTURE: the owner reads his own turn, so he reads its ask: {views:?}"
    );
    views[0].clone()
}

/// The candidates the owner's card offers, as 32 hex; someone new has none.
fn offered(view: &IdentityAskView) -> BTreeSet<String> {
    view.options
        .iter()
        .filter_map(|option| option.entity.clone())
        .collect()
}

#[test]
fn an_archived_person_a_name_sounds_like_is_an_option_on_the_owners_card() {
    let fixture = open();
    let vault = &fixture.vault;
    let (owen, _turn, provisional) = archived_owen_is_asked_about(&fixture);
    let read = owner_read(vault, fixture.owner);

    let view = the_owners_ask(vault, &read);

    assert_eq!(
        offered(&view),
        BTreeSet::from([owen.to_hex(), provisional.to_hex()]),
        "the owner's card offers the archived Owen beside the mention's own person: {view:?}"
    );
    assert!(
        view.options.iter().any(|option| option.entity.is_none()),
        "someone new stays an option: {view:?}"
    );
    let due = vault.identity_asks_due(&read, NOW, 4).expect("due asks");
    assert_eq!(
        due,
        vec![view.ask.clone()],
        "the owner's lane reads the ask whole, the archived Owen included"
    );
    assert!(
        vault.archived_entity(&owen).expect("read").is_some(),
        "reading the ask restores no one: Owen stays archived until a settle names him"
    );
}

#[test]
fn the_owner_who_picks_the_archived_person_restores_him_and_mints_no_twin() {
    let fixture = open();
    let vault = &fixture.vault;
    let (owen, turn, provisional) = archived_owen_is_asked_about(&fixture);
    let read = owner_read(vault, fixture.owner);
    let view = the_owners_ask(vault, &read);

    let settled = vault
        .answer_identity_ask(
            &read,
            &fixture.proof,
            &view.ask,
            &format!("is:{}", owen.to_hex()),
            NOW,
        )
        .expect("the owner's answer names an option of his card");

    assert_eq!(settled.entity, owen.to_hex(), "the mention is Owen");
    assert!(
        vault.archived_entity(&owen).expect("read").is_none(),
        "the answer restored Owen: he bears no archive marker"
    );
    assert!(
        vault
            .provisional_entity(&provisional)
            .expect("provisional read")
            .is_none(),
        "the mention's own provisional person is retired, not a twin of Owen"
    );
    let link = saved_link(vault, &turn);
    assert!(
        link.entities().contains(&owen) && !link.entities().contains(&provisional),
        "the mention names Owen: {link:?}"
    );
    assert!(
        vault.identity_asks(&read).expect("asks").is_empty(),
        "the answered ask is closed"
    );
}

#[test]
fn the_archive_stays_hidden_from_every_other_read_of_the_owners_lane() {
    let fixture = open();
    let vault = &fixture.vault;
    let (owen, _turn, _provisional) = archived_owen_is_asked_about(&fixture);
    let read = owner_read(vault, fixture.owner);
    the_owners_ask(vault, &read);

    assert!(
        !read.is_ref_readable(&owen).expect("named read"),
        "a named read of the archived Owen still finds none: only the ask's candidate read \
         lifts the archive"
    );
    assert!(
        vault.archived_entity(&owen).expect("read").is_some(),
        "listing the ask restores no one"
    );
}

#[test]
fn the_owner_who_picks_an_archived_person_of_two_who_sound_alike_restores_him() {
    let fixture = open();
    let vault = &fixture.vault;
    let owen = person(vault, ARCHIVED);
    let other = person(vault, "Owen Smyth");
    let (turn, link) = save_as(vault, fixture.owner, &format!("{MENTION} called."), MENTION);
    assert_eq!(
        link.entities().iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([owen, other]),
        "FIXTURE: two people who sound alike are both candidates, not a mint: {link:?}"
    );
    let asks = run_identity_recheck(vault, NOW).expect("recheck");
    assert_eq!(
        asks.len(),
        1,
        "FIXTURE: one ask for the one mention: {asks:?}"
    );
    assert_eq!(
        asks[0].provisional, None,
        "FIXTURE: the ask has no provisional person a settle could absorb"
    );
    archive_as_cleanup(vault, &owen).expect("the cleanup archives Owen");
    let read = owner_read(vault, fixture.owner);
    let view = the_owners_ask(vault, &read);

    let settled = vault
        .answer_identity_ask(
            &read,
            &fixture.proof,
            &view.ask,
            &format!("is:{}", owen.to_hex()),
            NOW,
        )
        .expect("the owner's answer names an option of his card");

    assert_eq!(settled.entity, owen.to_hex(), "the mention is Owen");
    assert!(
        vault.archived_entity(&owen).expect("read").is_none(),
        "the answer restored Owen though it absorbed no provisional person"
    );
    assert!(
        read.is_ref_readable(&owen).expect("named read"),
        "the owner's plain read finds the restored Owen"
    );
    assert_eq!(
        saved_link(vault, &turn).entities(),
        [owen],
        "the mention names Owen alone"
    );
    assert!(
        vault.identity_asks(&read).expect("asks").is_empty(),
        "the answered ask is closed"
    );
}

/// The owner's act-now on `name`: who is it, before a send?
fn act_now(fixture: &Fixture, name: &str) -> IdentityActNow {
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .identity_act_now(&IdentityActNowRequest {
            name: name.to_owned(),
            conversation: None,
            effect: IdentityEffect::Send,
            prompt: format!("Which {name}?"),
            someone_new: "Someone new".to_owned(),
            provisional: None,
        })
        .expect("the act-now answer")
}

#[test]
fn an_act_now_on_a_name_whose_one_person_is_archived_answers_unknown() {
    let fixture = open();
    let vault = &fixture.vault;
    let owen = person(vault, ARCHIVED);
    let (_turn, link) = save_as(
        vault,
        fixture.owner,
        &format!("{ARCHIVED} called."),
        ARCHIVED,
    );
    assert_eq!(
        link.entities(),
        [owen],
        "FIXTURE: the identity key links the mention to Owen alone: {link:?}"
    );
    let before = act_now(&fixture, ARCHIVED);
    assert!(
        matches!(&before, IdentityActNow::Settled { entity } if *entity == owen.to_hex()),
        "FIXTURE: before the archive, the one linked person answers at once: {before:?}"
    );
    archive_as_cleanup(vault, &owen).expect("the cleanup archives Owen");

    let after = act_now(&fixture, ARCHIVED);

    assert!(
        matches!(after, IdentityActNow::Unknown),
        "an archived person no answer restores is no one the act-now names: {after:?}"
    );
    assert!(
        vault.archived_entity(&owen).expect("read").is_some(),
        "the act-now restores no one"
    );
}

/// Owen Smith, an extraction mint, and Owen Smyth both sound like
/// "Owan Smyth": the mention names both, and the nightly re-check opens one
/// ask with no provisional person of its own. Then the cleanup archives the
/// claimless Owen, and the Dreamer settles the ask as him. Returns Owen and
/// the ask's key.
fn the_dreamer_picks_archived_owen(fixture: &Fixture) -> (EntityId, [u8; 32]) {
    let vault = &fixture.vault;
    let owen = extraction_person(vault, ARCHIVED);
    let other = person(vault, "Owen Smyth");
    let (turn, link) = save_as(vault, fixture.owner, &format!("{MENTION} called."), MENTION);
    assert_eq!(
        link.entities().iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([owen, other]),
        "FIXTURE: two people who sound alike are both candidates, not a mint: {link:?}"
    );
    let asks = run_identity_recheck(vault, NOW).expect("recheck");
    assert_eq!(
        asks.len(),
        1,
        "FIXTURE: one ask for the one mention: {asks:?}"
    );
    assert_eq!(
        asks[0].provisional, None,
        "FIXTURE: the ask has no provisional person a settle could absorb"
    );
    archive_as_cleanup(vault, &owen).expect("the cleanup archives Owen");
    let settled = settle_identity_asks_of_turn_as_dreamer(vault, &turn, owen, NOW)
        .expect("the Dreamer's settle");
    assert_eq!(settled.len(), 1, "FIXTURE: the Dreamer settles the one ask");
    assert!(
        vault.archived_entity(&owen).expect("read").is_none(),
        "FIXTURE: the Dreamer's pick restored Owen"
    );
    (owen, settled[0])
}

#[test]
fn the_owners_revert_of_the_dreamers_pick_puts_the_archived_person_back() {
    let fixture = open();
    let vault = &fixture.vault;
    let (owen, key) = the_dreamer_picks_archived_owen(&fixture);

    let reverted = vault
        .revert_dreamer_maintenance(
            &fixture.proof,
            MaintenanceTarget::IdentityAsk(key),
            NOW + 60,
        )
        .expect("the owner's revert");

    assert!(
        vault.archived_entity(&owen).expect("read").is_some(),
        "the revert puts Owen back in the cleanup archive, as he stood before the Dreamer's \
         pick: {reverted:?}"
    );
    assert!(
        reverted.closed.contains(&owen),
        "the revert names Owen's restore among what it closed: {reverted:?}"
    );
    let read = owner_read(vault, fixture.owner);
    assert!(
        !read.is_ref_readable(&owen).expect("named read"),
        "the owner's plain read finds no Owen again"
    );
}

#[test]
fn a_person_a_later_mention_names_stays_restored_through_the_revert() {
    let fixture = open();
    let vault = &fixture.vault;
    let (owen, key) = the_dreamer_picks_archived_owen(&fixture);
    let (_later, link) = save_in(
        vault,
        fixture.owner,
        LATER_TURN,
        &format!("{ARCHIVED} called."),
        ARCHIVED,
    );
    assert!(
        link.entities().contains(&owen),
        "FIXTURE: the later mention names the restored Owen: {link:?}"
    );

    let reverted = vault
        .revert_dreamer_maintenance(
            &fixture.proof,
            MaintenanceTarget::IdentityAsk(key),
            NOW + 60,
        )
        .expect("the owner's revert");

    assert!(
        vault.archived_entity(&owen).expect("read").is_none(),
        "a later mention keeps Owen restored through the revert: {reverted:?}"
    );
    assert!(
        reverted.left_alone.contains(&owen.to_hex()),
        "the revert lists Owen's restore as left alone: {reverted:?}"
    );
}
