//! FIX [RECIPIENT-NOTICE-READ-BY-ANY-READER], owner half PR 3: an identity
//! ask raised from a member's own source goes to that member.
//!
//! The lead (21 Nov 11:3x, OWNER-NOTICE-EXISTENCE Q2 = C): "Never compose an
//! owner-addressed notice from words he cannot read. An Ask raised from a
//! member's own source goes to that member, who knows who they meant. The
//! owner gets the actionable stub 'a member has a pending question about
//! <kind>'." The lead (21 Nov 13:2x, OWNER-NOTICE-MEMBER-ASK-ROUTE): Q1 = A,
//! "Answer::Is applies on the member's answer"; Q2 = A, "when no live
//! non-owner person can open the ask, the owner gets the stub ... The ask
//! stays open".
//!
//! Each ask quotes a saved mention, and every door reads it through its
//! caller's lane, so an ask whose turn only a member reads opens for the
//! member and looks absent to the owner. The fixture: the owner says "Owan
//! Smyth called." in a room (the tagger mints its own provisional person),
//! the nightly re-check opens one ask (is it Owen Smith or someone new?),
//! then the turn is bound to a source policy only the member reads, standing
//! in for a turn landed from the member's own mailbox, and the ask is sent.
//!
//! Red on main (the first two tests and the last): every ask goes to the
//! owners whatever their lane reads, so the owner gets an Ask he cannot
//! open, the member gets nothing, and the member's answer is refused
//! "only a vault owner answers an identity ask". The other two are guards
//! that hold on both: a member's "someone new" is the owner's decision, and
//! an ask every owner reads still goes to the owner alone.
//!
//! Each `FIXTURE:` assertion checks the setup, never the fix.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test identity_member_ask_route`.

#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::authority::VerifiedSlip;
use oneiron::dreamer_runner::maintenance::identity::{
    IDENTITY_NOTIFICATION_PRODUCER, IdentityAnswerRequest, IdentitySettled,
};
use oneiron::edge::EdgeActorClass;
use oneiron::inbox::NotificationRow;
use oneiron::memory::extraction::{EncoderOutput, NerSpan};
use oneiron::memory::{
    MEMORY_CODE_FORBIDDEN, MemoryError, WitnessAssertions, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::tagging::{HeldTagsOutcome, MentionLink, TaggingMarkerConfig, TaggingMode};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::identity_recheck::{escalate_identity_asks, run_identity_recheck};
use oneiron::test_doors::label_writers::{embedded_owner, open_member_vault};
use oneiron::test_doors::source_audience_binding::bind_turn_read_by;
use oneiron::test_support::test_host_issuer;
use oneiron::{EntityId, Vault, VaultConfig};

const CHECKPOINT: &str = "0123456789abcdef";
const ROOM: &str = "52525252525252525252525252525252";
const TURN: &str = "76767676767676767676767676767676";

/// The person the mention may mean.
const KNOWN: &str = "Owen Smith";
/// The mention: no name or alias of [`KNOWN`], so the identity key misses
/// it, but every part sounds like his (Soundex O500 and S530).
const MENTION: &str = "Owan Smyth";
/// The producer of the owner's stub for an ask he cannot open, as the head
/// names it (the base has none).
const STUB_PRODUCER: &str = "dreamer.identity.member_question";
/// The stub's words, the only words the owner's notice carries.
const STUB_DETAIL: &str = "a member has a pending question about identity";

/// The pass's clock, in seconds: the re-check, the send and the answer
/// compare `now` only with the ask's own stamps.
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

/// The vault, its embedded owner, and a member: a live PERSON who holds an
/// ordinary credential of their own (a human slip cut from the test host
/// root for them, verified on its binding), with the `core:read` grant the
/// fixture vault gives each member.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    owner: EntityId,
    member: EntityId,
    member_proof: VerifiedSlip,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("dir");
        let member = EntityId::now();
        let vault = Arc::new(
            open_member_vault(dir.path(), tagging_config(), &[member.to_hex().as_str()])
                .expect("fixture vault"),
        );
        let (owner, _proof) = embedded_owner(&vault).expect("the owner");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        put_person(&vault, member, "Quinn Member");
        let member_proof = human_slip(&vault, member, [0x52; 32]);
        Self {
            _dir: dir,
            vault,
            owner,
            member,
            member_proof,
        }
    }

    /// Owen Smith; then the owner says "Owan Smyth called.", which mints its
    /// own provisional person (a lone sound match is unsure), and the
    /// nightly re-check opens one ask: is it Owen or someone new? Returns
    /// Owen and the turn.
    fn owen_is_asked_about(&self) -> (EntityId, EntityId) {
        let owen = EntityId::now();
        put_person(&self.vault, owen, KNOWN);
        let turn = save_turn(&self.vault, self.owner, &format!("{MENTION} called."));
        let asks = run_identity_recheck(&self.vault, NOW).expect("recheck");
        assert_eq!(
            asks.len(),
            1,
            "FIXTURE: one ask for the one mention: {asks:?}"
        );
        assert_eq!(asks[0].turn, turn, "FIXTURE: the ask quotes the turn");
        assert!(
            asks[0].candidates.contains(&owen),
            "FIXTURE: Owen is a candidate: {asks:?}"
        );
        (owen, turn)
    }

    /// [`Self::owen_is_asked_about`], the turn then bound to a source policy
    /// that only `readers` read, and the ask sent: the Ask's route is judged
    /// now. Returns Owen and the turn.
    fn owen_is_asked_about_in_a_source_read_by(
        &self,
        readers: &[EntityId],
    ) -> (EntityId, EntityId) {
        let (owen, turn) = self.owen_is_asked_about();
        bind_turn_read_by(&self.vault, turn, readers).expect("FIXTURE: the turn is bound");
        assert_eq!(
            escalate_identity_asks(&self.vault, NOW).expect("send the ask"),
            1,
            "FIXTURE: the one ask is sent"
        );
        (owen, turn)
    }

    /// Every notice in `person`'s inbox.
    fn inbox(&self, person: EntityId) -> Vec<NotificationRow> {
        self.vault
            .memory(person, EdgeActorClass::Human)
            .inbox_list(None, 500)
            .expect("an inbox reads")
            .rows
    }

    /// The identity Asks in `person`'s inbox, each one's ask key.
    fn identity_asks(&self, person: EntityId) -> Vec<Option<String>> {
        self.inbox(person)
            .into_iter()
            .filter(|row| row.source.producer == IDENTITY_NOTIFICATION_PRODUCER)
            .map(|row| row.source.result)
            .collect()
    }

    /// The member-question stubs in `person`'s inbox.
    fn stubs(&self, person: EntityId) -> Vec<NotificationRow> {
        self.inbox(person)
            .into_iter()
            .filter(|row| row.source.producer == STUB_PRODUCER)
            .collect()
    }

    /// The member's answer `choice` to `ask`, on their own credential.
    fn members_answer(&self, ask: &str, choice: &str) -> Result<IdentitySettled, MemoryError> {
        self.vault
            .memory(self.member, EdgeActorClass::Human)
            .with_read_proof(&self.member_proof)
            .identity_answer(&IdentityAnswerRequest {
                ask: ask.to_owned(),
                choice: choice.to_owned(),
            })
    }

    /// The one ask key of the member's identity Ask.
    fn members_ask(&self) -> String {
        let asks = self.identity_asks(self.member);
        assert_eq!(
            asks.len(),
            1,
            "the member, whose source the ask came from, gets its Ask: {asks:?}"
        );
        asks[0].clone().expect("an identity Ask names its ask")
    }
}

/// A PERSON `id` named `name`; its birth writes its identity hints and its
/// phonetic postings.
fn put_person(vault: &Vault, id: EntityId, name: &str) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).expect("body"),
        )
        .expect("a person");
}

/// A human slip `slip_id` cut from the test host root for `holder` and
/// verified on its binding, as their request presents it.
fn human_slip(vault: &Vault, holder: EntityId, slip_id: [u8; 32]) -> VerifiedSlip {
    let issuer = test_host_issuer();
    let root = vault
        .ensure_host_root_slip(&issuer)
        .expect("the host root slip");
    let issued_at = vault.capability_slip_now().expect("the slip clock");
    let mut claims = root.claims;
    claims.slip_id = slip_id;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.issued_at = issued_at;
    claims.expires_at = issued_at + 3_600;
    claims.ttl_secs = 3_600;
    let slip = vault
        .mint_capability_slip(&issuer, claims)
        .expect("the holder's slip");
    let challenge = b"identity-member-ask-route";
    let binding = issuer
        .binding_proof(&slip, challenge)
        .expect("the binding proof");
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, challenge, &binding)
        .expect("the slip verifies")
}

/// Witnesses `text` as one turn of `author` in the room, its held tags
/// naming [`MENTION`] in it as a `PERSON`, saved in the witness write;
/// returns the turn. The mention mints its own provisional person.
fn save_turn(vault: &Vault, author: EntityId, text: &str) -> EntityId {
    let start = text.find(MENTION).expect("the name is in the text");
    let turn = WitnessTurn {
        conversation_ref: ROOM.into(),
        turn_ref: Some(TURN.to_owned()),
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
            end: start + MENTION.len(),
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
    let turn = EntityId::from_hex(TURN).expect("turn id");
    let saved = vault
        .turn_tags(&turn)
        .expect("tags read")
        .expect("FIXTURE: the turn has saved tags");
    assert!(
        saved.mentions.len() == 1 && matches!(saved.mentions[0].link, MentionLink::Minted { .. }),
        "FIXTURE: a lone sound match mints its own provisional person: {:?}",
        saved.mentions
    );
    turn
}

#[test]
fn an_ask_from_a_members_own_source_goes_to_the_member_and_the_owner_gets_a_stub() {
    let fixture = Fixture::open();
    fixture.owen_is_asked_about_in_a_source_read_by(&[fixture.member]);

    let owners_asks = fixture.identity_asks(fixture.owner);
    assert!(
        owners_asks.is_empty(),
        "the owner, who cannot read the turn, gets no Ask naming it: {owners_asks:?}"
    );
    fixture.members_ask();
    let stubs = fixture.stubs(fixture.owner);
    assert_eq!(
        stubs.len(),
        1,
        "the owner gets one stub: {:?}",
        fixture.inbox(fixture.owner)
    );
    let stub = &stubs[0];
    assert_eq!(
        stub.source.detail.as_deref(),
        Some(STUB_DETAIL),
        "the stub says only that a member has a pending question: {stub:?}"
    );
    assert!(
        stub.source.result.is_none()
            && stub.subject_refs.is_empty()
            && stub.origin_conversation.is_none(),
        "the stub names no ask, row or conversation: {stub:?}"
    );
    assert!(
        fixture.stubs(fixture.member).is_empty(),
        "the member gets the Ask, not a stub"
    );
}

#[test]
fn the_members_answer_naming_a_candidate_settles_the_ask_from_their_own_source() {
    let fixture = Fixture::open();
    let (owen, turn) = fixture.owen_is_asked_about_in_a_source_read_by(&[fixture.member]);
    let ask = fixture.members_ask();

    let settled = fixture
        .members_answer(&ask, &format!("is:{}", owen.to_hex()))
        .expect("the member's answer naming Owen applies");

    assert_eq!(settled.entity, owen.to_hex(), "the mention is Owen");
    let saved = fixture
        .vault
        .turn_tags(&turn)
        .expect("tags read")
        .expect("the turn keeps its tags");
    assert_eq!(
        saved.mentions[0].link.entities(),
        [owen],
        "the mention names Owen alone"
    );
    let again = fixture.members_answer(&ask, &format!("is:{}", owen.to_hex()));
    assert!(again.is_err(), "the answered ask is closed: {again:?}");
}

#[test]
fn a_members_someone_new_answer_is_the_owners_decision() {
    let fixture = Fixture::open();
    let (owen, _turn) = fixture.owen_is_asked_about_in_a_source_read_by(&[fixture.member]);
    let ask = fixture.members_ask();

    let refused = fixture
        .members_answer(&ask, "someone_new")
        .expect_err("a member's someone-new answer does not apply");

    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    fixture
        .members_answer(&ask, &format!("is:{}", owen.to_hex()))
        .expect("the ask stays open after the refused answer");
}

#[test]
fn an_ask_every_owner_reads_still_goes_to_the_owner_alone() {
    let fixture = Fixture::open();
    let (owen, turn) = fixture.owen_is_asked_about();
    assert_eq!(
        escalate_identity_asks(&fixture.vault, NOW).expect("send the ask"),
        1,
        "FIXTURE: the one ask is sent"
    );

    let owners_asks = fixture.identity_asks(fixture.owner);
    assert_eq!(
        owners_asks.len(),
        1,
        "the owner, who reads his own turn, gets the Ask: {owners_asks:?}"
    );
    assert!(
        owners_asks[0].is_some(),
        "the owner's Ask names its ask: {owners_asks:?}"
    );
    assert!(
        fixture.identity_asks(fixture.member).is_empty() && fixture.stubs(fixture.owner).is_empty(),
        "no member gets it and the owner gets no stub"
    );
    let refused = fixture.members_answer(
        &owners_asks[0].clone().unwrap_or_default(),
        &format!("is:{}", owen.to_hex()),
    );
    assert!(
        refused.is_err(),
        "an ask every owner reads stays the owner's to answer: {refused:?}"
    );
    let saved = fixture
        .vault
        .turn_tags(&turn)
        .expect("tags read")
        .expect("the turn keeps its tags");
    assert!(
        matches!(saved.mentions[0].link, MentionLink::Minted { .. }),
        "the member's refused answer settled nothing: {:?}",
        saved.mentions
    );
}

#[test]
fn an_ask_no_live_person_but_the_source_can_open_leaves_the_owner_only_the_stub() {
    let fixture = Fixture::open();
    // A person the source names who holds no credential in this vault: no
    // one the ask may go to opens it.
    let stranger = EntityId::now();
    put_person(&fixture.vault, stranger, "Robin Stranger");
    fixture.owen_is_asked_about_in_a_source_read_by(&[stranger]);

    assert!(
        fixture.identity_asks(fixture.owner).is_empty(),
        "the owner gets no Ask he cannot open"
    );
    assert_eq!(
        fixture.stubs(fixture.owner).len(),
        1,
        "the owner gets the stub: {:?}",
        fixture.inbox(fixture.owner)
    );
    assert!(
        fixture.identity_asks(fixture.member).is_empty(),
        "a member the source does not name gets nothing"
    );
}
