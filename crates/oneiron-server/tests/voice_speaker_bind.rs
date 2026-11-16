#![cfg(oneiron_test_support)]
//! UNBUILT-02-SPEAKER-BIND: the owner names a call's unmatched speaker.
//!
//! Every kept call turn of another person carries its call ref, its speaker key and the label
//! kept with it. The owner says "this speaker of this call is PERSON P" through
//! `vault.calls.speakers.bind`, and removes it through `vault.calls.speakers.unbind`. The
//! transcript shows the bound name on every turn of that (call, speaker) at read time; no turn
//! is ever rewritten, metadata stays byte-identical, and the turn stays another person's.
//!
//! The call's brain is the one a room call's boot builds
//! (`oneiron_server::test_doors::voice_call::RoomCall`), its answering agent the seeded default
//! agent, on a served vault whose chat seat is one scripted model. The owner reads the room.
//! Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test voice_speaker_bind`.

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::path::PathBuf;
use std::sync::Arc;

use engine_stack::on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::compaction::{ChatLog, read_chat_log};
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind, HistoryChoice};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND, MemoryError,
    SafeDeleteReason, TranscriptMessage, TranscriptPage,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::sdk::{
    IdentityEvidence, IdentityMergeRequest, IdentitySurvivorshipPlan, IdentityTopologyResult,
    invoke, merge_identity_as_owner,
};
use oneiron::test_doors::coach::define_agent;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::voice_call::{PhoneCall, RoomCall};
use serde_json::{Value, json};

type TestError = Box<dyn std::error::Error>;
type TestResult<T = ()> = Result<T, TestError>;

/// What the answering agent answers every turn.
const ANSWER: &str = "Yes, I hear you loud and clear.";
/// The bind verb.
const BIND: &str = "vault.calls.speakers.bind";
/// The unbind verb.
const UNBIND: &str = "vault.calls.speakers.unbind";
/// The public gate-decision reader.
const GATE_GET: &str = "vault.gate.decision.get";

/// The scripted model: every call is the answering agent's answer.
fn reply(_body: &Value) -> String {
    ANSWER.to_owned()
}

/// The `[models]` table: one scripted local model serves every role.
fn models_text(base_url: &str) -> String {
    let prompts = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../oneiron/tests/fixtures/prompts")
        .canonicalize()
        .expect("the fixture prompt package");
    format!(
        "default = \"local:test-model\"\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [code_mode]\nprompt_package = {prompts:?}\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n\
         context_tokens = 500000\n",
        prompts = prompts.display().to_string(),
    )
}

/// A served vault with its owner.
struct Fixture {
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    _host: AiHost,
    _model: FakeLlm,
    _dir: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> TestResult<Self> {
        let model = FakeLlm::start(Vec::new(), Some(Reply::Computed(Arc::new(reply)))).await;
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (owner, owner_proof) = embedded_owner(&vault)?;
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("voice-speaker-bind".into()),
                ..Default::default()
            },
        )?;
        let models = ModelsConfig::from_toml(&models_text(&model.base_url), None)?;
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        Ok(Self {
            server: Arc::new(server),
            vault,
            owner,
            owner_proof,
            _host: host,
            _model: model,
            _dir: dir,
        })
    }

    /// The room's log, as its owner reads it.
    fn log(&self, room: EntityId) -> TestResult<ChatLog> {
        let reader = self.vault.memory(self.owner, EdgeActorClass::Human);
        Ok(read_chat_log(&reader, room, 1, usize::MAX)?)
    }

    /// The room's transcript, as its owner reads it, with each message's
    /// metadata.
    fn transcript(&self, room: EntityId) -> TestResult<TranscriptPage> {
        let reader = self.vault.memory(self.owner, EdgeActorClass::Human);
        Ok(reader.conversation_transcript(&room, None, 100)?.value)
    }

    /// An ordinary room seating the owner and one member, with its counterparty contact.
    fn room_with_contact(&self) -> TestResult<(EntityId, EntityId, EntityId)> {
        let person = self.make_person()?;
        let contact = self.make_contact(person, "Owen")?;
        let room = self.make_room(&[person])?;
        Ok((room, person, contact))
    }

    /// An ordinary Group room seating the owner and `members`.
    fn make_room(&self, members: &[EntityId]) -> TestResult<EntityId> {
        let vault = &self.vault;
        let room = EntityId::now();
        let by_owner = WriteActor::new(self.owner, EdgeActorClass::Human);
        vault.create_conversation(
            room,
            &ConversationBody {
                kind: ConversationKind::Group,
                member_ids: vec![self.owner],
                ..Default::default()
            },
            by_owner,
            vault.now_recorded_at(),
        )?;
        for member in members {
            vault.join_member(
                room,
                *member,
                by_owner,
                vault.now_recorded_at(),
                HistoryChoice::Share,
            )?;
        }
        Ok(room)
    }

    /// A live PERSON with a dummy body.
    fn make_person(&self) -> TestResult<EntityId> {
        let person = EntityId::now();
        let now = self.vault.now_recorded_at();
        self.vault.put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"person",
        )?;
        Ok(person)
    }

    /// A live PERSON named `name`.
    fn make_person_named(&self, name: &str) -> TestResult<EntityId> {
        let person = EntityId::now();
        let now = self.vault.now_recorded_at();
        let body = rmp_serde::to_vec_named(&json!({"display_name": name}))
            .expect("FIXTURE: the person name body");
        self.vault.put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &body,
        )?;
        Ok(person)
    }

    /// An active counterparty contact naming `person` as `name`.
    fn make_contact(&self, person: EntityId, name: &str) -> TestResult<EntityId> {
        let contact = EntityId::now();
        let record = CounterpartyContactRecord::public(person, name, self.vault.now_recorded_at())?;
        self.vault.create_counterparty_contact(&contact, &record)?;
        Ok(contact)
    }
}

/// One verb call through the public invoke path, as `actor` of `class`.
fn call(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    verb: &str,
    input: Value,
) -> Result<Value, MemoryError> {
    invoke(&vault.memory(actor, class), verb, input)
}

/// The owner's bind of `speaker` of `call_ref` to `person`.
fn bind(
    fixture: &Fixture,
    call_ref: &str,
    speaker: &str,
    person: EntityId,
) -> Result<Value, MemoryError> {
    call(
        &fixture.vault,
        fixture.owner,
        EdgeActorClass::Human,
        BIND,
        json!({"call": call_ref, "speaker": speaker, "person": person.to_hex()}),
    )
}

/// The owner's unbind of `speaker` of `call_ref`.
fn unbind(fixture: &Fixture, call_ref: &str, speaker: &str) -> Result<Value, MemoryError> {
    call(
        &fixture.vault,
        fixture.owner,
        EdgeActorClass::Human,
        UNBIND,
        json!({"call": call_ref, "speaker": speaker}),
    )
}

/// The receipt's gate decision, 32-hex.
fn decision_of(receipt: &Value) -> TestResult<&str> {
    receipt
        .get("decision")
        .and_then(Value::as_str)
        .ok_or_else(|| "a bind receipt names its gate decision".into())
}

/// Every message of `page` in turn order, with its metadata.
fn messages(page: &TranscriptPage) -> Vec<&TranscriptMessage> {
    page.turns.iter().flat_map(|turn| &turn.messages).collect()
}

/// Every counterparty message of `page` in turn order.
fn counterparty(page: &TranscriptPage) -> Vec<&TranscriptMessage> {
    messages(page)
        .into_iter()
        .filter(|row| row.role == "counterparty")
        .collect()
}

/// The `voice` object of `message`'s metadata.
fn voice_of(message: &TranscriptMessage) -> TestResult<&Value> {
    message
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("voice"))
        .ok_or_else(|| "a kept row names its call".into())
}

/// The call ref of `message`'s voice metadata.
fn call_of(message: &TranscriptMessage) -> TestResult<&str> {
    voice_of(message)?
        .get("call")
        .and_then(Value::as_str)
        .ok_or_else(|| "a kept row names its call".into())
}

/// The speaker field of `message`: its label and its PERSON, when it names one.
fn speaker_of(message: &TranscriptMessage) -> TestResult<(&str, Option<&str>)> {
    let speaker = message
        .speaker
        .as_ref()
        .ok_or("a kept turn of a keyed speaker names its speaker")?;
    Ok((speaker.label.as_str(), speaker.person.as_deref()))
}

#[test]
fn a_bound_speaker_shows_the_persons_name_on_every_turn_of_the_call() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let (room, _, _) = fixture.room_with_contact()?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        call.say(1, "first voice", Some("k1")).await?;
        call.say(2, "second voice", Some("k1")).await?;
        call.hang_up();

        let page = fixture.transcript(room)?;
        let words = counterparty(&page);
        assert_eq!(words.len(), 2, "each keyed final keeps its words");
        let call_ref = call_of(words[0])?.to_owned();
        let pam = fixture.make_person_named("Pam")?;
        let receipt = bind(&fixture, &call_ref, "k1", pam).expect("the owner binds k1");
        assert_eq!(receipt["person"], json!(pam.to_hex()));
        assert_eq!(
            decision_of(&receipt)?.len(),
            32,
            "the receipt names its gate decision"
        );

        let page = fixture.transcript(room)?;
        let words = counterparty(&page);
        assert_eq!(words.len(), 2, "the bind keeps every turn");
        for word in words {
            assert_eq!(word.role, "counterparty");
            let (label, person) = speaker_of(word)?;
            assert_eq!(label, "Pam", "the turn shows the bound PERSON's name");
            assert_eq!(
                person,
                Some(pam.to_hex()).as_deref(),
                "the turn names the bound PERSON"
            );
            let voice = voice_of(word)?;
            assert_eq!(
                voice.get("speaker_label").and_then(Value::as_str),
                Some("Another speaker"),
                "the kept label stays as kept"
            );
        }
        Ok(())
    })
}

#[test]
fn another_key_of_the_same_call_keeps_its_stored_label() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let (room, _, _) = fixture.room_with_contact()?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        call.say(1, "first voice", Some("k1")).await?;
        call.say(2, "second voice", Some("k2")).await?;
        call.hang_up();

        let page = fixture.transcript(room)?;
        let words = counterparty(&page);
        assert_eq!(words.len(), 2);
        let call_ref = call_of(words[0])?.to_owned();
        let pam = fixture.make_person_named("Pam")?;
        bind(&fixture, &call_ref, "k1", pam).expect("the owner binds k1");

        let page = fixture.transcript(room)?;
        let words = counterparty(&page);
        let (label, person) = speaker_of(words[0])?;
        assert_eq!((label, person), ("Pam", Some(pam.to_hex()).as_deref()));
        let (label, person) = speaker_of(words[1])?;
        assert_eq!(
            (label, person),
            ("Another speaker 2", None),
            "the unbound key keeps its stored label"
        );
        Ok(())
    })
}

#[test]
fn unbind_returns_the_stored_label_and_leaves_metadata_as_kept() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let (room, _, _) = fixture.room_with_contact()?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        call.say(1, "first voice", Some("k1")).await?;
        call.hang_up();

        let page = fixture.transcript(room)?;
        let kept: Vec<Option<Value>> = messages(&page)
            .iter()
            .map(|row| row.metadata.clone())
            .collect();
        let words = counterparty(&page);
        let call_ref = call_of(words[0])?.to_owned();
        let pam = fixture.make_person_named("Pam")?;
        bind(&fixture, &call_ref, "k1", pam).expect("the owner binds k1");
        let receipt = unbind(&fixture, &call_ref, "k1").expect("the owner unbinds k1");
        assert!(
            receipt.get("person").is_none_or(Value::is_null),
            "the unbind receipt names no person: {receipt}"
        );

        let page = fixture.transcript(room)?;
        let stored: Vec<Option<Value>> = messages(&page)
            .iter()
            .map(|row| row.metadata.clone())
            .collect();
        assert_eq!(
            stored, kept,
            "no turn is rewritten: metadata after the unbind equals metadata before the bind"
        );
        let words = counterparty(&page);
        assert_eq!(words.len(), 1);
        let (label, person) = speaker_of(words[0])?;
        assert_eq!(
            (label, person),
            ("Another speaker", None),
            "the unbound turn shows its stored label again"
        );
        Ok(())
    })
}

#[test]
fn a_rebind_names_the_latest_person() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let (room, _, _) = fixture.room_with_contact()?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        call.say(1, "first voice", Some("k1")).await?;
        call.hang_up();

        let page = fixture.transcript(room)?;
        let words = counterparty(&page);
        let call_ref = call_of(words[0])?.to_owned();
        let pam = fixture.make_person_named("Pam")?;
        let quinn = fixture.make_person_named("Quinn")?;
        bind(&fixture, &call_ref, "k1", pam).expect("the owner binds k1");
        bind(&fixture, &call_ref, "k1", quinn).expect("the owner rebinds k1");

        let page = fixture.transcript(room)?;
        let words = counterparty(&page);
        let (label, person) = speaker_of(words[0])?;
        assert_eq!(
            (label, person),
            ("Quinn", Some(quinn.to_hex()).as_deref()),
            "the latest bind wins"
        );
        Ok(())
    })
}

#[test]
fn an_agent_is_refused_and_writes_nothing() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let (room, _, _) = fixture.room_with_contact()?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        call.say(1, "first voice", Some("k1")).await?;
        call.hang_up();

        let page = fixture.transcript(room)?;
        let words = counterparty(&page);
        let call_ref = call_of(words[0])?.to_owned();
        let pam = fixture.make_person_named("Pam")?;
        let before = fixture.transcript(room)?;
        let agent = define_agent(&fixture.vault).expect("an agent");
        let refused = call(
            &fixture.vault,
            agent,
            EdgeActorClass::Agent,
            BIND,
            json!({"call": call_ref, "speaker": "k1", "person": pam.to_hex()}),
        )
        .expect_err("an agent never binds a call speaker");
        assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
        assert!(
            refused.message.contains("is the vault owner's"),
            "the refusal names the owner: {refused:?}"
        );
        let refused = call(
            &fixture.vault,
            agent,
            EdgeActorClass::Agent,
            UNBIND,
            json!({"call": call_ref, "speaker": "k1"}),
        )
        .expect_err("an agent never unbinds a call speaker");
        assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
        assert!(
            refused.message.contains("is the vault owner's"),
            "the refusal names the owner: {refused:?}"
        );
        assert_eq!(
            fixture.transcript(room)?,
            before,
            "a refused act writes nothing"
        );
        Ok(())
    })
}

#[test]
fn a_bound_turn_stays_another_persons() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let (room, _, _) = fixture.room_with_contact()?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        call.say(1, "first voice", Some("k1")).await?;
        call.hang_up();

        let page = fixture.transcript(room)?;
        let words = counterparty(&page);
        let call_ref = call_of(words[0])?.to_owned();
        let log = fixture.log(room)?;
        let pam = fixture.make_person_named("Pam")?;
        bind(&fixture, &call_ref, "k1", pam).expect("the owner binds k1");

        let page = fixture.transcript(room)?;
        let words = counterparty(&page);
        assert_eq!(
            words[0].role, "counterparty",
            "a bound turn stays another person's"
        );
        assert_eq!(
            fixture.log(room)?,
            log,
            "the chat log line is unchanged by the bind"
        );
        Ok(())
    })
}

#[test]
fn a_bind_names_only_its_own_call() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let (room, _, _) = fixture.room_with_contact()?;
        let mut first = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        first.say(1, "call one", Some("k1")).await?;
        first.hang_up();
        let mut second = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        second.say(1, "call two", Some("k1")).await?;
        second.hang_up();

        let page = fixture.transcript(room)?;
        let words = counterparty(&page);
        assert_eq!(words.len(), 2, "both calls keep their words");
        let first_ref = call_of(words[0])?.to_owned();
        let second_ref = call_of(words[1])?.to_owned();
        assert_ne!(first_ref, second_ref, "FIXTURE: two calls, two refs");
        let pam = fixture.make_person_named("Pam")?;
        bind(&fixture, &first_ref, "k1", pam).expect("the owner binds call one's k1");

        let page = fixture.transcript(room)?;
        let words = counterparty(&page);
        let (label, person) = speaker_of(words[0])?;
        assert_eq!(
            (label, person),
            ("Pam", Some(pam.to_hex()).as_deref()),
            "the bound call shows the name"
        );
        let (label, person) = speaker_of(words[1])?;
        assert_eq!(
            (label, person),
            ("Another speaker", None),
            "the same key of another call keeps its stored label"
        );
        Ok(())
    })
}

#[test]
fn each_act_mints_a_receipt() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let (room, _, _) = fixture.room_with_contact()?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        call.say(1, "first voice", Some("k1")).await?;
        call.hang_up();

        let page = fixture.transcript(room)?;
        let words = counterparty(&page);
        let call_ref = call_of(words[0])?.to_owned();
        let pam = fixture.make_person_named("Pam")?;
        let quinn = fixture.make_person_named("Quinn")?;
        let bound = decision_of(&bind(&fixture, &call_ref, "k1", pam).expect("bind"))?.to_owned();
        let rebound =
            decision_of(&bind(&fixture, &call_ref, "k1", quinn).expect("rebind"))?.to_owned();
        let unbound = decision_of(&unbind(&fixture, &call_ref, "k1").expect("unbind"))?.to_owned();
        assert_ne!(bound, rebound, "each act mints its own receipt");
        assert_ne!(bound, unbound, "each act mints its own receipt");
        assert_ne!(rebound, unbound, "each act mints its own receipt");
        for decision in [bound, rebound, unbound] {
            let out = call(
                &fixture.vault,
                fixture.owner,
                EdgeActorClass::Human,
                GATE_GET,
                json!({"receipt": format!("gate:{decision}")}),
            )
            .expect("the owner reads the receipt");
            assert_eq!(
                out["value"]["receipt_id"],
                json!(format!("gate:{decision}")),
                "{out}"
            );
            assert_eq!(
                out["value"]["content_kind"],
                json!("speaker_bind"),
                "each act's receipt is a speaker_bind receipt: {out}"
            );
            assert_eq!(out["value"]["outcome"], json!("approved"), "{out}");
        }
        Ok(())
    })
}

#[test]
fn a_merged_person_follows_its_head_and_an_erased_one_falls_back() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let (room, _, _) = fixture.room_with_contact()?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        call.say(1, "first voice", Some("k1")).await?;
        call.hang_up();

        let page = fixture.transcript(room)?;
        let words = counterparty(&page);
        let call_ref = call_of(words[0])?.to_owned();
        let pam = fixture.make_person_named("Pam")?;
        let quinn = fixture.make_person_named("Quinn")?;
        bind(&fixture, &call_ref, "k1", pam).expect("the owner binds k1");
        let merged = merge_identity_as_owner(
            &fixture.vault,
            &fixture.owner_proof,
            ActSurface::ThisInstall,
            IdentityMergeRequest {
                sources: vec![pam],
                survivor: quinn,
                evidence: IdentityEvidence {
                    refs: vec![],
                    rationale: "the speaker is Quinn".to_owned(),
                },
                survivorship_plan: IdentitySurvivorshipPlan::ReadThrough,
            },
        )
        .expect("the owner merges Pam into Quinn");
        assert!(
            matches!(merged, IdentityTopologyResult::Applied { .. }),
            "FIXTURE: the merge applies: {merged:?}"
        );

        let page = fixture.transcript(room)?;
        let words = counterparty(&page);
        let (label, person) = speaker_of(words[0])?;
        assert_eq!(
            (label, person),
            ("Quinn", Some(quinn.to_hex()).as_deref()),
            "a merged bind follows its head"
        );

        fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .safe_delete(&quinn.to_hex(), SafeDeleteReason::UserDelete)
            .expect("the owner erases Quinn");
        let page = fixture.transcript(room)?;
        let words = counterparty(&page);
        let (label, person) = speaker_of(words[0])?;
        assert_eq!(
            (label, person),
            ("Another speaker", None),
            "an erased bind falls back to its stored label"
        );
        Ok(())
    })
}

#[test]
fn a_phone_callers_speaker_binds() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let mut call = PhoneCall::answer(&fixture.server, Some("+1 555-0100"))?;
        let thread = call.conversation();
        call.say(1, "Hello, the clinic calling").await?;
        call.hang_up();

        let page = fixture.transcript(thread)?;
        let words = counterparty(&page);
        assert_eq!(words.len(), 1, "the caller's words are kept");
        let voice = voice_of(words[0])?;
        assert_eq!(
            voice.get("speaker").and_then(Value::as_str),
            Some("caller"),
            "FIXTURE: the phone caller speaks under its key"
        );
        assert_eq!(
            voice.get("speaker_label").and_then(Value::as_str),
            Some("Another speaker"),
            "FIXTURE: the phone caller keeps its label"
        );
        let call_ref = call_of(words[0])?.to_owned();
        let pam = fixture.make_person_named("Pam")?;
        bind(&fixture, &call_ref, "caller", pam).expect("the owner binds the caller");

        let page = fixture.transcript(thread)?;
        let words = counterparty(&page);
        let (label, person) = speaker_of(words[0])?;
        assert_eq!(
            (label, person),
            ("Pam", Some(pam.to_hex()).as_deref()),
            "the phone caller's turn shows the bound name"
        );
        Ok(())
    })
}

#[test]
fn a_bind_to_no_person_or_a_malformed_call_is_refused() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let (room, _, _) = fixture.room_with_contact()?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        call.say(1, "first voice", Some("k1")).await?;
        call.hang_up();

        let page = fixture.transcript(room)?;
        let words = counterparty(&page);
        let call_ref = call_of(words[0])?.to_owned();
        let before = fixture.transcript(room)?;
        let pam = fixture.make_person_named("Pam")?;

        let refused = bind(&fixture, &call_ref, "k1", room).expect_err("a room is not a PERSON");
        assert_eq!(refused.code, MEMORY_CODE_NOT_FOUND, "{refused:?}");
        assert_eq!(fixture.transcript(room)?, before, "nothing is written");
        let refused = bind(&fixture, &call_ref, "k1", EntityId::now())
            .expect_err("an unknown id is no PERSON");
        assert_eq!(refused.code, MEMORY_CODE_NOT_FOUND, "{refused:?}");
        assert_eq!(fixture.transcript(room)?, before, "nothing is written");

        let refused = call(
            &fixture.vault,
            fixture.owner,
            EdgeActorClass::Human,
            BIND,
            json!({"call": "x", "speaker": "k1", "person": pam.to_hex()}),
        )
        .expect_err("a malformed call is refused");
        assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");
        assert_eq!(fixture.transcript(room)?, before, "nothing is written");
        let refused = call(
            &fixture.vault,
            fixture.owner,
            EdgeActorClass::Human,
            BIND,
            json!({"call": call_ref, "speaker": "", "person": pam.to_hex()}),
        )
        .expect_err("an empty speaker is refused");
        assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");
        assert_eq!(fixture.transcript(room)?, before, "nothing is written");
        Ok(())
    })
}
