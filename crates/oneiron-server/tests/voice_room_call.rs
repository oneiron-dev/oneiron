#![cfg(oneiron_test_support)]
//! UNBUILT-02 PR 4: a room call keeps its turns like any other conversation,
//! under the owner's own setting (VOICE-CALL-SCOPE, corrected 15 Nov 22:53).
//! An owner-only room call keeps as a standalone call does (User +
//! Companion in the owner's sitting, no dividers, no room line). A call with
//! other people keeps between its two divider rows: each speaker's words as
//! theirs (Counterparty, labelled with the call's speaker key), the answer
//! the agent's own, with the room line written after the start row when the
//! owner's `voice.call_transcripts.announce` is on. With keep off, only the
//! dividers are kept; in a stretch the room keeps no record of, nothing is.
//! A call in a thread and a project-room call keep nothing yet.
//!
//! The call's brain is the one a room call's boot builds
//! (`oneiron_server::test_doors::voice_call::RoomCall`), its answering agent
//! the seeded default agent, on a served vault whose chat seat is one
//! scripted model. The owner reads the room. Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test voice_room_call`.

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::path::PathBuf;
use std::sync::Arc;

use engine_stack::on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::authority::MachineRole;
use oneiron::compaction::{ChatLog, ChatLogLine, read_chat_log};
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::voice_roster::{
    VoiceAttributionEvidence, VoicePrintCalibration, VoiceResolvedSegment, VoiceSessionRosterV1,
};
use oneiron::conversation::{ConversationBody, ConversationKind, HistoryChoice};
use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::memory::{
    TranscriptMessage, TranscriptPage, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::off_record::OffRecordBackendClass;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::setting::{SetSetting, SettingCaller, SettingMode, SettingScope};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::voice_roster::put_voice_session_roster;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::voice_call::RoomCall;
use serde_json::{Value, json};

type TestError = Box<dyn std::error::Error>;
type TestResult<T = ()> = Result<T, TestError>;

/// What the room's speaker says.
const TRANSCRIPT: &str = "Hello, can you hear me in the room?";
/// What the answering agent answers every turn.
const ANSWER: &str = "Yes, I hear you loud and clear.";
/// The room line a call with other people writes after its start row.
const ROOM_LINE: &str = "This call is transcribed, like the rest of this room.";
/// A contact's name for the roster and divider tests.
const CONTACT_NAME: &str = "Owen";
/// The owner's display name for the owner-print test.
const OWNER_NAME: &str = "Alex";

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
                auth_secret: Some("voice-room-call".into()),
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

    /// The owner turns transcripts of calls with other people off.
    fn keep_no_transcripts(&self) -> TestResult {
        self.turn_off("voice.call_transcripts.keep")
    }

    /// The owner turns the call announcement off.
    fn announce_off(&self) -> TestResult {
        self.turn_off("voice.call_transcripts.announce")
    }

    /// The owner turns one of the call-transcript keys off.
    fn turn_off(&self, key: &str) -> TestResult {
        self.vault.set_setting(
            SettingCaller::Owner(&self.owner_proof),
            SetSetting {
                key: key.to_owned(),
                item: None,
                scope: SettingScope::Vault,
                mode: SettingMode::Value,
                value: Some(json!(false)),
                expected_revision: None,
                why: None,
                check_in_ref: None,
            },
        )?;
        Ok(())
    }

    /// An ordinary room seating the owner alone.
    fn room_owner_only(&self) -> TestResult<EntityId> {
        self.make_room(&[])
    }

    /// An ordinary room seating the owner and one contact member named
    /// `CONTACT_NAME`, with its counterparty contact. The room, the person,
    /// and the contact.
    fn room_with_contact(&self) -> TestResult<(EntityId, EntityId, EntityId)> {
        let person = self.make_person()?;
        let contact = self.make_contact(person, CONTACT_NAME)?;
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

    /// An active counterparty contact naming `person` as `name`.
    fn make_contact(&self, person: EntityId, name: &str) -> TestResult<EntityId> {
        let contact = EntityId::now();
        let record = CounterpartyContactRecord::public(person, name, self.vault.now_recorded_at())?;
        self.vault.create_counterparty_contact(&contact, &record)?;
        Ok(contact)
    }

    /// Stores a roster naming `voice_session_ref` with `segments`.
    fn put_roster(
        &self,
        voice_session_ref: &str,
        segments: Vec<VoiceResolvedSegment>,
    ) -> TestResult {
        let roster = VoiceSessionRosterV1 {
            voice_session_ref: voice_session_ref.to_owned(),
            recording_id: "recording-1".to_owned(),
            embedding_space_id: "space-1".to_owned(),
            known_threshold: 0.65,
            segments,
            created_at: self.vault.now_recorded_at(),
            roster_revision: 1,
        };
        put_voice_session_roster(&self.vault, &roster)?;
        Ok(())
    }

    /// A no-record stretch open in `room`, held for the vault's length.
    fn enter_stretch(&self, room: EntityId, name: &str) -> TestResult {
        let stretch = self.vault.off_record_session_vault().enter_in_room_as(
            name,
            OffRecordBackendClass::Local,
            room,
            &self.owner_proof,
        )?;
        std::mem::forget(stretch);
        Ok(())
    }
}

/// One resolved segment placing `speaker_key` on `contact` by enrolled print.
fn enrolled_contact_segment(
    speaker_key: &str,
    person: EntityId,
    contact: EntityId,
) -> VoiceResolvedSegment {
    VoiceResolvedSegment {
        segment_id: format!("seg-{speaker_key}"),
        start_ms: 0,
        end_ms: 1000,
        speaker_label: format!("Speaker {speaker_key}"),
        speaker_key: speaker_key.to_owned(),
        subject_ref: Some(person),
        contact_ref: Some(contact),
        evidence: VoiceAttributionEvidence::EnrolledPrint {
            subject_ref: person,
            score: 0.7,
            calibration: VoicePrintCalibration::Calibrated,
            print_generation: EntityId::now(),
        },
    }
}

/// One resolved segment matching an owner print for `speaker_key`.
fn owner_print_segment(speaker_key: &str) -> VoiceResolvedSegment {
    VoiceResolvedSegment {
        segment_id: format!("seg-{speaker_key}"),
        start_ms: 0,
        end_ms: 1000,
        speaker_label: format!("Speaker {speaker_key}"),
        speaker_key: speaker_key.to_owned(),
        subject_ref: None,
        contact_ref: None,
        evidence: VoiceAttributionEvidence::EnrolledPrint {
            subject_ref: EntityId::now(),
            score: 0.7,
            calibration: VoicePrintCalibration::Calibrated,
            print_generation: EntityId::now(),
        },
    }
}

/// The owner's one-message turn saying `content` at `occurred_at`.
fn owner_turn(content: String, occurred_at: u64) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: String::new(),
        turn_ref: None,
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content,
            metadata: None,
            is_visible: true,
            order: 0,
            parts: None,
            quote: None,
        }],
        occurred_at,
        assertions: Default::default(),
    }
}

/// What a kept line is: a divider row, the room line, or a speaker's words.
#[derive(Debug, PartialEq, Eq)]
enum Kept {
    Started,
    Ended,
    RoomLine,
    Words(WitnessAuthor, String),
}

/// The room's lines, the divider rows and the room line by their words.
fn kept(log: &ChatLog) -> Vec<Kept> {
    log.lines
        .iter()
        .filter_map(|line| match line {
            ChatLogLine::Message { author, text } => Some(if text.starts_with("call with ") {
                Kept::Started
            } else if text.starts_with("call ended · ") {
                Kept::Ended
            } else if text == ROOM_LINE {
                Kept::RoomLine
            } else {
                Kept::Words(*author, text.clone())
            }),
            ChatLogLine::Summary { .. } => None,
        })
        .collect()
}

/// Every message of `page` in turn order, with its metadata.
fn messages(page: &TranscriptPage) -> Vec<&TranscriptMessage> {
    page.turns.iter().flat_map(|turn| &turn.messages).collect()
}

/// The `voice` object of `message`'s metadata.
fn voice_of(message: &TranscriptMessage) -> TestResult<&Value> {
    message
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("voice"))
        .ok_or_else(|| "a kept row names its call".into())
}

#[test]
fn an_owner_only_room_call_keeps_the_owners_words_and_the_answer() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let room = fixture.room_owner_only()?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        assert_eq!(
            call.conversation(),
            room,
            "an owner-only room call lands in the room"
        );
        call.say(1, TRANSCRIPT, None).await?;
        call.hang_up();

        assert_eq!(
            kept(&fixture.log(room)?),
            vec![
                Kept::Words(WitnessAuthor::User, TRANSCRIPT.to_owned()),
                Kept::Words(WitnessAuthor::Companion, ANSWER.to_owned()),
            ],
            "an owner-only room call keeps User + Companion, no divider, no room line"
        );
        Ok(())
    })
}

#[test]
fn a_call_with_others_keeps_their_words_as_another_speaker() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let (room, _, _) = fixture.room_with_contact()?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        call.say(1, TRANSCRIPT, None).await?;
        call.hang_up();

        let page = fixture.transcript(room)?;
        let rows = messages(&page);
        assert_eq!(
            rows.len(),
            5,
            "start divider, room line, words, answer, end divider"
        );
        assert_eq!(
            rows[0].role, "companion",
            "the start divider is the agent's own row"
        );
        assert_eq!(
            rows[1].text, ROOM_LINE,
            "the room line follows the start divider"
        );
        assert_eq!(
            rows[2].role, "counterparty",
            "another person's words are theirs, never the owner's"
        );
        assert_eq!(
            rows[2].text, TRANSCRIPT,
            "the kept words are the final's transcript"
        );
        let voice = voice_of(rows[2])?;
        assert!(
            voice.get("speaker").is_none(),
            "an unkeyed final keeps no speaker key"
        );
        assert_eq!(
            voice.get("speaker_label").and_then(Value::as_str),
            Some("Another speaker"),
            "an unkeyed final is labelled another speaker"
        );
        assert_eq!(rows[3].role, "companion", "the answer is the agent's own");
        assert_eq!(rows[3].text, ANSWER, "the kept answer is the answer");
        assert_eq!(
            rows[4].role, "companion",
            "the end divider is the agent's own row"
        );
        Ok(())
    })
}

#[test]
fn speaker_keys_number_unplaced_speakers_by_first_heard() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let (room, _, _) = fixture.room_with_contact()?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        call.say(1, "first voice", Some("k1")).await?;
        call.say(2, "second voice", Some("k2")).await?;
        call.say(3, "first voice again", Some("k1")).await?;
        call.hang_up();

        let page = fixture.transcript(room)?;
        let rows = messages(&page);
        let words: Vec<&&TranscriptMessage> = rows
            .iter()
            .filter(|row| row.role == "counterparty")
            .collect();
        assert_eq!(words.len(), 3, "each keyed final keeps its words");
        let labels: Vec<Option<&str>> = words
            .iter()
            .map(|row| {
                voice_of(row)
                    .ok()
                    .and_then(|voice| voice.get("speaker_label").and_then(Value::as_str))
            })
            .collect();
        assert_eq!(
            labels,
            vec![
                Some("Another speaker"),
                Some("Another speaker 2"),
                Some("Another speaker")
            ],
            "unplaced keys number by first-heard order"
        );
        let keys: Vec<Option<&str>> = words
            .iter()
            .map(|row| {
                voice_of(row)
                    .ok()
                    .and_then(|voice| voice.get("speaker").and_then(Value::as_str))
            })
            .collect();
        assert_eq!(
            keys,
            vec![Some("k1"), Some("k2"), Some("k1")],
            "each kept turn carries its speaker key"
        );
        Ok(())
    })
}

#[test]
fn a_key_the_roster_places_on_a_contact_keeps_the_contacts_name() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let (room, person, contact) = fixture.room_with_contact()?;
        let roster_ref = "roster-contact-1";
        fixture.put_roster(
            roster_ref,
            vec![enrolled_contact_segment("k1", person, contact)],
        )?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, Some(roster_ref))?;
        call.say(1, TRANSCRIPT, Some("k1")).await?;
        call.hang_up();

        let page = fixture.transcript(room)?;
        let rows = messages(&page);
        let words = rows
            .iter()
            .find(|row| row.role == "counterparty")
            .ok_or("FIXTURE: the caller's words")?;
        assert_eq!(
            words.text, TRANSCRIPT,
            "the kept words are the final's transcript"
        );
        let voice = voice_of(words)?;
        assert_eq!(
            voice.get("speaker").and_then(Value::as_str),
            Some("k1"),
            "the kept turn carries its speaker key"
        );
        assert_eq!(
            voice.get("speaker_label").and_then(Value::as_str),
            Some(CONTACT_NAME),
            "a key the roster places on a contact keeps the contact's name"
        );
        Ok(())
    })
}

#[test]
fn an_owner_print_key_keeps_as_another_person_labelled_the_owners_name() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let (room, _, _) = fixture.room_with_contact()?;
        // The owner's display name on their own PERSON row; the embedded
        // owner's seeded name names no one until the vault records one.
        let now = fixture.vault.now_recorded_at();
        let body = rmp_serde::to_vec_named(&json!({"display_name": OWNER_NAME}))
            .expect("FIXTURE: the owner name body");
        fixture.vault.put_entity(
            &fixture.owner,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &body,
        )?;
        assert_eq!(
            fixture.vault.call_owner_display_name()?,
            Some(OWNER_NAME.to_owned()),
            "FIXTURE: the vault names its owner"
        );
        let roster_ref = "roster-owner-print-1";
        fixture.put_roster(roster_ref, vec![owner_print_segment("k1")])?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, Some(roster_ref))?;
        call.say(1, TRANSCRIPT, Some("k1")).await?;
        call.hang_up();

        let page = fixture.transcript(room)?;
        let rows = messages(&page);
        let words = rows
            .iter()
            .find(|row| row.role == "counterparty")
            .ok_or("FIXTURE: the caller's words")?;
        let voice = voice_of(words)?;
        assert_eq!(
            voice.get("speaker_label").and_then(Value::as_str),
            Some(OWNER_NAME),
            "an owner-print key keeps as another person labelled the owner's name"
        );
        Ok(())
    })
}

#[test]
fn with_keep_off_a_call_with_others_keeps_only_its_dividers() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        fixture.keep_no_transcripts()?;
        let (room, _, _) = fixture.room_with_contact()?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        call.say(1, TRANSCRIPT, None).await?;
        call.hang_up();

        assert_eq!(
            kept(&fixture.log(room)?),
            vec![Kept::Started, Kept::Ended],
            "with the owner's keep off, only the rows where the call starts and ends are kept"
        );
        Ok(())
    })
}

#[test]
fn a_no_record_stretch_keeps_nothing() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let (room, _, _) = fixture.room_with_contact()?;
        fixture.enter_stretch(room, "roomcall-no-record")?;
        assert!(
            fixture.vault.room_has_unrecorded_stretch(room),
            "FIXTURE: the room keeps no record while the stretch is open"
        );
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        call.say(1, TRANSCRIPT, None).await?;
        call.hang_up();

        assert!(
            fixture.transcript(room)?.turns.is_empty(),
            "a no-record stretch keeps no divider, no line, no turn, and no end divider"
        );
        Ok(())
    })
}

#[test]
fn the_room_line_follows_the_start_divider_when_announce_is_on() -> TestResult {
    on_engine_stack(|| async {
        // Announce on, keep on: the room line follows the start divider.
        let fixture = Fixture::new().await?;
        let (room, _, _) = fixture.room_with_contact()?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        call.say(1, TRANSCRIPT, None).await?;
        call.hang_up();
        assert_eq!(
            kept(&fixture.log(room)?),
            vec![
                Kept::Started,
                Kept::RoomLine,
                Kept::Words(WitnessAuthor::Counterparty, TRANSCRIPT.to_owned()),
                Kept::Words(WitnessAuthor::Companion, ANSWER.to_owned()),
                Kept::Ended,
            ],
            "with announce on, the start divider is followed by the room line, then the words"
        );

        // Announce off, keep on: no room line.
        let fixture = Fixture::new().await?;
        fixture.announce_off()?;
        let (room, _, _) = fixture.room_with_contact()?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        call.say(1, TRANSCRIPT, None).await?;
        call.hang_up();
        assert_eq!(
            kept(&fixture.log(room)?),
            vec![
                Kept::Started,
                Kept::Words(WitnessAuthor::Counterparty, TRANSCRIPT.to_owned()),
                Kept::Words(WitnessAuthor::Companion, ANSWER.to_owned()),
                Kept::Ended,
            ],
            "with announce off, the call keeps no room line"
        );

        // Keep off: no room line either.
        let fixture = Fixture::new().await?;
        fixture.keep_no_transcripts()?;
        let (room, _, _) = fixture.room_with_contact()?;
        let mut call = RoomCall::open(&fixture.server, fixture.owner, room, None)?;
        call.say(1, TRANSCRIPT, None).await?;
        call.hang_up();
        assert_eq!(
            kept(&fixture.log(room)?),
            vec![Kept::Started, Kept::Ended],
            "with keep off, the call keeps no room line"
        );
        Ok(())
    })
}

#[test]
fn a_thread_call_and_a_project_room_call_keep_nothing_yet() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        // A thread of an ordinary room: a trunk turn, then a DAG reply in a
        // thread on it.
        let room = fixture.room_owner_only()?;
        let writer = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
        let mut trunk = owner_turn("trunk words".to_owned(), fixture.vault.now_recorded_at());
        trunk.conversation_ref = room.to_hex();
        let trunk_turn = writer.witness(&trunk)?.turn_id;
        let now = fixture.vault.now_recorded_at();
        let reply = AppendRecord {
            conversation: room,
            parent: None,
            reply_to: None,
            quote: None,
            address: AddressMode::Broadcast,
            recipients: vec![],
            advance: false,
            kind: ENTITY_TYPE_TURN,
            containing_turn: None,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            body: vec![0x80],
            text: vec![],
            session: None,
            actor: WriteActor::new(fixture.owner, EdgeActorClass::Human),
            thread_audience: None,
        };
        let thread_turn = fixture
            .vault
            .reply_in_thread(&writer, trunk_turn, &reply)?
            .id;
        assert!(
            RoomCall::open_in(&fixture.server, fixture.owner, thread_turn, None)?.is_none(),
            "a call in a thread keeps no turn yet"
        );

        // A project room.
        let root = fixture.vault.root_project()?;
        let project = EntityId::now();
        let record = ProjectRecord::new(project, Some(root), root, fixture.owner)?;
        fixture
            .vault
            .put_project(project, &record, fixture.vault.now_recorded_at())?;
        let project_room = EntityId::from_hex(&record.home_room)?;
        assert!(
            RoomCall::open_in(&fixture.server, fixture.owner, project_room, None)?.is_none(),
            "a project-room call keeps no turn yet"
        );
        Ok(())
    })
}
