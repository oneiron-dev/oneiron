#![cfg(oneiron_test_support)]
//! UNBUILT-02 PR 3B: with the owner's `voice.call_transcripts.announce` on
//! (its default), the line agent opens a phone call by saying it is
//! transcribed, before the caller's first words (VOICE-CALL-SCOPE, corrected
//! 15 Nov 22:53; the UI words of 22:55). The line is the session's own
//! generation, spoken like any answer, with no model call. With
//! `voice.call_transcripts.keep` on it is the call's first kept answer,
//! after the row where the call starts; with keep off it is spoken and not
//! kept; with the announcement off the call opens silent.
//!
//! The call's brain and opening line are the ones a phone call's boot builds
//! (`oneiron_server::test_doors::voice_call::PhoneCall`), its line agent the
//! seeded default agent, on a served vault whose chat seat is one scripted
//! model and whose owner has named themselves nowhere. The owner reads the
//! thread. Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test voice_call_announcement`.

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
use oneiron::memory::WitnessAuthor;
use oneiron::setting::{SetSetting, SettingCaller, SettingMode, SettingScope};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::voice_call::PhoneCall;
use serde_json::{Value, json};

type TestError = Box<dyn std::error::Error>;
type TestResult<T = ()> = Result<T, TestError>;

/// The caller's number as the line's provider gives it.
const CALLER: &str = "+81 90-1234-5678";
/// The number the thread keeps.
const KEPT_NUMBER: &str = "+819012345678";
/// The seeded default agent's display name.
const AGENT_NAME: &str = "Default";
/// What the agent says first: its name, and no owner's, since the owner has
/// named themselves nowhere.
const ANNOUNCEMENT: &str = "Hello, this is Default, an assistant. This call is transcribed.";
/// What the caller says.
const TRANSCRIPT: &str = "Hello, this is the clinic calling about the appointment on Thursday.";
/// What the line agent answers every turn.
const ANSWER: &str = "Thank you. I will pass the Thursday appointment on.";

/// The scripted model: every call is the line agent's answer.
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
                auth_secret: Some("voice-call-announcement".into()),
                ..Default::default()
            },
        )?;
        let models = ModelsConfig::from_toml(&models_text(&model.base_url), None)?;
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        let (_, definition) = vault
            .get_seeded_agent_definition_by_logical_id("sys.default")?
            .ok_or("FIXTURE: the seeded default agent")?;
        assert_eq!(
            definition.display_name.as_deref(),
            Some(AGENT_NAME),
            "FIXTURE: the line agent's display name"
        );
        assert_eq!(
            vault.call_owner_display_name()?,
            None,
            "FIXTURE: the embedded owner's seeded name names no one"
        );
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

    /// The thread's log, as its owner reads it.
    fn log(&self, thread: EntityId) -> TestResult<ChatLog> {
        let reader = self.vault.memory(self.owner, EdgeActorClass::Human);
        Ok(read_chat_log(&reader, thread, 1, usize::MAX)?)
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
}

/// What a kept line is: a divider row, or a speaker's words.
#[derive(Debug, PartialEq, Eq)]
enum Kept {
    Started,
    Ended,
    Words(WitnessAuthor, String),
}

/// The thread's lines, the divider rows by their words.
fn kept(log: &ChatLog) -> Vec<Kept> {
    let started = format!("call with {KEPT_NUMBER} · ");
    log.lines
        .iter()
        .filter_map(|line| match line {
            ChatLogLine::Message { author, text } => Some(if text.starts_with(&started) {
                Kept::Started
            } else if text.starts_with("call ended · ") {
                Kept::Ended
            } else {
                Kept::Words(*author, text.clone())
            }),
            ChatLogLine::Summary { .. } => None,
        })
        .collect()
}

/// One answered turn's two kept lines.
fn answered_turn() -> [Kept; 2] {
    [
        Kept::Words(WitnessAuthor::Counterparty, TRANSCRIPT.to_owned()),
        Kept::Words(WitnessAuthor::Companion, ANSWER.to_owned()),
    ]
}

#[test]
fn a_phone_call_opens_by_saying_it_is_transcribed_and_keeps_that_line_first() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let mut call = PhoneCall::answer(&fixture.server, Some(CALLER))?;
        let thread = call.conversation();
        assert_eq!(
            call.open().await?.as_deref(),
            Some(ANNOUNCEMENT),
            "the agent opens the call by saying it is transcribed, naming itself"
        );
        call.say(2, TRANSCRIPT).await?;
        call.hang_up();

        let [caller, answer] = answered_turn();
        assert_eq!(
            kept(&fixture.log(thread)?),
            vec![
                Kept::Started,
                Kept::Words(WitnessAuthor::Companion, ANNOUNCEMENT.to_owned()),
                caller,
                answer,
                Kept::Ended,
            ],
            "the announcement is the call's first answer, after the start row and before the caller's words"
        );
        Ok(())
    })
}

#[test]
fn with_the_announcement_off_a_phone_call_opens_silent() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        fixture.turn_off("voice.call_transcripts.announce")?;
        let mut call = PhoneCall::answer(&fixture.server, Some(CALLER))?;
        let thread = call.conversation();
        assert_eq!(
            call.open().await?,
            None,
            "with the owner's announcement off, the agent says nothing before the caller"
        );
        call.say(2, TRANSCRIPT).await?;
        call.hang_up();

        let [caller, answer] = answered_turn();
        assert_eq!(
            kept(&fixture.log(thread)?),
            vec![Kept::Started, caller, answer, Kept::Ended],
            "no announcement is kept"
        );
        Ok(())
    })
}

#[test]
fn with_transcripts_off_the_announcement_is_spoken_and_not_kept() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        fixture.turn_off("voice.call_transcripts.keep")?;
        let mut call = PhoneCall::answer(&fixture.server, Some(CALLER))?;
        let thread = call.conversation();
        assert_eq!(
            call.open().await?.as_deref(),
            Some(ANNOUNCEMENT),
            "the announcement follows its own key, not the keep key"
        );
        call.say(2, TRANSCRIPT).await?;
        call.hang_up();

        assert_eq!(
            kept(&fixture.log(thread)?),
            vec![Kept::Started, Kept::Ended],
            "with the owner's keep off, only the rows where the call starts and ends are kept"
        );
        Ok(())
    })
}
