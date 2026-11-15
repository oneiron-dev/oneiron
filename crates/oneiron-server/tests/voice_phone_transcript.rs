#![cfg(oneiron_test_support)]
//! UNBUILT-02 PR 3: a phone call is kept like any other conversation, under
//! the owner's own setting (VOICE-CALL-SCOPE, corrected 15 Nov 22:53). Each
//! answered turn keeps the caller's words as theirs (a counterparty turn) and
//! the line agent's answer as its own, between a row where the call starts
//! and one where it ends, in the agent's thread with that number, its turns
//! held in the thread's own SESSION (PHONE-CALL-SESSION = A). With the
//! owner's `voice.call_transcripts.keep` off, only the two rows are kept.
//!
//! The call's brain is the one a phone call's boot builds
//! (`oneiron_server::test_doors::voice_call::PhoneCall`), its line agent the
//! seeded default agent, on a served vault whose chat seat is one scripted
//! model. The owner reads the thread. Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test voice_phone_transcript`.

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
use oneiron::test_doors::connector_thread_session::thread_session;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::voice_call::PhoneCall;
use oneiron_server::voice_host::{caller_number, voice_phone_conversation_id};
use serde_json::{Value, json};

type TestError = Box<dyn std::error::Error>;
type TestResult<T = ()> = Result<T, TestError>;

/// The caller's number as the line's provider gives it.
const CALLER: &str = "+81 90-1234-5678";
/// The same number as a later arrival spells it.
const CALLER_AGAIN: &str = "+81 90 1234 5678";
/// The number the thread keeps.
const KEPT_NUMBER: &str = "+819012345678";
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
                auth_secret: Some("voice-phone-transcript".into()),
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

    /// The thread's log, as its owner reads it.
    fn log(&self, thread: EntityId) -> TestResult<ChatLog> {
        let reader = self.vault.memory(self.owner, EdgeActorClass::Human);
        Ok(read_chat_log(&reader, thread, 1, usize::MAX)?)
    }

    /// The owner turns transcripts of calls with other people off.
    fn keep_no_transcripts(&self) -> TestResult {
        self.vault.set_setting(
            SettingCaller::Owner(&self.owner_proof),
            SetSetting {
                key: "voice.call_transcripts.keep".to_owned(),
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
fn a_phone_call_keeps_the_callers_words_as_theirs_between_its_dividers() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let mut call = PhoneCall::answer(&fixture.server, Some(CALLER))?;
        let thread = call.conversation();
        assert_eq!(
            thread,
            voice_phone_conversation_id(call.agent(), Some(KEPT_NUMBER), "unused")?,
            "the call lands in the line agent's thread with the caller's number"
        );
        call.say(1, TRANSCRIPT).await?;
        call.hang_up();

        let log = fixture.log(thread)?;
        let [caller, answer] = answered_turn();
        assert_eq!(
            kept(&log),
            vec![Kept::Started, caller, answer, Kept::Ended],
            "the caller's words are a counterparty turn and the answer the agent's own, between the call's two rows"
        );
        assert_eq!(
            log.session,
            Some(thread_session(thread)?),
            "the call's turns are held in the thread's own SESSION, no one's sitting"
        );
        Ok(())
    })
}

#[test]
fn with_transcripts_off_a_phone_call_keeps_only_its_dividers() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        fixture.keep_no_transcripts()?;
        let mut call = PhoneCall::answer(&fixture.server, Some(CALLER))?;
        let thread = call.conversation();
        call.say(1, TRANSCRIPT).await?;
        call.hang_up();

        assert_eq!(
            kept(&fixture.log(thread)?),
            vec![Kept::Started, Kept::Ended],
            "with the owner's keep off, only the rows where the call starts and ends are kept"
        );
        Ok(())
    })
}

#[test]
fn a_second_call_from_the_same_number_lands_in_the_same_thread() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let mut first = PhoneCall::answer(&fixture.server, Some(CALLER))?;
        let thread = first.conversation();
        first.say(1, TRANSCRIPT).await?;
        first.hang_up();
        let mut second = PhoneCall::answer(&fixture.server, Some(CALLER_AGAIN))?;
        assert_eq!(
            second.conversation(),
            thread,
            "the same number, spelt another way, is the same thread"
        );
        second.say(1, TRANSCRIPT).await?;
        second.hang_up();

        let [caller, answer] = answered_turn();
        let [caller_again, answer_again] = answered_turn();
        assert_eq!(
            kept(&fixture.log(thread)?),
            vec![
                Kept::Started,
                caller,
                answer,
                Kept::Ended,
                Kept::Started,
                caller_again,
                answer_again,
                Kept::Ended,
            ],
            "both calls are kept in the one thread, each between its own rows"
        );

        let withheld = PhoneCall::answer(&fixture.server, None)?;
        assert_ne!(
            withheld.conversation(),
            thread,
            "a call whose number is withheld gets a thread of its own"
        );
        assert_eq!(caller_number(Some("anonymous")), None);
        withheld.hang_up();
        Ok(())
    })
}
