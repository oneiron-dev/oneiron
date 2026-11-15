#![cfg(oneiron_test_support)]
//! UNBUILT-02 PR 2: an owner's own voice call is an ordinary conversation
//! (VOICE-EPOCH-SOURCE = B). A standalone call keeps each answered turn as
//! two TURN rows, the person's final transcript and the agent's answer, in
//! the home conversation derived from the person and the agent
//! (VOICE-HOME-THREAD = A), in the owner's sitting; past the agent's
//! threshold, its earlier turns compact in the agent's own voice, as a
//! chat's do.
//!
//! The call's brain is the one a standalone call's boot builds
//! (`oneiron_server::test_doors::voice_call`), on a served vault whose chat
//! seat and compaction seat are one scripted model. The seeded default agent
//! carries no memory profile, so it compacts as itself on the host's window
//! (FIX 7744), set small here. The landing re-proves the agent's byline
//! (`check_conversation_landing` refuses any other writer), so a summary
//! standing in the log is the agent's own. Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test voice_self_epoch`.

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use engine_stack::on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::authority::MachineRole;
use oneiron::compaction::{ChatLog, ChatLogLine, read_chat_log};
use oneiron::memory::WitnessAuthor;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::voice_call::StandaloneCall;
use oneiron_server::voice_host::voice_home_conversation_id;
use serde_json::{Value, json};

type TestError = Box<dyn std::error::Error>;
type TestResult<T = ()> = Result<T, TestError>;

/// The host's compaction window, in tokens: the self agent's threshold.
const WINDOW_TOKENS: u64 = 2_000;
/// What the person says each turn, about the length of a spoken paragraph.
const TRANSCRIPT: &str = "I am walking back from the allotment now. Remember that the new \
    garden gate code is four four one seven, that the tomato beds by the shed need water \
    on Thursday, that Mira borrowed the long ladder and will bring it back after the \
    weekend, and that the compost order from the cooperative arrives on the twelfth. \
    Can you keep all of that for me and remind me of the ladder on Sunday evening?";
/// What the agent answers each turn.
const ANSWER: &str = "Got it. The gate code is four four one seven, the tomato beds by the \
    shed need water on Thursday, Mira has the long ladder until after the weekend, and \
    the compost arrives on the twelfth. I will remind you about the ladder on Sunday \
    evening.";
/// A fact every compaction summary carries, so the test finds its words.
const SUMMARY_FACT: &str = "the gate code is four four one seven";
/// How long the call's compaction flight may take to land.
const FLIGHT_PATIENCE: Duration = Duration::from_secs(60);

/// A chat message's text, whether a string or an array of text parts.
fn content(message: &Value) -> String {
    match &message["content"] {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| part["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// The scripted model: a compaction pass gets a summary of its span, with
/// every pin copied word for word; any other call is the call's answer.
fn reply(body: &Value) -> String {
    let messages = body["messages"].as_array().cloned().unwrap_or_default();
    let texts: Vec<String> = messages.iter().map(content).collect();
    if texts.iter().any(|text| text.contains("You compact")) {
        let input = texts
            .iter()
            .rev()
            .find_map(|text| {
                serde_json::from_str::<Value>(text)
                    .ok()
                    .filter(|input| input.get("from").is_some())
            })
            .unwrap_or_default();
        let mut summary = format!(
            "On the call the person listed their garden errands and I kept them: {SUMMARY_FACT}."
        );
        for pin in input["pins"].as_array().cloned().unwrap_or_default() {
            summary.push('\n');
            summary.push_str(pin.as_str().unwrap_or_default());
        }
        return json!({"from": input["from"], "through": input["through"], "summary": summary})
            .to_string();
    }
    ANSWER.to_owned()
}

/// The `[models]` table: one scripted local model serves every role, and
/// compaction runs on the host's small window.
fn models_text(base_url: &str) -> String {
    let prompts = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../oneiron/tests/fixtures/prompts")
        .canonicalize()
        .expect("the fixture prompt package");
    format!(
        "default = \"local:test-model\"\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [code_mode]\nprompt_package = {prompts:?}\n\
         [code_mode.compaction]\nwindow_tokens = {WINDOW_TOKENS}\nhot_steps = 1\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n\
         context_tokens = 500000\n",
        prompts = prompts.display().to_string(),
    )
}

/// A served vault with its owner, and the host that runs its flights.
struct Fixture {
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    owner: EntityId,
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
        let (owner, _proof) = embedded_owner(&vault)?;
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("voice-self-epoch".into()),
                ..Default::default()
            },
        )?;
        let models = ModelsConfig::from_toml(&models_text(&model.base_url), None)?;
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        Ok(Self {
            server: Arc::new(server),
            vault,
            owner,
            _host: host,
            _model: model,
            _dir: dir,
        })
    }

    /// The home conversation's log, as its owner reads it.
    fn log(&self, home: EntityId) -> TestResult<ChatLog> {
        let reader = self.vault.memory(self.owner, EdgeActorClass::Human);
        Ok(read_chat_log(&reader, home, 1, usize::MAX)?)
    }
}

/// The summaries standing in `log`: (summary, epoch, words).
fn summaries(log: &ChatLog) -> Vec<(EntityId, u64, String)> {
    log.lines
        .iter()
        .filter_map(|line| match line {
            ChatLogLine::Summary {
                summary,
                epoch,
                text,
            } => Some((*summary, *epoch, text.clone())),
            ChatLogLine::Message { .. } => None,
        })
        .collect()
}

#[test]
fn standalone_call_lands_epoch_in_main_thread() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let mut call = StandaloneCall::open(&fixture.server, fixture.owner)?;
        let home = voice_home_conversation_id(fixture.owner, call.agent())?;

        // The first turn lands in the home: the person's words, then the
        // agent's answer, text only, in the owner's sitting.
        call.say(1, TRANSCRIPT).await?;
        let first = fixture.log(home)?;
        let lines: Vec<(WitnessAuthor, &str)> = first
            .lines
            .iter()
            .filter_map(|line| match line {
                ChatLogLine::Message { author, text } => Some((*author, text.as_str())),
                ChatLogLine::Summary { .. } => None,
            })
            .collect();
        assert_eq!(
            lines,
            vec![
                (WitnessAuthor::User, TRANSCRIPT),
                (WitnessAuthor::Companion, ANSWER)
            ],
            "the call's first turn is kept as its two TURN rows"
        );
        assert!(
            first.session.is_some(),
            "the turn joined the owner's sitting"
        );

        // Enough turns that the raw ones outgrow the window, the last one
        // still hot.
        let per_turn = (oneiron::count_context_pack_tokens(TRANSCRIPT)
            + oneiron::count_context_pack_tokens(ANSWER)) as u64;
        let turns = WINDOW_TOKENS / per_turn.max(1) + 2;
        for generation in 2..=turns {
            call.say(generation, TRANSCRIPT).await?;
        }

        // The flight runs off the call's path: wait for its epoch to stand.
        let deadline = Instant::now() + FLIGHT_PATIENCE;
        let log = loop {
            let log = fixture.log(home)?;
            if !summaries(&log).is_empty() || Instant::now() > deadline {
                break log;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let standing = summaries(&log);
        assert_eq!(
            standing.len(),
            1,
            "one epoch stands in the call's home after {turns} turns ({per_turn} tokens each, window {WINDOW_TOKENS})"
        );
        let (summary, epoch, words) = &standing[0];
        assert_eq!(*epoch, 1, "the home's first epoch");
        assert!(
            words.contains(SUMMARY_FACT),
            "the summary is the agent's own words about the call: {words}"
        );
        let spans = fixture
            .vault
            .summary_folded_spans(summary)?
            .ok_or("the summary's receipt names the turns it covers")?;
        assert!(
            spans.len() >= 2,
            "the epoch covers the call's earlier turns: {}",
            spans.len()
        );
        assert_eq!(
            spans[0].role,
            WitnessAuthor::User.as_str(),
            "the epoch starts at the person's first words"
        );
        assert!(
            matches!(
                log.lines.last(),
                Some(ChatLogLine::Message { author: WitnessAuthor::Companion, text }) if text == ANSWER
            ),
            "the call's last answer stays raw"
        );
        Ok(())
    })
}
