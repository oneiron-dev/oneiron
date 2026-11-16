#![cfg(oneiron_test_support)]
//! Row VOICE-ROOM-TURN-SOURCED-OFF-RECORD (census L5-25): a room call's voice
//! turn runs unsourced during an off-record stretch, and sourced otherwise.
//!
//! One turn of a call heard in a room, driven through the room-turn door
//! (`oneiron_server::test_doors::room_turn_call::RoomTurnCall`), with the
//! turn's run receipts going to an in-memory sink. (a) Control, no stretch in
//! the room: the turn's run is sourced, and some `Admitted` receipt of it
//! names the answering agent's row. (b) After a member starts an off-record
//! stretch in that room: one more turn calls the model again, and every
//! `Admitted` receipt recorded during it names no source rows and no source
//! worlds. A second test closes the stretch and shows the next turn is
//! sourced again.
//!
//! On the base the (b) turn's receipts still name the agent row, so the test
//! is red; with the fix the turn's run is `off_record()` and the test is
//! green. Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test voice_room_turn_off_record`.

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::path::PathBuf;
use std::sync::Arc;

use engine_stack::on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::authority::MachineRole;
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind};
use oneiron::llm::run_admission::{MemoryReceipts, PermitFacts, RunEvent, RunReceipt};
use oneiron::off_record::{OffRecordBackendClass, OffRecordMode};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::room_turn_call::RoomTurnCall;
use serde_json::Value;

type TestError = Box<dyn std::error::Error>;
type TestResult<T = ()> = Result<T, TestError>;

/// What the room's speaker says each turn.
const TRANSCRIPT: &str = "Hello, can you hear me in the room?";
/// What the answering agent answers each turn.
const ANSWER: &str = "Yes, I hear you loud and clear.";

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

/// A served vault with its owner, the host that runs its turns, and the sink
/// the turns' run receipts go to.
struct Fixture {
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    receipts: Arc<MemoryReceipts>,
    _host: AiHost,
    model: FakeLlm,
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
        let receipts = Arc::new(MemoryReceipts::default());
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("voice-room-turn-off-record".into()),
                ..Default::default()
            },
        )?
        .with_run_receipts(receipts.clone());
        let models = ModelsConfig::from_toml(&models_text(&model.base_url), None)?;
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        Ok(Self {
            server: Arc::new(server),
            vault,
            owner,
            owner_proof,
            receipts,
            _host: host,
            model,
            _dir: dir,
        })
    }

    /// An ordinary Group room seating the owner alone.
    fn make_room(&self) -> TestResult<EntityId> {
        let room = EntityId::now();
        self.vault.create_conversation(
            room,
            &ConversationBody {
                kind: ConversationKind::Group,
                member_ids: vec![self.owner],
                ..Default::default()
            },
            WriteActor::new(self.owner, EdgeActorClass::Human),
            self.vault.now_recorded_at(),
        )?;
        Ok(room)
    }

    /// How many model calls the fake has answered so far.
    fn model_calls(&self) -> usize {
        self.model.seen().len()
    }
}

/// Every `Admitted` receipt's facts among `rows`, in order.
fn admitted_from(rows: &[RunReceipt]) -> Vec<&PermitFacts> {
    rows.iter()
        .filter_map(|row| match &row.event {
            RunEvent::Admitted(facts) => Some(facts.as_ref()),
            _ => None,
        })
        .collect()
}

/// Whether some `Admitted` facts name `agent` among their source rows.
fn names_agent(admitted: &[&PermitFacts], agent: EntityId) -> bool {
    admitted.iter().any(|facts| {
        facts
            .source_rows
            .as_ref()
            .is_some_and(|named| named.contains(&agent))
    })
}

#[test]
fn a_room_call_turn_runs_unsourced_during_an_off_record_stretch() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let room = fixture.make_room()?;
        let mut call = RoomTurnCall::open(&fixture.server, fixture.owner, room)?;
        let agent = call.agent();

        // (a) Control: with no stretch in the room, the turn's run is
        // sourced, and some Admitted receipt of it names the agent row, so
        // (b) cannot pass vacuously.
        assert!(
            !fixture.vault.room_has_unrecorded_stretch(room),
            "no stretch is open before the control turn",
        );
        let before = fixture.receipts.rows().len();
        call.say(1, TRANSCRIPT).await?;
        let rows = fixture.receipts.rows();
        let admitted = admitted_from(&rows[before..]);
        assert!(
            names_agent(&admitted, agent),
            "the control turn is sourced: some Admitted receipt names the agent row",
        );

        // (b) After a member starts an off-record stretch in the room, one
        // more turn calls the model again, and every Admitted receipt it
        // records names no source rows and no source worlds.
        let stretch = fixture.vault.off_record_session_vault().enter_in_room_as(
            "room-turn-off-record",
            OffRecordBackendClass::Local,
            room,
            &fixture.owner_proof,
        )?;
        assert_eq!(
            stretch.mode()?,
            OffRecordMode::OffRecord,
            "the stretch keeps no record",
        );
        assert!(
            fixture.vault.room_has_unrecorded_stretch(room),
            "the room has a live stretch that keeps no record before the off-record turn",
        );
        let calls = fixture.model_calls();
        let before = fixture.receipts.rows().len();
        // The turn answered to its stop: `say` fails a turn that did not.
        call.say(2, TRANSCRIPT).await?;
        assert!(
            fixture.model_calls() > calls,
            "the off-record turn called the model again",
        );
        let rows = fixture.receipts.rows();
        let admitted = admitted_from(&rows[before..]);
        assert!(
            !admitted.is_empty(),
            "the off-record turn admitted its model call",
        );
        for facts in &admitted {
            assert!(
                facts.source_rows.as_ref().is_none_or(Vec::is_empty),
                "an off-record turn's receipt names no source rows: {:?}",
                facts.source_rows,
            );
            assert!(
                facts.source_worlds.is_none(),
                "an off-record turn's receipt names no source worlds: {:?}",
                facts.source_worlds,
            );
        }
        Ok(())
    })
}

#[test]
fn a_closed_stretch_leaves_the_next_turn_sourced_again() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let room = fixture.make_room()?;
        let mut call = RoomTurnCall::open(&fixture.server, fixture.owner, room)?;
        let agent = call.agent();

        let stretch = fixture.vault.off_record_session_vault().enter_in_room_as(
            "room-turn-closed",
            OffRecordBackendClass::Local,
            room,
            &fixture.owner_proof,
        )?;
        assert!(
            fixture.vault.room_has_unrecorded_stretch(room),
            "the room keeps no record while the stretch is open",
        );
        stretch.close()?;
        assert!(
            !fixture.vault.room_has_unrecorded_stretch(room),
            "a closed stretch is no longer a live stretch that keeps no record",
        );
        let before = fixture.receipts.rows().len();
        call.say(1, TRANSCRIPT).await?;
        let rows = fixture.receipts.rows();
        let admitted = admitted_from(&rows[before..]);
        assert!(
            names_agent(&admitted, agent),
            "after the stretch closed, the turn is sourced again",
        );
        Ok(())
    })
}
