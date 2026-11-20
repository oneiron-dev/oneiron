#![cfg(oneiron_test_support)]
//! FIX-LIST COMPACTION-FIRST-TURN-PAST-INPUT-ROOM-STALLS: a chat turn whose
//! text alone does not fit the compaction writer's input stops its
//! conversation's compaction. A window holds whole turns only, and that turn
//! heads every later window, so no later flight takes it while the writer's
//! room stays the same. The flight said only `no_window`, whose causes are a
//! turn that is open, incomplete, outside a recorded SESSION, not read
//! exactly or already covered, so a host could not see the stall. It now
//! names it, `turn_past_input_room`, as `pins_do_not_fit` names the same
//! stall for the agent's own pins (FIX 9837).
//!
//! The log is the door's (`test_doors::compaction_request::chat_log_window`):
//! its window holds the turns the test writes, in a fresh SESSION, past the
//! profile's threshold. The writer is a network-free backend whose input room
//! the test sets.
//!
//! Red on main 315a7f87ba6 with this file and its door alone: both stalled
//! flights read `no_window`. The guards hold on both. Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test compaction_turn_past_input_room`.

use std::sync::Arc;
use std::time::Duration;

use oneiron::agent_def::{CompactionOwnership, MemoryProfile};
use oneiron::compaction::{
    CompactionBackend, CompactionBackendRegistry, CompactionCheck, CompactionDriver,
    CompactionGatePolicy, CompactionProduct, CompactionRefusal, CompactionRequest,
    CompactionTierClass, ConversationCompactionUnavailable, seal_conversation_flight,
};
use oneiron::test_doors::compaction_request::chat_log_window;
use oneiron::{
    EdgeActorClass, EntityId, FinishReason, ModelTierRef, Vault, VaultConfig, WriteActor,
};

/// The backend's registry key, named by the profile.
const WRITER_KEY: &str = "turn-past-input-room-writer";
/// The profile's window: its threshold is at most this many tokens.
const WINDOW_TOKENS: u64 = 1_000;
/// The writer's input room beside its reply: the window's frame and a short
/// turn fit it, a long one does not.
const INPUT_ROOM: u64 = 200;
/// A turn that fits the room with the window's frame.
const SHORT_TURN: &str = "Please keep the gate code for me.";

/// A turn of about `words` tokens, far past [`INPUT_ROOM`].
fn long_turn(words: usize) -> String {
    vec!["allotment"; words].join(" ")
}

/// A network-free writer whose input room the test sets. No flight is flown
/// here, so its summary is never read.
struct RoomBoundWriter {
    room: Option<u64>,
}

impl CompactionBackend for RoomBoundWriter {
    fn backend_key(&self) -> &str {
        WRITER_KEY
    }

    fn tier_class(&self) -> CompactionTierClass {
        CompactionTierClass::Cheap
    }

    fn input_token_limit(&self, _summary_token_budget: u64) -> Option<u64> {
        self.room
    }

    fn compact(
        &self,
        _request: &CompactionRequest,
        _retry: Option<CompactionCheck>,
    ) -> Result<CompactionProduct, CompactionRefusal> {
        Ok(CompactionProduct {
            summary_text: r#"{"from": 0, "through": 0, "summary": "kept"}"#.into(),
            finish: FinishReason::Stop,
            latency: Duration::from_millis(1),
        })
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    registry: CompactionBackendRegistry,
    profile: MemoryProfile,
    byline: WriteActor,
    conversation: EntityId,
}

fn fixture(room: Option<u64>) -> Fixture {
    let dir = tempfile::tempdir().expect("FIXTURE: a temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("FIXTURE: a fresh vault");
    let mut registry = CompactionBackendRegistry::new();
    registry
        .register(Arc::new(RoomBoundWriter { room }))
        .expect("FIXTURE: the writer registers");
    let profile = MemoryProfile::new(
        WINDOW_TOKENS,
        ModelTierRef(WRITER_KEY.into()),
        CompactionOwnership::Engine,
    );
    Fixture {
        _dir: dir,
        vault,
        registry,
        profile,
        byline: WriteActor::new(EntityId::now(), EdgeActorClass::Agent),
        conversation: EntityId::now(),
    }
}

/// One breakpoint's flight over a log whose window holds `turns`, past the
/// threshold: `Ok(())` when its flight sealed, else the reason it names.
fn seal(fixture: &Fixture, turns: &[&str]) -> Result<(), &'static str> {
    let mut driver = CompactionDriver::for_profile(&fixture.profile, &fixture.registry)
        .expect("FIXTURE: the driver resolves")
        .expect("FIXTURE: an engine-owned profile compacts");
    let log = chat_log_window(fixture.conversation, turns, u64::MAX);
    seal_conversation_flight(
        &fixture.vault,
        &mut driver,
        CompactionGatePolicy::default(),
        fixture.byline,
        None,
        &log,
        EntityId::now(),
    )
    .map(|_| ())
    .map_err(|why: ConversationCompactionUnavailable| why.as_str())
}

#[test]
fn a_first_turn_past_the_writers_room_names_the_stall_at_every_breakpoint() {
    let fixture = fixture(Some(INPUT_ROOM));
    let long = long_turn(2_000);
    assert_eq!(
        seal(&fixture, &[&long, SHORT_TURN]),
        Err("turn_past_input_room"),
        "a first turn the writer cannot take even alone names the stall, not no_window"
    );
    // A later breakpoint, a turn later: the same turn heads the window, so
    // the conversation stays stalled on the same room, and says so again.
    assert_eq!(
        seal(&fixture, &[&long, SHORT_TURN, SHORT_TURN]),
        Err("turn_past_input_room"),
        "the over-room turn heads every later window"
    );
}

#[test]
fn a_first_turn_that_fits_seals_its_flight_and_the_long_one_waits() {
    let fixture = fixture(Some(INPUT_ROOM));
    let long = long_turn(2_000);
    assert_eq!(
        seal(&fixture, &[SHORT_TURN, &long]),
        Ok(()),
        "the window keeps the whole turns that fit; the long turn waits"
    );
}

#[test]
fn a_writer_with_no_bound_takes_the_long_turn() {
    let fixture = fixture(None);
    let long = long_turn(2_000);
    assert_eq!(
        seal(&fixture, &[&long, SHORT_TURN]),
        Ok(()),
        "nothing bounds the input, so no turn is past the room"
    );
}
