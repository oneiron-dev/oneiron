#![cfg(oneiron_test_support)]
//! FIX-LIST COMPACTION-FIRST-TURN-PAST-INPUT-ROOM-STALLS (Engine ruling
//! COMPACTION-OVER-ROOM-TURN-INTENT = CHUNKED): a chat turn whose text alone
//! does not fit the compaction writer's input stopped its conversation's
//! compaction for good. A window holds whole turns only, that turn headed
//! every later window, and the flight said only `no_window`. Such a turn now
//! flies alone, read in pieces: each piece fits the writer beside a marker
//! naming its bytes and is summarised by a pass of its own, and the turn's
//! entry is written from the piece summaries, each under the byte range it
//! covers, with the whole turn's pins (FIX 9837). A piece call that fails
//! falls back to the turn's head with a marker naming the cut. A room that
//! holds no piece still names the stall, `turn_past_input_room`.
//!
//! The log is the door's (`test_doors::compaction_request::chat_log_window`):
//! its window holds the turns the test writes, in a fresh SESSION, past the
//! profile's threshold. The writer is a network-free backend whose input
//! room the test sets; it answers every request with a one-line summary
//! that names its call and every pin, and records each request it is sent.
//! It files no writer receipt, so an accepted entry ends the flight as
//! `no_writer_receipt`: the gate accepted it, and only the landing, which
//! this harness cannot make, is left.
//!
//! Red on main 315a7f87ba6 with this file and its door alone: the two pieced
//! flights and the stalled one read `no_window`. The guards hold on both.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test compaction_turn_past_input_room`.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use oneiron::agent_def::{CompactionOwnership, MemoryProfile};
use oneiron::compaction::{
    CompactionBackend, CompactionBackendRegistry, CompactionCheck, CompactionDriver,
    CompactionGatePolicy, CompactionProduct, CompactionRefusal, CompactionRequest,
    CompactionSuppression, CompactionTierClass, ConversationCompactionUnavailable,
    ConversationFlightOutcome, compaction_request_input, seal_conversation_flight,
};
use oneiron::test_doors::compaction_request::chat_log_window;
use oneiron::{
    EdgeActorClass, EntityId, FinishReason, ModelTierRef, Vault, VaultConfig, WriteActor,
    count_context_pack_tokens,
};

/// The backend's registry key, named by the profile.
const WRITER_KEY: &str = "turn-past-input-room-writer";
/// The profile's window: its summary budget is a quarter of it.
const WINDOW_TOKENS: u64 = 4_000;
/// The writer's input room beside its reply: the short turn fits it, the
/// long one does not, and a few pieces of the long one each do.
const INPUT_ROOM: u64 = 1_200;
/// A room that holds the request's frame and no piece of a turn.
const NO_PIECE_ROOM: u64 = 40;
/// A turn that fits the room whole.
const SHORT_TURN: &str = "Please keep the gate code for me, remind me on Sunday evening that \
    Mira still has the long ladder from the allotment shed, and that the compost order from \
    the cooperative arrives on the twelfth.";
/// The agent's own pin; the long turn holds it only at its end.
const PIN: &str = "gate code four four one seven";
/// What every summary the writer writes says, before its call number.
const SUMMARY_WORDS: &str =
    "The person listed the shed beds by number and the day of the week each one needs water";

/// A turn of a few thousand tokens that ends with [`PIN`].
fn long_turn() -> String {
    let beds: Vec<String> = (0..300)
        .map(|bed| format!("Bed {bed} by the shed needs water on day {}.", bed % 7 + 1))
        .collect();
    format!("{} Remember the {PIN}.", beds.join(" "))
}

/// The turn's text as the window holds it: its author's role, then its words.
fn window_text(words: &str) -> String {
    format!("user: {words}")
}

/// A network-free writer with a set input room: it answers each request
/// with a one-line summary naming its call and every pin of the request,
/// refuses the call numbered `refuse_call`, and records every request.
struct ScriptedWriter {
    room: Option<u64>,
    refuse_call: Option<usize>,
    requests: Mutex<Vec<CompactionRequest>>,
}

impl CompactionBackend for ScriptedWriter {
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
        request: &CompactionRequest,
        _retry: Option<CompactionCheck>,
    ) -> Result<CompactionProduct, CompactionRefusal> {
        let mut requests = self.requests.lock().unwrap_or_else(PoisonError::into_inner);
        let call = requests.len();
        requests.push(request.clone());
        if self.refuse_call == Some(call) {
            return Err(CompactionRefusal {
                suppression: CompactionSuppression::TurnScoped { check: None },
                detail: "the scripted writer refuses this call".to_owned(),
            });
        }
        let through = request
            .window
            .last()
            .map_or(request.turn_start, |message| message.turn);
        let summary = format!("{SUMMARY_WORDS}, call {call}. {}", request.pins.join(" "));
        Ok(CompactionProduct {
            summary_text: format!(
                r#"{{"from": {}, "through": {through}, "summary": "{}"}}"#,
                request.turn_start,
                summary.trim()
            ),
            finish: FinishReason::Stop,
            latency: Duration::from_millis(1),
        })
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    writer: Arc<ScriptedWriter>,
    registry: CompactionBackendRegistry,
    profile: MemoryProfile,
    byline: WriteActor,
    conversation: EntityId,
}

fn fixture(room: Option<u64>, refuse_call: Option<usize>) -> Fixture {
    let dir = tempfile::tempdir().expect("FIXTURE: a temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("FIXTURE: a fresh vault");
    let writer = Arc::new(ScriptedWriter {
        room,
        refuse_call,
        requests: Mutex::new(Vec::new()),
    });
    let mut registry = CompactionBackendRegistry::new();
    registry
        .register(writer.clone())
        .expect("FIXTURE: the writer registers");
    let profile = MemoryProfile::new(
        WINDOW_TOKENS,
        ModelTierRef(WRITER_KEY.into()),
        CompactionOwnership::Engine,
    )
    .with_verbatim_pins(vec![PIN.to_owned()]);
    Fixture {
        _dir: dir,
        vault,
        writer,
        registry,
        profile,
        byline: WriteActor::new(EntityId::now(), EdgeActorClass::Agent),
        conversation: EntityId::now(),
    }
}

/// One breakpoint over a log whose window holds `turns`, past the
/// threshold, flown when it seals: how the flight ended, or the reason no
/// flight sealed, and every request the writer was sent, in order.
fn breakpoint(
    fixture: &Fixture,
    turns: &[&str],
) -> (
    Result<ConversationFlightOutcome, &'static str>,
    Vec<CompactionRequest>,
) {
    let mut driver = CompactionDriver::for_profile(&fixture.profile, &fixture.registry)
        .expect("FIXTURE: the driver resolves")
        .expect("FIXTURE: an engine-owned profile compacts");
    let log = chat_log_window(fixture.conversation, turns, u64::MAX);
    let outcome = seal_conversation_flight(
        &fixture.vault,
        &mut driver,
        CompactionGatePolicy::default(),
        fixture.byline,
        None,
        &log,
        EntityId::now(),
    )
    .map(|flight| flight.fly(&fixture.vault))
    .map_err(|why: ConversationCompactionUnavailable| why.as_str());
    let requests = std::mem::take(
        &mut *fixture
            .writer
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner),
    );
    (outcome, requests)
}

/// The tokens `request`'s rendered input holds on its costliest try, as the
/// room is held against it.
fn input_tokens(request: &CompactionRequest) -> u64 {
    [
        None,
        Some(CompactionCheck::NaturalStop),
        Some(CompactionCheck::Schema),
        Some(CompactionCheck::Size),
        Some(CompactionCheck::Pins),
        Some(CompactionCheck::Degeneracy),
        Some(CompactionCheck::Coverage),
    ]
    .into_iter()
    .map(|retry| count_context_pack_tokens(&compaction_request_input(request, retry).to_string()))
    .max()
    .map_or(0, |tokens| tokens as u64)
}

/// An accepted entry in this harness: the gate passed it, and the writer
/// files no receipt to land it with.
fn accepted() -> Result<ConversationFlightOutcome, &'static str> {
    Ok(ConversationFlightOutcome::Refused(
        "no_writer_receipt".to_owned(),
    ))
}

#[test]
fn a_first_turn_past_the_writers_room_is_summarised_in_pieces_that_cover_every_byte() {
    let fixture = fixture(Some(INPUT_ROOM), None);
    let long = long_turn();
    let text = window_text(&long);
    let (outcome, requests) = breakpoint(&fixture, &[&long, SHORT_TURN]);
    assert_eq!(
        outcome,
        accepted(),
        "the over-room turn compacts: its entry passes the gate"
    );
    let (entry, pieces) = requests
        .split_last()
        .expect("the writer was sent the turn's pieces and its entry");
    assert!(
        pieces.len() >= 2,
        "the turn is read in at least two pieces, got {}",
        pieces.len()
    );
    let mut next = 0;
    for (call, piece) in pieces.iter().enumerate() {
        let [message] = piece.window.as_slice() else {
            panic!("piece {call} holds one message, got {}", piece.window.len());
        };
        assert_eq!(message.turn, 0, "piece {call} is of the first turn");
        assert!(piece.pins.is_empty(), "piece {call} carries no pins");
        let (marker, bytes) = message
            .content
            .split_once('\n')
            .expect("a piece opens with the marker naming its bytes");
        let end = next + bytes.len();
        assert_eq!(
            marker,
            format!(
                "[bytes {next}..{end} of {} of this turn's text; summarise only these bytes]",
                text.len()
            ),
            "piece {call} names exactly its bytes"
        );
        assert_eq!(bytes, &text[next..end], "piece {call} holds those bytes");
        assert!(
            input_tokens(piece) <= INPUT_ROOM,
            "piece {call} fits the writer's input room"
        );
        let summarised = format!(
            "[bytes {next}..{end} of {}] {SUMMARY_WORDS}, call {call}.",
            text.len()
        );
        assert!(
            entry.window[0].content.contains(&summarised),
            "the entry holds piece {call}'s summary under its byte range: {}",
            entry.window[0].content
        );
        next = end;
    }
    assert_eq!(
        next,
        text.len(),
        "the pieces cover every byte of the turn, in order"
    );
    assert_eq!(entry.window.len(), 1, "the entry is the one turn's");
    assert_eq!(entry.window[0].turn, 0);
    assert!(
        entry.window[0].content.starts_with(&format!(
            "[this turn's text is {} bytes, read in {} pieces;",
            text.len(),
            pieces.len()
        )),
        "the entry says how the turn was read: {}",
        entry.window[0].content
    );
    assert_eq!(
        entry.pins,
        vec![PIN.to_owned()],
        "the whole turn's pin rides the entry, though only its last piece holds it"
    );
    assert!(
        input_tokens(entry) <= INPUT_ROOM,
        "the entry fits the writer's input room"
    );
}

#[test]
fn a_refused_piece_call_falls_back_to_the_turns_head_with_the_cut_named() {
    let fixture = fixture(Some(INPUT_ROOM), Some(1));
    let long = long_turn();
    let text = window_text(&long);
    let (outcome, requests) = breakpoint(&fixture, &[&long, SHORT_TURN]);
    assert_eq!(
        outcome,
        accepted(),
        "the over-room turn still compacts, from its head"
    );
    assert_eq!(
        requests.len(),
        3,
        "the first piece, the refused second, then the entry: no piece follows a refused one"
    );
    let entry = &requests[2];
    let [message] = entry.window.as_slice() else {
        panic!("the entry holds one message, got {}", entry.window.len());
    };
    let (head, cut) = message
        .content
        .rsplit_once('\n')
        .expect("the entry holds the turn's head, then the marker naming the cut");
    assert!(
        text.starts_with(head) && head.len() < text.len(),
        "the entry holds the turn's head"
    );
    assert!(
        cut.starts_with(&format!(
            "[cut: this turn's text is {} bytes (about ",
            text.len()
        )) && cut.contains(&format!("only bytes 0..{} (about ", head.len())),
        "the marker names the kept and the total bytes: {cut}"
    );
    assert_eq!(
        entry.pins,
        vec![PIN.to_owned()],
        "the whole turn's pin rides the entry, though the head does not hold it"
    );
    assert!(
        input_tokens(entry) <= INPUT_ROOM,
        "the entry fits the writer's input room"
    );
}

#[test]
fn a_room_that_holds_no_piece_still_names_the_stall() {
    let fixture = fixture(Some(NO_PIECE_ROOM), None);
    let long = long_turn();
    let (outcome, requests) = breakpoint(&fixture, &[&long, SHORT_TURN]);
    assert_eq!(
        outcome,
        Err("turn_past_input_room"),
        "a turn no piece of which fits names the stall, not no_window"
    );
    assert!(requests.is_empty(), "no call is sent");
}

#[test]
fn a_first_turn_that_fits_flies_whole_and_the_long_one_waits() {
    let fixture = fixture(Some(INPUT_ROOM), None);
    let long = long_turn();
    let (outcome, requests) = breakpoint(&fixture, &[SHORT_TURN, &long]);
    assert_eq!(
        outcome,
        accepted(),
        "the short turn's summary passes the gate"
    );
    let [request] = requests.as_slice() else {
        panic!("one call over the whole short turn, got {}", requests.len());
    };
    let contents: Vec<&str> = request
        .window
        .iter()
        .map(|message| message.content.as_str())
        .collect();
    assert_eq!(
        contents,
        vec![window_text(SHORT_TURN).as_str()],
        "the window keeps the whole turns that fit; the long turn waits"
    );
}

#[test]
fn a_writer_with_no_bound_takes_the_long_turn_whole() {
    let fixture = fixture(None, None);
    let long = long_turn();
    let (outcome, requests) = breakpoint(&fixture, &[&long, SHORT_TURN]);
    assert_eq!(outcome, accepted(), "the window's summary passes the gate");
    let [request] = requests.as_slice() else {
        panic!("one call over the whole window, got {}", requests.len());
    };
    let contents: Vec<&str> = request
        .window
        .iter()
        .map(|message| message.content.as_str())
        .collect();
    assert_eq!(
        contents,
        vec![
            window_text(&long).as_str(),
            window_text(SHORT_TURN).as_str()
        ],
        "nothing bounds the input, so no turn is read in pieces"
    );
}
