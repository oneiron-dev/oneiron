//! FIX-LIST COMPACTION-CHECK-JUDGES-PER-CHUNK (Engine answer 21 Nov 07:39;
//! the Oneiron lead: "the check judges per chunk, each chunk's summary
//! against exactly its bytes"): a chat turn past its cheap writer's input
//! room is summarised in pieces (#10050), and the Dreamer's check of that
//! summary judged the span whole. A span past the judge's window settled
//! unjudged, `span_past_judge_room`, however well each piece fit it. The
//! check now judges each piece summary, read back out of the kept entry,
//! against exactly its bytes of the turn, and then the landed summary
//! against the entry its writer read. The first part the judge does not find
//! supported decides the check, and the finding names that piece's bytes.
//!
//! The owner's first turn in a sitting is far longer than the cheap writer's
//! room (a small served context), so the first flight reads it in pieces and
//! lands its entry, and that landing declares the check. The test admits the
//! check and runs it as the Dreamer's host does. The judge's window holds
//! each part but not the turn whole; the judge is a network-free backend
//! that records each request.
//!
//! Red at 4364e7a38a2 (#10050 with #10089 merged in) with this file and its
//! helpers alone: the check settles `span_past_judge_room` with no judge
//! call. The guard, a span of whole turns judged whole in one call, is
//! `ai_chat_check_judge_room::a_span_within_the_judges_window_is_judged`.
//!
//! Review round 1 of #10272 adds three cases, red at c57da6b6054 (#10272's
//! head then) with this file alone:
//! - a piece summary holding a GitHub token, which the check material's
//!   side-row wall keeps as its handle, so the kept entry is shorter than the
//!   one sent: the check must still find each piece summary (red: it settled
//!   `turn_reading_unreadable` with no judge call);
//! - a verbatim pin of the agent's profile that the long turn holds and no
//!   piece summary keeps: its writer was given it beside the entry and had to
//!   copy it, so the landed summary's evidence carries it (red: absent);
//! - the owner deletes the turn's MESSAGE, a source of the span, while the
//!   judge reads the first piece: no later piece goes out (red: every piece
//!   went out from the text read before the delete).
//!
//! Review round 2 of #10272 adds two cases, red at ff1d09069dc (#10272's
//! head then) with this file alone; in each the owner deletes the turn's
//! MESSAGE while the judge reads the first piece:
//! - the judge finds that piece supported, its reason quoting the owner's
//!   words: the check stops on its next read, and its finding keeps none of
//!   what the judge said of the deleted text (red: the finding's `pieces`
//!   kept the quoting reason);
//! - with the host's decisions lent, the typed support read would send the
//!   piece's text again after its diagnostic: it does not go out (red: it
//!   went out from the text read before the delete).
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --lib -- api::tests::ai_chat_check_per_chunk`.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use oneiron::agent_def::{CompactionOwnership, MemoryProfile};
use oneiron::dreamer_runner::maintenance::compaction_check::COMPACTION_CHECK_FACET;
use oneiron::dreamer_runner::{AdmitDreamerAttempt, DreamerAdmissionOutcome};
use oneiron::{
    BudgetLease, ContentPart, DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerRunnerStore,
    EdgeActorClass, EntityId, FatalLlmError, FinishReason, LlmBackend, LlmCapability, LlmError,
    LlmGenerateFuture, LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest,
    LlmResponse, LlmStreamResult, LlmUsage, ModelTierRef, SafeDeleteReason, TimeRange,
    UnsupportedCapability,
};
use serde_json::{Value, json};

use super::ai_chat_check_judge_room::{finding, run_check, run_check_lent, vault_seconds};
use super::ai_chat_self_compaction::{
    chat_text, compaction_calls_report, log_report, open_owner_sitting, reply, self_row_server_on,
};
use crate::ai_host::AiHost;
use crate::ai_host::test_support::{eventually, route_extraction};
use crate::decision_host::DecisionHost;
use crate::fake_llm::{FakeLlm, Reply};
use crate::server::SyncServer;

/// The served model's context: its cheap writer's room is a fraction of the
/// owner's long turn, and still holds the 1500-token window code mode asks.
const WRITER_CONTEXT_TOKENS: u64 = 6_000;
/// The tide readings in the owner's long turn: some 11,000 tokens.
const LONG_TURN_READINGS: u64 = 700;
/// The marker the writer's piece calls end their byte range with.
const PIECE_MARKER_END: &str = " of this turn's text; summarise only these bytes]";
/// The key the check's declaration rides under in its attempt's input.
const CONVERSATION_DECLARATION_KEY: &str = "conversation_declaration";
/// A verbatim pin of the self agent's profile, said once at the end of the
/// owner's long turn.
const DEADLINE_PIN: &str = "the jetty survey deadline is Friday";

/// A GitHub personal token the write door's provider rule places (`ghp_`
/// and 36 token characters), spelled in parts so no scanner of this source
/// reads a token.
fn provider_token() -> String {
    ["gh", "p_", "0123456789abcdefghijklmnopqrstuvwxyz"].concat()
}

/// The owner's long turn, as the owner says it.
fn long_turn() -> String {
    (0..LONG_TURN_READINGS)
        .map(|reading| {
            format!(
                "Reading {reading} at the south jetty gauge stood at {} centimetres.",
                120 + reading % 97
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The judge's reason for a part it finds supported, unless the test names
/// another.
const SUPPORTED_REASON: &str = "the text carries every assertion";
/// A supported reason that quotes the owner's first reading word for word.
const QUOTING_REASON: &str =
    "the owner wrote: Reading 0 at the south jetty gauge stood at 120 centimetres.";

/// The judge: it records every request it is sent and answers each
/// `supported` for `reason`, except a piece whose bytes start at
/// `mismatch_at`, which it answers `mismatch`, citing the span's one turn.
/// `on_first` runs once, as the first request comes in.
struct PartJudge {
    mismatch_at: Option<u64>,
    reason: &'static str,
    requests: Mutex<Vec<LlmRequest>>,
    on_first: Option<Box<dyn Fn() + Send + Sync>>,
}

impl PartJudge {
    fn new(mismatch_at: Option<u64>) -> Self {
        Self {
            mismatch_at,
            reason: SUPPORTED_REASON,
            requests: Mutex::new(Vec::new()),
            on_first: None,
        }
    }

    /// The same judge, giving `reason` for each part it finds supported.
    fn reasoning(self, reason: &'static str) -> Self {
        Self { reason, ..self }
    }

    /// A judge that answers each part `supported` and runs `on_first` as the
    /// first request comes in.
    fn on_first(on_first: impl Fn() + Send + Sync + 'static) -> Self {
        Self {
            on_first: Some(Box::new(on_first)),
            ..Self::new(None)
        }
    }

    /// The input of every request the judge was sent, in order.
    fn inputs(&self) -> Vec<Value> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(input_of)
            .collect()
    }
}

/// What a judge request asks about: its last turn's text, as JSON.
fn input_of(request: &LlmRequest) -> Value {
    let text: String = request
        .messages
        .last()
        .into_iter()
        .flat_map(|message| &message.content)
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

/// The judge's reply `answer`, with nonzero usage.
fn judge_reply(answer: &Value) -> LlmResponse {
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: answer.to_string(),
                signature: None,
            }],
        },
        usage: LlmUsage {
            input: LlmInputUsage {
                total: 10,
                cache_read: 0,
                cache_write: 0,
            },
            output: LlmOutputUsage {
                total: 5,
                text: 5,
                reasoning: 0,
            },
            raw_provider: Value::Null,
            call_metadata: None,
        },
        finish_reason: FinishReason::Stop,
        reply_assertions: Default::default(),
        token_scores: None,
    }
}

impl LlmBackend for PartJudge {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let start = input_of(&request)["span"]["bytes"][0].as_u64();
        let first = {
            let mut requests = self.requests.lock().unwrap_or_else(PoisonError::into_inner);
            requests.push(request);
            requests.len() == 1
        };
        if let (true, Some(on_first)) = (first, &self.on_first) {
            on_first();
        }
        let answer = if start.is_some() && start == self.mismatch_at {
            json!({
                "verdict": "mismatch",
                "conflicts": [{"assertion": 1, "turns": [0]}],
                "reason": "the piece's bytes log no such reading",
            })
        } else {
            json!({
                "verdict": "supported",
                "conflicts": [],
                "reason": self.reason,
            })
        };
        let response = judge_reply(&answer);
        Box::pin(async move { Ok(response) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(LlmError::Fatal(FatalLlmError::Unsupported(
            UnsupportedCapability {
                capability: LlmCapability::Streaming,
                model: None,
                reason: None,
            },
        )))
    }
}

/// Each byte range the writer's piece calls read, `(start, end)`, in order,
/// and the length of the text they cut.
fn writer_pieces(fake: &FakeLlm) -> (Vec<(u64, u64)>, Option<u64>) {
    let mut pieces = Vec::new();
    let mut total = None;
    for seen in fake.seen() {
        let body = seen.body.to_string();
        let mut rest = body.as_str();
        while let Some(at) = rest.find("[bytes ") {
            rest = &rest[at + "[bytes ".len()..];
            let Some(end) = rest.find(PIECE_MARKER_END) else {
                break;
            };
            let parsed = rest[..end].split_once(" of ").and_then(|(range, of)| {
                let (start, end) = range.split_once("..")?;
                Some((start.parse().ok()?, end.parse().ok()?, of.parse().ok()?))
            });
            if let Some((start, end, of)) = parsed {
                if !pieces.contains(&(start, end)) {
                    pieces.push((start, end));
                }
                total = Some(of);
            }
        }
    }
    pieces.sort_unstable();
    (pieces, total)
}

/// The fake writer's reply, with `token` added to the summary of the piece
/// whose bytes start at 0.
fn reply_with_token_in_first_piece(token: String) -> impl Fn(&Value) -> String {
    move |body| {
        let answer = reply(body);
        let sent = body.to_string();
        if !(sent.contains("[bytes 0..") && sent.contains(PIECE_MARKER_END)) {
            return answer;
        }
        let Ok(mut answer) = serde_json::from_str::<Value>(&answer) else {
            return answer;
        };
        let summary = answer["summary"].as_str().unwrap_or_default().to_owned();
        answer["summary"] = Value::from(format!("{summary} The gauge's deploy key is {token}."));
        answer.to_string()
    }
}

/// What a pieced landing sets up beyond the owner's long turn.
#[derive(Default)]
struct Setup {
    /// The fake writer adds a GitHub token to the first piece's summary.
    token_in_first_piece: bool,
    /// The self agent's profile pins [`DEADLINE_PIN`], and the owner's long
    /// turn ends with it.
    deadline_pin: bool,
}

/// What [`pieced_landing`] leaves: the served vault whose self agent's chat
/// landed its own summary of the owner's long turn, read in pieces; the
/// agent; the owner; the landing's admitted check; the turn's window text
/// as the pieces cut it; the pieces; and a judge window that holds each part
/// but not the turn whole.
struct PiecedLanding {
    _dir: tempfile::TempDir,
    _prompts: tempfile::TempDir,
    server: Arc<SyncServer>,
    _host: AiHost,
    _fake: FakeLlm,
    agent: EntityId,
    owner: EntityId,
    check: DreamerAdmittedAttempt,
    window: String,
    pieces: Vec<(u64, u64)>,
    judge_window: u64,
}

/// The owner's long first turn lands its summary in pieces, and the check
/// its landing declared is admitted.
async fn pieced_landing() -> PiecedLanding {
    pieced_landing_with(Setup::default()).await
}

/// [`pieced_landing`] with what `setup` adds.
async fn pieced_landing_with(setup: Setup) -> PiecedLanding {
    let compute: Arc<dyn Fn(&Value) -> String + Send + Sync> = if setup.token_in_first_piece {
        Arc::new(reply_with_token_in_first_piece(provider_token()))
    } else {
        Arc::new(reply)
    };
    let fake = FakeLlm::start(Vec::new(), Some(Reply::Computed(compute))).await;
    let (dir, prompts, server, host) = self_row_server_on(
        &fake.base_url,
        oneiron::llm::SelfCompactionSource::RetainedTurns,
        WRITER_CONTEXT_TOKENS,
    )
    .await;
    let (agent, mut definition) = server
        .vault()
        .get_seeded_agent_definition_by_logical_id("sys.default")
        .unwrap()
        .expect("seeded default agent");
    if setup.deadline_pin {
        // The host's own profile made the agent's, as a definition with no
        // profile compacts by, with the one pin added.
        definition.version = format!("{}-deadline-pin", definition.version);
        definition.memory_profile = Some(
            MemoryProfile::new(
                1_500,
                ModelTierRef("self".to_owned()),
                CompactionOwnership::Engine,
            )
            .with_verbatim_pins(vec![DEADLINE_PIN.to_owned()]),
        );
        server
            .vault()
            .update_agent_definition(&agent, &definition, TimeRange { start: 1, end: 1 }, 1)
            .expect("the self agent's profile pins the deadline");
    }
    let conversation = EntityId::now().to_hex();
    let id = EntityId::from_hex(&conversation).unwrap();
    let (owner, _) = open_owner_sitting(&server);
    let mut words = long_turn();
    if setup.deadline_pin {
        words.push_str(&format!(" Note that {DEADLINE_PIN}."));
    }
    chat_text(&server, &conversation, &words).await;
    let reader = server.vault().memory(owner, oneiron::EdgeActorClass::Human);
    let history_lines = server.ai.chat_settings().history_turns;
    let mut turn = 0;
    let landed = loop {
        let landed = eventually(Duration::from_secs(20), || {
            oneiron::compaction::read_chat_log(&reader, id, 1, history_lines)
                .ok()
                .is_some_and(|log| !log.summaries.is_empty())
        })
        .await;
        if landed || turn == 3 {
            break landed;
        }
        let text = format!("Log the south jetty tide, turn {turn}.");
        chat_text(&server, &conversation, &text).await;
        turn += 1;
    };
    assert!(
        landed,
        "no summary landed; compaction calls: {:?}; owner's read: {}",
        compaction_calls_report(&fake),
        log_report(&server, owner, &conversation),
    );
    let window = format!("user: {words}");
    let (pieces, total) = writer_pieces(&fake);
    assert!(
        pieces.len() >= 2 && total == Some(window.len() as u64),
        "the writer read the owner's {}-byte turn in pieces, read {pieces:?} of {total:?}; \
         compaction calls: {:?}",
        window.len(),
        compaction_calls_report(&fake),
    );
    let ends: Vec<u64> = pieces.iter().map(|(_, end)| *end).collect();
    let starts: Vec<u64> = pieces.iter().map(|(start, _)| *start).collect();
    assert!(
        starts[0] == 0 && starts[1..] == ends[..ends.len() - 1] && ends.last() == total.as_ref(),
        "the pieces cover the turn in order: {pieces:?}"
    );
    // The judge input of the span whole runs past the turn's own words, and
    // each part runs well short of them.
    let judge_window = oneiron::count_context_pack_tokens(&words) as u64;
    route_extraction(server.vault());
    let store = DreamerRunnerStore::new(server.vault());
    let mut admitted_types = Vec::new();
    let check = loop {
        let outcome = store
            .admit_next_maintenance(AdmitDreamerAttempt {
                lease_owner: "compaction-check-per-chunk-test".to_owned(),
                now: vault_seconds(&server) + 1,
                budget_id: "wake".to_owned(),
                budget_total_units: 100_000,
                reserve_units: 100,
                started_milestone: None,
            })
            .unwrap();
        let DreamerAdmissionOutcome::Admitted(admitted) = outcome else {
            panic!(
                "no compaction check was declared; admitted {admitted_types:?}, then {outcome:?}"
            );
        };
        if admitted.status.payload.attempt_type == COMPACTION_CHECK_FACET {
            break *admitted;
        }
        admitted_types.push(admitted.status.payload.attempt_type.clone());
    };
    PiecedLanding {
        _dir: dir,
        _prompts: prompts,
        server,
        _host: host,
        _fake: fake,
        agent,
        owner,
        check,
        window,
        pieces,
        judge_window,
    }
}

/// The span's one turn's MESSAGE, as the admitted check's declaration names
/// it.
fn declared_message(check: &DreamerAdmittedAttempt) -> EntityId {
    let declaration = check
        .status
        .payload
        .input
        .as_map()
        .and_then(|entries| {
            entries
                .iter()
                .find(|(key, _)| key.as_str() == Some(CONVERSATION_DECLARATION_KEY))
        })
        .and_then(|(_, value)| value.as_str())
        .expect("the check carries its declaration");
    let declaration: Value = serde_json::from_str(declaration).unwrap();
    let message = declaration["turns"][0]["messages"][0]
        .as_str()
        .unwrap_or_else(|| panic!("the declared turn names its message: {declaration}"));
    EntityId::from_hex(message).unwrap()
}

/// Each judge input's span and the start of its evidence, for a failure's
/// report.
fn spans(inputs: &[Value]) -> Vec<String> {
    inputs
        .iter()
        .map(|input| {
            let evidence = input["evidence"].as_str().unwrap_or_default();
            let head: String = evidence.chars().take(60).collect();
            format!("{} {head:?}", input["span"])
        })
        .collect()
}

/// Whether `input` asks about exactly the bytes `start..end` of `window`:
/// its span names them, and its evidence is those bytes under their marker.
fn reads_exactly(input: &Value, window: &str, (start, end): (u64, u64)) -> bool {
    let bytes = &window[start as usize..end as usize];
    input["span"]["bytes"] == json!([start, end])
        && input["evidence"]
            .as_str()
            .and_then(|evidence| evidence.strip_suffix(bytes))
            .is_some_and(|marker| !marker.contains("Reading ") && marker.len() < 80)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_turn_read_in_pieces_is_judged_piece_by_piece_against_exactly_its_bytes() {
    let landed = pieced_landing().await;
    let judge = PartJudge::new(None);
    let execution = run_check(&landed.server, &landed.check, &judge, landed.judge_window).await;

    let inputs = judge.inputs();
    assert_eq!(
        inputs.len(),
        landed.pieces.len() + 1,
        "one judge call per piece, then one for the landed summary: {execution:?}; the judge \
         read {:?}",
        spans(&inputs),
    );
    for (input, piece) in inputs.iter().zip(&landed.pieces) {
        assert!(
            reads_exactly(input, &landed.window, *piece),
            "the judge reads piece {piece:?} and nothing else: {:?}",
            spans(std::slice::from_ref(input)),
        );
    }
    let entry = &inputs[landed.pieces.len()];
    assert_eq!(entry["span"], json!({"turns": 1}), "{entry}");
    assert!(
        entry["evidence"].as_str().is_some_and(|evidence| {
            evidence.contains(&format!("read in {} pieces", landed.pieces.len()))
                && !evidence.contains("Reading ")
        }),
        "the landed summary is judged against the entry its writer read, the piece summaries: \
         {entry}"
    );
    assert!(
        matches!(
            &execution,
            DreamerAttemptExecution::Completed { step_bindings, .. }
                if step_bindings.len() == inputs.len()
        ),
        "the check completes with each judge step booked once: {execution:?}"
    );
    let finding = finding(&landed.server, &landed.agent).expect("the check records its finding");
    assert_eq!(finding["verdict"], "supported", "{finding}");
    let pieces = finding["pieces"].as_array().cloned().unwrap_or_default();
    let judged: Vec<(Value, Value)> = pieces
        .iter()
        .map(|piece| (piece["bytes"].clone(), piece["verdict"].clone()))
        .collect();
    let expected: Vec<(Value, Value)> = landed
        .pieces
        .iter()
        .map(|(start, end)| (json!([start, end]), json!("supported")))
        .collect();
    assert_eq!(
        judged, expected,
        "the finding lists each piece judged: {finding}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_piece_its_bytes_do_not_support_decides_the_check_naming_its_bytes() {
    let landed = pieced_landing().await;
    let (start, end) = landed.pieces[1];
    let judge = PartJudge::new(Some(start));
    let execution = run_check(&landed.server, &landed.check, &judge, landed.judge_window).await;

    let inputs = judge.inputs();
    assert_eq!(
        inputs.len(),
        2,
        "the judge reads the first two pieces, and no part after the one it does not find \
         supported: {:?}",
        spans(&inputs),
    );
    assert!(
        reads_exactly(&inputs[1], &landed.window, (start, end)),
        "{:?}",
        spans(&inputs),
    );
    assert!(
        matches!(
            &execution,
            DreamerAttemptExecution::Completed { step_bindings, .. } if step_bindings.len() == 2
        ),
        "the check completes with both judge steps booked: {execution:?}"
    );
    let finding = finding(&landed.server, &landed.agent).expect("the check records its finding");
    assert_eq!(finding["verdict"], "mismatch", "{finding}");
    assert_eq!(
        finding["conflicts"][0]["bytes"],
        json!([start, end]),
        "the mismatch names the piece's bytes: {finding}"
    );
    assert_eq!(
        finding["conflicts"][0]["turns"].as_array().map(Vec::len),
        Some(1),
        "the conflict cites the span's one turn: {finding}"
    );
    let verdicts: Vec<Value> = finding["pieces"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|piece| piece["verdict"].clone())
        .collect();
    assert_eq!(
        verdicts,
        vec![json!("supported"), json!("mismatch")],
        "{finding}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handle_the_wall_puts_in_a_piece_summary_leaves_each_piece_judged() {
    let landed = pieced_landing_with(Setup {
        token_in_first_piece: true,
        ..Setup::default()
    })
    .await;
    let judge = PartJudge::new(None);
    let execution = run_check(&landed.server, &landed.check, &judge, landed.judge_window).await;

    let inputs = judge.inputs();
    let finding = finding(&landed.server, &landed.agent).expect("the check records its finding");
    assert_eq!(
        inputs.len(),
        landed.pieces.len() + 1,
        "each piece, then the landed summary, is judged although the kept entry holds a handle \
         where the first piece summary held the token: {execution:?}; the judge read {:?}; \
         finding {finding}",
        spans(&inputs),
    );
    let first = inputs[0]["summary"].as_str().unwrap_or_default();
    assert!(
        first.contains("[secret ") && !first.contains(&provider_token()),
        "the first piece summary is read back out of the kept entry, with the wall's handle in \
         place of the token: {first:?}"
    );
    for (input, piece) in inputs.iter().zip(&landed.pieces) {
        assert!(
            reads_exactly(input, &landed.window, *piece),
            "the judge reads piece {piece:?} and nothing else: {:?}",
            spans(std::slice::from_ref(input)),
        );
    }
    assert_eq!(finding["verdict"], "supported", "{finding}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pin_its_writer_copied_is_evidence_for_the_landed_summary() {
    let landed = pieced_landing_with(Setup {
        deadline_pin: true,
        ..Setup::default()
    })
    .await;
    let judge = PartJudge::new(None);
    let execution = run_check(&landed.server, &landed.check, &judge, landed.judge_window).await;

    let inputs = judge.inputs();
    assert_eq!(
        inputs.len(),
        landed.pieces.len() + 1,
        "{execution:?}; the judge read {:?}",
        spans(&inputs),
    );
    let entry = &inputs[landed.pieces.len()];
    assert!(
        entry["summary"]
            .as_str()
            .is_some_and(|summary| summary.contains(DEADLINE_PIN)),
        "the landed summary copies the pin its writer was given: {entry}"
    );
    assert!(
        entry["evidence"].as_str().is_some_and(|evidence| {
            evidence.contains(&format!("read in {} pieces", landed.pieces.len()))
                && evidence.contains(DEADLINE_PIN)
        }),
        "the landed summary is judged against the entry and the pin its writer was given, \
         which the turn holds word for word: {entry}"
    );
    let finding = finding(&landed.server, &landed.agent).expect("the check records its finding");
    assert_eq!(finding["verdict"], "supported", "{finding}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_source_deleted_while_a_piece_is_judged_sends_no_later_piece() {
    let landed = pieced_landing().await;
    let message = declared_message(&landed.check);
    let (server, owner) = (Arc::clone(&landed.server), landed.owner);
    let judge = PartJudge::on_first(move || {
        server
            .vault()
            .memory(owner, EdgeActorClass::Human)
            .safe_delete(&message.to_hex(), SafeDeleteReason::UserDelete)
            .expect("the owner deletes the turn's message");
    });
    let execution = run_check(&landed.server, &landed.check, &judge, landed.judge_window).await;

    let inputs = judge.inputs();
    let finding = finding(&landed.server, &landed.agent).expect("the check records its finding");
    assert_eq!(
        inputs.len(),
        1,
        "the first piece goes out before the delete, and no part after it: {execution:?}; the \
         judge read {:?}; finding {finding}",
        spans(&inputs),
    );
    assert!(
        reads_exactly(&inputs[0], &landed.window, landed.pieces[0]),
        "{:?}",
        spans(&inputs),
    );
    assert_ne!(
        finding["verdict"], "supported",
        "a check whose source went away mid-judgment is not supported: {finding}"
    );
    assert!(
        matches!(
            &execution,
            DreamerAttemptExecution::Completed { step_bindings, .. } if step_bindings.len() == 1
        ),
        "the check completes with the one judge step booked: {execution:?}"
    );
}

/// A judge that deletes the owner's MESSAGE, the span's one source, as the
/// first request comes in, and finds each part supported for `reason`.
fn deleting_judge(landed: &PiecedLanding, reason: &'static str) -> PartJudge {
    let message = declared_message(&landed.check);
    let (server, owner) = (Arc::clone(&landed.server), landed.owner);
    PartJudge::on_first(move || {
        server
            .vault()
            .memory(owner, EdgeActorClass::Human)
            .safe_delete(&message.to_hex(), SafeDeleteReason::UserDelete)
            .expect("the owner deletes the turn's message");
    })
    .reasoning(reason)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_judgment_of_a_source_deleted_mid_check_is_not_kept_in_its_finding() {
    let landed = pieced_landing().await;
    let judge = deleting_judge(&landed, QUOTING_REASON);
    let execution = run_check(&landed.server, &landed.check, &judge, landed.judge_window).await;

    let inputs = judge.inputs();
    let finding = finding(&landed.server, &landed.agent).expect("the check records its finding");
    assert_eq!(
        inputs.len(),
        1,
        "the first piece goes out before the delete, and no part after it: {execution:?}; the \
         judge read {:?}; finding {finding}",
        spans(&inputs),
    );
    assert_ne!(
        finding["verdict"], "supported",
        "a check whose source went away mid-judgment is not supported: {finding}"
    );
    assert!(
        finding.get("pieces").is_none() && !finding.to_string().contains(QUOTING_REASON),
        "a finding its last read stopped keeps no judgment of the deleted text: {finding}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_source_deleted_while_a_piece_is_diagnosed_sends_no_typed_read_of_it() {
    let landed = pieced_landing().await;
    let decisions = DecisionHost::new(landed.server.vault());
    let judge = deleting_judge(&landed, SUPPORTED_REASON);
    let execution = run_check_lent(
        &landed.server,
        &landed.check,
        &judge,
        None,
        Some(&decisions),
    )
    .await;

    let inputs = judge.inputs();
    let finding = finding(&landed.server, &landed.agent).expect("the check records its finding");
    assert_eq!(
        inputs.len(),
        1,
        "the first piece's diagnostic goes out before the delete, and neither its typed read nor \
         a later part goes out: {execution:?}; the judge read {:?}; finding {finding}",
        spans(&inputs),
    );
    assert!(
        reads_exactly(&inputs[0], &landed.window, landed.pieces[0]),
        "{:?}",
        spans(&inputs),
    );
    assert_ne!(
        finding["verdict"], "supported",
        "a check whose source went away mid-judgment is not supported: {finding}"
    );
}
