//! HOUSE-SCHEMA-CHECK stage 2: the nightly answer-schema check. TURN extraction calls
//! built with the schema are captured once; an erase of a source row drops its capture; the
//! draw is stable for a night, takes at most eight, and skips unreadable sources; the shadow
//! arm drops the schema and its own-server entry while both arms carry one seed; two grammar
//! faults in one night suspend at once while one keeps; the seven-night window suspends only
//! past thirty pairs with its upper bound below zero; each arm scores F1 against the pooled
//! supported candidates; a night over budget skips with its reason; a second run returns its
//! receipt; the check retires the night's captures; and a night whose schema replies break
//! suspends with the digest saying so. Review round 1 of #10538 added: an unsupported claim
//! costs its arm precision (P1-6); a night over budget skips while an extraction stays open
//! (P1-4); a schema arm the server refuses is a grammar fault, its shadow still sent (P1-5);
//! a capture whose source was erased before its write keeps nothing (P1-2). Round 2 added:
//! a capture whose world now stays off the house rung's destination sends nothing there; an
//! erase of a capture's second row takes the reply of a check call already made from it; a
//! case-variant repeat of a supported claim still costs its arm precision.
//! Reaches the engine through `oneiron::test_doors::dreamer_answer_schema`, built only
//! under `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::Mutex;

use oneiron::attempt_queue::AttemptId;
use oneiron::authority::{ActSurface, PeerMachine, ReadLocation, WorldPrivacy};
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::OWN_SERVER_ONLY_PARAM;
use oneiron::setting::{SetSetting, SettingCaller};
use oneiron::settings::ReadDestination;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::dreamer_answer_schema as door;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, ContentPart, DreamerAttemptExecution,
    EntityId, FinishReason, LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest,
    LlmResponse, LlmStreamResult, LlmUsage, ModelId, Vault,
};
use serde_json::{Value, json};

const ANSWER_SCHEMA: &str = "dreamer.extraction.answer_schema";
const T0: u64 = 1_790_000_000;
const DAY: u64 = 86_400;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = open_dreamer_vault(dir.path(), "test-reader").expect("dreamer vault");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _dir: dir,
            owner_proof,
        }
    }

    fn set_as_owner(&self, key: &str, value: Value) -> oneiron::Result<()> {
        self.vault
            .set_setting(
                SettingCaller::Owner(&self.owner_proof),
                SetSetting::vault_value(key, value),
            )
            .map(|_| ())
    }
}

/// Polls a scripted run to settlement: the scripted backend answers without I/O.
fn ready<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    for _ in 0..1_000_000 {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(output) => return output,
            std::task::Poll::Pending => {}
        }
    }
    panic!("MODEL: the scripted run never settled");
}

/// A scripted house: schema arms answer `schema`, shadow arms `shadow`, and judge turns
/// answer all-true lists of the presented lengths. Counts every call.
struct ScriptBackend {
    schema: String,
    shadow: String,
    calls: Mutex<u32>,
}

/// A house whose schema arms the server refuses, as it answers a schema its grammar cannot
/// compile (HTTP 400), while shadow arms and judge turns answer as [`ScriptBackend`]'s.
struct RefusingSchemaBackend {
    script: ScriptBackend,
}

impl LlmBackend for RefusingSchemaBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        if !is_judge(&request) && request.params.contains_key("answer_schema") {
            *self.script.calls.lock().unwrap() += 1;
            return Box::pin(async {
                Err(oneiron::LlmError::Fatal(
                    oneiron::FatalLlmError::InvalidRequest,
                ))
            });
        }
        self.script.generate(request, lease)
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.script.stream(request, lease)
    }
}

/// A house whose shadow arms fail fatally, so the check stops at its first pair's shadow
/// with the schema arm's reply kept, while schema arms and judge turns answer as
/// [`ScriptBackend`]'s.
struct RefusingShadowBackend {
    script: ScriptBackend,
}

impl LlmBackend for RefusingShadowBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        if !is_judge(&request) && !request.params.contains_key("answer_schema") {
            *self.script.calls.lock().unwrap() += 1;
            return Box::pin(async {
                Err(oneiron::LlmError::Fatal(
                    oneiron::FatalLlmError::InvalidRequest,
                ))
            });
        }
        self.script.generate(request, lease)
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.script.stream(request, lease)
    }
}

impl ScriptBackend {
    fn calls(&self) -> u32 {
        *self.calls.lock().unwrap()
    }
}

/// Whether the call is a judge turn: its user text presents List 1.
fn is_judge(request: &LlmRequest) -> bool {
    request.messages.iter().any(|message| {
        message.role == LlmMessageRole::User
            && message.content.iter().any(|part| match part {
                ContentPart::Text { text, .. } => text.contains("List 1:"),
                _ => false,
            })
    })
}

/// All-true judge answers for the lists the user turn presents.
fn judge_all_true(user: &str) -> String {
    let len = |marker: &str| {
        user.split(marker)
            .nth(1)
            .and_then(|rest| {
                let line = rest.trim_start().lines().next()?;
                serde_json::from_str::<Value>(line)
                    .ok()
                    .and_then(|value| value.as_array().map(Vec::len))
            })
            .unwrap_or(0)
    };
    json!({
        "list1": vec![true; len("\nList 1:\n")],
        "list2": vec![true; len("\nList 2:\n")],
    })
    .to_string()
}

impl LlmBackend for ScriptBackend {
    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        *self.calls.lock().unwrap() += 1;
        let text = if is_judge(&request) {
            let user = request
                .messages
                .iter()
                .rev()
                .filter(|message| message.role == LlmMessageRole::User)
                .flat_map(|message| message.content.iter())
                .filter_map(|part| match part {
                    ContentPart::Text { text, .. } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<String>();
            judge_all_true(&user)
        } else if request.params.contains_key("answer_schema") {
            self.schema.clone()
        } else {
            self.shadow.clone()
        };
        Box::pin(async move {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text,
                        signature: None,
                    }],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
                reply_assertions: Default::default(),
                token_scores: None,
            })
        })
    }

    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(oneiron::LlmError::Fatal(
            oneiron::FatalLlmError::InvalidRequest,
        ))
    }
}

fn house_guard() -> BudgetGuard {
    BudgetGuard::with_reserve_units(
        "test-answer-schema-check",
        100_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    )
}

fn house_model() -> ModelId {
    ModelId::new("test/house@1").unwrap()
}

/// One whole extraction reply: a single candidate that meets the contract.
fn whole_reply() -> String {
    json!({"candidates": [{
        "subject": "P1",
        "predicate": "profile.name",
        "value": "owen",
        "confidence": 0.8,
        "evidence_refs": [{"source": "T1", "quote": "owen is here"}],
    }]})
    .to_string()
}

#[test]
fn a_turn_call_in_force_is_captured_once() {
    let fixture = Fixture::new();
    let vault = &fixture.vault;
    assert!(
        door::in_force(vault).expect("in-force reads"),
        "the switch ships in force"
    );
    let night = door::plant_night(vault).expect("night");
    let child = door::plant_child(vault, night).expect("child");
    let turn = door::plant_turn(vault, "owen is here").expect("turn");
    assert!(
        door::capture_if_in_force(vault, child, "owen is here", &[turn], T0).expect("capture"),
        "the first call writes"
    );
    assert!(
        !door::capture_if_in_force(vault, child, "owen is here", &[turn], T0)
            .expect("capture again"),
        "a memo hit writes nothing new"
    );
    assert_eq!(
        door::capture_count(vault).expect("count"),
        1,
        "captured once"
    );
    assert_eq!(
        door::captures_for_night(vault, night).expect("night count"),
        1,
        "under its night"
    );
}

#[test]
fn a_call_out_of_force_is_not_captured() {
    let fixture = Fixture::new();
    fixture
        .set_as_owner(ANSWER_SCHEMA, json!(false))
        .expect("owner turns it off");
    assert!(
        !door::in_force(&fixture.vault).expect("in-force reads"),
        "out of force"
    );
    let night = door::plant_night(&fixture.vault).expect("night");
    let child = door::plant_child(&fixture.vault, night).expect("child");
    let turn = door::plant_turn(&fixture.vault, "owen is here").expect("turn");
    assert!(
        !door::capture_if_in_force(&fixture.vault, child, "owen is here", &[turn], T0)
            .expect("capture"),
        "out of force writes nothing"
    );
    assert_eq!(
        door::capture_count(&fixture.vault).expect("count"),
        0,
        "no capture"
    );
}

#[test]
fn erasing_a_source_row_drops_its_capture() {
    let fixture = Fixture::new();
    let vault = &fixture.vault;
    let night = door::plant_night(vault).expect("night");
    let child = door::plant_child(vault, night).expect("child");
    let turn = door::plant_turn(vault, "owen is here").expect("turn");
    door::plant_capture(vault, child, &[turn], "owen is here", T0).expect("capture");
    assert_eq!(door::capture_count(vault).expect("count"), 1);
    assert!(
        vault.delete_entity(&turn).expect("delete"),
        "the turn existed"
    );
    assert_eq!(
        door::capture_count(vault).expect("count after"),
        0,
        "the erase dropped its capture"
    );
}

#[test]
fn the_draw_is_the_same_for_a_night_and_takes_at_most_eight() {
    let fixture = Fixture::new();
    let vault = &fixture.vault;
    let night = door::plant_night(vault).expect("night");
    let children: Vec<AttemptId> = (0..3)
        .map(|_| door::plant_child(vault, night).expect("child"))
        .collect();
    for index in 0..10 {
        let words = format!("turn {index} words");
        let turn = door::plant_turn(vault, &words).expect("turn");
        door::plant_capture(vault, children[index % 3], &[turn], &words, T0).expect("capture");
    }
    let first = door::draw(vault, night).expect("draw");
    let second = door::draw(vault, night).expect("draw again");
    assert_eq!(first, second, "the draw is stable for a night");
    assert_eq!(first.len(), 8, "at most eight");
}

#[test]
fn the_draw_skips_a_capture_whose_source_no_longer_reads() {
    let fixture = Fixture::new();
    let vault = &fixture.vault;
    let night = door::plant_night(vault).expect("night");
    let child = door::plant_child(vault, night).expect("child");
    let live = door::plant_turn(vault, "live words").expect("turn");
    // No row: reads nothing, as an erased source does.
    let gone = EntityId::now();
    let live_step =
        door::plant_capture(vault, child, &[live], "live words", T0).expect("live capture");
    door::plant_capture(vault, child, &[gone], "gone words", T0).expect("gone capture");
    assert_eq!(
        door::draw(vault, night).expect("draw"),
        vec![(child, live_step)],
        "only the readable capture draws"
    );
}

#[test]
fn the_shadow_arm_drops_the_schema_and_its_own_server_entry_and_both_carry_one_seed() {
    let (schema, shadow) = door::pair_arms("turn words", 7).expect("arms");
    assert!(
        schema.contains_key("answer_schema"),
        "arm S carries the schema"
    );
    assert_eq!(
        schema.get("seed"),
        Some(&json!(7)),
        "arm S carries the seed"
    );
    assert!(
        !shadow.contains_key("answer_schema"),
        "arm N drops the schema"
    );
    assert_eq!(shadow.get("seed"), Some(&json!(7)), "both carry one seed");
    let only = |params: &BTreeMap<String, Value>| {
        params
            .get(OWN_SERVER_ONLY_PARAM)
            .and_then(Value::as_array)
            .expect("own-server-only list")
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert!(
        only(&schema).contains(&"answer_schema".to_owned()),
        "arm S lists the schema own-server-only"
    );
    assert!(
        !only(&shadow).contains(&"answer_schema".to_owned()),
        "arm N drops its own-server entry"
    );
    for (key, value) in &schema {
        if key == "answer_schema" || key == OWN_SERVER_ONLY_PARAM {
            continue;
        }
        assert_eq!(shadow.get(key), Some(value), "arm N keeps {key}");
    }
}

#[test]
fn two_grammar_faults_in_one_night_suspend_at_once() {
    assert_eq!(
        door::grammar_suspends(&[(false, true), (false, true)], "2026-11-22"),
        Some(("2026-11-22".to_owned(), 2)),
        "two faults suspend at once"
    );
}

#[test]
fn one_grammar_fault_keeps() {
    assert_eq!(
        door::grammar_suspends(&[(false, true), (true, true)], "2026-11-22"),
        None,
        "one fault keeps"
    );
    assert_eq!(
        door::grammar_suspends(&[(false, false), (true, false)], "2026-11-22"),
        None,
        "a shadow that breaks too is no grammar fault"
    );
}

#[test]
fn a_window_under_30_pairs_keeps() {
    let night = AttemptId::from_bytes(&[7; 16]).expect("test night");
    let diffs = [(0.0, 0.5); 29];
    assert_eq!(
        door::window_stats(&diffs, night, 4),
        None,
        "fewer than thirty pairs keeps"
    );
}

#[test]
fn a_window_lower_with_its_upper_bound_below_zero_suspends() {
    let night = AttemptId::from_bytes(&[7; 16]).expect("test night");
    // Every pair lower by the same margin: every resample lands there too.
    let diffs = [(0.0, 0.5); 30];
    let stats = door::window_stats(&diffs, night, 4).expect("thirty pairs evaluate");
    assert_eq!(stats.n, 30);
    assert_eq!(stats.nights, 4);
    assert!(stats.d < 0.0, "lower on average: d={}", stats.d);
    assert!(
        stats.upper < 0.0,
        "upper bound below zero: upper={}",
        stats.upper
    );
    assert!(door::window_suspends(&stats), "suspends");
}

#[test]
fn a_window_lower_on_average_whose_upper_bound_reaches_zero_keeps() {
    let night = AttemptId::from_bytes(&[7; 16]).expect("test night");
    let mut diffs = [(0.0, 1.0); 30];
    for (schema, shadow) in diffs.iter_mut().skip(15) {
        *schema = 0.9;
        *shadow = 0.0;
    }
    let stats = door::window_stats(&diffs, night, 4).expect("thirty pairs evaluate");
    assert!(stats.d < 0.0, "lower on average: d={}", stats.d);
    assert!(
        stats.upper >= 0.0,
        "upper bound reaches zero: upper={}",
        stats.upper
    );
    assert!(!door::window_suspends(&stats), "keeps");
}

#[test]
fn f1_scores_each_arm_against_the_pooled_supported_candidates() {
    let schema = [
        json!({"subject": "P1", "predicate": "name", "value": "Owen", "quote": "owen"}),
        json!({"subject": "P1", "predicate": "nick", "value": "O", "quote": "o"}),
    ];
    // The same nick candidate, spaced and cased differently: one gold key.
    let shadow = [json!({"subject": " p1 ", "predicate": "nick", "value": " o ", "quote": "o"})];
    // Seed 8 is even: order 1 reads List 1 as arm S, List 2 as arm N; order 2 swaps.
    let (schema_f1, shadow_f1) = door::f1(
        &schema,
        &shadow,
        8,
        (&[true, true], &[true]),
        (&[true], &[true, true]),
    );
    assert_eq!(schema_f1, Some(1.0), "arm S takes the whole gold");
    let shadow_f1 = shadow_f1.expect("shadow quality");
    assert!(
        (shadow_f1 - 2.0 / 3.0).abs() < 1e-9,
        "arm N takes half the gold: F1 2/3, got {shadow_f1}"
    );
}

#[test]
fn a_night_over_budget_skips_with_its_reason() {
    let fixture = Fixture::new();
    let vault = &fixture.vault;
    let night = door::plant_night(vault).expect("night");
    door::plant_overrun(vault, night).expect("latch");
    let backend = ScriptBackend {
        schema: "unused".to_owned(),
        shadow: "unused".to_owned(),
        calls: Mutex::new(0),
    };
    let guard = house_guard();
    let (receipt, outcome) = ready(door::run_check(
        vault,
        night,
        &backend,
        &guard,
        house_model(),
        T0,
    ))
    .expect("run");
    assert!(
        matches!(outcome, DreamerAttemptExecution::Completed { .. }),
        "a skip completes: {outcome:?}"
    );
    assert_eq!(receipt.action, "skip");
    assert_eq!(receipt.reason.as_deref(), Some("over_budget"));
    assert_eq!(receipt.pairs, 0);
    assert_eq!(backend.calls(), 0, "no house call");
    let line = &receipt.line;
    assert!(
        line.contains("action=skip reason=over_budget"),
        "line: {line}"
    );
}

#[test]
fn a_night_with_no_house_rung_skips_with_its_reason() {
    let fixture = Fixture::new();
    let vault = &fixture.vault;
    let night = door::plant_night(vault).expect("night");
    let child = door::plant_child(vault, night).expect("child");
    let turn = door::plant_turn(vault, "owen is here").expect("turn");
    door::plant_capture(vault, child, &[turn], "owen is here", T0).expect("capture");
    let (receipt, outcome) = ready(door::run_check_no_house(vault, night, T0)).expect("run");
    assert!(
        matches!(outcome, DreamerAttemptExecution::Completed { .. }),
        "a skip completes: {outcome:?}"
    );
    assert_eq!(receipt.action, "skip");
    assert_eq!(receipt.reason.as_deref(), Some("no_house_rung"));
    assert_eq!(receipt.pairs, 0);
    assert_eq!(
        receipt.selection, 1,
        "the pool drew before the house missed"
    );
    assert_eq!(
        door::capture_count(vault).expect("count"),
        0,
        "a skip retires the sample too"
    );
    let line = &receipt.line;
    assert!(
        line.contains("action=skip reason=no_house_rung"),
        "line: {line}"
    );
}

#[test]
fn a_second_run_of_a_night_returns_its_receipt() {
    let fixture = Fixture::new();
    let vault = &fixture.vault;
    let night = door::plant_night(vault).expect("night");
    let child = door::plant_child(vault, night).expect("child");
    let turn = door::plant_turn(vault, "owen is here").expect("turn");
    door::plant_capture(vault, child, &[turn], "owen is here", T0).expect("capture");
    let backend = ScriptBackend {
        schema: whole_reply(),
        shadow: whole_reply(),
        calls: Mutex::new(0),
    };
    let guard = house_guard();
    let (first, outcome) = ready(door::run_check(
        vault,
        night,
        &backend,
        &guard,
        house_model(),
        T0,
    ))
    .expect("run");
    assert!(
        matches!(outcome, DreamerAttemptExecution::Completed { .. }),
        "the run completes: {outcome:?}"
    );
    assert_eq!(first.action, "keep");
    assert_eq!(first.pairs, 1);
    let line = &first.line;
    assert!(
        line.contains(
            "pairs=1 fault schema=0 shadow=0 quality schema=1.00 shadow=1.00 action=keep"
        ),
        "line: {line}"
    );
    let rows = door::pairs(vault, night).expect("pair rows");
    assert_eq!(rows.len(), 1, "one pair row");
    assert_eq!(rows[0].schema_candidates, 1, "the schema reply decoded one");
    assert_eq!(rows[0].shadow_candidates, 1, "the shadow reply decoded one");
    assert_eq!(backend.calls(), 4, "two arms and two judge turns");
    let (second, outcome) = ready(door::run_check(
        vault,
        night,
        &backend,
        &guard,
        house_model(),
        T0,
    ))
    .expect("second run");
    assert!(
        matches!(outcome, DreamerAttemptExecution::Completed { .. }),
        "the second run completes: {outcome:?}"
    );
    assert_eq!(second, first, "the second run returns its receipt");
    assert_eq!(backend.calls(), 4, "no second call");
}

#[test]
fn the_check_retires_the_nights_captures() {
    let fixture = Fixture::new();
    let vault = &fixture.vault;
    let night = door::plant_night(vault).expect("night");
    let child = door::plant_child(vault, night).expect("child");
    let turn = door::plant_turn(vault, "owen is here").expect("turn");
    door::plant_capture(vault, child, &[turn], "owen is here", T0).expect("capture");
    let other = door::plant_night(vault).expect("other night");
    let other_child = door::plant_child(vault, other).expect("other child");
    let other_turn = door::plant_turn(vault, "other words").expect("other turn");
    door::plant_capture(vault, other_child, &[other_turn], "other words", T0)
        .expect("other capture");
    door::plant_capture(
        vault,
        other_child,
        &[other_turn],
        "stale words",
        T0 - 9 * DAY,
    )
    .expect("stale capture");
    assert_eq!(door::captures_for_night(vault, night).expect("n"), 1);
    assert_eq!(door::captures_for_night(vault, other).expect("o"), 2);
    let backend = ScriptBackend {
        schema: whole_reply(),
        shadow: whole_reply(),
        calls: Mutex::new(0),
    };
    let guard = house_guard();
    let (receipt, _) = ready(door::run_check(
        vault,
        night,
        &backend,
        &guard,
        house_model(),
        T0,
    ))
    .expect("run");
    assert_eq!(receipt.action, "keep");
    assert_eq!(
        door::captures_for_night(vault, night).expect("n after"),
        0,
        "the night's captures retire"
    );
    assert_eq!(
        door::captures_for_night(vault, other).expect("o after"),
        1,
        "another night's fresh capture stays while its stale one goes"
    );
}

#[test]
fn a_night_whose_schema_replies_break_suspends_and_the_digest_says_so() {
    let fixture = Fixture::new();
    let vault = &fixture.vault;
    let night = door::plant_night(vault).expect("night");
    for index in 0..2 {
        let child = door::plant_child(vault, night).expect("child");
        let words = format!("turn {index} names owen");
        let turn = door::plant_turn(vault, &words).expect("turn");
        door::plant_capture(vault, child, &[turn], &words, T0).expect("capture");
    }
    let backend = ScriptBackend {
        schema: "definitely not json".to_owned(),
        shadow: whole_reply(),
        calls: Mutex::new(0),
    };
    let guard = house_guard();
    let (receipt, outcome) = ready(door::run_check(
        vault,
        night,
        &backend,
        &guard,
        house_model(),
        T0,
    ))
    .expect("run");
    assert!(
        matches!(outcome, DreamerAttemptExecution::Completed { .. }),
        "the run completes: {outcome:?}"
    );
    assert_eq!(receipt.action, "suspend");
    assert_eq!(receipt.pairs, 2);
    assert_eq!(
        backend.calls(),
        8,
        "both arms re-sent per pair, judged twice"
    );
    let event = receipt.event.expect("receipt id");
    assert_eq!(
        door::hold(vault).expect("hold"),
        Some(event),
        "the hold carries the receipt id"
    );
    let line = &receipt.line;
    let suspended = format!("action=suspend receipt={}", event.to_hex());
    assert!(line.contains(&suspended), "line: {line}");
    let view = vault
        .proactivity_digest(&fixture.owner_proof, T0, None)
        .expect("digest assembles")
        .expect("digest due");
    let line = view.answer_schema.expect("answer-schema line");
    assert_eq!(line.items.len(), 1);
    assert_eq!(line.items[0].event, event.to_hex());
    assert_eq!(line.items[0].kind, "paused");
    let summary = &line.items[0].summary;
    assert!(
        summary.contains("did not come back whole"),
        "summary: {summary}"
    );
}

#[test]
fn an_unsupported_claim_costs_its_arm_precision() {
    // Arm S gives the supported name and an unsupported nick; arm N gives the name alone.
    let schema = [
        json!({"subject": "P1", "predicate": "name", "value": "Owen", "quote": "owen"}),
        json!({"subject": "P1", "predicate": "nick", "value": "O", "quote": "o"}),
    ];
    let shadow = [json!({"subject": "P1", "predicate": "name", "value": "Owen", "quote": "owen"})];
    // Seed 8 is even: order 1 reads List 1 as arm S, List 2 as arm N; order 2 swaps. Both
    // orders find the nick unsupported.
    let (schema_f1, shadow_f1) = door::f1(
        &schema,
        &shadow,
        8,
        (&[true, false], &[true]),
        (&[true], &[true, false]),
    );
    let schema_f1 = schema_f1.expect("schema quality");
    assert!(
        (schema_f1 - 2.0 / 3.0).abs() < 1e-9,
        "arm S: precision 1/2, recall 1: F1 2/3, got {schema_f1}"
    );
    assert_eq!(shadow_f1, Some(1.0), "arm N gave only the supported claim");
}

#[test]
fn a_night_over_budget_skips_while_an_extraction_stays_open() {
    let fixture = Fixture::new();
    let vault = &fixture.vault;
    let night = door::plant_night(vault).expect("night");
    door::plant_open_child(vault, night).expect("open child");
    door::plant_overrun(vault, night).expect("latch");
    let backend = ScriptBackend {
        schema: "unused".to_owned(),
        shadow: "unused".to_owned(),
        calls: Mutex::new(0),
    };
    let guard = house_guard();
    let (receipt, outcome) = ready(door::run_check(
        vault,
        night,
        &backend,
        &guard,
        house_model(),
        T0,
    ))
    .expect("run");
    assert!(
        matches!(outcome, DreamerAttemptExecution::Completed { .. }),
        "the latched night skips at once, the open child no gate: {outcome:?}"
    );
    assert_eq!(receipt.action, "skip");
    assert_eq!(receipt.reason.as_deref(), Some("over_budget"));
    assert_eq!(backend.calls(), 0, "no house call");
}

#[test]
fn a_schema_arm_the_server_refuses_is_a_grammar_fault() {
    let fixture = Fixture::new();
    let vault = &fixture.vault;
    let night = door::plant_night(vault).expect("night");
    for index in 0..2 {
        let child = door::plant_child(vault, night).expect("child");
        let words = format!("turn {index} names owen");
        let turn = door::plant_turn(vault, &words).expect("turn");
        door::plant_capture(vault, child, &[turn], &words, T0).expect("capture");
    }
    let backend = RefusingSchemaBackend {
        script: ScriptBackend {
            schema: "unused".to_owned(),
            shadow: whole_reply(),
            calls: Mutex::new(0),
        },
    };
    let guard = house_guard();
    let (receipt, outcome) = ready(door::run_check(
        vault,
        night,
        &backend,
        &guard,
        house_model(),
        T0,
    ))
    .expect("run");
    assert!(
        matches!(outcome, DreamerAttemptExecution::Completed { .. }),
        "a refused schema arm is an answer of the pair, not a park: {outcome:?}"
    );
    assert_eq!(receipt.action, "suspend", "two grammar faults in one night");
    assert_eq!(receipt.pairs, 2);
    let pairs = door::pairs(vault, night).expect("pairs");
    assert!(
        pairs
            .iter()
            .all(|pair| !pair.schema_whole && pair.shadow_whole),
        "each refused schema arm came back not whole beside a whole shadow: {pairs:?}"
    );
    assert!(
        backend.script.calls() >= 4,
        "each pair sent its shadow arm after the refused schema arm"
    );
}

#[test]
fn a_capture_whose_source_was_erased_first_keeps_nothing() {
    let fixture = Fixture::new();
    let vault = &fixture.vault;
    let night = door::plant_night(vault).expect("night");
    let child = door::plant_child(vault, night).expect("child");
    let turn = door::plant_turn(vault, "owen is here").expect("turn");
    assert!(
        vault.delete_entity(&turn).expect("delete"),
        "the turn existed"
    );
    door::capture_if_in_force(vault, child, "owen is here", &[turn], T0).expect("capture");
    assert_eq!(
        door::capture_count(vault).expect("count"),
        0,
        "the erased turn's words are not stored again"
    );
}

#[test]
fn a_capture_whose_world_now_stays_on_the_device_sends_nothing_off_it() {
    let fixture = Fixture::new();
    let vault = &fixture.vault;
    let night = door::plant_night(vault).expect("night");
    let child = door::plant_child(vault, night).expect("child");
    let turn = door::plant_turn(vault, "owen is here").expect("turn");
    door::plant_capture(vault, child, &[turn], "owen is here", T0).expect("capture");
    // The house rung's offer sends to a machine nobody proved.
    let toward = ReadDestination::toward(PeerMachine::Unknown);
    assert!(
        vault
            .model_call_may_leave_for(None, &toward)
            .expect("judge"),
        "FIXTURE: no world stays on the device when the call is captured"
    );
    let world = vault
        .create_world(&fixture.owner_proof, "Kept here", vault.now_recorded_at())
        .expect("world");
    vault
        .set_world_privacy_as(
            &fixture.owner_proof,
            ActSurface::ThisInstall,
            world,
            WorldPrivacy {
                read: ReadLocation::MyMachines,
                ..WorldPrivacy::default()
            },
            None,
        )
        .expect("the owner keeps the world on the owner's machines");
    assert!(
        !vault
            .model_call_may_leave_for(None, &toward)
            .expect("judge"),
        "FIXTURE: a call that names no world now stays off a machine nobody proved"
    );
    let backend = ScriptBackend {
        schema: whole_reply(),
        shadow: whole_reply(),
        calls: Mutex::new(0),
    };
    let guard = house_guard();
    let (receipt, _) = ready(door::run_check_toward(
        vault,
        night,
        &backend,
        &guard,
        house_model(),
        toward,
        T0,
    ))
    .expect("run");
    assert_eq!(
        backend.calls(),
        0,
        "no call went to the house rung's machine"
    );
    assert_eq!(receipt.pairs, 0, "the capture's pair dropped");
}

#[test]
fn an_erase_of_a_captures_second_row_takes_its_check_replies() {
    let fixture = Fixture::new();
    let vault = &fixture.vault;
    let night = door::plant_night(vault).expect("night");
    let child = door::plant_child(vault, night).expect("child");
    let first = door::plant_turn(vault, "owen is here").expect("first turn");
    let second = door::plant_turn(vault, "owen moved to kyoto").expect("second turn");
    let words = "owen is here\nowen moved to kyoto";
    door::plant_capture(vault, child, &[first, second], words, T0).expect("capture");
    let backend = RefusingShadowBackend {
        script: ScriptBackend {
            schema: whole_reply(),
            shadow: "unused".to_owned(),
            calls: Mutex::new(0),
        },
    };
    let guard = house_guard();
    let outcome = ready(door::run_check_outcome(
        vault,
        night,
        &backend,
        &guard,
        house_model(),
        T0,
    ))
    .expect("run");
    assert!(
        !matches!(outcome, DreamerAttemptExecution::Completed { .. }),
        "the failed shadow arm stops the check before it lands: {outcome:?}"
    );
    assert!(
        door::check_replies_kept(vault, night).expect("kept") >= 1,
        "the schema arm's reply is kept while the check waits"
    );
    assert!(
        vault.delete_entity(&second).expect("delete"),
        "the second turn existed"
    );
    assert_eq!(
        door::check_replies_kept(vault, night).expect("kept after"),
        0,
        "the erase of the capture's second row took the reply quoting it"
    );
}

#[test]
fn a_case_variant_repeat_of_a_supported_claim_costs_its_arm_precision() {
    // Arm S gives the exact path /Work and a wrong /work, arm N /Work alone; both judge
    // orders reject /work. The two share one gold key, yet each emitted candidate counts.
    let schema = [
        json!({"subject": "P1", "predicate": "file.path", "value": "/Work", "quote": "/Work"}),
        json!({"subject": "P1", "predicate": "file.path", "value": "/work", "quote": "/Work"}),
    ];
    let shadow =
        [json!({"subject": "P1", "predicate": "file.path", "value": "/Work", "quote": "/Work"})];
    let (schema_f1, shadow_f1) = door::f1(
        &schema,
        &shadow,
        8,
        (&[true, false], &[true]),
        (&[true], &[true, false]),
    );
    let schema_f1 = schema_f1.expect("schema quality");
    assert!(
        (schema_f1 - 2.0 / 3.0).abs() < 1e-9,
        "arm S: precision 1/2, recall 1: F1 2/3, got {schema_f1}"
    );
    assert_eq!(shadow_f1, Some(1.0), "arm N gave only the supported claim");
}
