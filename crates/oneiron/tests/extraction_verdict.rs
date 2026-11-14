//! One bound Extraction `ai.verdict` pack, checked and rebuilt before any loan.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_verdict`.
#![cfg(oneiron_test_support)]

use oneiron::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptBinding};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryResult,
};
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{narrow_steward_grant_to_project, source_version};
use oneiron::test_doors::dreamer_attempt_binding::{
    admit_conflict_settle_attempt, enqueue_conflict_settle_attempt, enqueue_strength_attempt,
};
use oneiron::test_doors::extraction_inputs::{
    append_extraction_turn_words, enqueue_admitted_extraction_attempt,
    settle_extraction_rows_in_project, witness_extraction_turns,
};
use oneiron::test_doors::extraction_verdict::{
    ExtractionVerdictFixture, attach_extraction_verdict_lender,
    dreamer_extraction_verdict_source_version, fixture_charge_binding_count, fixture_charge_units,
    fixture_spent_observations, land_extraction_verdict_listing_claim,
    run_extraction_verdict_native_pack,
};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{
    AttemptId, BudgetLease, EdgeActorClass, EntityId, FatalLlmError, LlmBackend, LlmCapability,
    LlmError, LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId, UnsupportedCapability,
    Vault, VaultConfig,
};
use oneiron_testkit::{ScriptedBackend, Step};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Returns a fixture or assertion error without hiding its source.
type ExtractionVerdictTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The bound verdict verb under test, invoked by name with plain JSON, so this file
/// compiles without naming the handler and fails at runtime below its facet allow-list.
const AI_VERDICT_VERB: &str = "ai.verdict";

/// The inputs page an extraction attempt reads its turns and pins through.
const EXTRACTION_INPUTS_PAGE_VERB: &str = "vault.consolidation.extraction.inputs.page";

/// The queue clock every enqueue and admission here runs at, in seconds.
const QUEUE_NOW: u64 = 1_000;

/// Opens a vault the way the extraction inputs page test does: the Dreamer fixture
/// vault, reopened owned, with engine machines provisioned and the embedded owner ensured.
fn open_extraction_verdict_vault(dir: &tempfile::TempDir) -> ExtractionVerdictTestResult<Vault> {
    drop(open_dreamer_vault(dir.path(), "owen")?);
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    Ok(vault)
}

/// Returns the attempt id as the page names it: its bytes as lowercase hex.
fn extraction_attempt_hex(id: AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Reads the extraction inputs page for `attempt` through `binding`.
fn read_bound_extraction_page(
    binding: &DreamerAttemptBinding,
    attempt: &str,
) -> MemoryResult<Value> {
    binding
        .invoke(
            EXTRACTION_INPUTS_PAGE_VERB,
            json!({"attempt": attempt}),
            None,
        )
        .map(|answer| answer["value"].clone())
}

/// Asks one bound verdict through `binding` with `request` as plain JSON.
fn invoke_bound_verdict(binding: &DreamerAttemptBinding, request: Value) -> MemoryResult<Value> {
    binding
        .invoke(AI_VERDICT_VERB, request, None)
        .map(|answer| answer["value"].clone())
}

/// Binds `admitted` in `vault` and returns the live extraction binding.
fn bind_extraction(
    vault: &Arc<Vault>,
    admitted: &DreamerAdmittedAttempt,
) -> ExtractionVerdictTestResult<DreamerAttemptBinding> {
    Ok(vault.bind_dreamer_attempt(admitted)?)
}

/// Builds one bound Extraction verdict request with `question`, a Choice contract over
/// `options`, empty evidence and `pack` as its state.
fn extraction_verdict_request(question: &str, options: Value, pack: Value) -> Value {
    json!({
        "question": question,
        "contract": {"kind": "choice", "options": options},
        "evidence": [],
        "state": pack,
        "ceiling": "big",
        "reversibility": "reversible_read",
        "routine": false,
        "misses": 0,
    })
}

/// Builds one candidate operand over `subject` and `predicate` with `value`, citing one
/// turn with its pin and quoting its whole words.
fn extraction_candidate(
    subject: &str,
    predicate: &str,
    value: Value,
    turn: &str,
    version: Value,
) -> Value {
    json!({
        "subject": subject,
        "predicate": predicate,
        "value": value,
        "evidence": [{"turn": turn, "version": version}],
    })
}

/// Reads the turn refs with their served versions from a bound inputs page.
fn page_turns_with_versions(page: &Value) -> Vec<(String, Value)> {
    page["turns"]
        .as_array()
        .unwrap_or_else(|| panic!("turns is an array"))
        .iter()
        .map(|served| {
            let turn = served["turn"]
                .as_str()
                .unwrap_or_else(|| panic!("the turn is a string"))
                .to_owned();
            (turn, served["version"].clone())
        })
        .collect()
}

/// The native resolution options in native order, as the conflict pack builds them.
fn native_resolution_options() -> Value {
    json!(["merge", "supersede", "accumulate", "escalate"])
}

/// A checked whole resolution pack over two candidates answers that no extraction loan is
/// lent: the engine rebuilds the resolution question with its identity group and refuses
/// with model unavailable before any model is asked.
#[test]
fn a_checked_resolution_pack_answers_model_unavailable() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 2);
    let pack = json!({
        "read": "resolution",
        "part": {"kind": "whole"},
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("coffee"), &turns[1].0, turns[1].1.clone()),
        ],
        "listed": [],
        "priors": [],
        "questions": [
            {"key": ["resolution"], "options": native_resolution_options()},
            {"key": ["identity", "0"], "options": ["none", "candidate:0", "candidate:1"]},
        ],
        "earlier": [],
    });
    let request = extraction_verdict_request("resolution", native_resolution_options(), pack);
    let Err(unlent) = invoke_bound_verdict(&binding, request) else {
        panic!("a checked pack without a loan answers model unavailable");
    };
    assert_eq!(unlent.code, MEMORY_CODE_MODEL_UNAVAILABLE);
    Ok(())
}

/// A checked whole correction pack over one listed claim answers that no extraction loan
/// is lent: the engine rebuilds the one correction group and refuses with model unavailable.
#[test]
fn a_checked_correction_pack_answers_model_unavailable() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let (subject, listed) = land_extraction_verdict_listing_claim(&vault)?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1);
    let pin = dreamer_extraction_verdict_source_version(&vault, listed)?
        .unwrap_or_else(|| panic!("the Dreamer reads the listed claim"));
    let pin = serde_json::to_value(pin)?;
    let pack = json!({
        "read": "correction",
        "part": {"kind": "whole"},
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.name", json!("yuki"), &turns[0].0, turns[0].1.clone()),
        ],
        "listed": [{"claim": listed.to_hex(), "version": pin}],
        "priors": [],
        "questions": [
            {"key": ["0", "0"], "options": ["none", listed.to_hex()]},
        ],
        "earlier": [],
    });
    let options = json!(["none", listed.to_hex()]);
    let request = extraction_verdict_request("correction", options, pack);
    let Err(unlent) = invoke_bound_verdict(&binding, request) else {
        panic!("a checked correction pack without a loan answers model unavailable");
    };
    assert_eq!(unlent.code, MEMORY_CODE_MODEL_UNAVAILABLE);
    Ok(())
}

/// A pack whose options or key parts leave native order is refused before any loan: two
/// swapped options, then one wrong key part, each answer bad request and never model
/// unavailable.
#[test]
fn pack_keys_or_options_out_of_native_order_are_refused() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    let candidates = json!([
        extraction_candidate(
            &subject.to_hex(),
            "profile.hobby",
            json!("tea"),
            &turns[0].0,
            turns[0].1.clone()
        ),
        extraction_candidate(
            &subject.to_hex(),
            "profile.hobby",
            json!("coffee"),
            &turns[1].0,
            turns[1].1.clone()
        ),
    ]);
    let swapped = json!(["supersede", "merge", "accumulate", "escalate"]);
    let pack = json!({
        "read": "resolution",
        "part": {"kind": "whole"},
        "candidates": candidates.clone(),
        "listed": [],
        "priors": [],
        "questions": [
            {"key": ["resolution"], "options": swapped.clone()},
            {"key": ["identity", "0"], "options": ["none", "candidate:0", "candidate:1"]},
        ],
        "earlier": [],
    });
    let Err(order) = invoke_bound_verdict(
        &binding,
        extraction_verdict_request("resolution", swapped, pack),
    ) else {
        panic!("swapped options are refused");
    };
    assert_eq!(order.code, MEMORY_CODE_BAD_REQUEST);
    let pack = json!({
        "read": "resolution",
        "part": {"kind": "whole"},
        "candidates": candidates,
        "listed": [],
        "priors": [],
        "questions": [
            {"key": ["resolution", "wrong"], "options": native_resolution_options()},
            {"key": ["identity", "0"], "options": ["none", "candidate:0", "candidate:1"]},
        ],
        "earlier": [],
    });
    let Err(key) = invoke_bound_verdict(
        &binding,
        extraction_verdict_request("resolution", native_resolution_options(), pack),
    ) else {
        panic!("a wrong key part is refused");
    };
    assert_eq!(key.code, MEMORY_CODE_BAD_REQUEST);
    Ok(())
}

/// A pack citing a turn at a moved pin is refused before any loan: after the turn words
/// change, the stale pin answers forbidden with the moved source reason, never model
/// unavailable.
#[test]
fn a_moved_turn_pin_is_refused_before_the_loan() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    append_extraction_turn_words(
        &vault,
        witnessed.conversation,
        witnessed.turns[0],
        "and yuki joins owen",
    )?;
    let pack = json!({
        "read": "resolution",
        "part": {"kind": "whole"},
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("coffee"), &turns[1].0, turns[1].1.clone()),
        ],
        "listed": [],
        "priors": [],
        "questions": [
            {"key": ["resolution"], "options": native_resolution_options()},
            {"key": ["identity", "0"], "options": ["none", "candidate:0", "candidate:1"]},
        ],
        "earlier": [],
    });
    let request = extraction_verdict_request("resolution", native_resolution_options(), pack);
    let Err(moved) = invoke_bound_verdict(&binding, request) else {
        panic!("a moved pin is refused");
    };
    assert_eq!(moved.code, MEMORY_CODE_FORBIDDEN);
    let denial = moved
        .gate_denial
        .as_ref()
        .unwrap_or_else(|| panic!("a moved pin carries its gate denial"));
    assert!(
        denial
            .reason_codes
            .contains(&oneiron::derive::SOURCE_MOVED.to_owned())
    );
    Ok(())
}

/// A pack citing a turn outside the Dreamer grant is refused before any loan: the
/// unserved turn answers forbidden below the facet allow list, never model unavailable.
#[test]
fn a_turn_outside_the_dreamer_grant_is_refused() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "yuki likes tea"])?;
    let outside = witnessed.turns[1];
    let project = EntityId::now();
    settle_extraction_rows_in_project(&vault, &[outside, witnessed.messages[1]], project)?;
    let grant = stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    narrow_steward_grant_to_project(&vault, grant, oneiron::claim::default_project_id())?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1);
    let owner = vault.ensure_embedded_owner_actor()?;
    let unserved = source_version(&vault, owner, EdgeActorClass::Human, outside)?
        .unwrap_or_else(|| panic!("the owner reads the outside turn"));
    let unserved = serde_json::to_value(unserved)?;
    let pack = json!({
        "read": "resolution",
        "part": {"kind": "whole"},
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("coffee"), &outside.to_hex(), unserved),
        ],
        "listed": [],
        "priors": [],
        "questions": [
            {"key": ["resolution"], "options": native_resolution_options()},
            {"key": ["identity", "0"], "options": ["none", "candidate:0", "candidate:1"]},
        ],
        "earlier": [],
    });
    let request = extraction_verdict_request("resolution", native_resolution_options(), pack);
    let Err(withheld) = invoke_bound_verdict(&binding, request) else {
        panic!("an unserved turn is refused");
    };
    assert_eq!(withheld.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        !withheld.message.contains("facet does not admit"),
        "an unserved row refuses below the facet allow list: {withheld:?}"
    );
    Ok(())
}

/// A claim cited as turn evidence, and a pack carrying an unknown field, are each refused
/// with bad request and never reach any loan.
#[test]
fn claim_locators_and_unknown_fields_are_refused() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let (_, listed) = land_extraction_verdict_listing_claim(&vault)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    let pin = dreamer_extraction_verdict_source_version(&vault, listed)?
        .unwrap_or_else(|| panic!("the Dreamer reads the listed claim"));
    let pin = serde_json::to_value(pin)?;
    let pack = json!({
        "read": "resolution",
        "part": {"kind": "whole"},
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &listed.to_hex(), pin),
        ],
        "listed": [],
        "priors": [],
        "questions": [
            {"key": ["resolution"], "options": native_resolution_options()},
            {"key": ["identity", "0"], "options": ["none", "candidate:0"]},
        ],
        "earlier": [],
    });
    let request = extraction_verdict_request("resolution", native_resolution_options(), pack);
    let Err(locator) = invoke_bound_verdict(&binding, request) else {
        panic!("a claim locator is refused");
    };
    assert_eq!(locator.code, MEMORY_CODE_BAD_REQUEST);
    let pack = json!({
        "read": "resolution",
        "part": {"kind": "whole"},
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("coffee"), &turns[0].0, turns[0].1.clone()),
        ],
        "listed": [],
        "priors": [],
        "questions": [
            {"key": ["resolution"], "options": native_resolution_options()},
            {"key": ["identity", "0"], "options": ["none", "candidate:0", "candidate:1"]},
        ],
        "earlier": [],
        "unknown_field": "the pack refuses what it does not name",
    });
    let request = extraction_verdict_request("resolution", native_resolution_options(), pack);
    let Err(unknown) = invoke_bound_verdict(&binding, request) else {
        panic!("an unknown field is refused");
    };
    assert_eq!(unknown.code, MEMORY_CODE_BAD_REQUEST);
    Ok(())
}

/// A final pack over two native pages whose second page answer leaves its page options is
/// refused with bad request and never reaches any loan. Large candidate values force the
/// native resolution state into one candidate per page, and the final options repeat the
/// deduped earlier answers so the refusal names option membership only.
#[test]
fn an_earlier_answer_outside_its_canonical_options_is_refused() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    let first_value = format!("tea-{}", "o".repeat(50_000));
    let second_value = format!("coffee-{}", "o".repeat(50_000));
    let final_options = json!(["merge", "bogus"]);
    let pack = json!({
        "read": "resolution_final",
        "part": {"kind": "final", "round": 0},
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!(first_value), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!(second_value), &turns[1].0, turns[1].1.clone()),
        ],
        "listed": [],
        "priors": [],
        "questions": [
            {"key": ["resolution", "final"], "options": final_options.clone()},
        ],
        "earlier": [
            {"key": ["resolution", "page", "0"], "answer": "merge"},
            {"key": ["resolution", "page", "1"], "answer": "bogus"},
        ],
    });
    let request = extraction_verdict_request("resolution", final_options, pack);
    let Err(earlier) = invoke_bound_verdict(&binding, request) else {
        panic!("an earlier answer outside its options is refused");
    };
    assert_eq!(earlier.code, MEMORY_CODE_BAD_REQUEST);
    Ok(())
}

/// Other facets keep their verdict rules: strength admits no verdict, a settlement binding
/// given an extraction pack keeps its page decode refusal, and an extraction binding given
/// a settlement page answers bad request.
#[test]
fn other_facets_keep_their_verdict_rules() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea"])?;
    let (extraction_id, extraction_admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let extraction = bind_extraction(&vault, &extraction_admitted)?;
    let strength_admitted = enqueue_strength_attempt(&vault, extraction_id, QUEUE_NOW)?;
    let strength = vault.bind_dreamer_attempt(&strength_admitted)?;
    let Err(strength_refused) = invoke_bound_verdict(&strength, json!({"question": "resolution"}))
    else {
        panic!("a strength binding admits no verdict");
    };
    assert_eq!(strength_refused.code, MEMORY_CODE_FORBIDDEN);
    enqueue_conflict_settle_attempt(&vault, QUEUE_NOW)?;
    let settle_admitted = admit_conflict_settle_attempt(&vault, QUEUE_NOW)?;
    let settle = vault.bind_dreamer_attempt(&settle_admitted)?;
    let page = read_bound_extraction_page(&extraction, &extraction_attempt_hex(extraction_id))?;
    let turns = page_turns_with_versions(&page);
    let pack = json!({
        "read": "resolution",
        "part": {"kind": "whole"},
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &turns[0].0, turns[0].1.clone()),
        ],
        "listed": [],
        "priors": [],
        "questions": [
            {"key": ["resolution"], "options": native_resolution_options()},
        ],
        "earlier": [],
    });
    let Err(settle_decode) = invoke_bound_verdict(
        &settle,
        json!({
            "question": "Which member keeps?",
            "contract": {"kind": "choice", "options": ["hold_both", "dismiss"]},
            "evidence": [],
            "state": pack,
            "ceiling": "big",
            "reversibility": "outbound_effect",
            "routine": false,
            "misses": 0,
        }),
    ) else {
        panic!("a settlement binding keeps its page decode refusal");
    };
    assert_eq!(settle_decode.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        settle_decode
            .message
            .contains("invalid settlement page state")
    );
    let Err(extraction_decode) = invoke_bound_verdict(
        &extraction,
        extraction_verdict_request(
            "resolution",
            native_resolution_options(),
            json!({"round": 0, "page": 0, "pages": 1, "page_answers": []}),
        ),
    ) else {
        panic!("an extraction binding refuses a settlement page state");
    };
    assert_eq!(extraction_decode.code, MEMORY_CODE_BAD_REQUEST);
    Ok(())
}

/// Answers the one pack generation from a per-request scripted backend and counts the
/// generations it serves.
struct ParityReasoner {
    /// Holds the fixed both-question reply text.
    reply: String,
    /// Declares the reply's input tokens.
    input_tokens: u64,
    /// Declares the reply's output tokens.
    output_tokens: u64,
    /// Counts the generations served so far.
    calls: AtomicUsize,
}

impl ParityReasoner {
    /// Builds a reasoner answering every generation with `reply`, declaring the token counts.
    fn new(reply: String, input_tokens: u64, output_tokens: u64) -> Self {
        Self {
            reply,
            input_tokens,
            output_tokens,
            calls: AtomicUsize::new(0),
        }
    }

    /// Returns the generations served so far.
    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl LlmBackend for ParityReasoner {
    /// The scripted backend answers every model, so this reasoner does too.
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    /// Answers the generation from a scripted backend matching this request's digest.
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let reply = self.reply.clone();
        let (input_tokens, output_tokens) = (self.input_tokens, self.output_tokens);
        Box::pin(async move {
            let digest = ScriptedBackend::digest_of(&request);
            let backend = ScriptedBackend::new(vec![
                Step::text("parity-pack", digest, reply)
                    .buffered()
                    .usage(input_tokens, output_tokens),
            ])
            .map_err(|error| {
                LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                    message: format!("the parity scripted backend did not build: {error}"),
                    code: None,
                })
            })?;
            let response = backend.generate(request, lease).await;
            let seen = backend.finish();
            self.calls.fetch_add(seen.len(), Ordering::SeqCst);
            response
        })
    }

    /// The parity legs never stream; a streamed call fails loudly.
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

/// Builds the fixed pack reply answering accumulate for the resolution question and none
/// for the identity question, with every shown label weighted.
fn parity_pack_reply() -> String {
    json!({
        "Q1": {"merge": 0.05, "supersede": 0.05, "accumulate": 0.85, "escalate": 0.05},
        "Q2": {"none": 0.7, "C1": 0.2, "C2": 0.1},
    })
    .to_string()
}

/// Reads the same whole resolution pack through the native oracle and the bound verdict
/// and answers the same: equal answers, probabilities, rungs and question ids in pack
/// order, the top level fields equal to the first pack entry, the bound generation
/// replaying the native sealed request from its memo, and one terminal charge for the
/// shared attempt.
#[test]
fn extraction_native_pack_matches_bound_verdict() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let page_binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&page_binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 2);
    let pack = json!({
        "read": "resolution",
        "part": {"kind": "whole"},
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("coffee"), &turns[1].0, turns[1].1.clone()),
        ],
        "listed": [],
        "priors": [],
        "questions": [
            {"key": ["resolution"], "options": native_resolution_options()},
            {"key": ["identity", "0"], "options": ["none", "candidate:0", "candidate:1"]},
        ],
        "earlier": [],
    });
    let reasoner = Arc::new(ParityReasoner::new(parity_pack_reply(), 100, 50));
    let fixture = ExtractionVerdictFixture::new(reasoner.clone())?;
    let native = run_extraction_verdict_native_pack(&vault, &admitted, &pack, &fixture);
    let binding = attach_extraction_verdict_lender(bind_extraction(&vault, &admitted)?, &fixture);
    let bound = invoke_bound_verdict(
        &binding,
        extraction_verdict_request("resolution", native_resolution_options(), pack),
    );
    let native = native.expect("the native leg reads its pack");
    let bound = bound.expect("the bound leg answers its pack");
    assert_eq!(native.resolution.as_deref(), Some("accumulate"));
    assert_eq!(native.identity, None);
    let entries = bound["pack"]
        .as_array()
        .expect("the bound verdict answers its pack");
    assert_eq!(entries.len(), 2);
    assert_eq!(native.answers.len(), 2);
    assert_eq!(entries[0]["key"], json!(["resolution"]));
    assert_eq!(entries[1]["key"], json!(["identity", "0"]));
    for (index, (answer, entry)) in native.answers.iter().zip(entries.iter()).enumerate() {
        assert_eq!(answer.question_index, index);
        assert_eq!(answer.answer, entry["answer"]);
        assert_eq!(entry["p"].as_f64(), answer.p);
        assert!(answer.p.is_some_and(|p| p > 0.5 && p < 1.0));
        assert_eq!(answer.rung, entry["rung"]);
        assert_eq!(
            Some(answer.question_id.as_str()),
            entry["question"].as_str()
        );
        let mut native_receipt = answer.receipt.clone();
        let mut bound_receipt = entry["receipt"].clone();
        for receipt in [&mut native_receipt, &mut bound_receipt] {
            if let Some(used) = receipt.pointer_mut("/time/used_ms") {
                *used = Value::from(0);
            }
        }
        assert!(native_receipt.pointer("/time/used_ms").is_some());
        assert_eq!(native_receipt, bound_receipt);
    }
    assert_eq!(bound["answer"], entries[0]["answer"]);
    assert_eq!(bound["p"], entries[0]["p"]);
    assert_eq!(bound["rung"], entries[0]["rung"]);
    assert_eq!(bound["receipt"], entries[0]["receipt"]);
    assert_eq!(native.spent.len(), 1);
    assert!(!native.spent[0].memoized);
    assert_eq!(native.tally_units, 150);
    assert_eq!(native.tally_bindings, 1);
    let spent = fixture_spent_observations(&fixture);
    assert_eq!(spent.len(), 2);
    assert!(!spent[0].memoized);
    assert!(spent[1].memoized);
    assert_eq!(spent[0].request_hash_hex, spent[1].request_hash_hex);
    assert_eq!(spent[0], native.spent[0]);
    assert_eq!(spent[1].request_hash_hex, native.spent[0].request_hash_hex);
    assert_eq!(spent[0].step_hash_hex, spent[1].step_hash_hex);
    assert!(spent[0].step_hash_hex.is_some());
    assert_eq!(spent[0].attempt_hex, spent[1].attempt_hex);
    for observation in &spent {
        assert_eq!(observation.input_total, 100);
        assert_eq!(observation.output_total, 50);
    }
    assert_eq!(fixture_charge_units(&fixture), native.tally_units);
    assert_eq!(
        fixture_charge_binding_count(&fixture),
        native.tally_bindings
    );
    assert_eq!(reasoner.call_count(), 1);
    Ok(())
}
