//! `vault.research.advance` (LEARNING-09; ruling LEARN-ROOT-09 = B, ADVANCE-EXPOSURE = A)
//! through the generated verb dispatch (`oneiron::task_verb::sdk::invoke`), as a client calls
//! it: JSON in, JSON out. The owner, or an agent whose live owner Grant lists the verb, runs
//! the host pass for one campaign bound with an execution spec, and reads each continuation's
//! pending task, the task in flight, its state and the line that holds it.
//! - The bootstrap measure reserves its token work and dispatches the scorer once; a second
//!   pass while the run is queued dispatches nothing more.
//! - A pinned share with no room holds the measure on the token line: nothing reserved,
//!   nothing dispatched, still held after a top-up alone; after the owner's resume the same
//!   task dispatches.
//! - A confirmation reserves one exposure on the exploration line before its token work and
//!   before the sealed shot. With no exposure left it holds on that line, the shot unspent and
//!   the cohort unserved; after a top-up and resume it serves the cohort once, spends exactly
//!   one exposure and queues the referee's run.
//! - An agent with no Grant is refused FORBIDDEN; a campaign its own workflow drives, and an
//!   unbound root, are refused.
//! - Each pass step commits its accounting in the same write as its row, after checking that
//!   no other pass moved the row (REVIEW-RESEARCH-ADVANCE D1-D3): a pass that lost its row
//!   reserves nothing; the step that spends the shot serves the cohort and settles its
//!   exposure in one write; a stale confirmation pass leaves the winner's token work open,
//!   and the winner's referee runs on it; a pass that read the row before the dispatch
//!   enqueues no second run, even after the winner's run has ended (REVIEW-7694 P1). These
//!   four take single steps through the `test_doors::research_continuation::step` door, on a
//!   row as a pass read it.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_vault_research_advance`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptState, ClaimAttempt, ClaimOutcome, CompleteAttempt,
};
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::autoreason_campaign::research::{
    ResearchContinuation, ResearchSplit, ResearchTask, ResearchWork, research_continuations,
    research_promotions, research_reservations,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::{RsiBudgetConfig, RsiBudgetShare, RsiSettlement, RsiTopUp};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError};
use oneiron::skill_optimize::{
    CutDecision, DerivationKind, EvalCaseDraft, EvalCohortSetup, EvalSeat, FamilyPurpose,
    eval_authoring_inventory, setup_eval_cohorts,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::test_doors::research_continuation::{seed_continuation, step};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, ResearchChildWire,
    create_agent_definition_as, mint_agent_grant_as, research_create_child_as_owner,
};
use oneiron::{EdgeActorClass, EntityId, Error, Vault, VaultConfig};
use oneiron_store::dreamer_attempt_payload::decode_dreamer_attempt_payload;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const VERB: &str = "vault.research.advance";
const CREATE_ROOT_VERB: &str = "vault.research.create_root";
const BIND_VERB: &str = "vault.research.bind";

/// The vault clock's fixed time for every test here: no wall time, no sleeps.
const T0: u64 = 1_780_000_000;
const DAY: u64 = 86_400;

/// Token units each run of the campaign reserves.
const UNITS: u64 = 10;

/// The lease owner this file's runs are claimed by.
const WORKER: &str = "research-advance-test";

/// The rubric revision the sealed cohort is cut under.
const RUBRIC: &str = "fixture-rubric";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

/// A rooted vault with its install enrolled, its embedded owner and proof. The owner's
/// Grant acts on `ThisInstall` need the full five-step install first.
fn rooted_vault() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("serving install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    Fixture {
        vault,
        _dir: dir,
        owner,
        owner_proof,
    }
}

fn owner_memory(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn attempt_of(hex: &str) -> AttemptId {
    AttemptId::from_bytes(EntityId::from_hex(hex).expect("an id").as_bytes())
        .expect("an attempt id")
}

/// The vault's RSI lines: a token line of `limit`, an exposure line of `exposures`, and the
/// named shares.
fn configure_rsi(fixture: &Fixture, limit: u64, exposures: u64, shares: &[(&str, u64, bool)]) {
    fixture
        .vault
        .configure_rsi_budget(RsiBudgetConfig {
            limit,
            exploration_exposure_limit: exposures,
            shares: shares
                .iter()
                .map(|(name, units, pinned)| {
                    (
                        (*name).to_owned(),
                        RsiBudgetShare {
                            units: *units,
                            pinned: *pinned,
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        })
        .expect("the owner configures the RSI lines");
}

fn top_up(fixture: &Fixture, line: RsiTopUp) {
    fixture
        .vault
        .top_up_rsi_budget(line)
        .expect("the owner tops up the line");
}

fn resume(fixture: &Fixture) {
    fixture
        .vault
        .resume_rsi_budget()
        .expect("the owner resumes the RSI line");
}

/// The agents a host-driven campaign names: experimenter, scorer and referee.
struct Agents {
    experimenter: EntityId,
    scorer: EntityId,
    referee: EntityId,
}

fn agents(fixture: &Fixture) -> Agents {
    Agents {
        experimenter: define_agent(&fixture.vault, "research-advance-experimenter")
            .expect("define the experimenter"),
        scorer: define_agent(&fixture.vault, "research-advance-scorer").expect("define the scorer"),
        referee: define_agent(&fixture.vault, "research-advance-referee")
            .expect("define the referee"),
    }
}

/// A root `vault.research.create_root` enqueued, with its run.
struct Root {
    hex: String,
    id: AttemptId,
    run_id: String,
}

fn create_root(fixture: &Fixture, intent_key: &str) -> Root {
    let target = define_agent(
        &fixture.vault,
        &format!("research-advance-root-{intent_key}"),
    )
    .expect("define the root's agent");
    let receipt = invoke(
        &owner_memory(fixture),
        CREATE_ROOT_VERB,
        json!({
            "agent": target.to_hex(),
            "intent_key": intent_key,
            "briefing": "Search the parameter axis for a better quality score.",
        }),
    )
    .expect("the owner creates a root");
    let hex = receipt["root"].as_str().expect("the root").to_owned();
    Root {
        id: attempt_of(&hex),
        run_id: receipt["run_id"].as_str().expect("the run").to_owned(),
        hex,
    }
}

/// A general config campaign over `root`: three distinct dataset revisions, one primary
/// metric, a lease of 100 token units and 10 exposures, the incumbent pinned by its digest,
/// and the host execution spec when `agents` names one.
fn bind(
    fixture: &Fixture,
    root: &Root,
    agents: Option<&Agents>,
    confirmation: Option<EntityId>,
    share: Option<&str>,
) -> Value {
    let execution = agents.map(|agents| {
        json!({
            "experimenter": agents.experimenter.to_hex(),
            "scorer": agents.scorer.to_hex(),
            "referee": confirmation.map(|_| agents.referee.to_hex()),
            "experiment_units": UNITS,
            "measure_units": UNITS,
            "confirm_units": UNITS,
        })
    });
    let body = json!({
        "root": root.hex,
        "config": {
            "campaign_id": "advance-fixture",
            "search_axes": [{ "name": "parameter", "values": ["baseline", "alternative"] }],
            "metric_set": {
                "set_id": "fixture-quality",
                "revision": "r1",
                "axes": [{ "name": "quality", "direction": "higher", "role": "primary" }],
            },
            "splits": {
                "search": { "dataset_id": "fixture-search", "revision": "r1" },
                "held_out": { "dataset_id": "fixture-held-out", "revision": "r1" },
                "sealed": { "dataset_id": "fixture-sealed", "revision": "r1" },
            },
            "budget": { "budget_id": "fixture-lease", "max_units": 100, "exploration_units": 10 },
            "decide": { "kind": "dominance" },
        },
        "target": { "config": { "subject": "advance-fixture" } },
        "holder": null,
        "confirmation": confirmation.map(|cohort| json!({ "seat": "companion", "cohort": cohort.to_hex() })),
        "share": share,
        "incumbent": {
            "config_ref": "fixture-config:baseline",
            "config_sha256": sha256_hex(br#"{"parameter":"baseline"}"#),
        },
        "prior_ladder": [],
        "execution": execution,
    });
    invoke(&owner_memory(fixture), BIND_VERB, body).expect("the owner binds the campaign")
}

fn advance(memory: &Memory<'_>, root: &Root) -> Result<Value, MemoryError> {
    invoke(memory, VERB, json!({ "root": root.hex }))
}

/// The one continuation an advance answer lists.
fn only_continuation(answer: &Value) -> &Value {
    let rows = answer["continuations"]
        .as_array()
        .expect("the answer lists continuations");
    assert_eq!(rows.len(), 1, "one continuation: {answer}");
    &rows[0]
}

fn measure(fixture: &Fixture, root: &Root, attempt: &str, split: &str, quality: f64) {
    let owner = owner_memory(fixture);
    let measurement = |dataset: &str| {
        json!({
            "dataset": { "dataset_id": dataset, "revision": "r1" },
            "metric_set_id": "fixture-quality",
            "metric_set_revision": "r1",
            "scores": { "quality": quality },
        })
    };
    let receipt = format!("fixture:{attempt}:{split}");
    match split {
        "search" => invoke(
            &owner,
            "vault.research.measure_search",
            json!({
                "root": root.hex,
                "attempt": attempt,
                "evidence": {
                    "measurement": measurement("fixture-search"),
                    "confirmed_hits": quality,
                    "attribution": 1.0,
                    "hop_cost": 0.0,
                    "expected_gain": 0.0,
                    "estimator_version": "beta-eig/2",
                    "knob_reliability": null,
                    "receipt_refs": [receipt],
                },
            }),
        ),
        _ => invoke(
            &owner,
            "vault.research.measure_held_out",
            json!({
                "root": root.hex,
                "attempt": attempt,
                "measurement": measurement("fixture-held-out"),
                "receipt_refs": [receipt],
            }),
        ),
    }
    .expect("the owner records the measurement");
}

/// One sealed Companion family of a single receipt case, cut by the owner's setup into an
/// unretired cohort of its own.
fn sealed_cohort(fixture: &Fixture, source: &str) -> EntityId {
    let vault = &fixture.vault;
    vault
        .assign_eval_family(
            &EvalSeat::Companion,
            &BTreeSet::from([source.to_owned()]),
            FamilyPurpose::SealedConfirmation,
            T0,
        )
        .expect("assign the sealed family");
    vault
        .record_eval_case(
            &EvalCaseDraft {
                seat: EvalSeat::Companion,
                kind: DerivationKind::Receipt,
                receipts: vec![source.to_owned()],
                parents: Vec::new(),
                stratum: None,
                draw_probability: None,
                source_at: T0 - DAY,
            },
            T0,
        )
        .expect("record the sealed case");
    let inventory = eval_authoring_inventory(vault, T0).expect("inventory");
    let report = setup_eval_cohorts(
        vault,
        &fixture.owner_proof,
        EvalCohortSetup {
            inventory_at: T0,
            inventory_digest: inventory.inventory_digest,
            families: Vec::new(),
            cases: Vec::new(),
            cuts: vec![CutDecision {
                seat: EvalSeat::Companion,
                from: T0 - 2 * DAY,
                until: T0,
                rubric_revision: RUBRIC.to_owned(),
                reference: false,
            }],
        },
        T0,
    )
    .expect("the owner cuts the cohort");
    assert_eq!(report.cohorts_cut.len(), 1, "one cohort cut: {report:?}");
    report.cohorts_cut[0]
}

/// A campaign whose child beats the root on held-out, so its basis reads Promote, bound to
/// a sealed cohort with a referee, and one round continuation seeded at that basis.
struct Confirmable {
    root: Root,
    cohort: EntityId,
    child_hex: String,
}

fn confirmable(fixture: &Fixture) -> Confirmable {
    let agents = agents(fixture);
    let cohort = sealed_cohort(fixture, "fixture-source:advance-confirmation");
    let root = create_root(fixture, "confirmable");
    bind(fixture, &root, Some(&agents), Some(cohort), None);
    measure(fixture, &root, &root.hex, "search", 0.2);
    measure(fixture, &root, &root.hex, "held_out", 0.2);
    let root_entity = EntityId::from_hex(&root.hex).expect("root id");
    let child = research_create_child_as_owner(
        &fixture.vault,
        &fixture.owner_proof,
        ResearchChildWire {
            root: root_entity,
            parent: root_entity,
            agent: agents.experimenter,
            intent_key: "advance-child".to_owned(),
            briefing: "Measure the alternative parameter.".to_owned(),
        },
    )
    .expect("the owner enqueues the child")
    .child;
    let child_hex = child.to_hex();
    invoke(
        &owner_memory(fixture),
        "vault.research.fork",
        json!({
            "root": root.hex,
            "parent": root.hex,
            "child": child_hex,
            "kind": "variation",
            "candidate": {
                "config_ref": "fixture-config:alternative",
                "config_sha256": sha256_hex(br#"{"parameter":"alternative"}"#),
            },
        }),
    )
    .expect("the owner records the fork");
    measure(fixture, &root, &child_hex, "held_out", 0.8);
    let basis = invoke(
        &owner_memory(fixture),
        "vault.research.promotion_basis",
        json!({ "root": root.hex, "candidate": child_hex, "archive": null }),
    )
    .expect("the owner records the held-out basis");
    assert_eq!(
        basis["call"],
        json!("promote"),
        "the child promotes: {basis}"
    );
    seed_continuation(
        &fixture.vault,
        root.id,
        ResearchWork::Round(0),
        vec![ResearchTask::Basis {
            candidate: attempt_of(&child_hex),
        }],
        T0,
    )
    .expect("seed the round continuation at its basis");
    Confirmable {
        root,
        cohort,
        child_hex,
    }
}

fn assert_forbidden(error: &MemoryError, what: &str) {
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "{what}: FORBIDDEN, not the unknown-verb code; got {}: {}",
        error.code, error.message,
    );
}

#[test]
fn owner_advance_dispatches_the_bootstrap_measure_once() {
    let fixture = rooted_vault();
    configure_rsi(&fixture, 120, 2, &[]);
    let agents = agents(&fixture);
    let root = create_root(&fixture, "bootstrap");
    bind(&fixture, &root, Some(&agents), None, None);
    let owner = owner_memory(&fixture);

    let first = advance(&owner, &root).expect("the owner advances the campaign");
    let row = only_continuation(&first);
    assert_eq!(row["work"], json!("bootstrap"), "{row}");
    assert_eq!(row["state"], json!("open"), "{row}");
    assert_eq!(row["held_line"], Value::Null, "{row}");
    assert_eq!(row["pending"], json!([]), "{row}");
    let running = &row["running"];
    assert_eq!(
        running["task"],
        json!({ "measure": { "node": root.hex, "split": "search" } }),
        "the incumbent root is measured on the search split: {row}"
    );
    assert_eq!(
        running["exposure"],
        Value::Null,
        "a measure serves no cohort"
    );
    assert_eq!(running["released"], json!(false));
    let run_hex = running["run"]
        .as_str()
        .expect("the scorer run is dispatched");
    assert_eq!(row["runs"], json!([run_hex]), "the run trail names it");
    assert_eq!(first["budget"]["work_reserved"], json!(UNITS), "{first}");
    assert_eq!(first["budget"]["exploration_reserved"], json!(0));
    assert_eq!(
        fixture.vault.rsi_budget().expect("token line").reserved,
        UNITS,
        "the vault token line holds the reservation"
    );

    let record = AttemptQueue::new(&fixture.vault)
        .get(attempt_of(run_hex))
        .expect("read the scorer run")
        .expect("the scorer run is queued");
    assert_eq!(record.state, AttemptState::Queued);
    assert_eq!(
        record.run_id.as_deref(),
        Some(root.run_id.as_str()),
        "the scorer runs in the campaign's run"
    );
    let payload = decode_dreamer_attempt_payload(&record.payload).expect("payload");
    assert_eq!(payload.parent_attempt, Some(root.id), "under the root");

    let second = advance(&owner, &root).expect("a second pass");
    let again = only_continuation(&second);
    assert_eq!(
        again["running"]["run"],
        json!(run_hex),
        "the queued run is still the one in flight"
    );
    assert_eq!(again["runs"], json!([run_hex]), "no second dispatch");
    assert_eq!(
        second["budget"]["work_reserved"],
        json!(UNITS),
        "no second reservation"
    );
}

#[test]
fn pinned_share_hold_resumes_the_same_measure() {
    let fixture = rooted_vault();
    configure_rsi(&fixture, 120, 2, &[("pinned", UNITS / 2, true)]);
    let agents = agents(&fixture);
    let root = create_root(&fixture, "pinned");
    bind(&fixture, &root, Some(&agents), None, Some("pinned"));
    let owner = owner_memory(&fixture);
    let measure_task = json!({ "measure": { "node": root.hex, "split": "search" } });

    let held = advance(&owner, &root).expect("the pass holds, it does not fail");
    let row = only_continuation(&held);
    assert_eq!(
        row["state"],
        json!({ "held": { "reason": "budget" } }),
        "{row}"
    );
    assert_eq!(
        row["held_line"],
        json!({ "work": { "purpose": "Judge" } }),
        "the token line under the pinned share holds the measure: {row}"
    );
    assert_eq!(
        row["pending"],
        json!([measure_task]),
        "the task waits at the front"
    );
    assert_eq!(row["running"], Value::Null, "nothing in flight");
    assert_eq!(row["runs"], json!([]), "nothing dispatched");
    assert_eq!(
        held["budget"]["work_reserved"],
        json!(0),
        "nothing reserved"
    );
    assert!(
        fixture.vault.rsi_budget().expect("token line").suspended,
        "the refusal holds the RSI line"
    );

    top_up(
        &fixture,
        RsiTopUp::Share {
            share: "pinned".to_owned(),
            units: UNITS,
        },
    );
    let still = advance(&owner, &root).expect("a pass after the top-up alone");
    let row = only_continuation(&still);
    assert_eq!(
        row["state"],
        json!({ "held": { "reason": "budget" } }),
        "a top-up does not resume by itself: {row}"
    );
    assert_eq!(row["runs"], json!([]));

    resume(&fixture);
    let resumed = advance(&owner, &root).expect("a pass after the owner resumes");
    let row = only_continuation(&resumed);
    assert_eq!(row["work"], json!("bootstrap"), "the same continuation");
    assert_eq!(row["state"], json!("open"), "{row}");
    assert_eq!(row["held_line"], Value::Null, "{row}");
    assert_eq!(
        row["running"]["task"], measure_task,
        "the same task goes on: {row}"
    );
    let run_hex = row["running"]["run"].as_str().expect("the scorer run");
    assert_eq!(
        row["runs"],
        json!([run_hex]),
        "one run, dispatched after the resume"
    );
    assert_eq!(resumed["budget"]["work_reserved"], json!(UNITS));
}

#[test]
fn confirmation_holds_on_the_exposure_line_then_serves_once() {
    let fixture = rooted_vault();
    configure_rsi(&fixture, 120, 0, &[]);
    let campaign = confirmable(&fixture);
    let root = &campaign.root;
    let owner = owner_memory(&fixture);
    let confirm_task = json!({ "confirm": { "candidate": campaign.child_hex } });

    let held = advance(&owner, root).expect("the pass holds, it does not fail");
    let row = only_continuation(&held);
    assert_eq!(row["work"], json!({ "round": 0 }), "{row}");
    assert_eq!(
        row["state"],
        json!({ "held": { "reason": "budget" } }),
        "{row}"
    );
    assert_eq!(
        row["held_line"],
        json!("exploration"),
        "the exposure line holds the confirmation: {row}"
    );
    assert_eq!(
        row["pending"],
        json!([confirm_task]),
        "the confirmation waits at the front"
    );
    assert_eq!(row["running"], Value::Null, "nothing in flight");
    assert_eq!(row["runs"], json!([]), "no referee run");
    assert_eq!(held["budget"]["exploration_reserved"], json!(0));
    assert_eq!(held["budget"]["exploration_spent"], json!(0));
    assert_eq!(
        held["budget"]["work_reserved"],
        json!(0),
        "no token work is reserved ahead of the exposure"
    );
    assert_eq!(
        fixture
            .vault
            .eval_cohort_exposure(&campaign.cohort)
            .expect("cohort exposure")
            .candidates,
        0,
        "the sealed cohort is not served"
    );
    let archive = invoke(
        &owner,
        "vault.research.archive",
        json!({ "root": root.hex }),
    )
    .expect("read the campaign");
    assert_eq!(
        archive["promotions"][0]["confirmation"],
        Value::Null,
        "the sealed shot is unspent: {archive}"
    );
    assert!(
        fixture
            .vault
            .rsi_exploration()
            .expect("exposure line")
            .suspended,
        "the refusal holds the RSI line"
    );

    top_up(&fixture, RsiTopUp::Exploration { units: 1 });
    resume(&fixture);
    let served = advance(&owner, root).expect("a pass after the top-up and resume");
    let row = only_continuation(&served);
    assert_eq!(row["state"], json!("open"), "{row}");
    assert_eq!(row["held_line"], Value::Null, "{row}");
    assert_eq!(row["pending"], json!([]), "{row}");
    let running = &row["running"];
    assert_eq!(
        running["task"], confirm_task,
        "the same task goes on: {row}"
    );
    assert_eq!(
        running["released"],
        json!(true),
        "the cohort went to the referee"
    );
    assert!(
        running["exposure"].is_string(),
        "the exposure reservation: {row}"
    );
    let run_hex = running["run"].as_str().expect("the referee run is queued");
    assert_eq!(row["runs"], json!([run_hex]));
    assert_eq!(served["budget"]["exploration_spent"], json!(1), "{served}");
    assert_eq!(
        served["budget"]["exploration_reserved"],
        json!(0),
        "{served}"
    );
    assert_eq!(served["budget"]["work_reserved"], json!(UNITS), "{served}");
    let line = fixture.vault.rsi_exploration().expect("exposure line");
    assert_eq!(
        (line.spent_exposure, line.reserved_exposure),
        (1, 0),
        "one serving spent one exposure on the vault line"
    );
    assert_eq!(
        fixture.vault.rsi_budget().expect("token line").spent,
        0,
        "no exposure is counted as token spend"
    );
    assert_eq!(
        fixture
            .vault
            .eval_cohort_exposure(&campaign.cohort)
            .expect("cohort exposure")
            .candidates,
        1,
        "the sealed cohort served once"
    );
    let record = AttemptQueue::new(&fixture.vault)
        .get(attempt_of(run_hex))
        .expect("read the referee run")
        .expect("the referee run is queued");
    assert_eq!(record.state, AttemptState::Queued);

    let again = advance(&owner, root).expect("a pass while the referee is queued");
    let row = only_continuation(&again);
    assert_eq!(row["runs"], json!([run_hex]), "no second referee run");
    assert_eq!(
        again["budget"]["exploration_spent"],
        json!(1),
        "no second exposure"
    );
    assert_eq!(
        fixture
            .vault
            .eval_cohort_exposure(&campaign.cohort)
            .expect("cohort exposure")
            .candidates,
        1,
        "no second serving"
    );
}

/// The campaign's one continuation, as the store holds it.
fn stored_continuation(fixture: &Fixture, root: &Root) -> ResearchContinuation {
    let rows = research_continuations(&fixture.vault, root.id).expect("read the continuations");
    assert_eq!(rows.len(), 1, "one continuation: {rows:?}");
    rows.into_iter().next().expect("one continuation")
}

/// One pass step on the continuation as the store holds it now.
fn step_stored(fixture: &Fixture, root: &Root) {
    let row = stored_continuation(fixture, root);
    step(&fixture.vault, root.id, &row, T0).expect("one pass step");
}

/// Reservation `id`'s settlement; `None` while it is open.
fn settlement(fixture: &Fixture, root: &Root, id: EntityId) -> Option<RsiSettlement> {
    research_reservations(&fixture.vault, root.id)
        .expect("read the reservations")
        .into_iter()
        .find(|row| row.id == id)
        .expect("the campaign holds the reservation")
        .settlement
}

fn cohort_servings(fixture: &Fixture, cohort: &EntityId) -> u64 {
    fixture
        .vault
        .eval_cohort_exposure(cohort)
        .expect("cohort exposure")
        .candidates
}

#[test]
fn a_pass_that_lost_its_row_reserves_nothing() {
    let fixture = rooted_vault();
    configure_rsi(&fixture, 120, 2, &[]);
    let agents = agents(&fixture);
    let root = create_root(&fixture, "lost-row");
    bind(&fixture, &root, Some(&agents), None, None);
    seed_continuation(
        &fixture.vault,
        root.id,
        ResearchWork::Bootstrap,
        vec![ResearchTask::Measure {
            node: root.id,
            split: ResearchSplit::Search,
        }],
        T0,
    )
    .expect("seed the bootstrap measure");
    // A pass reads the row; another pass takes it first, reserves and dispatches.
    let read = stored_continuation(&fixture, &root);
    advance(&owner_memory(&fixture), &root).expect("the owner advances the campaign");
    let reservations = research_reservations(&fixture.vault, root.id).expect("reservations");
    assert_eq!(
        reservations.len(),
        1,
        "the winner's one reservation: {reservations:?}"
    );
    let winner = reservations[0].id;

    let lost = step(&fixture.vault, root.id, &read, T0)
        .expect_err("the row moved since this pass read it");
    assert!(matches!(lost, Error::ConcurrentWrite(_)), "{lost:?}");
    let reservations = research_reservations(&fixture.vault, root.id).expect("reservations");
    assert_eq!(
        reservations.len(),
        1,
        "the pass that lost its row reserved nothing, not even a refunded row: {reservations:?}"
    );
    assert_eq!(reservations[0].id, winner);
    assert_eq!(
        reservations[0].settlement, None,
        "the winner's reservation stays open"
    );
    assert_eq!(
        fixture.vault.rsi_budget().expect("token line").reserved,
        UNITS,
        "the vault token line holds the winner's reservation alone"
    );
}

/// The scorer runs queued under `root` in its campaign's run, in creation order.
fn scorer_runs(fixture: &Fixture, root: &Root) -> Vec<AttemptId> {
    AttemptQueue::new(&fixture.vault)
        .list_run(&root.run_id)
        .expect("read the campaign's runs")
        .into_iter()
        .filter(|record| {
            record.kind == DREAMER_RUNNER_ATTEMPT_KIND
                && decode_dreamer_attempt_payload(&record.payload)
                    .is_ok_and(|payload| payload.parent_attempt == Some(root.id))
        })
        .map(|record| record.id)
        .collect()
}

/// Runs `run` to its end: leased to this file's worker, then completed. The runner's rows
/// are claimed oldest first, so rows queued before it are claimed past.
fn complete_run(fixture: &Fixture, run: AttemptId) {
    let queue = AttemptQueue::new(&fixture.vault);
    let claimed = (0..64).any(|_| {
        match queue
            .claim_kind(
                DREAMER_RUNNER_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: WORKER.to_owned(),
                    now: u64::MAX,
                },
            )
            .expect("claim the next queued row")
        {
            ClaimOutcome::Claimed(row) => row.id == run,
            _ => panic!("the queue ran out before the run was claimed"),
        }
    });
    assert!(claimed, "the run is claimed");
    let leased = queue
        .get(run)
        .expect("read the leased run")
        .expect("the leased run reads back");
    queue
        .complete(CompleteAttempt {
            id: run,
            lease_owner: WORKER.to_owned(),
            attempt_count: leased.attempt_count,
            now: leased.updated_at,
        })
        .expect("the run completes");
}

#[test]
fn a_stale_pass_dispatches_nothing_after_the_run_it_lost_to_ended() {
    let fixture = rooted_vault();
    configure_rsi(&fixture, 120, 2, &[]);
    let agents = agents(&fixture);
    let root = create_root(&fixture, "stale-dispatch");
    bind(&fixture, &root, Some(&agents), None, None);
    seed_continuation(
        &fixture.vault,
        root.id,
        ResearchWork::Bootstrap,
        vec![ResearchTask::Measure {
            node: root.id,
            split: ResearchSplit::Search,
        }],
        T0,
    )
    .expect("seed the bootstrap measure");
    // The first step reserves the measure's token work. A pass reads the row then, before
    // the dispatch; another pass dispatches the scorer, and the scorer's run ends, so the
    // dedupe key no longer finds a pending run.
    step_stored(&fixture, &root);
    let read = stored_continuation(&fixture, &root);
    let reservation = read
        .running
        .as_ref()
        .filter(|running| running.run.is_none())
        .expect("the measure is reserved, not yet dispatched")
        .reservation;
    step_stored(&fixture, &root);
    let run = stored_continuation(&fixture, &root)
        .running
        .and_then(|running| running.run)
        .expect("the scorer run is dispatched");
    assert_eq!(scorer_runs(&fixture, &root), vec![run]);
    complete_run(&fixture, run);

    let lost = step(&fixture.vault, root.id, &read, T0)
        .expect_err("the row moved since this pass read it");
    assert!(matches!(lost, Error::ConcurrentWrite(_)), "{lost:?}");
    assert_eq!(
        scorer_runs(&fixture, &root),
        vec![run],
        "the stale pass enqueued no second scorer run"
    );
    let row = stored_continuation(&fixture, &root);
    assert_eq!(row.runs, vec![run], "{row:?}");
    assert_eq!(row.running.and_then(|running| running.run), Some(run));
    assert_eq!(
        settlement(&fixture, &root, reservation),
        None,
        "the stale pass refunded nothing of the winner's"
    );
}

#[test]
fn the_confirmation_serving_settles_its_exposure_in_the_same_write() {
    let fixture = rooted_vault();
    configure_rsi(&fixture, 120, 1, &[]);
    let campaign = confirmable(&fixture);
    let root = &campaign.root;
    let child = attempt_of(&campaign.child_hex);
    // The basis puts the confirmation in front; the next step reserves its exposure and its
    // token work.
    step_stored(&fixture, root);
    step_stored(&fixture, root);
    let running = stored_continuation(&fixture, root)
        .running
        .expect("the confirmation is in flight");
    assert_eq!(running.task, ResearchTask::Confirm { candidate: child });
    assert!(
        running.release.is_none() && running.run.is_none(),
        "{running:?}"
    );
    let exposure = running.exposure.expect("the exposure reservation");
    assert_eq!(settlement(&fixture, root, exposure), None);

    // The step that spends the shot serves the cohort and settles the exposure with it.
    step_stored(&fixture, root);
    let row = stored_continuation(&fixture, root);
    let running = row.running.as_ref().expect("the confirmation is in flight");
    let release = running
        .release
        .as_ref()
        .expect("the cohort went to the referee");
    assert!(running.run.is_none(), "the referee is dispatched next");
    assert_eq!(
        settlement(&fixture, root, exposure),
        Some(RsiSettlement::Exposure(1)),
        "the serving spent its exposure in its own write"
    );
    assert_eq!(
        settlement(&fixture, root, running.reservation),
        None,
        "the referee's token work stays reserved"
    );
    assert_eq!(cohort_servings(&fixture, &campaign.cohort), 1);
    let basis = research_promotions(&fixture.vault, root.id)
        .expect("read the promotions")
        .into_iter()
        .find(|basis| basis.candidate == child)
        .expect("the candidate's basis");
    assert_eq!(
        basis
            .confirmation
            .and_then(|confirmation| confirmation.exposure),
        Some(release.exposure.id),
        "the basis marks the serving"
    );
    let line = fixture.vault.rsi_exploration().expect("exposure line");
    assert_eq!((line.spent_exposure, line.reserved_exposure), (1, 0));
}

#[test]
fn a_stale_confirmation_pass_leaves_the_winning_reservation_open() {
    let fixture = rooted_vault();
    configure_rsi(&fixture, 120, 1, &[]);
    let campaign = confirmable(&fixture);
    let root = &campaign.root;
    step_stored(&fixture, root);
    step_stored(&fixture, root);
    // Two passes read the confirmation before either spends the shot.
    let read = stored_continuation(&fixture, root);
    let running = read.running.clone().expect("the confirmation is in flight");
    let exposure = running.exposure.expect("the exposure reservation");
    step(&fixture.vault, root.id, &read, T0).expect("the first pass serves the cohort");
    let lost = step(&fixture.vault, root.id, &read, T0)
        .expect_err("the second pass read the row before the first moved it");
    assert!(matches!(lost, Error::ConcurrentWrite(_)), "{lost:?}");

    assert_eq!(
        settlement(&fixture, root, running.reservation),
        None,
        "the stale pass refunded nothing of the winner's"
    );
    assert_eq!(
        settlement(&fixture, root, exposure),
        Some(RsiSettlement::Exposure(1)),
        "one serving, its exposure spent once"
    );
    assert_eq!(
        research_reservations(&fixture.vault, root.id)
            .expect("reservations")
            .len(),
        2,
        "no other reservation"
    );
    assert_eq!(cohort_servings(&fixture, &campaign.cohort), 1);

    // The winner goes on: the referee runs on its open reservation.
    let answer = advance(&owner_memory(&fixture), root).expect("the owner advances");
    let row = only_continuation(&answer);
    let run_hex = row["running"]["run"]
        .as_str()
        .expect("the referee run is queued");
    assert_eq!(row["runs"], json!([run_hex]), "{row}");
    assert_eq!(
        answer["budget"]["work_reserved"],
        json!(UNITS),
        "the referee's work is reserved, not refunded: {answer}"
    );
    assert_eq!(settlement(&fixture, root, running.reservation), None);
    assert_eq!(cohort_servings(&fixture, &campaign.cohort), 1);
}

/// An enabled, active agent definition the owner creates: the advancing caller.
fn calling_agent(fixture: &Fixture) -> EntityId {
    let id = fixture.vault.new_entity_id().expect("agent id");
    create_agent_definition_as(
        &fixture.vault,
        &fixture.owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: id,
            definition: serde_json::from_value(json!({
                "agent_id": "research-advance-caller",
                "desc": "research advance fixture",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("agent spec"),
        },
    )
    .expect("owner creates the calling agent");
    id
}

fn grant_advance(fixture: &Fixture, agent: EntityId) {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), VERB.to_owned()]));
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the advance Grant");
    assert!(minted.grant.confers, "the advance Grant confers");
}

#[test]
fn granted_agent_advances_and_an_agent_without_a_grant_is_refused() {
    let fixture = rooted_vault();
    configure_rsi(&fixture, 120, 2, &[]);
    let agents = agents(&fixture);
    let root = create_root(&fixture, "granted");
    bind(&fixture, &root, Some(&agents), None, None);
    let caller = calling_agent(&fixture);
    let agent = fixture.vault.memory(caller, EdgeActorClass::Agent);

    let error = advance(&agent, &root).expect_err("an agent with no Grant is refused");
    assert_forbidden(&error, "a no-grant advance");
    assert!(
        error.message.contains(VERB),
        "the refusal names the verb: {}",
        error.message
    );
    assert_eq!(
        fixture.vault.rsi_budget().expect("token line").reserved,
        0,
        "a refused caller reserves nothing"
    );

    grant_advance(&fixture, caller);
    let answer = advance(&agent, &root).expect("the granted agent advances the campaign");
    let row = only_continuation(&answer);
    assert!(
        row["running"]["run"].is_string(),
        "the bound scorer is dispatched: {row}"
    );
}

#[test]
fn workflow_driven_and_unbound_roots_are_refused() {
    let fixture = rooted_vault();
    configure_rsi(&fixture, 120, 2, &[]);
    let owner = owner_memory(&fixture);

    let workflow = create_root(&fixture, "workflow");
    bind(&fixture, &workflow, None, None, None);
    let error = advance(&owner, &workflow).expect_err("a workflow-driven campaign is refused");
    assert!(
        error.message.contains("no execution spec"),
        "the refusal says why: {}",
        error.message
    );

    let unbound = create_root(&fixture, "unbound");
    let error = advance(&owner, &unbound).expect_err("an unbound root is refused");
    assert!(
        error.message.contains("no research campaign is bound"),
        "the refusal says why: {}",
        error.message
    );
    assert_eq!(
        fixture.vault.rsi_budget().expect("token line").reserved,
        0,
        "neither refusal reserves"
    );
}
