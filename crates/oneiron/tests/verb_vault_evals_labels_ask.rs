//! `vault.evals.labels.ask` through the generated verb dispatch
//! (`oneiron::task_verb::sdk::invoke`), as a client calls it: JSON in, JSON out, on the
//! caller's own `Memory`. The waiting decision is a stock-switch training offer the Coach
//! recorded through its own leased offer attempt (owner trigger, Coach host admission,
//! `Vault::run_coach_training_offer`), with the sufficiency card the offer stored. A
//! label-helping unknown card gets one ask that quotes the policy's minutes, and a repeat
//! returns it; a not-worse card asks nothing; an offer with no card, an answered offer and
//! a case of another seat are refused. An agent asks only under a live owner Grant listing
//! the verb, and its ask goes to that owner; with no Grant, or a revoked one, it is refused
//! FORBIDDEN. The case's family root is a fixture name: the ask reads the case's seat and
//! cohort, never its lineage.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_vault_evals_labels_ask`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerRunnerStore};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, Memory, MemoryError};
use oneiron::skill_optimize::offer_doors::{
    OfferAnswerRequest, OfferPassRequest, answer as answer_offer, trigger as trigger_offer_pass,
};
use oneiron::skill_optimize::{
    ComputeDestination, DerivationKind, EvalCaseDraft, EvalSeat, FamilyPurpose, OfferAnswer,
    OfferCandidate, OfferCost, OfferEvidence, OfferModelPin, OfferOption, SeatWorkload,
    SufficiencyCard, SufficiencyInput, TrainingOffer, TrainingOfferDraft, sufficiency_card,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, AgentGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const VERB: &str = "vault.evals.labels.ask";

/// The vault clock's fixed time for every test here: no wall time, no sleeps.
const T0: u64 = 1_780_000_000;
const DAY: u64 = 86_400;

/// The minutes an ask quotes on a vault with no judge-calibration manifest row: the
/// resolved policy's default (gate/judge_calibration.rs).
const DEFAULT_ASK_MINUTES: u64 = 1;

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

/// An enabled, active agent definition the owner creates: the asking caller.
fn asking_agent(fixture: &Fixture) -> EntityId {
    let id = fixture.vault.new_entity_id().expect("agent id");
    create_agent_definition_as(
        &fixture.vault,
        &fixture.owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: id,
            definition: serde_json::from_value(json!({
                "agent_id": "eval-label-asker",
                "desc": "eval label ask fixture",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("agent spec"),
        },
    )
    .expect("owner creates the asking agent");
    id
}

/// The owner's live Grant naming `read` and this verb for `agent`; the grant's row.
fn grant_ask(fixture: &Fixture, agent: EntityId) -> EntityId {
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
    .expect("owner mints the label-ask Grant");
    assert!(minted.grant.confers, "the label-ask Grant confers");
    minted.grant.grant_ref
}

fn revoke_grant(fixture: &Fixture, grant_ref: EntityId) {
    let owner_proof = fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            &fixture.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref,
            seen: None,
        },
    )
    .expect("owner revokes the grant");
    assert!(revoked.changed, "the revoke lands");
}

fn owner_memory(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

/// One case of `seat` in the derivation ledger, in a family of its own.
fn record_case(fixture: &Fixture, seat: &EvalSeat, root: &str) -> EntityId {
    fixture
        .vault
        .assign_eval_family(
            seat,
            &BTreeSet::from([root.to_owned()]),
            FamilyPurpose::Development,
            T0,
        )
        .expect("assign the case's family");
    fixture
        .vault
        .record_eval_case(
            &EvalCaseDraft {
                seat: seat.clone(),
                kind: DerivationKind::Receipt,
                receipts: vec![root.to_owned()],
                parents: Vec::new(),
                stratum: None,
                draw_probability: None,
                source_at: T0 - DAY,
            },
            T0,
        )
        .expect("record the case")
        .id
}

/// A card unknown for reasons more labels settle: a floor slice with too few families,
/// and a paired interval that spans the margin. Set, rubric and canary are unchanged.
fn sparse_card() -> SufficiencyCard {
    sufficiency_card(SufficiencyInput {
        families: 3,
        floor_slices: BTreeMap::from([("rare".to_owned(), 1)]),
        min_families_per_slice: 2,
        retest_noise: Some(0.02),
        owner_margin: None,
        paired_interval: Some((-0.05, 0.04)),
        detectable_effect: Some(0.03),
        set_changed: false,
        rubric_changed: false,
        canary_diverged: Some(false),
    })
    .expect("a sparse card")
}

/// A card that reads not worse: enough families in every slice, the interval above
/// minus the margin.
fn not_worse_card() -> SufficiencyCard {
    let card = sufficiency_card(SufficiencyInput {
        families: 12,
        floor_slices: BTreeMap::from([("rare".to_owned(), 4)]),
        min_families_per_slice: 2,
        retest_noise: Some(0.02),
        owner_margin: None,
        paired_interval: Some((0.0, 0.04)),
        detectable_effect: Some(0.03),
        set_changed: false,
        rubric_changed: false,
        canary_diverged: Some(false),
    })
    .expect("a known card");
    assert!(card.approves(), "the fixture card reads not worse");
    card
}

fn pin(model: &str) -> OfferModelPin {
    OfferModelPin {
        model: model.to_owned(),
        revision: "r1".to_owned(),
        content_hash: None,
    }
}

fn cost() -> OfferCost {
    OfferCost {
        currency: "USD".to_owned(),
        monthly_before: Some(40.0),
        monthly_after: Some(25.0),
        one_off: None,
        payback_months: None,
    }
}

/// What the offer skill drafts: switch the Companion seat to a stock model, on `card`.
fn stock_switch_draft(card: Option<SufficiencyCard>) -> TrainingOfferDraft {
    TrainingOfferDraft {
        seat: EvalSeat::Companion,
        offer_skill: None,
        incumbent: pin("incumbent-model"),
        candidate: OfferCandidate::Stock {
            model: pin("stock-model"),
            licence: "apache-2.0".to_owned(),
            source: "fixture-registry".to_owned(),
        },
        baseline: OfferOption {
            label: "today".to_owned(),
            model: pin("incumbent-model"),
            cost: cost(),
            score: None,
            evidence_refs: Vec::new(),
        },
        alternatives: Vec::new(),
        workload: SeatWorkload {
            from: T0 - 30 * DAY,
            until: T0,
            calls: None,
            input_tokens: None,
            output_tokens: None,
            complete: false,
            receipt_refs: vec!["fixture-workload:companion".to_owned()],
        },
        cost: cost(),
        evidence: OfferEvidence {
            cohort: None,
            exposures: Vec::new(),
            rubric_revision: None,
            card,
            paired_measurement: None,
            losses: Vec::new(),
            risk: None,
        },
        destination: ComputeDestination::OnDevice,
        previous: None,
        what_changed: None,
        check_at: T0 + 7 * DAY,
        source_rows: Some(Vec::new()),
    }
}

/// The Coach records `draft` as the production pass does: the owner queues the offer
/// pass, the Coach host admits that very job, and the offer writer runs on its lease.
fn coach_records_offer(fixture: &Fixture, draft: TrainingOfferDraft) -> TrainingOffer {
    let pass = trigger_offer_pass(&fixture.vault, &fixture.owner_proof, OfferPassRequest {})
        .expect("the owner queues the offer pass");
    let DreamerAdmissionOutcome::Admitted(admitted) = DreamerRunnerStore::new(&fixture.vault)
        .admit_next_coach_host_job(AdmitDreamerAttempt {
            lease_owner: "label-ask-fixture".to_owned(),
            now: T0,
            budget_id: "label-ask-fixture".to_owned(),
            budget_total_units: 1 << 20,
            reserve_units: 1,
            started_milestone: None,
        })
        .expect("admit the Coach host job")
    else {
        panic!("the queued offer pass is admitted");
    };
    assert_eq!(
        admitted.status.attempt.id.as_bytes(),
        pass.attempt.as_bytes(),
        "the Coach host admitted the owner's offer pass"
    );
    fixture
        .vault
        .run_coach_training_offer(&admitted, draft, T0)
        .expect("the Coach records the offer")
}

fn call_ask(memory: &Memory<'_>, offer: EntityId, case: EntityId) -> Result<Value, MemoryError> {
    invoke(
        memory,
        VERB,
        json!({
            "offer": offer.to_hex(),
            "case": case.to_hex(),
            "option_a": "The reply answers the request",
            "option_b": "The reply misses the request",
        }),
    )
}

fn decision_of(offer: EntityId) -> String {
    format!("training_offer:{}", offer.to_hex())
}

fn assert_refused(error: &MemoryError, code: &str, phrase: &str) {
    assert_eq!(
        error.code, code,
        "the verb's own refusal, not the unknown-verb error; got {}: {}",
        error.code, error.message,
    );
    assert!(
        error.message.contains(phrase),
        "the refusal names why ({phrase}): {}",
        error.message
    );
}

#[test]
fn owner_asks_one_label_for_a_pending_stock_offer() {
    let fixture = rooted_vault();
    let case = record_case(&fixture, &EvalSeat::Companion, "fixture-source:owner-ask");
    let offer = coach_records_offer(&fixture, stock_switch_draft(Some(sparse_card())));
    let owner = owner_memory(&fixture);

    let ask = call_ask(&owner, offer.id, case).expect("the owner asks for a label");
    assert_eq!(
        ask["decision"].as_str(),
        Some(decision_of(offer.id).as_str())
    );
    assert_eq!(ask["case"].as_str(), Some(case.to_hex().as_str()));
    assert_eq!(ask["seat"], json!("companion"));
    assert_eq!(
        ask["responsible"].as_str(),
        Some(fixture.owner.to_hex().as_str()),
        "the calling owner answers the ask"
    );
    assert_eq!(ask["minutes"].as_u64(), Some(DEFAULT_ASK_MINUTES));
    assert_eq!(ask["chosen"], Value::Null, "an ask is not an answer");

    let repeat = call_ask(&owner, offer.id, case).expect("a repeat on a pending offer");
    assert_eq!(
        repeat["id"], ask["id"],
        "one ask stands per decision and case"
    );

    let open = fixture
        .vault
        .eval_label_asks_for(&fixture.owner)
        .expect("the owner's open asks");
    assert_eq!(open.len(), 1, "the repeat wrote no second ask");
    assert_eq!(open[0].decision, decision_of(offer.id));
}

#[test]
fn granted_agent_asks_the_owner_who_granted_it() {
    let fixture = rooted_vault();
    let case = record_case(&fixture, &EvalSeat::Companion, "fixture-source:agent-ask");
    let offer = coach_records_offer(&fixture, stock_switch_draft(Some(sparse_card())));
    let asker = asking_agent(&fixture);
    grant_ask(&fixture, asker);
    let agent = fixture.vault.memory(asker, EdgeActorClass::Agent);

    let ask = call_ask(&agent, offer.id, case).expect("an agent whose Grant lists the verb asks");
    assert_eq!(
        ask["responsible"].as_str(),
        Some(fixture.owner.to_hex().as_str()),
        "the ask goes to the owner who gave the Grant, not to the agent"
    );
    assert_eq!(
        ask["decision"].as_str(),
        Some(decision_of(offer.id).as_str())
    );
}

#[test]
fn agent_without_a_live_grant_is_refused() {
    let fixture = rooted_vault();
    let case = record_case(&fixture, &EvalSeat::Companion, "fixture-source:grantless");
    let offer = coach_records_offer(&fixture, stock_switch_draft(Some(sparse_card())));
    let asker = asking_agent(&fixture);
    let agent = fixture.vault.memory(asker, EdgeActorClass::Agent);

    let error = call_ask(&agent, offer.id, case).expect_err("no Grant lists the verb");
    assert_refused(&error, MEMORY_CODE_FORBIDDEN, VERB);
    assert!(
        fixture
            .vault
            .eval_label_asks_for(&fixture.owner)
            .expect("open asks")
            .is_empty(),
        "a refused caller writes no ask"
    );

    let grant = grant_ask(&fixture, asker);
    call_ask(&agent, offer.id, case).expect("the granted agent asks");
    revoke_grant(&fixture, grant);
    let error = call_ask(&agent, offer.id, case)
        .expect_err("a revoked Grant admits no repeat of an existing ask");
    assert_refused(&error, MEMORY_CODE_FORBIDDEN, VERB);
}

#[test]
fn a_not_worse_card_asks_nothing() {
    let fixture = rooted_vault();
    let case = record_case(&fixture, &EvalSeat::Companion, "fixture-source:known");
    let offer = coach_records_offer(&fixture, stock_switch_draft(Some(not_worse_card())));

    let answer =
        call_ask(&owner_memory(&fixture), offer.id, case).expect("a known card is not an error");
    assert_eq!(
        answer,
        Value::Null,
        "no label is asked when the card is known"
    );
    assert!(
        fixture
            .vault
            .eval_label_asks_for(&fixture.owner)
            .expect("open asks")
            .is_empty()
    );
}

#[test]
fn an_offer_with_no_card_is_refused() {
    let fixture = rooted_vault();
    let case = record_case(&fixture, &EvalSeat::Companion, "fixture-source:no-card");
    let offer = coach_records_offer(&fixture, stock_switch_draft(None));

    let error = call_ask(&owner_memory(&fixture), offer.id, case)
        .expect_err("an offer that stored no card");
    assert_refused(&error, MEMORY_CODE_BAD_REQUEST, "sufficiency card");
}

#[test]
fn an_answered_offer_waits_on_no_label() {
    let fixture = rooted_vault();
    let case = record_case(&fixture, &EvalSeat::Companion, "fixture-source:answered");
    let offer = coach_records_offer(&fixture, stock_switch_draft(Some(sparse_card())));
    answer_offer(
        &fixture.vault,
        &fixture.owner_proof,
        OfferAnswerRequest {
            offer: offer.id,
            digest: offer.digest.clone(),
            answer: OfferAnswer::Decline,
        },
    )
    .expect("the owner declines the offer");

    let error = call_ask(&owner_memory(&fixture), offer.id, case)
        .expect_err("the declined offer waits on nothing");
    assert_refused(&error, MEMORY_CODE_BAD_REQUEST, "no pending training offer");
}

#[test]
fn a_case_of_another_seat_is_refused() {
    let fixture = rooted_vault();
    let case = record_case(&fixture, &EvalSeat::Decision, "fixture-source:other-seat");
    let offer = coach_records_offer(&fixture, stock_switch_draft(Some(sparse_card())));

    let error = call_ask(&owner_memory(&fixture), offer.id, case)
        .expect_err("a Decision-seat case for a Companion offer");
    assert_refused(&error, MEMORY_CODE_BAD_REQUEST, "another seat");
}
