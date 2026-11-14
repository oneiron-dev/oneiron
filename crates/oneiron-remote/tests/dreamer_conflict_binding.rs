//! A conflict-settlement attempt's job client (untangle 6.9d S69D3): `OneironClient::for_dreamer_attempt`
//! over the binding the engine mints from the admitted attempt. The client pages the open
//! conflicts, asks `ai.verdict` on the host's lent ladder and commits Settle items as the
//! Dreamer, and each call proves the attempt's lease (owner and generation) and the Dreamer's
//! live Steward reach and MACHINE binding again, so a call refuses, and writes nothing, once
//! the generation moves, the reach or binding is revoked, or the lease ends.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-remote
//! --features oneiron/test-support --test dreamer_conflict_binding` (the
//! oneiron features of its `--all-features` build added).
#![cfg(oneiron_test_support)]

use std::sync::{Arc, Mutex};

use oneiron::attempt_queue::AttemptQueue;
use oneiron::dreamer_runner::{
    CompleteDreamerAttempt, CompleteDreamerAttemptOutcome, DreamerAdmittedAttempt,
    DreamerDecisionLender, DreamerParkCause, DreamerRunnerStore,
};
use oneiron::dreamer_wake::DreamerAttemptExecution;
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionCall, DecisionLadder,
    DecisionProvider, DecisionQuestion, DecisionRung, HumanDecisionQueue, HumanDecisionRequest,
    ProviderDecision, ProviderPin, TypedDecision,
};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_LEASE_REQUIRED,
    MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError,
};
use oneiron::model_decision::catalogue::CONFLICT_SETTLE;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn_pair, open_dreamer_vault};
use oneiron::test_doors::derive::{
    Claim, Derived, Named, claim_lifecycle, commit, narrow_steward_grant_to_project, open_conflict,
    witness_turn,
};
use oneiron::test_doors::dreamer_attempt_binding::{
    CONFLICT_SETTLE_LEASE_OWNER, CONFLICT_SETTLE_RUN, admit_conflict_settle_attempt,
    enqueue_conflict_settle_attempt, enqueue_strength_attempt, execute_unlent_conflict_settle,
    observe_strength_claim,
};
use oneiron::test_doors::run_lifecycle::release_lease;
use oneiron::test_doors::steward::{
    STEWARD_VERBS, archive_every_quiet_claim, dreamer, stand_steward_grant,
};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_remote::OneironClient;
use serde_json::{Value, json};

type ConflictTestResult<T> = Result<T, Box<dyn std::error::Error>>;

const PAGE: &str = "vault.consolidation.conflicts.page";
const VERDICT: &str = "ai.verdict";
const COMMIT: &str = "vault.derive.commit";
const STRENGTH_PAGE: &str = "vault.consolidation.strength.observations.page";
/// The queue clock every admission and release here runs at, in seconds.
const QUEUE_NOW: u64 = 1_000;
/// Supplies the wording every settlement ask here uses, so the request and expected
/// question share it.
const CONFLICT_VERDICT_WORDING: &str = "Which member keeps?";

/// What the fake lender saw: how many verdicts ran through it, the principal the ladder
/// decided for, the evidence its Big provider read, the shown options and question Big
/// answered, and the rung whose answer stands. The receipt keeps no dial ceiling (see
/// `DecisionReceipt`), so the answered rung is not a ceiling proof; the ceiling probe
/// below proves the cap another way.
#[derive(Debug, Clone, Default)]
struct Recorded {
    calls: usize,
    principal: Option<EntityId>,
    evidence: Vec<EntityId>,
    shown_options: Vec<String>,
    question: Option<DecisionQuestion>,
    answered: Option<DecisionRung>,
}

/// The host's lent decisions, faked: Big answers the shown option at the test's index,
/// or abstains when built abstaining, and the lender records the Dreamer principal, the
/// rung whose answer stands, the evidence Big read and the shown options and question it
/// saw. The provider sees the shown question and evidence only; principal and rung come
/// from the decided `TypedDecision` after `decide` returns. The receipt keeps no dial
/// ceiling, so this records no ceiling; the abstain probe proves the cap by never
/// reaching the person.
struct FakeLender {
    pick: Option<usize>,
    recorded: Mutex<Recorded>,
}

impl FakeLender {
    fn new(pick: usize) -> Self {
        Self {
            pick: Some(pick),
            recorded: Mutex::new(Recorded::default()),
        }
    }

    fn abstaining() -> Self {
        Self {
            pick: None,
            recorded: Mutex::new(Recorded::default()),
        }
    }
}

/// Records the evidence, shown options and shown question Big read when it
/// answered the call.
#[derive(Debug, Clone, Default)]
struct BigSeen {
    evidence: Vec<EntityId>,
    shown_options: Vec<String>,
    question: Option<DecisionQuestion>,
}

/// Selects the shown option at the configured index with high confidence, or abstains
/// when no index is configured. It records the evidence, shown options and question
/// it read either way.
struct FixedBig {
    pick: Option<usize>,
    seen: Mutex<BigSeen>,
}

impl DecisionProvider for FixedBig {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Big,
            model: "test-big".to_owned(),
            version: "v1".to_owned(),
        }
    }

    fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        let shown_options = match &call.question.contract {
            AnswerContract::Choice { options } => options.clone(),
            _ => Vec::new(),
        };
        *self.seen.lock().expect("big seen") = BigSeen {
            evidence: call.evidence.to_vec(),
            shown_options: shown_options.clone(),
            question: Some(call.question.clone()),
        };
        match self.pick {
            Some(pick) => {
                let chosen = shown_options
                    .get(pick)
                    .expect("Big pick is a shown option")
                    .clone();
                Ok(ProviderDecision {
                    answer: DecisionAnswer::Choice(chosen),
                    probability: Some(0.9),
                    paired: None,
                    person: None,
                    served: None,
                    cost_per_thousand: None,
                })
            }
            None => Ok(ProviderDecision {
                answer: DecisionAnswer::Abstain,
                probability: None,
                paired: None,
                person: None,
                served: None,
                cost_per_thousand: None,
            }),
        }
    }
}

/// No person ask: the verdict ceiling stops at Big, so a queued ask is the defect.
struct NoHuman;

impl HumanDecisionQueue for NoHuman {
    fn queue(&self, _request: HumanDecisionRequest) -> oneiron::Result<()> {
        panic!("the conflict verdict must never queue a person ask");
    }
}

impl DreamerDecisionLender for FakeLender {
    fn lend(
        &self,
        decide: &mut dyn FnMut(
            &DecisionLadder<'_>,
            &DecisionBandPolicy,
        ) -> oneiron::Result<TypedDecision>,
    ) -> oneiron::Result<TypedDecision> {
        self.recorded.lock().expect("fake lender recorded").calls += 1;
        let big = FixedBig {
            pick: self.pick,
            seen: Mutex::new(BigSeen::default()),
        };
        let human = NoHuman;
        let ladder = DecisionLadder {
            rule: None,
            local: None,
            system_one: None,
            escalation: None,
            big: Some(&big),
            human: &human,
            human_pin: ProviderPin {
                rung: DecisionRung::Human,
                model: "test-human".to_owned(),
                version: "q1".to_owned(),
            },
            ask_to: None,
            paired: None,
            person: None,
            presence: None,
            correlation: None,
        };
        let policy = DecisionBandPolicy::default();
        let decision = decide(&ladder, &policy)?;
        let seen = big.seen.lock().expect("big seen").clone();
        let mut recorded = self.recorded.lock().expect("fake lender recorded");
        recorded.principal = Some(decision.receipt.principal);
        recorded.evidence = seen.evidence;
        recorded.shown_options = seen.shown_options;
        recorded.question = seen.question;
        recorded.answered = decision.receipt.time.and_then(|time| time.answered);
        Ok(decision)
    }
}

/// One admitted conflict-settlement attempt over one open conflict, and the job client the
/// engine minted for it, lent the fake ladder.
struct BoundConflict {
    vault: Arc<Vault>,
    dreamer: EntityId,
    person: EntityId,
    first: EntityId,
    second: EntityId,
    marker: EntityId,
    admitted: DreamerAdmittedAttempt,
    client: OneironClient,
    lender: Arc<FakeLender>,
}

/// What a refused call must leave as it found: the Dreamer's batches and both members'
/// lifecycles.
#[derive(Debug, PartialEq, Eq)]
struct Written {
    batches: usize,
    first: Option<String>,
    second: Option<String>,
}

fn written(bound: &BoundConflict) -> ConflictTestResult<Written> {
    Ok(Written {
        batches: bound.vault.derive_batches_of(bound.dreamer)?.len(),
        first: claim_lifecycle(&bound.vault, bound.first)?,
        second: claim_lifecycle(&bound.vault, bound.second)?,
    })
}

/// Seeds one named person through the existing fixture door.
fn seed_person(vault: &Vault, name: &str) -> ConflictTestResult<EntityId> {
    let person = EntityId::now();
    seed_named_person(vault, &person, name, vault.now_recorded_at())?;
    Ok(person)
}

/// Lands one Dreamer claim about `person`, citing the witnessed `turn`, in a batch of its
/// own; its id.
fn landed_claim(
    vault: &Vault,
    actor: EntityId,
    person: EntityId,
    turn: EntityId,
    run: &str,
    value: &str,
) -> ConflictTestResult<EntityId> {
    let committed = commit(
        vault,
        actor,
        EdgeActorClass::System,
        run,
        &[Derived::Claim(Claim {
            local: "claim",
            predicate: "preference.coffee",
            subject: Named::Stored(person),
            value: json!(value),
            evidence: vec![Named::Stored(turn)],
        })],
    )?;
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(item.landed, "the claim lands: {item:?}");
    Ok(item.rows[0])
}

/// Lands two Dreamer claims about `person` with unequal coffee values, each in a batch of
/// its own, and returns their ids.
fn commit_conflicting_pair(
    vault: &Vault,
    actor: EntityId,
    person: EntityId,
    turn: EntityId,
) -> ConflictTestResult<(EntityId, EntityId)> {
    let first = landed_claim(
        vault,
        actor,
        person,
        turn,
        "run-conflict-first",
        "an oat milk flat white",
    )?;
    let second = landed_claim(
        vault,
        actor,
        person,
        turn,
        "run-conflict-second",
        "a cortado",
    )?;
    Ok((first, second))
}

/// A Dreamer with a full live Steward grant and a MACHINE binding, one open conflict between
/// two of its claims about owen, and its conflict-settlement attempt admitted.
struct ConflictSetup {
    vault: Arc<Vault>,
    dreamer: EntityId,
    person: EntityId,
    first: EntityId,
    second: EntityId,
    marker: EntityId,
    admitted: DreamerAdmittedAttempt,
}

fn conflict_setup(dir: &tempfile::TempDir) -> ConflictTestResult<ConflictSetup> {
    drop(open_dreamer_vault(dir.path(), "owen")?);
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let vault = Arc::new(vault);
    let dreamer = dreamer(&vault)?;
    stand_steward_grant(&vault, dreamer, &STEWARD_VERBS)?;
    let person = seed_person(&vault, "owen")?;
    let turn = witness_turn(&vault, "call me owen")?;
    let (first, second) = commit_conflicting_pair(&vault, dreamer, person, turn)?;
    // The marker names `[first, second]`, so the whole ask offers them in that order.
    let marker = open_conflict(&vault, first, second)?;
    assert!(
        enqueue_conflict_settle_attempt(&vault, QUEUE_NOW)?,
        "a fresh vault enqueues"
    );
    let admitted = admit_conflict_settle_attempt(&vault, QUEUE_NOW)?;
    Ok(ConflictSetup {
        vault,
        dreamer,
        person,
        first,
        second,
        marker,
        admitted,
    })
}

/// [`conflict_setup`] with the client bound to the admitted attempt, lent the fake ladder
/// answering every verdict with the shown option at index 4, the second keep of the whole
/// ask.
fn bound_conflict(dir: &tempfile::TempDir) -> ConflictTestResult<BoundConflict> {
    let setup = conflict_setup(dir)?;
    let lender = Arc::new(FakeLender::new(4));
    let lent: Arc<dyn DreamerDecisionLender> = lender.clone();
    let binding = setup
        .vault
        .bind_dreamer_attempt(&setup.admitted)?
        .lend_decisions(lent);
    let client = OneironClient::for_dreamer_attempt(binding);
    Ok(BoundConflict {
        vault: setup.vault,
        dreamer: setup.dreamer,
        person: setup.person,
        first: setup.first,
        second: setup.second,
        marker: setup.marker,
        admitted: setup.admitted,
        client,
        lender,
    })
}

/// The bound client's page must serve the open conflict, and the Settle batch keeping the
/// second member.
fn page_and_settle(bound: &BoundConflict) -> ConflictTestResult<Value> {
    let page = bound.client.agent_verb(PAGE, json!({}))?;
    let page = &page["value"];
    let conflicts = page["conflicts"]
        .as_array()
        .unwrap_or_else(|| panic!("the page serves conflicts: {page}"));
    let served = conflicts
        .iter()
        .find(|served| served["marker"] == bound.marker.to_hex())
        .unwrap_or_else(|| panic!("the page serves the open conflict: {page}"));
    let members = served["members"]
        .as_array()
        .unwrap_or_else(|| panic!("the conflict serves members: {served}"));
    assert_eq!(members.len(), 2, "{served}");
    for member in members {
        assert_eq!(member["keep"], true, "{member}");
    }
    Ok(json!({
        "items": [{
            "kind": "settle",
            "spec": {
                "local": "keep_second",
                "marker": {"stored": bound.marker},
                "settlement": {"keep": {"stored": bound.second}},
            },
        }],
        "sources": [],
    }))
}

/// Builds canonical settlement options in offered order, starting with hold both,
/// dismiss and escalate, then adding a keep per row.
fn canonical_options(offered: &[EntityId]) -> Vec<String> {
    let mut options = vec![
        "hold_both".to_owned(),
        "dismiss".to_owned(),
        "escalate".to_owned(),
    ];
    for id in offered {
        options.push(format!("keep:{}", id.to_hex()));
    }
    options
}

/// Builds one whole-conflict `ai.verdict` with the marker and both members as evidence,
/// canonical whole options, outbound-effect reversibility and no page.
fn verdict_request(marker: EntityId, first: EntityId, second: EntityId) -> Value {
    json!({
        "question": CONFLICT_VERDICT_WORDING,
        "contract": {"kind": "choice", "options": canonical_options(&[first, second])},
        "evidence": [marker.to_hex(), first.to_hex(), second.to_hex()],
        "ceiling": "big",
        "reversibility": "outbound_effect",
        "state": null,
    })
}

/// One Archive item, as a strength attempt commits it; the conflict facet refuses it before
/// its pins are judged, so dummy pins do.
fn archive_item(claim: EntityId) -> Value {
    json!({
        "kind": "archive",
        "spec": {
            "local": "weak",
            "claim": {"stored": claim},
            "signals": {"type_prior": 0.1, "frequency": 0.1, "recency": 0.1, "diversity": 0.1},
            "score": 0.1,
            "observation_pin": "",
            "policy_pin": "",
            "config_pin": "",
        },
    })
}

/// One Settle item keeping `kept` of `marker`; the strength facet refuses it before the
/// marker is read, so dummy ids do for a refusal probe.
fn settle_item(marker: EntityId, kept: EntityId) -> Value {
    json!({
        "kind": "settle",
        "spec": {
            "local": "keep",
            "marker": {"stored": marker},
            "settlement": {"keep": {"stored": kept}},
        },
    })
}

/// `call` refuses with `code`, its message naming `about`.
fn refused(call: Result<Value, MemoryError>, code: &str, about: &str) {
    let refusal = call.expect_err(about);
    assert_eq!(refusal.code, code, "{about}: {refusal:?}");
    assert!(refusal.message.contains(about), "{about}: {refusal:?}");
}

/// All three of the bound client's calls refuse with `code` and `about`, and none writes a
/// batch or moves a member.
fn all_three_refuse(
    bound: &BoundConflict,
    settle: &Value,
    verdict: &Value,
    code: &str,
    about: &str,
) -> ConflictTestResult<()> {
    let before = written(bound)?;
    refused(bound.client.agent_verb(PAGE, json!({})), code, about);
    refused(
        bound.client.agent_verb(VERDICT, verdict.clone()),
        code,
        about,
    );
    refused(bound.client.agent_verb(COMMIT, settle.clone()), code, about);
    assert_eq!(written(bound)?, before, "{about}: the refused calls wrote");
    Ok(())
}

/// The project a stored claim landed in.
fn claim_project(vault: &Vault, claim: EntityId) -> ConflictTestResult<EntityId> {
    Ok(vault
        .get_claim(&claim)?
        .unwrap_or_else(|| panic!("the landed claim exists"))
        .scope_project)
}

#[test]
fn bound_conflict_client_reads_page_verdict_and_commits_settle_keep_as_dreamer()
-> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let bound = bound_conflict(&dir)?;
    let settle = page_and_settle(&bound)?;
    let verdict_input = verdict_request(bound.marker, bound.first, bound.second);

    // The facet admits Settle items only, and the handle acts as nobody else.
    let mut mixed = settle.clone();
    mixed["items"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("the batch has items"))
        .insert(
            0,
            json!({"kind": "claim", "spec": {
                "local": "other",
                "predicate": "profile.drink",
                "subject": {"stored": bound.person},
                "value": "tea",
                "confidence": 0.9,
                "evidence": [{"stored": bound.first}],
            }}),
        );
    let before = written(&bound)?;
    let facet = "the Dreamer conflict settlement facet does not admit this operation";
    refused(
        bound.client.agent_verb(COMMIT, mixed),
        MEMORY_CODE_FORBIDDEN,
        facet,
    );
    refused(
        bound
            .client
            .agent_verb("vault.derive.revert", json!({"batch": EntityId::now()})),
        MEMORY_CODE_FORBIDDEN,
        facet,
    );
    assert_eq!(written(&bound)?, before, "a refused operation wrote");
    let rebind = bound
        .client
        .as_actor(&format!("system:{}", bound.dreamer.to_hex()))
        .expect_err("a bound handle cannot rebind");
    assert_eq!(rebind.code, MEMORY_CODE_FORBIDDEN, "{rebind:?}");
    assert_eq!(
        bound.client.actor_ref(),
        Some(bound.dreamer.to_hex()),
        "the handle acts as the Dreamer"
    );

    // The verdict runs on the lent ladder for the Dreamer, over the conflict's evidence,
    // and answers the canonical keep Big picked by its shown index.
    let verdict = bound.client.agent_verb(VERDICT, verdict_input)?;
    let expected_keep = format!("keep:{}", bound.second.to_hex());
    assert_eq!(
        verdict["answer"],
        json!({"kind": "choice", "value": expected_keep}),
        "{verdict}"
    );
    assert_eq!(verdict["rung"], "big", "{verdict}");
    let recorded = bound
        .lender
        .recorded
        .lock()
        .expect("lender recorded")
        .clone();
    assert_eq!(recorded.calls, 1, "one verdict ran through the lender");
    assert_eq!(
        recorded.principal,
        Some(bound.dreamer),
        "the ladder decides for the Dreamer"
    );
    assert_eq!(recorded.answered, Some(DecisionRung::Big), "Big answers");
    let mut seen = recorded.evidence.clone();
    seen.sort();
    let mut expected = vec![bound.marker, bound.first, bound.second];
    expected.sort();
    assert_eq!(seen, expected, "Big reads the conflict's evidence");
    // Big saw call-local labels, not hex: no shown option holds either member's hex.
    assert_eq!(recorded.shown_options.len(), 5, "{recorded:?}");
    assert_eq!(
        &recorded.shown_options[..3],
        &["hold_both", "dismiss", "escalate"]
    );
    for shown in &recorded.shown_options {
        assert!(
            !shown.contains(&bound.first.to_hex()) && !shown.contains(&bound.second.to_hex()),
            "Big saw labels, not hex: {recorded:?}"
        );
    }
    // The question is today's: the `CONFLICT_SETTLE` family keyed by the contested
    // predicates, over the same wording and options.
    let canonical = canonical_options(&[bound.first, bound.second]);
    let expected_question = CONFLICT_SETTLE
        .question(
            &["preference.coffee".as_bytes()],
            CONFLICT_VERDICT_WORDING.to_owned(),
            AnswerContract::Choice { options: canonical },
        )
        .expect("the expected settlement question builds");
    let asked = recorded.question.as_ref().expect("Big saw a question");
    assert_eq!(asked.id, expected_question.id, "the question is today's");
    assert_eq!(asked.text, CONFLICT_VERDICT_WORDING);

    // The commit keeps the member the answer names.
    let kept = verdict["answer"]["value"]
        .as_str()
        .and_then(|answer| answer.strip_prefix("keep:"))
        .and_then(|hex| EntityId::from_hex(hex).ok())
        .expect("the verdict names a canonical keep");
    let settle = json!({
        "items": [settle_item(bound.marker, kept)],
        "sources": [],
    });
    let view = bound.client.agent_verb(COMMIT, settle)?;
    assert_eq!(view["items"][0]["landed"], true, "{view}");
    let batches = bound.vault.derive_batches_of(bound.dreamer)?;
    assert_eq!(batches.len(), before.batches + 1, "one batch lands");
    let batch: EntityId = serde_json::from_value(view["batch"].clone())?;
    assert_eq!(batches.last(), Some(&batch));
    let record = bound
        .vault
        .derive_batch(batch)?
        .unwrap_or_else(|| panic!("the batch is recorded"));
    assert_eq!(record.actor, bound.dreamer, "the Dreamer commits it");
    assert_eq!(record.actor_class, "system");
    assert_eq!(record.run.as_deref(), Some(CONFLICT_SETTLE_RUN));
    assert_eq!(record.items.len(), 1);
    assert_eq!(record.items[0].kind, "settle");
    assert_eq!(
        record.items[0].rows.len(),
        4,
        "resolved, marker and members"
    );
    assert!(record.items[0].rows.contains(&bound.marker));
    assert!(record.items[0].rows.contains(&bound.first));
    assert!(record.items[0].rows.contains(&bound.second));
    assert_eq!(
        claim_lifecycle(&bound.vault, bound.second)?,
        Some("active".to_owned()),
        "the kept member stands"
    );
    assert_eq!(
        claim_lifecycle(&bound.vault, bound.first)?,
        Some("superseded".to_owned()),
        "the other member is superseded by the kept one"
    );
    // The settled marker no longer opens.
    let after = bound.client.agent_verb(PAGE, json!({}))?;
    let after = &after["value"];
    let open = after["conflicts"]
        .as_array()
        .unwrap_or_else(|| panic!("the page serves conflicts: {after}"));
    assert!(
        open.iter()
            .all(|served| served["marker"] != bound.marker.to_hex()),
        "the settled marker no longer opens: {after}"
    );
    assert_eq!(
        bound.lender.recorded.lock().expect("lender recorded").calls,
        1,
        "the commit runs no verdict"
    );
    Ok(())
}

#[test]
fn conflict_binding_forbids_strength_page_and_archive() -> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let bound = bound_conflict(&dir)?;
    let before = written(&bound)?;
    let facet = "the Dreamer conflict settlement facet does not admit this operation";
    refused(
        bound.client.agent_verb(STRENGTH_PAGE, json!({})),
        MEMORY_CODE_FORBIDDEN,
        facet,
    );
    let archive = json!({
        "items": [archive_item(bound.first)],
        "sources": [],
    });
    refused(
        bound.client.agent_verb(COMMIT, archive),
        MEMORY_CODE_FORBIDDEN,
        facet,
    );
    assert_eq!(written(&bound)?, before, "a refused operation wrote");
    assert_eq!(
        bound.lender.recorded.lock().expect("lender recorded").calls,
        0,
        "a refused operation runs no verdict"
    );
    Ok(())
}

#[test]
fn strength_binding_refuses_conflict_page_verdict_and_settle() -> ConflictTestResult<()> {
    // A strength attempt's binding, admitted for its own facet. No quiet wait: a refusal
    // needs no observation to read.
    let dir = tempfile::tempdir()?;
    drop(open_dreamer_vault(dir.path(), "owen")?);
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let vault = Arc::new(vault);
    let dreamer = dreamer(&vault)?;
    stand_steward_grant(&vault, dreamer, &STEWARD_VERBS)?;
    let observed = observe_strength_claim(&vault)?;
    archive_every_quiet_claim(&vault)?;
    let admitted = enqueue_strength_attempt(&vault, observed.seed, QUEUE_NOW)?;
    let client = OneironClient::for_dreamer_attempt(vault.bind_dreamer_attempt(&admitted)?);
    let person = seed_person(&vault, "owen")?;
    let turn = witness_turn(&vault, "call me owen")?;
    let (first, second) = commit_conflicting_pair(&vault, dreamer, person, turn)?;
    let marker = open_conflict(&vault, first, second)?;
    let before = vault.derive_batches_of(dreamer)?.len();

    let facet = "the Dreamer strength facet does not admit this operation";
    refused(
        client.agent_verb(PAGE, json!({})),
        MEMORY_CODE_FORBIDDEN,
        facet,
    );
    refused(
        client.agent_verb(VERDICT, verdict_request(marker, first, second)),
        MEMORY_CODE_FORBIDDEN,
        facet,
    );
    let settle = json!({
        "items": [settle_item(marker, second)],
        "sources": [],
    });
    refused(
        client.agent_verb(COMMIT, settle),
        MEMORY_CODE_FORBIDDEN,
        facet,
    );
    assert_eq!(
        vault.derive_batches_of(dreamer)?.len(),
        before,
        "a refused operation wrote"
    );
    Ok(())
}

#[test]
fn verdict_without_lender_is_model_unavailable() -> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let setup = conflict_setup(&dir)?;
    let client =
        OneironClient::for_dreamer_attempt(setup.vault.bind_dreamer_attempt(&setup.admitted)?);

    // The page reads without a ladder; only the verdict needs one.
    let page = client.agent_verb(PAGE, json!({}))?;
    assert_eq!(
        page["value"]["conflicts"]
            .as_array()
            .unwrap_or_else(|| panic!("the page serves conflicts: {page}"))
            .len(),
        1
    );

    let input = verdict_request(setup.marker, setup.first, setup.second);
    let refusal = client
        .agent_verb(VERDICT, input)
        .expect_err("no ladder is lent");
    assert_eq!(refusal.code, MEMORY_CODE_MODEL_UNAVAILABLE, "{refusal:?}");
    assert!(
        refusal.message.contains("ladder")
            || refusal.message.contains("lends")
            || refusal.message.contains("decision"),
        "{refusal:?}"
    );

    // The commit lands without a ladder too: Settle items need no verdict.
    let settle = json!({
        "items": [settle_item(setup.marker, setup.second)],
        "sources": [],
    });
    let view = client.agent_verb(COMMIT, settle)?;
    assert_eq!(view["items"][0]["landed"], true, "{view}");
    Ok(())
}

#[test]
fn abstaining_big_never_reaches_human_under_big_ceiling() -> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let setup = conflict_setup(&dir)?;
    let lender = Arc::new(FakeLender::abstaining());
    let lent: Arc<dyn DreamerDecisionLender> = lender.clone();
    let client = OneironClient::for_dreamer_attempt(
        setup
            .vault
            .bind_dreamer_attempt(&setup.admitted)?
            .lend_decisions(lent),
    );

    // Big abstains, so the ladder would climb past Big were the dial to allow it. The
    // verdict caps at Big, the person never queues (a queue panics here), and the call
    // abstains with no rung answering. The receipt keeps no dial ceiling to read back;
    // the unqueued person is the cap's proof.
    let input = verdict_request(setup.marker, setup.first, setup.second);
    let verdict = client.agent_verb(VERDICT, input)?;
    assert_eq!(verdict["answer"], json!({"kind": "abstain"}), "{verdict}");
    assert!(verdict["rung"].is_null(), "{verdict}");
    let recorded = lender.recorded.lock().expect("lender recorded").clone();
    assert_eq!(recorded.calls, 1, "one verdict ran through the lender");
    assert_eq!(
        recorded.principal,
        Some(setup.dreamer),
        "the ladder decides for the Dreamer"
    );
    assert_eq!(recorded.answered, None, "no rung answers an abstain");
    let mut seen = recorded.evidence.clone();
    seen.sort();
    let mut expected = vec![setup.marker, setup.first, setup.second];
    expected.sort();
    assert_eq!(seen, expected, "Big reads the evidence before it abstains");
    Ok(())
}

#[test]
fn unread_verdict_evidence_is_forbidden() -> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    drop(open_dreamer_vault(dir.path(), "owen")?);
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let vault = Arc::new(vault);
    let dreamer = dreamer(&vault)?;

    // As `crates/oneiron/tests/conflicts_page.rs`
    // `a_conflict_with_a_member_the_reader_does_not_read_is_left_out`: each TURN names
    // both people, so either TURN holds either quote, and each claim lands in its own
    // TURN's project.
    let reply = json!({
        "persons": [
            {"id": "new:P1", "name": "owen", "evidence_turn_refs": ["T1"]},
            {"id": "new:P2", "name": "yuki", "evidence_turn_refs": ["T2"]},
        ],
        "candidates": [
            {
                "subject": "new:P1", "predicate": "profile.name", "value": "owen",
                "confidence": 0.8, "evidence_refs": [{"source": "T1", "quote": "owen"}],
            },
            {
                "subject": "new:P2", "predicate": "profile.name", "value": "yuki",
                "confidence": 0.8, "evidence_refs": [{"source": "T2", "quote": "yuki"}],
            },
        ],
    })
    .to_string();
    let pass = consolidate_unbound_turn_pair(
        &vault,
        "call me owen, and this is yuki",
        "call me yuki, and this is owen",
        EntityId::now(),
        &reply,
    )?;
    assert_eq!(pass.landed.len(), 2);
    let mut claims = pass.landed;
    claims.sort_by_key(EntityId::to_hex);
    let (read, unread) = (claims[0], claims[1]);
    let read_project = claim_project(&vault, read)?;
    assert_ne!(
        read_project,
        claim_project(&vault, unread)?,
        "each claim lands in its own TURN's project"
    );
    // The marker inherits its project from the member the Dreamer keeps reading, so the
    // marker reads and only the member is outside the grant.
    let marker = open_conflict(&vault, read, unread)?;
    let grant = stand_steward_grant(&vault, dreamer, &STEWARD_VERBS)?;
    narrow_steward_grant_to_project(&vault, grant, read_project)?;
    assert!(
        enqueue_conflict_settle_attempt(&vault, QUEUE_NOW)?,
        "a fresh vault enqueues"
    );
    let admitted = admit_conflict_settle_attempt(&vault, QUEUE_NOW)?;
    let lender = Arc::new(FakeLender::new(3));
    let lent: Arc<dyn DreamerDecisionLender> = lender.clone();
    let client = OneironClient::for_dreamer_attempt(
        vault.bind_dreamer_attempt(&admitted)?.lend_decisions(lent),
    );
    let before = vault.derive_batches_of(dreamer)?.len();

    // The bound page leaves the conflict out whole, as the unbound page does for the
    // narrowed reader.
    let page = client.agent_verb(PAGE, json!({}))?;
    let conflicts = page["value"]["conflicts"]
        .as_array()
        .unwrap_or_else(|| panic!("the page serves conflicts: {page}"));
    assert!(
        conflicts.is_empty(),
        "the unread member withholds the conflict: {page}"
    );
    let served = page.to_string();
    assert!(!served.contains(&marker.to_hex()));
    assert!(!served.contains(&read.to_hex()));
    assert!(!served.contains(&unread.to_hex()));

    // Asking only the readable member still refuses: the verdict checks the marker and
    // every member, not just the offered rows, before any lender call.
    let offered = json!({
        "question": CONFLICT_VERDICT_WORDING,
        "contract": {"kind": "choice", "options": canonical_options(&[read])},
        "evidence": [marker.to_hex(), read.to_hex()],
        "ceiling": "big",
        "reversibility": "outbound_effect",
        "state": null,
    });
    let about =
        "the conflict marker and every member must read for the Dreamer attempt's conflicts page";
    refused(
        client.agent_verb(VERDICT, offered),
        MEMORY_CODE_FORBIDDEN,
        about,
    );
    // An unknown marker is not served either.
    let unknown = json!({
        "question": CONFLICT_VERDICT_WORDING,
        "contract": {"kind": "choice", "options": canonical_options(&[read])},
        "evidence": [EntityId::now().to_hex(), read.to_hex()],
        "ceiling": "big",
        "reversibility": "outbound_effect",
        "state": null,
    });
    refused(
        client.agent_verb(VERDICT, unknown),
        MEMORY_CODE_FORBIDDEN,
        about,
    );
    assert_eq!(
        vault.derive_batches_of(dreamer)?.len(),
        before,
        "a refused verdict wrote"
    );
    assert_eq!(
        lender.recorded.lock().expect("lender recorded").calls,
        0,
        "an unread conflict runs no verdict"
    );
    Ok(())
}

#[test]
fn verdict_with_wrong_options_names_expected() -> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let bound = bound_conflict(&dir)?;
    let before = written(&bound)?;
    let input = json!({
        "question": CONFLICT_VERDICT_WORDING,
        "contract": {"kind": "choice", "options": ["owen", "yuki"]},
        "evidence": [bound.marker.to_hex(), bound.first.to_hex(), bound.second.to_hex()],
        "ceiling": "big",
        "reversibility": "outbound_effect",
        "state": null,
    });
    let refusal = bound
        .client
        .agent_verb(VERDICT, input)
        .expect_err("wrong options refuse");
    assert_eq!(refusal.code, MEMORY_CODE_BAD_REQUEST, "{refusal:?}");
    assert!(
        refusal
            .message
            .contains("settlement contract must match the expected options"),
        "{refusal:?}"
    );
    assert!(
        refusal.message.contains(&bound.second.to_hex()),
        "the error names the expected options: {refusal:?}"
    );
    assert_eq!(written(&bound)?, before, "a refused verdict wrote");
    assert_eq!(
        bound.lender.recorded.lock().expect("lender recorded").calls,
        0,
        "a refused verdict runs no lender call"
    );
    Ok(())
}

#[test]
fn verdict_with_non_row_member_is_bad_request() -> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let bound = bound_conflict(&dir)?;
    let before = written(&bound)?;
    let input = json!({
        "question": CONFLICT_VERDICT_WORDING,
        "contract": {"kind": "choice", "options": canonical_options(&[bound.person])},
        "evidence": [bound.marker.to_hex(), bound.person.to_hex()],
        "ceiling": "big",
        "reversibility": "outbound_effect",
        "state": null,
    });
    refused(
        bound.client.agent_verb(VERDICT, input),
        MEMORY_CODE_BAD_REQUEST,
        "each offered member must be a settlement row of the conflict",
    );
    assert_eq!(written(&bound)?, before, "a refused verdict wrote");
    assert_eq!(
        bound.lender.recorded.lock().expect("lender recorded").calls,
        0,
        "a refused verdict runs no lender call"
    );
    Ok(())
}

#[test]
fn verdict_with_reversible_read_is_bad_request() -> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let bound = bound_conflict(&dir)?;
    let before = written(&bound)?;
    let input = json!({
        "question": CONFLICT_VERDICT_WORDING,
        "contract": {"kind": "choice", "options": canonical_options(&[bound.first, bound.second])},
        "evidence": [bound.marker.to_hex(), bound.first.to_hex(), bound.second.to_hex()],
        "ceiling": "big",
        "reversibility": "reversible_read",
        "state": null,
    });
    refused(
        bound.client.agent_verb(VERDICT, input),
        MEMORY_CODE_BAD_REQUEST,
        "requires outbound_effect reversibility",
    );
    assert_eq!(written(&bound)?, before, "a refused verdict wrote");
    assert_eq!(
        bound.lender.recorded.lock().expect("lender recorded").calls,
        0,
        "a refused verdict runs no lender call"
    );
    Ok(())
}

#[test]
fn verdict_with_member_as_marker_is_forbidden() -> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let bound = bound_conflict(&dir)?;
    let before = written(&bound)?;
    // `evidence[0]` names a member, not the marker.
    let input = json!({
        "question": CONFLICT_VERDICT_WORDING,
        "contract": {"kind": "choice", "options": canonical_options(&[bound.second])},
        "evidence": [bound.first.to_hex(), bound.second.to_hex()],
        "ceiling": "big",
        "reversibility": "outbound_effect",
        "state": null,
    });
    refused(
        bound.client.agent_verb(VERDICT, input),
        MEMORY_CODE_FORBIDDEN,
        "the conflict marker and every member must read for the Dreamer attempt's conflicts page",
    );
    assert_eq!(written(&bound)?, before, "a refused verdict wrote");
    assert_eq!(
        bound.lender.recorded.lock().expect("lender recorded").calls,
        0,
        "a refused verdict runs no lender call"
    );
    Ok(())
}

#[test]
fn paged_verdict_asks_with_page_key() -> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let setup = conflict_setup(&dir)?;
    let lender = Arc::new(FakeLender::new(3));
    let lent: Arc<dyn DreamerDecisionLender> = lender.clone();
    let client = OneironClient::for_dreamer_attempt(
        setup
            .vault
            .bind_dreamer_attempt(&setup.admitted)?
            .lend_decisions(lent),
    );
    // The second page of two, offering the second member alone.
    let input = json!({
        "question": CONFLICT_VERDICT_WORDING,
        "contract": {"kind": "choice", "options": canonical_options(&[setup.second])},
        "evidence": [setup.marker.to_hex(), setup.second.to_hex()],
        "ceiling": "big",
        "reversibility": "outbound_effect",
        "state": {"round": 0, "page": 1, "pages": 2, "page_answers": []},
    });
    let verdict = client.agent_verb(VERDICT, input)?;
    let expected_keep = format!("keep:{}", setup.second.to_hex());
    assert_eq!(
        verdict["answer"],
        json!({"kind": "choice", "value": expected_keep}),
        "{verdict}"
    );
    assert_eq!(verdict["rung"], "big", "{verdict}");
    let recorded = lender.recorded.lock().expect("lender recorded").clone();
    assert_eq!(recorded.calls, 1, "one verdict ran through the lender");
    assert_eq!(
        recorded.principal,
        Some(setup.dreamer),
        "the ladder decides for the Dreamer"
    );
    assert_eq!(recorded.answered, Some(DecisionRung::Big), "Big answers");
    // The ladder still reads the marker and every member, not just the offered one.
    let mut seen = recorded.evidence.clone();
    seen.sort();
    let mut expected = vec![setup.marker, setup.first, setup.second];
    expected.sort();
    assert_eq!(seen, expected, "Big reads the whole conflict's evidence");
    // The paged question is keyed with the page. This test checks the key before the
    // labels and the whole-ask test checks the labels before the key, so each of the two
    // fails at its own assertion when only that one is lost.
    let canonical = canonical_options(&[setup.second]);
    let expected_question = CONFLICT_SETTLE
        .question(
            &["preference.coffee".as_bytes(), b"page", b"0.1"],
            CONFLICT_VERDICT_WORDING.to_owned(),
            AnswerContract::Choice { options: canonical },
        )
        .expect("the expected paged question builds");
    let asked = recorded.question.as_ref().expect("Big saw a question");
    assert_eq!(
        asked.id, expected_question.id,
        "the paged question is keyed"
    );
    assert_eq!(recorded.shown_options.len(), 4, "{recorded:?}");
    for shown in &recorded.shown_options {
        assert!(
            !shown.contains(&setup.first.to_hex()) && !shown.contains(&setup.second.to_hex()),
            "Big saw labels, not hex: {recorded:?}"
        );
    }
    Ok(())
}

#[test]
fn ended_conflict_attempt_lease_refuses_all_three() -> ConflictTestResult<()> {
    // The lease is released and no worker takes the try again.
    let dir = tempfile::tempdir()?;
    let bound = bound_conflict(&dir)?;
    let settle = page_and_settle(&bound)?;
    let verdict = verdict_request(bound.marker, bound.first, bound.second);
    let attempt = &bound.admitted.status.attempt;
    assert!(release_lease(
        &bound.vault,
        attempt.id,
        CONFLICT_SETTLE_LEASE_OWNER,
        QUEUE_NOW
    )?);
    all_three_refuse(
        &bound,
        &settle,
        &verdict,
        MEMORY_CODE_LEASE_REQUIRED,
        "the Dreamer attempt lease no longer holds",
    )?;

    // The attempt completes.
    let dir = tempfile::tempdir()?;
    let bound = bound_conflict(&dir)?;
    let settle = page_and_settle(&bound)?;
    let verdict = verdict_request(bound.marker, bound.first, bound.second);
    let attempt = &bound.admitted.status.attempt;
    let completed = DreamerRunnerStore::new(&bound.vault).complete(CompleteDreamerAttempt {
        id: attempt.id,
        lease_owner: CONFLICT_SETTLE_LEASE_OWNER.to_owned(),
        attempt_count: attempt.attempt_count,
        now: QUEUE_NOW,
    })?;
    assert!(
        matches!(completed, CompleteDreamerAttemptOutcome::Completed(_)),
        "{completed:?}"
    );
    all_three_refuse(
        &bound,
        &settle,
        &verdict,
        MEMORY_CODE_LEASE_REQUIRED,
        "the Dreamer attempt lease no longer holds",
    )
}

#[test]
fn conflict_settle_enqueue_dedupes_until_completion() -> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    drop(open_dreamer_vault(dir.path(), "owen")?);
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let dreamer = dreamer(&vault)?;
    stand_steward_grant(&vault, dreamer, &STEWARD_VERBS)?;

    assert!(
        enqueue_conflict_settle_attempt(&vault, QUEUE_NOW)?,
        "the first enqueue lands"
    );
    assert!(
        !enqueue_conflict_settle_attempt(&vault, QUEUE_NOW)?,
        "the second dedupes while one pends"
    );
    assert_eq!(
        AttemptQueue::new(&vault)
            .list_run(CONFLICT_SETTLE_RUN)?
            .len(),
        1,
        "exactly one queues before admission"
    );
    let admitted = admit_conflict_settle_attempt(&vault, QUEUE_NOW)?;
    assert!(
        !enqueue_conflict_settle_attempt(&vault, QUEUE_NOW)?,
        "while leased another enqueue refuses"
    );
    let attempt = &admitted.status.attempt;
    assert_eq!(
        attempt.lease_owner.as_deref(),
        Some(CONFLICT_SETTLE_LEASE_OWNER)
    );
    assert_eq!(attempt.run_id.as_deref(), Some(CONFLICT_SETTLE_RUN));
    let completed = DreamerRunnerStore::new(&vault).complete(CompleteDreamerAttempt {
        id: attempt.id,
        lease_owner: CONFLICT_SETTLE_LEASE_OWNER.to_owned(),
        attempt_count: attempt.attempt_count,
        now: QUEUE_NOW,
    })?;
    assert!(
        matches!(completed, CompleteDreamerAttemptOutcome::Completed(_)),
        "{completed:?}"
    );
    assert!(
        enqueue_conflict_settle_attempt(&vault, QUEUE_NOW)?,
        "after completion one enqueues again"
    );
    Ok(())
}

#[test]
fn native_conflict_settle_dispatch_parks_without_host() -> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    drop(open_dreamer_vault(dir.path(), "owen")?);
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let dreamer = dreamer(&vault)?;
    stand_steward_grant(&vault, dreamer, &STEWARD_VERBS)?;

    assert!(
        enqueue_conflict_settle_attempt(&vault, QUEUE_NOW)?,
        "a fresh vault enqueues"
    );
    let admitted = admit_conflict_settle_attempt(&vault, QUEUE_NOW)?;
    let execution = execute_unlent_conflict_settle(&vault, &admitted, QUEUE_NOW)?;
    assert!(
        matches!(&execution, DreamerAttemptExecution::Park { .. }),
        "native dispatch parks without a host: {execution:?}"
    );
    match execution {
        DreamerAttemptExecution::Park { reason, cause } => {
            assert_eq!(cause, DreamerParkCause::Retry);
            assert!(reason.contains("no host lends"), "{reason}");
        }
        other => panic!("native dispatch parks without a host: {other:?}"),
    }
    Ok(())
}
