//! The production conflict-settlement facet (untangle 6.9d S69D4). One wake pass through the production factory's executor and the core dispatch settles an open conflict as one derive batch by the Dreamer actor, with a Settle item, and the owner's `vault.derive.revert` reopens it. A user-stated member is never superseded, with no ladder lent the attempt parks retryable and nothing settles, a conflict too large for one ask is asked in pages the engine accepts, pages that hold both and dismiss are ruled by one final ask over the marker alone, and a ladder withheld mid-run lands the rulings made before it and parks the attempt.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-driver --all-features --test dreamer_conflict_settle` (the driver's dev dependency turns on the engine's `test-support` feature).
#![cfg(oneiron_test_support)]
// The layout of `run_wake_pass`'s future (the wake driver, the dispatch and
// the job adapter, all async) needs a query depth of about 130, past
// rustc's default limit of 128.
#![recursion_limit = "256"]

use std::sync::{Arc, Mutex};

use oneiron::attempt_queue::{AttemptQueue, AttemptState};
use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::dreamer_promotion::AttemptPromotionSink;
use oneiron::dreamer_runner::{DreamerDecisionLender, DreamerParkCause, DreamerRunnerStore};
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionCall, DecisionLadder,
    DecisionProvider, DecisionQuestion, DecisionRung, HumanDecisionQueue, HumanDecisionRequest,
    ProviderDecision, ProviderPin, TypedDecision,
};
use oneiron::model_decision::MAX_DECISION_STATE_BYTES;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{
    Claim, Derived, Named, claim_lifecycle, commit, open_conflict, wake_reads_about_facts,
    witness_turn,
};
use oneiron::test_doors::derive_verbs::revert_as_owner;
use oneiron::test_doors::dreamer_attempt_binding::CONFLICT_SETTLE_RUN;
use oneiron::test_doors::run_lifecycle::defer_enqueued;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, owner, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::test_doors::wake_d1_park_release::load_or_mint_client_id;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, DreamerClaimAuthoringStrategy, DreamerConsolidationScope,
    DreamerWakeDriver, EdgeActorClass, EntityId, RunWakePass, TimeRange, Vault, VaultConfig,
    WakeCancellation, WakePassDeadline, WakeTrigger,
};
use oneiron_driver::{ConflictSettleCursor, ConsolidationExecutorFactory, PassExecutorFactory};
use serde_json::{Value, json};

type ConflictTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The predicate the coffee conflicts contest.
const COFFEE: &str = "preference.coffee";
/// The predicate the second conflict of the withheld-ladder test contests.
const TEA: &str = "preference.tea";
/// The pick that makes the fake lender withhold its ladder, as a paused host does.
const WITHHOLD: &str = "withhold";

/// The conflict facet calls no model. A call reaching this backend is the defect.
struct NoModelBackend;

impl oneiron::LlmBackend for NoModelBackend {
    fn generate<'a>(
        &'a self,
        _request: oneiron::LlmRequest,
        _lease: &'a oneiron::BudgetLease,
    ) -> oneiron::LlmGenerateFuture<'a> {
        Box::pin(async { panic!("the conflict facet must never call a model") })
    }

    fn stream<'a>(
        &'a self,
        _request: oneiron::LlmRequest,
        _lease: &'a oneiron::BudgetLease,
    ) -> oneiron::LlmStreamResult<'a> {
        panic!("the conflict facet must never stream")
    }
}

/// One settlement ask the fake lender recorded. It holds the principal the ladder decided for, the evidence Big read, the shown options and question it saw, the rung whose answer stands, and the state it read with its encoded bytes.
#[derive(Debug, Clone)]
struct RecordedAsk {
    principal: EntityId,
    evidence: Vec<EntityId>,
    shown_options: Vec<String>,
    question: DecisionQuestion,
    answered: Option<DecisionRung>,
    state: Value,
    bytes: usize,
}

/// What Big read when it answered one call. It holds the evidence, shown options and question it saw, and the state it read with its encoded bytes.
#[derive(Debug, Clone, Default)]
struct BigSeen {
    evidence: Vec<EntityId>,
    shown_options: Vec<String>,
    question: Option<DecisionQuestion>,
    state: Value,
    bytes: usize,
}

/// Big faked to answer one shown label. It answers the shown option its pick label names with high confidence, and it records the evidence, shown options, question, state and bytes it read.
struct FixedBig {
    pick_label: String,
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
        let bytes = match serde_json::to_vec(call.state) {
            Ok(encoded) => encoded.len(),
            Err(_) => usize::MAX,
        };
        let seen = BigSeen {
            evidence: call.evidence.to_vec(),
            shown_options: shown_options.clone(),
            question: Some(call.question.clone()),
            state: call.state.clone(),
            bytes,
        };
        match self.seen.lock() {
            Ok(mut guard) => {
                *guard = seen;
            }
            Err(_) => {
                return Err(oneiron::Error::InvalidConfig(
                    "the fake Big lock is poisoned".to_owned(),
                ));
            }
        }
        let chosen = shown_options
            .iter()
            .find(|shown| shown.as_str() == self.pick_label.as_str())
            .cloned();
        let Some(chosen) = chosen else {
            panic!("the pick label is a shown option");
        };
        Ok(ProviderDecision {
            answer: DecisionAnswer::Choice(chosen),
            probability: Some(0.9),
            paired: None,
            person: None,
            served: None,
            cost_per_thousand: None,
        })
    }
}

/// No person queue. The verdict ceiling stops at Big, so a queued ask is the defect.
struct NoHuman;

impl HumanDecisionQueue for NoHuman {
    fn queue(&self, _request: HumanDecisionRequest) -> oneiron::Result<()> {
        panic!("the conflict verdict must never queue a person ask");
    }
}

/// The host's lent decisions, faked. Big answers the n-th ask with the n-th pick label, and every later ask with the last; a [`WITHHOLD`] pick lends no ladder. The lender records each answered ask's principal, evidence, shown options, question, answering rung, state and bytes.
struct FakeLender {
    picks: Vec<String>,
    recorded: Mutex<Vec<RecordedAsk>>,
}

impl FakeLender {
    /// Fakes the host's ladder answering every ask with the shown option `pick_label` names.
    fn new(pick_label: &str) -> Self {
        Self::scripted(&[pick_label])
    }

    /// Fakes the host's ladder answering its asks in turn with `picks`.
    fn scripted(picks: &[&str]) -> Self {
        Self {
            picks: picks.iter().map(|pick| (*pick).to_owned()).collect(),
            recorded: Mutex::new(Vec::new()),
        }
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
        let asked_before = match self.recorded.lock() {
            Ok(guard) => guard.len(),
            Err(_) => {
                return Err(oneiron::Error::InvalidConfig(
                    "the fake lender lock is poisoned".to_owned(),
                ));
            }
        };
        let Some(pick_label) = self
            .picks
            .get(asked_before)
            .or_else(|| self.picks.last())
            .cloned()
        else {
            panic!("the fake lender has a pick");
        };
        if pick_label == WITHHOLD {
            return Err(oneiron::Error::ProviderUnavailable { retry_after: 60 });
        }
        let big = FixedBig {
            pick_label,
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
        let seen = match big.seen.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => {
                return Err(oneiron::Error::InvalidConfig(
                    "the fake Big lock is poisoned".to_owned(),
                ));
            }
        };
        let asked = RecordedAsk {
            principal: decision.receipt.principal,
            evidence: seen.evidence,
            shown_options: seen.shown_options,
            question: match seen.question {
                Some(question) => question,
                None => {
                    return Err(oneiron::Error::InvalidConfig(
                        "Big saw no question".to_owned(),
                    ));
                }
            },
            answered: decision.receipt.time.and_then(|time| time.answered),
            state: seen.state,
            bytes: seen.bytes,
        };
        match self.recorded.lock() {
            Ok(mut guard) => {
                guard.push(asked);
            }
            Err(_) => {
                return Err(oneiron::Error::InvalidConfig(
                    "the fake lender lock is poisoned".to_owned(),
                ));
            }
        }
        Ok(decision)
    }
}

/// A Dreamer with a full live Steward grant, one open conflict between two of its claims about owen, and its conflict-settlement attempt queued for the next wake pass, at the vault's clock in seconds.
struct QueuedConflict {
    vault: Arc<Vault>,
    dreamer: EntityId,
    person: EntityId,
    first: EntityId,
    second: EntityId,
    marker: EntityId,
    now: u64,
}

/// Seeds one named person through the existing fixture door.
fn seed_person(vault: &Vault, name: &str) -> ConflictTestResult<EntityId> {
    let person = EntityId::now();
    seed_named_person(vault, &person, name, vault.now_recorded_at())?;
    Ok(person)
}

/// Lands one Dreamer claim on `predicate` and returns its id. The claim is about `person`, cites the witnessed `turn`, and lands in a batch of its own.
fn landed_claim(
    seeded: &SeededVault,
    run: &str,
    predicate: &'static str,
    value: &str,
) -> ConflictTestResult<EntityId> {
    let committed = commit(
        &seeded.vault,
        seeded.dreamer,
        EdgeActorClass::System,
        run,
        &[Derived::Claim(Claim {
            local: "claim",
            predicate,
            subject: Named::Stored(seeded.person),
            value: json!(value),
            evidence: vec![Named::Stored(seeded.turn)],
        })],
    )?;
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(item.landed, "the claim lands: {item:?}");
    let [row] = item.rows.as_slice() else {
        panic!("one row: {item:?}");
    };
    Ok(*row)
}

/// Writes the owner's own user-stated claim about `person` and returns its id. It is a proposal, so the write meets no criticality confirm.
fn stated_claim(vault: &Vault, person: EntityId, value: &str) -> ConflictTestResult<EntityId> {
    let mut body = ClaimBody::new(
        COFFEE,
        ClaimSubject::Entity(person),
        rmpv::Value::from(value.to_owned()),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    let stated = EntityId::now();
    let at = vault.now_recorded_at();
    vault.put_claim(&stated, &body, TimeRange { start: at, end: at }, at)?;
    Ok(stated)
}

/// A Dreamer with a full live Steward grant, the person owen, and one witnessed turn its claims cite.
struct SeededVault {
    vault: Arc<Vault>,
    dreamer: EntityId,
    person: EntityId,
    turn: EntityId,
}

/// Opens a Dreamer vault with a full Steward grant, the person owen and one witnessed turn.
fn seeded_vault(dir: &tempfile::TempDir) -> ConflictTestResult<SeededVault> {
    drop(open_dreamer_vault(dir.path(), "owen")?);
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let vault = Arc::new(vault);
    let dreamer = dreamer(&vault)?;
    stand_steward_grant(&vault, dreamer, &STEWARD_VERBS)?;
    let person = seed_person(&vault, "owen")?;
    let turn = witness_turn(&vault, "call me owen")?;
    Ok(SeededVault {
        vault,
        dreamer,
        person,
        turn,
    })
}

/// Queues the conflict-settlement attempt for the next wake pass, with every other queued attempt deferred, and returns the vault's clock in seconds.
fn queue_settlement(vault: &Vault) -> ConflictTestResult<u64> {
    // A wake pass queues the PERSON `about` line at its start, and that line
    // calls a model. Queue it here instead, so the loop below defers it; the
    // pass then finds the person's facts already asked and queues nothing.
    wake_reads_about_facts(vault)?;
    let now = vault.now_recorded_at();
    // Only the conflict attempt is due in the pass: any other queued attempt
    // could call a model, and the pass returns the first executor error.
    for record in AttemptQueue::new(vault).list()? {
        if matches!(record.state, AttemptState::Queued) {
            defer_enqueued(vault, record.id, now + 86_400)?;
        }
    }
    let enqueued = vault.with_write_txn(|txn| {
        DreamerRunnerStore::new(vault).enqueue_conflict_settle_in_txn(
            txn,
            Some(CONFLICT_SETTLE_RUN.to_owned()),
            now,
        )
    })?;
    assert!(enqueued, "a fresh vault enqueues");
    Ok(now)
}

/// Builds a Dreamer with a full Steward grant, one open conflict between two Dreamer claims with `first_value` and `second_value`, and its settlement attempt queued for the next wake pass.
fn queued_pair(
    dir: &tempfile::TempDir,
    first_value: &str,
    second_value: &str,
) -> ConflictTestResult<QueuedConflict> {
    let seeded = seeded_vault(dir)?;
    let first = landed_claim(&seeded, "run-conflict-first", COFFEE, first_value)?;
    let second = landed_claim(&seeded, "run-conflict-second", COFFEE, second_value)?;
    // The marker names `[first, second]`, so the whole ask offers them in that order.
    let marker = open_conflict(&seeded.vault, first, second)?;
    let now = queue_settlement(&seeded.vault)?;
    Ok(QueuedConflict {
        vault: seeded.vault,
        dreamer: seeded.dreamer,
        person: seeded.person,
        first,
        second,
        marker,
        now,
    })
}

/// Builds a Dreamer with a full Steward grant, one open conflict between its generated claim and the owner's user-stated claim, and its settlement attempt queued for the next wake pass. The marker names the generated claim first, so the whole ask offers it first.
fn queued_stated_generated(dir: &tempfile::TempDir) -> ConflictTestResult<QueuedConflict> {
    let seeded = seeded_vault(dir)?;
    let generated = landed_claim(&seeded, "run-conflict-generated", COFFEE, "a cortado")?;
    let stated = stated_claim(&seeded.vault, seeded.person, "an oat milk flat white")?;
    let marker = open_conflict(&seeded.vault, generated, stated)?;
    let now = queue_settlement(&seeded.vault)?;
    Ok(QueuedConflict {
        vault: seeded.vault,
        dreamer: seeded.dreamer,
        person: seeded.person,
        first: generated,
        second: stated,
        marker,
        now,
    })
}

/// Reports whether `marker` is open for the Dreamer about `person`.
fn marker_open_for_dreamer(
    vault: &Vault,
    dreamer: EntityId,
    person: EntityId,
    marker: EntityId,
) -> ConflictTestResult<bool> {
    let open = vault
        .memory(dreamer, EdgeActorClass::System)
        .open_conflicts(None, Some(person), usize::MAX)?;
    Ok(open.iter().any(|conflict| conflict.marker == marker))
}

/// Reports whether `marker` is open for the vault's owner about `person`, including a reverted one the Dreamer no longer sees.
fn marker_open_for_owner(
    vault: &Vault,
    person: EntityId,
    marker: EntityId,
) -> ConflictTestResult<bool> {
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let proof = owner(vault)?;
    let open = vault
        .memory(owner_id, EdgeActorClass::Human)
        .open_conflicts(Some(&proof), Some(person), usize::MAX)?;
    Ok(open.iter().any(|conflict| conflict.marker == marker))
}

/// Builds the factory a served host builds for a pass, with the vault lent to the Dreamer's jobs and no settlement ladder lent.
fn production_factory(vault: &Arc<Vault>) -> ConflictTestResult<ConsolidationExecutorFactory> {
    let model = match oneiron::ModelId::new("test/model@v1") {
        Ok(model) => model,
        Err(_) => panic!("a model id"),
    };
    Ok(ConsolidationExecutorFactory::new(
        Arc::new(NoModelBackend),
        DreamerClaimAuthoringStrategy::SinglePass,
        vault.dreamer_authority()?,
        model.clone(),
        oneiron::llm::HostInferenceBinding::Advertised {
            model,
            locality: oneiron::ModelLocality::OwnServer,
            keyless: false,
        },
        None,
        Box::new(AttemptPromotionSink::new(Arc::clone(vault))),
    )
    .with_dreamer_job_vault(Arc::clone(vault)))
}

/// Builds the factory a served host builds for a pass, with the settlement ladder and cursor lent beside the vault lent to the Dreamer's jobs.
fn production_factory_with_host(
    vault: &Arc<Vault>,
    lender: Arc<FakeLender>,
    cursor: ConflictSettleCursor,
) -> ConflictTestResult<ConsolidationExecutorFactory> {
    let model = match oneiron::ModelId::new("test/model@v1") {
        Ok(model) => model,
        Err(_) => panic!("a model id"),
    };
    let lent: Arc<dyn DreamerDecisionLender> = lender;
    Ok(ConsolidationExecutorFactory::new(
        Arc::new(NoModelBackend),
        DreamerClaimAuthoringStrategy::SinglePass,
        vault.dreamer_authority()?,
        model.clone(),
        oneiron::llm::HostInferenceBinding::Advertised {
            model,
            locality: oneiron::ModelLocality::OwnServer,
            keyless: false,
        },
        None,
        Box::new(AttemptPromotionSink::new(Arc::clone(vault))),
    )
    .with_conflict_settle_host(lent, cursor)
    .with_dreamer_job_vault(Arc::clone(vault)))
}

/// Runs one wake pass at `now` through the given factory's executor and the engine's wake driver.
async fn run_wake_pass(
    vault: &Arc<Vault>,
    now: u64,
    factory: &mut ConsolidationExecutorFactory,
) -> ConflictTestResult<()> {
    let guard = BudgetGuard::new("wake".to_owned(), 10_000, BudgetExhaustionPolicy::Suspend);
    let mut executor = factory.executor(&guard)?;
    let mut driver = DreamerWakeDriver::new(vault, "wake", WakePassDeadline::new(180_000));
    driver
        .run_wake_pass(
            RunWakePass {
                trigger: WakeTrigger::Compaction,
                scope: DreamerConsolidationScope::Micro,
                local_node_id: load_or_mint_client_id(vault)?,
                lease_owner: "wake-worker".to_owned(),
                budget_total_units: 10_000,
                reserve_units: 100,
                now,
                host_scope: None,
                destination_bound: None,
            },
            &mut executor,
            &WakeCancellation::new(),
        )
        .await?;
    Ok(())
}

/// Reads the settlement label the standing answer `resolved` records (`hold_both`, `keep`, or `dismiss`), when it records one.
fn resolved_settlement(vault: &Vault, resolved: EntityId) -> ConflictTestResult<Option<String>> {
    let Some(body) = vault.get_claim(&resolved)? else {
        return Ok(None);
    };
    let rmpv::Value::Map(rows) = &body.value else {
        return Ok(None);
    };
    let Some((_, resolution)) = rows
        .iter()
        .find(|(key, _)| key.as_str() == Some("resolution"))
    else {
        return Ok(None);
    };
    let rmpv::Value::Map(fields) = resolution else {
        return Ok(None);
    };
    let Some((_, settlement)) = fields
        .iter()
        .find(|(key, _)| key.as_str() == Some("settlement"))
    else {
        return Ok(None);
    };
    Ok(settlement.as_str().map(str::to_owned))
}

/// Reads the loser id the Dreamer copy `copy` restores, when its provenance names one. It follows the engine's restored-marker door: the copy's evidence provenance names the settlement revert surface and the `restores` id.
fn copy_restores(vault: &Vault, copy: EntityId) -> ConflictTestResult<Option<EntityId>> {
    let Some(body) = vault.get_claim(&copy)? else {
        return Ok(None);
    };
    let Some(rmpv::Value::Map(fields)) = body.evidence.as_ref() else {
        return Ok(None);
    };
    let Some((_, provenance)) = fields.iter().find(|(key, _)| {
        key.as_str() == Some(oneiron::write_envelope::WRITE_ENVELOPE_EVIDENCE_PROVENANCE_KEY)
    }) else {
        return Ok(None);
    };
    let rmpv::Value::Map(rows) = provenance else {
        return Ok(None);
    };
    for (key, value) in rows {
        if key.as_str() != Some("restores") {
            continue;
        }
        if let rmpv::Value::Binary(bytes) = value
            && let Ok(raw) = <[u8; 16]>::try_from(bytes.as_slice())
            && let Ok(id) = EntityId::from_bytes(raw)
        {
            return Ok(Some(id));
        }
        return Ok(None);
    }
    Ok(None)
}

#[tokio::test]
async fn one_pass_after_the_enqueue_settles_the_conflict_in_one_dreamer_batch_and_the_owner_revert_reopens_it()
-> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let queued = queued_pair(&dir, "an oat milk flat white", "a cortado")?;
    let baseline = queued.vault.derive_batches_of(queued.dreamer)?.len();
    assert!(
        marker_open_for_dreamer(&queued.vault, queued.dreamer, queued.person, queued.marker)?,
        "the conflict opens before the pass"
    );
    let lender = Arc::new(FakeLender::new("keep:C1"));
    let mut factory = production_factory_with_host(
        &queued.vault,
        Arc::clone(&lender),
        ConflictSettleCursor::default(),
    )?;

    run_wake_pass(&queued.vault, queued.now, &mut factory).await?;

    let batches = queued.vault.derive_batches_of(queued.dreamer)?;
    assert_eq!(batches.len(), baseline + 1, "one derive batch lands");
    let Some(new) = batches.last().copied() else {
        panic!("one new batch: {batches:?}");
    };
    let Some(record) = queued.vault.derive_batch(new)? else {
        panic!("the batch is recorded");
    };
    assert_eq!(record.actor, queued.dreamer, "the Dreamer commits it");
    assert_eq!(record.actor_class, "system");
    assert_eq!(record.run.as_deref(), Some(CONFLICT_SETTLE_RUN));
    let [item] = record.items.as_slice() else {
        panic!("one item: {:?}", record.items);
    };
    assert!(item.landed, "the Settle lands: {item:?}");
    assert_eq!(item.kind, "settle");
    assert_eq!(item.rows.len(), 4, "resolved, marker and members");
    assert!(item.rows.contains(&queued.marker));
    assert!(item.rows.contains(&queued.first));
    assert!(item.rows.contains(&queued.second));
    assert_eq!(
        claim_lifecycle(&queued.vault, queued.first)?,
        Some("active".to_owned()),
        "the kept member stands"
    );
    assert_eq!(
        claim_lifecycle(&queued.vault, queued.second)?,
        Some("superseded".to_owned()),
        "the other member is superseded by the kept one"
    );
    let recorded = match lender.recorded.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => panic!("the fake lender lock is poisoned"),
    };
    assert_eq!(recorded.len(), 1, "one verdict ran through the lender");
    assert_eq!(
        recorded[0].principal, queued.dreamer,
        "the ladder decides for the Dreamer"
    );
    assert_eq!(recorded[0].answered, Some(DecisionRung::Big), "Big answers");
    let mut seen = recorded[0].evidence.clone();
    seen.sort();
    let mut expected = vec![queued.marker, queued.first, queued.second];
    expected.sort();
    assert_eq!(seen, expected, "Big reads the conflict's evidence");
    assert_eq!(
        recorded[0].shown_options.len(),
        5,
        "the whole ask shows five options"
    );
    assert_eq!(
        &recorded[0].shown_options[..3],
        &["hold_both", "dismiss", "escalate"],
        "the whole ask shows its fixed options first"
    );
    assert_eq!(
        &recorded[0].shown_options[3..],
        &["keep:C1", "keep:C2"],
        "the whole ask shows each member by its call-local label"
    );
    for shown in &recorded[0].shown_options {
        assert!(
            !shown.contains(&queued.first.to_hex()) && !shown.contains(&queued.second.to_hex()),
            "Big saw labels, not hex"
        );
    }
    assert_eq!(
        recorded[0].question.text.as_str(),
        "These claims about one subject contradict each other. Keep the one member that is true and let it supersede the rest, hold both if both can stand, dismiss if they do not really conflict, or escalate if you cannot tell.",
        "the ask uses the settlement wording"
    );
    assert!(
        !marker_open_for_dreamer(&queued.vault, queued.dreamer, queued.person, queued.marker)?,
        "the settled marker no longer opens"
    );

    revert_as_owner(&queued.vault, new)?;

    assert_eq!(
        claim_lifecycle(&queued.vault, queued.first)?,
        Some("active".to_owned()),
        "the winner stands after the revert"
    );
    assert!(
        marker_open_for_owner(&queued.vault, queued.person, queued.marker)?,
        "the revert reopens the marker for the owner"
    );
    if claim_lifecycle(&queued.vault, queued.second)? != Some("active".to_owned()) {
        let owner_id = queued.vault.ensure_embedded_owner_actor()?;
        let proof = owner(&queued.vault)?;
        let open = queued
            .vault
            .memory(owner_id, EdgeActorClass::Human)
            .open_conflicts(Some(&proof), Some(queued.person), usize::MAX)?;
        let Some(conflict) = open
            .iter()
            .find(|conflict| conflict.marker == queued.marker)
        else {
            panic!("the reopened conflict lists its members");
        };
        assert!(conflict.members.contains(&queued.first));
        let Some(copy) = conflict
            .members
            .iter()
            .find(|id| **id != queued.first && **id != queued.second)
        else {
            panic!(
                "a restores copy stands beside the winner: {:?}",
                conflict.members
            );
        };
        assert_eq!(
            claim_lifecycle(&queued.vault, *copy)?,
            Some("active".to_owned()),
            "the restores copy stands after the revert"
        );
        assert_eq!(
            copy_restores(&queued.vault, *copy)?,
            Some(queued.second),
            "the copy restores the superseded loser"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_user_stated_member_is_never_superseded_by_the_dreamer_settlement()
-> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let queued = queued_stated_generated(&dir)?;
    let baseline = queued.vault.derive_batches_of(queued.dreamer)?.len();
    let lender = Arc::new(FakeLender::new("keep:C1"));
    let mut factory = production_factory_with_host(
        &queued.vault,
        Arc::clone(&lender),
        ConflictSettleCursor::default(),
    )?;

    run_wake_pass(&queued.vault, queued.now, &mut factory).await?;

    assert_eq!(
        claim_lifecycle(&queued.vault, queued.second)?,
        Some("active".to_owned()),
        "the user-stated member stands"
    );
    assert_eq!(
        claim_lifecycle(&queued.vault, queued.first)?,
        Some("active".to_owned()),
        "the generated member stands beside a refusal"
    );
    assert!(
        marker_open_for_dreamer(&queued.vault, queued.dreamer, queued.person, queued.marker)?,
        "the refused conflict stays open"
    );
    let recorded = match lender.recorded.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => panic!("the fake lender lock is poisoned"),
    };
    assert!(!recorded.is_empty(), "the settlement ask was recorded");
    for ask in &recorded {
        assert_eq!(
            ask.principal, queued.dreamer,
            "the ladder decides for the Dreamer"
        );
    }
    let batches = queued.vault.derive_batches_of(queued.dreamer)?;
    for batch in batches.iter().skip(baseline) {
        let Some(record) = queued.vault.derive_batch(*batch)? else {
            panic!("the batch is recorded");
        };
        for item in &record.items {
            if item.kind == "settle" {
                assert!(
                    !item.landed,
                    "no Settle lands over user-stated truth: {item:?}"
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn with_no_ladder_lent_the_attempt_parks_and_nothing_settles() -> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let queued = queued_pair(&dir, "an oat milk flat white", "a cortado")?;
    let baseline = queued.vault.derive_batches_of(queued.dreamer)?.len();
    let listed = AttemptQueue::new(&queued.vault).list_run(CONFLICT_SETTLE_RUN)?;
    let [attempt] = listed.as_slice() else {
        panic!("one conflict attempt queues: {listed:?}");
    };
    let attempt_id = attempt.id;
    let mut factory = production_factory(&queued.vault)?;

    run_wake_pass(&queued.vault, queued.now, &mut factory).await?;

    assert_eq!(
        queued.vault.derive_batches_of(queued.dreamer)?.len(),
        baseline,
        "nothing settles without a ladder"
    );
    assert!(
        marker_open_for_dreamer(&queued.vault, queued.dreamer, queued.person, queued.marker)?,
        "the marker stays open"
    );
    let Some(parked) = DreamerRunnerStore::new(&queued.vault).parked_attempt(attempt_id)? else {
        panic!("the attempt parks without a host");
    };
    assert_eq!(parked.cause, DreamerParkCause::Retry);
    assert!(
        parked.reason.contains("host")
            || parked.reason.contains("lends")
            || parked.reason.contains("ladder"),
        "the park names the missing host: {}",
        parked.reason
    );
    Ok(())
}

#[tokio::test]
async fn a_conflict_too_large_for_one_ask_is_asked_in_pages_the_engine_accepts()
-> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let first_value = format!("first-{}", "x".repeat(40_000));
    let second_value = format!("second-{}", "y".repeat(40_000));
    let queued = queued_pair(&dir, &first_value, &second_value)?;
    let baseline = queued.vault.derive_batches_of(queued.dreamer)?.len();
    let lender = Arc::new(FakeLender::new("hold_both"));
    let mut factory = production_factory_with_host(
        &queued.vault,
        Arc::clone(&lender),
        ConflictSettleCursor::default(),
    )?;

    run_wake_pass(&queued.vault, queued.now, &mut factory).await?;

    let recorded = match lender.recorded.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => panic!("the fake lender lock is poisoned"),
    };
    assert!(
        recorded.len() >= 2,
        "the conflict pages: {}",
        recorded.len()
    );
    for ask in &recorded {
        assert_eq!(
            ask.principal, queued.dreamer,
            "the ladder decides for the Dreamer"
        );
        let state = &ask.state;
        let Some(page) = state.get("page") else {
            panic!("a paged ask carries its page: {state}");
        };
        let Some(pages) = state.get("pages") else {
            panic!("a paged ask carries its page count: {state}");
        };
        assert!(page.is_number() && pages.is_number(), "page state: {state}");
        let members = match state.get("members") {
            Some(Value::Array(members)) => members,
            _ => panic!("a paged ask lists its members: {state}"),
        };
        assert!(
            ask.bytes <= MAX_DECISION_STATE_BYTES || members.len() == 1,
            "each state fits unless it is a singleton: {}",
            ask.bytes
        );
    }
    let mut seen_first = 0;
    let mut seen_second = 0;
    for ask in &recorded {
        if ask.state.get("page_answers").is_some() {
            continue;
        }
        let members = match ask.state.get("members") {
            Some(Value::Array(members)) => members,
            _ => panic!("a paged ask lists its members: {}", ask.state),
        };
        for member in members {
            let Some(value) = member.get("value").and_then(Value::as_str) else {
                panic!("a member carries its value whole: {member}");
            };
            if value == first_value.as_str() {
                seen_first += 1;
            } else if value == second_value.as_str() {
                seen_second += 1;
            } else {
                panic!("an offered row is one of the conflict's: {value:.100}");
            }
        }
    }
    assert_eq!(seen_first, 1, "the first row is offered once in round zero");
    assert_eq!(
        seen_second, 1,
        "the second row is offered once in round zero"
    );

    let batches = queued.vault.derive_batches_of(queued.dreamer)?;
    assert_eq!(batches.len(), baseline + 1, "one derive batch lands");
    let Some(new) = batches.last().copied() else {
        panic!("one new batch: {batches:?}");
    };
    let Some(record) = queued.vault.derive_batch(new)? else {
        panic!("the batch is recorded");
    };
    let [item] = record.items.as_slice() else {
        panic!("one item: {:?}", record.items);
    };
    assert!(item.landed, "the Settle lands: {item:?}");
    assert_eq!(item.kind, "settle");
    let Some(resolved) = item.rows.first().copied() else {
        panic!("a landed Settle names its answer: {item:?}");
    };
    assert_eq!(
        resolved_settlement(&queued.vault, resolved)?,
        Some("hold_both".to_owned()),
        "the landed batch holds both"
    );
    assert_eq!(
        claim_lifecycle(&queued.vault, queued.first)?,
        Some("active".to_owned()),
        "hold both leaves the first active"
    );
    assert_eq!(
        claim_lifecycle(&queued.vault, queued.second)?,
        Some("active".to_owned()),
        "hold both leaves the second active"
    );
    assert!(
        !marker_open_for_dreamer(&queued.vault, queued.dreamer, queued.person, queued.marker)?,
        "the held marker no longer opens"
    );
    Ok(())
}

#[tokio::test]
async fn pages_that_hold_both_and_dismiss_are_ruled_by_one_final_ask_over_the_marker_alone()
-> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let first_value = format!("first-{}", "x".repeat(40_000));
    let second_value = format!("second-{}", "y".repeat(40_000));
    let queued = queued_pair(&dir, &first_value, &second_value)?;
    let baseline = queued.vault.derive_batches_of(queued.dreamer)?.len();
    let lender = Arc::new(FakeLender::scripted(&["hold_both", "dismiss", "dismiss"]));
    let mut factory = production_factory_with_host(
        &queued.vault,
        Arc::clone(&lender),
        ConflictSettleCursor::default(),
    )?;

    run_wake_pass(&queued.vault, queued.now, &mut factory).await?;

    let recorded = match lender.recorded.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => panic!("the fake lender lock is poisoned"),
    };
    assert_eq!(recorded.len(), 3, "two pages, then one final ask");
    let last = &recorded[2];
    assert_eq!(
        last.state.get("members"),
        Some(&json!([])),
        "the final ask offers no row: {}",
        last.state
    );
    assert_eq!(
        last.state.get("page_answers"),
        Some(&json!(["hold_both", "dismiss"])),
        "the final ask shows each page's answer: {}",
        last.state
    );
    assert_eq!(
        last.shown_options,
        ["hold_both", "dismiss", "escalate"],
        "the final ask offers no keep"
    );
    let mut seen = last.evidence.clone();
    seen.sort();
    let mut expected = vec![queued.marker, queued.first, queued.second];
    expected.sort();
    assert_eq!(seen, expected, "Big reads the marker and every member");

    let batches = queued.vault.derive_batches_of(queued.dreamer)?;
    assert_eq!(batches.len(), baseline + 1, "one derive batch lands");
    let Some(new) = batches.last().copied() else {
        panic!("one new batch: {batches:?}");
    };
    let Some(record) = queued.vault.derive_batch(new)? else {
        panic!("the batch is recorded");
    };
    let [item] = record.items.as_slice() else {
        panic!("one item: {:?}", record.items);
    };
    assert!(item.landed, "the Settle lands: {item:?}");
    let Some(resolved) = item.rows.first().copied() else {
        panic!("a landed Settle names its answer: {item:?}");
    };
    assert_eq!(
        resolved_settlement(&queued.vault, resolved)?,
        Some("dismiss".to_owned()),
        "the final ask's answer is the ruling"
    );
    assert_eq!(
        claim_lifecycle(&queued.vault, queued.first)?,
        Some("active".to_owned()),
        "dismiss leaves the first active"
    );
    assert_eq!(
        claim_lifecycle(&queued.vault, queued.second)?,
        Some("active".to_owned()),
        "dismiss leaves the second active"
    );
    assert!(
        !marker_open_for_dreamer(&queued.vault, queued.dreamer, queued.person, queued.marker)?,
        "the dismissed marker no longer opens"
    );
    Ok(())
}

#[tokio::test]
async fn a_ladder_withheld_mid_run_lands_the_rulings_made_and_parks_the_attempt()
-> ConflictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let seeded = seeded_vault(&dir)?;
    let flat_white = landed_claim(&seeded, "run-conflict-flat-white", COFFEE, "a flat white")?;
    let cortado = landed_claim(&seeded, "run-conflict-cortado", COFFEE, "a cortado")?;
    let coffee = open_conflict(&seeded.vault, flat_white, cortado)?;
    let green = landed_claim(&seeded, "run-conflict-green", TEA, "green tea")?;
    let black = landed_claim(&seeded, "run-conflict-black", TEA, "black tea")?;
    let tea = open_conflict(&seeded.vault, green, black)?;
    let now = queue_settlement(&seeded.vault)?;
    let listed = AttemptQueue::new(&seeded.vault).list_run(CONFLICT_SETTLE_RUN)?;
    let [attempt] = listed.as_slice() else {
        panic!("one conflict attempt queues: {listed:?}");
    };
    let attempt_id = attempt.id;
    let baseline = seeded.vault.derive_batches_of(seeded.dreamer)?.len();
    for marker in [coffee, tea] {
        assert!(
            marker_open_for_dreamer(&seeded.vault, seeded.dreamer, seeded.person, marker)?,
            "both conflicts open before the pass"
        );
    }
    let lender = Arc::new(FakeLender::scripted(&["keep:C1", WITHHOLD]));
    let mut factory = production_factory_with_host(
        &seeded.vault,
        Arc::clone(&lender),
        ConflictSettleCursor::default(),
    )?;

    run_wake_pass(&seeded.vault, now, &mut factory).await?;

    let recorded = match lender.recorded.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => panic!("the fake lender lock is poisoned"),
    };
    assert_eq!(
        recorded.len(),
        1,
        "one ask is answered before the ladder is withheld"
    );
    let batches = seeded.vault.derive_batches_of(seeded.dreamer)?;
    assert_eq!(
        batches.len(),
        baseline + 1,
        "the ruling made before the ladder was withheld lands"
    );
    let Some(new) = batches.last().copied() else {
        panic!("one new batch: {batches:?}");
    };
    let Some(record) = seeded.vault.derive_batch(new)? else {
        panic!("the batch is recorded");
    };
    let [item] = record.items.as_slice() else {
        panic!("one item: {:?}", record.items);
    };
    assert!(item.landed, "the Settle lands: {item:?}");
    let mut still_open = Vec::new();
    for marker in [coffee, tea] {
        if marker_open_for_dreamer(&seeded.vault, seeded.dreamer, seeded.person, marker)? {
            still_open.push(marker);
        }
    }
    assert_eq!(
        still_open.len(),
        1,
        "the conflict asked after the ladder was withheld stays open"
    );
    let Some(parked) = DreamerRunnerStore::new(&seeded.vault).parked_attempt(attempt_id)? else {
        panic!("the attempt parks once the ladder is withheld");
    };
    assert_eq!(parked.cause, DreamerParkCause::Retry);
    assert!(
        parked.reason.contains("MODEL_UNAVAILABLE"),
        "the park names the withheld ladder: {}",
        parked.reason
    );
    Ok(())
}
