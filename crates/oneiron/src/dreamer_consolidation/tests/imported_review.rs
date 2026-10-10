//! Claims from imported words wait in the owner's import review (ARCH-0027).
//! A pass that meets them again leaves them as the review holds them or as
//! the owner left them, and a whole history's backlog drains a wake at a time.
use super::*;
use crate::claim::ClaimApprovalStatus;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_promotion::{DreamerRunContext, PromotionWriterSink};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::dreamer_wake::{
    DreamerWakeDriver, RunWakePass, WakeCancellation, WakePassStop, WakeTrigger,
};
use crate::entity_id::derived_domains::HISTORY_TURN;
use crate::ingest::history::{
    HistoryConversation, HistoryMessage, HistoryRole, HistorySkips, HistorySource,
    HistoryThreadKind, history_import_review_id,
};
use crate::write_envelope::WriteActor;

const SOURCE: HistorySource = HistorySource::ClaudeCode;

fn said(native_id: &str, role: HistoryRole, text: &str) -> HistoryMessage {
    HistoryMessage {
        native_id: native_id.to_owned(),
        parent_id: None,
        role,
        text: text.to_owned(),
        at_ms: Some(1_700_000_000_000),
        said_by: None,
        tools: Vec::new(),
        alias: None,
    }
}

fn conversation(native_id: &str, messages: Vec<HistoryMessage>) -> HistoryConversation {
    HistoryConversation {
        native_id: native_id.to_owned(),
        kind: HistoryThreadKind::Main,
        parent: None,
        title: None,
        started_at_ms: None,
        messages,
        skipped: HistorySkips::default(),
    }
}

fn owner(vault: &Vault) -> Result<(EntityId, AuthenticatedOwner)> {
    let person = vault.ensure_embedded_owner_actor().expect("owner actor");
    let owner = vault.authenticate_owner(
        person,
        &person.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    Ok((person, owner))
}

fn import(vault: &Vault, owner: &AuthenticatedOwner, session: HistoryConversation, at: u64) {
    vault
        .import_history(owner, SOURCE, &session, at)
        .expect("import");
}

fn admit_meso(vault: &Vault) -> Result<DreamerAdmittedAttempt> {
    match DreamerRunnerStore::new(vault).admit_next_consolidation(
        AdmitDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Meso,
            local_node_id: crate::identity::load_or_mint_client_id(vault)?,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerAttempt {
                lease_owner: "import-worker".to_owned(),
                now: vault.now_recorded_at(),
                budget_id: "wake".to_owned(),
                budget_total_units: 10_000,
                reserve_units: 100,
                started_milestone: None,
            },
        },
    )? {
        DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
            admitted,
        )) => Ok(*admitted),
        other => panic!("{other:?}"),
    }
}

/// The production sink's run: the queue row names none, so the attempt id.
fn sink<'a>(
    vault: &'a Vault,
    admitted: &DreamerAdmittedAttempt,
) -> Result<PromotionWriterSink<'a>> {
    let attempt_id = admitted.status.attempt.id;
    Ok(PromotionWriterSink::new(
        vault,
        DreamerRunContext {
            run_id: bytes_to_hex_lower(attempt_id.as_bytes()),
            attempt_id,
            agent_actor: vault.dreamer_authority()?,
            now_ms: vault.now_recorded_at().saturating_mul(1_000),
        },
    ))
}

/// One direct execution of `admitted`, as a resumed lease runs it.
fn run(
    vault: &Vault,
    admitted: &DreamerAdmittedAttempt,
    backend: &dyn LlmBackend,
    sink: &mut dyn ConsolidationSink,
) -> Result<DreamerAttemptExecution> {
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut executor = ConsolidationExecutor {
        backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink,
        inference: test_inference_host(),
        scope: None,
    };
    block_on_ready(
        executor.execute(
            admitted,
            &mut WakeAttemptContext {
                vault,
                deadline: &deadline,
                budget_id: "wake",
                now_ms: vault
                    .now_recorded_at()
                    .saturating_add(2)
                    .saturating_mul(1_000),
                prepared_wake: None,
                prepared_attempt: None,
            },
        ),
    )
}

/// An extraction of `(predicate, value, byte range)` claims about `subject`,
/// each citing its range of `turn`.
fn extraction(
    subject: EntityId,
    turn: EntityId,
    claims: &[(&str, &str, (usize, usize))],
) -> crate::LlmResponse {
    let candidates: Vec<_> = claims
        .iter()
        .map(|(predicate, value, (start, end))| {
            serde_json::json!({
                "subject": subject.to_hex(), "predicate": predicate, "value": value,
                "confidence": 0.8,
                "evidence_refs": [{"source_id": turn.to_hex(), "byte_range": [start, end]}],
            })
        })
        .collect();
    text_response(serde_json::json!({ "candidates": candidates }).to_string())
}

/// The claims waiting in `review`, as the owner is shown them.
fn review_members(vault: &Vault, person: EntityId, review: &str) -> Result<Vec<EntityId>> {
    Ok(vault
        .review_gate_consent_bundle(&WriteActor::new(person, EdgeActorClass::Human), review)?
        .members
        .iter()
        .map(|member| member.claim_id)
        .collect())
}

/// Greptile 1357 P1 and Astra 1357 #1: a crash after an imported claim
/// committed and before its attempt completed runs the attempt again, before
/// or after the owner decides the review. The attempt completes and leaves
/// the claim as the review holds it or as the owner left it. Astra 1357 #3:
/// words a later import adds to the same TURN make the Dreamer read the old
/// words again; the claim the owner declined is not proposed again, and the
/// new words' claim waits in the later import's review.
#[test]
fn imported_claims_stay_as_the_review_holds_them_when_the_dreamer_meets_them_again() -> Result<()> {
    let (_dir, vault) = open_vault();
    super::prior_heads::policy(&vault, vault.dreamer_authority()?.entity_ref(), true)?;
    let (person, owner) = owner(&vault)?;
    let subject = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    let turn = EntityId::derive(
        HISTORY_TURN,
        &[b"claude-code".as_slice(), b"session-ana", b"u1"],
    )?;
    let first_import = vault.now_recorded_at();
    import(
        &vault,
        &owner,
        conversation(
            "session-ana",
            vec![said("u1", HistoryRole::User, "my name is Ana")],
        ),
        first_import,
    );
    assert_eq!(plan_dirty_turn_rounds(&vault, first_import)?, 1);
    let admitted = admit_meso(&vault)?;
    let backend = ScriptedBackend::new(vec![
        Ok(extraction(
            subject,
            turn,
            &[("profile.name", "Ana", (11, 14))],
        )),
        Ok(extraction(
            subject,
            turn,
            &[
                ("profile.name", "Ana", (11, 14)),
                ("profile.city", "Kyoto", (25, 30)),
            ],
        )),
    ]);
    let mut first = sink(&vault, &admitted)?;
    assert!(matches!(
        run(&vault, &admitted, &backend, &mut first)?,
        DreamerAttemptExecution::Completed { .. }
    ));
    let [name] = first.outcome.pended[..] else {
        panic!("one proposed claim: {:?}", first.outcome)
    };
    let review = history_import_review_id(SOURCE, first_import);
    assert_eq!(review_members(&vault, person, &review)?, [name]);

    // The attempt runs again: its extraction replays, and the claim stays in
    // the review as it is.
    let mut again = sink(&vault, &admitted)?;
    assert!(matches!(
        run(&vault, &admitted, &backend, &mut again)?,
        DreamerAttemptExecution::Completed { .. }
    ));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(again.outcome.pended, [name]);
    assert!(again.outcome.rejected.is_empty());
    assert_eq!(review_members(&vault, person, &review)?, [name]);

    // The owner declines the review; the attempt runs once more, and the
    // claim stays declined.
    let bundle = vault
        .review_gate_consent_bundle(&WriteActor::new(person, EdgeActorClass::Human), &review)?;
    vault.resolve_gate_consent_bundle(
        &owner,
        bundle.bundle_id,
        &review,
        crate::GateConsentBundleAction::Decline,
        vault.now_recorded_at(),
    )?;
    let mut declined = sink(&vault, &admitted)?;
    assert!(matches!(
        run(&vault, &admitted, &backend, &mut declined)?,
        DreamerAttemptExecution::Completed { .. }
    ));
    assert!(declined.outcome.rejected.is_empty());
    let stored = vault.get_claim(&name)?.expect("the declined claim");
    assert_eq!(stored.approval, ClaimApprovalStatus::Rejected);

    // A later import, a second later, adds the owner's next words to the
    // same TURN.
    while vault.now_recorded_at() <= first_import {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let second_import = vault.now_recorded_at();
    import(
        &vault,
        &owner,
        conversation(
            "session-ana",
            vec![
                said("u1", HistoryRole::User, "my name is Ana"),
                said("u2", HistoryRole::User, "I live in Kyoto"),
            ],
        ),
        second_import,
    );
    assert_eq!(plan_dirty_turn_rounds(&vault, second_import)?, 1);
    let next = admit_meso(&vault)?;
    let mut later = sink(&vault, &next)?;
    assert!(matches!(
        run(&vault, &next, &backend, &mut later)?,
        DreamerAttemptExecution::Completed { .. }
    ));
    assert_eq!(later.outcome.held, [name], "{:?}", later.outcome);
    let [city] = later.outcome.pended[..] else {
        panic!("one proposed claim: {:?}", later.outcome)
    };
    assert_eq!(
        vault.get_claim(&city)?.expect("the city claim").predicate,
        "profile.city"
    );
    assert_eq!(
        review_members(
            &vault,
            person,
            &history_import_review_id(SOURCE, second_import)
        )?,
        [city]
    );
    assert!(matches!(
        review_members(&vault, person, &review),
        Err(crate::Error::EntityNotFound)
    ));
    let names = vault
        .claims_for_subject(&subject)?
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).transpose())
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|body| body.predicate == "profile.name")
        .count();
    assert_eq!(names, 1, "the declined name is never proposed again");
    Ok(())
}

/// Completes every attempt the driver hands it.
struct Completing;

impl DreamerAttemptExecutor for Completing {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        Ok(DreamerAttemptExecution::Completed { completed_units: 0 })
    }
}

/// Astra 1357 #4: a whole history planned at once is a backlog larger than
/// one wake should read. A wake prepares one Meso round's worth of TURNs from
/// the head of the ready queue; its pass works through that head, stops at
/// the rest, and the passes after it drain the backlog.
#[test]
fn a_whole_history_import_drains_one_round_of_turns_per_wake_pass() -> Result<()> {
    const IMPORTED_AT: u64 = 1_800_000_000;
    let clock = crate::ports::ManualClock::new(IMPORTED_AT);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    crate::test_util::provision_engine_machines(&vault);
    install_shipped_policy(&vault)?;
    let (_, owner) = owner(&vault)?;
    // Three sessions of 200 one-message TURNs: past one round's 500.
    for session in ["a", "b", "c"] {
        let messages = (0..200)
            .map(|index| {
                let role = if index % 2 == 0 {
                    HistoryRole::User
                } else {
                    HistoryRole::Assistant
                };
                said(
                    &format!("{session}-{index}"),
                    role,
                    &format!("line {index}"),
                )
            })
            .collect();
        import(
            &vault,
            &owner,
            conversation(&format!("session-{session}"), messages),
            IMPORTED_AT,
        );
    }
    let queued = plan_dirty_turn_rounds(&vault, IMPORTED_AT)?;
    assert!(queued > 1, "{queued} attempts");

    let node_id = crate::identity::load_or_mint_client_id(&vault)?;
    let mut executor = Completing;
    let (mut stops, mut settled) = (Vec::new(), 0);
    for pass in 1..=10 {
        let now = IMPORTED_AT + 10 * pass;
        clock.set(now);
        let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
        let mut driver = DreamerWakeDriver::new(&vault, "wake", deadline);
        let input = RunWakePass {
            trigger: WakeTrigger::Compaction,
            scope: DreamerConsolidationScope::Meso,
            local_node_id: node_id,
            lease_owner: "import-worker".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 100,
            now,
            host_scope: None,
        };
        let cancellation = WakeCancellation::new();
        let mut future = std::pin::pin!(driver.run_wake_pass(input, &mut executor, &cancellation));
        let mut cx = Context::from_waker(Waker::noop());
        let report = loop {
            if let Poll::Ready(report) = future.as_mut().poll(&mut cx) {
                break report?;
            }
        };
        settled += report.completed + report.parked;
        stops.push(report.stop);
        if report.stop == WakePassStop::QueueEmpty {
            break;
        }
    }
    assert_eq!(stops[0], WakePassStop::BacklogLeft, "{stops:?}");
    assert_eq!(stops.last(), Some(&WakePassStop::QueueEmpty), "{stops:?}");
    assert_eq!(settled as usize, queued, "every queued attempt ran once");
    Ok(())
}
