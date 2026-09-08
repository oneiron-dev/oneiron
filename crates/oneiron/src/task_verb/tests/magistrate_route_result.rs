//! Task verb tests: Magistrate verdicts and provenance, counter and terminal projection, assignee routing, execution facts and result landing.

use super::support::*;
use super::*;

/// Authorship is re-derived from the vault's own claim/provenance
/// envelopes: a contested state written under the Dreamer run surface
/// recuses, and the SAME case shape over agent-authored state rules.
#[test]
fn magistrate_recuses_on_vault_derived_dreamer_authorship() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let subject = other_actor(&vault);
    let dreamer_state = ladder_id(0x94);
    let agent_state = ladder_id(0x95);
    let delta = ladder_id(0x96);
    // Dreamer-surface state, so GATE-12 asks it for evidence: cite the
    // subject this fixture seeds. Authorship derivation below is unchanged.
    put_envelope_claim_citing(
        &vault,
        dreamer_state,
        subject,
        actor,
        EdgeActorClass::Agent,
        dreamer_provenance(),
        Some(subject),
    );
    put_envelope_claim(
        &vault,
        agent_state,
        subject,
        actor,
        EdgeActorClass::Agent,
        agent_provenance(),
    );
    put_envelope_claim(
        &vault,
        delta,
        subject,
        actor,
        EdgeActorClass::Agent,
        agent_provenance(),
    );

    let dreamer_case = magistrate_case(dreamer_state, delta, CaseCriticality::Normal);
    let agent_case = magistrate_case(agent_state, delta, CaseCriticality::Normal);

    assert_eq!(
        derive_state_authorship(&vault, &dreamer_case).expect("authorship derives"),
        StateAuthorship::Dreamer
    );
    assert_eq!(
        derive_state_authorship(&vault, &agent_case).expect("authorship derives"),
        StateAuthorship::OtherAgent
    );
    assert_eq!(
        decide_magistrate(&vault, &dreamer_case).expect("verdict"),
        MagistrateVerdict::Recused {
            reason: MagistrateRecusal::DreamerAuthoredState
        }
    );
    // The recusal is the provenance talking, not a blanket refusal.
    assert_eq!(
        decide_magistrate(&vault, &agent_case).expect("verdict"),
        MagistrateVerdict::Rule {
            selected_delta_ref: delta,
            rationale_ref: ladder_id(0x92),
        }
    );
}

/// A caller cannot buy a ruling with a forged summary: with every case
/// field naming another agent, Dreamer authorship of the contested DELTA
/// still recuses, and unattributable state fails closed.
#[test]
fn forged_authorship_cannot_defeat_the_provenance_derivation() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let subject = other_actor(&vault);
    let agent_state = ladder_id(0x97);
    let dreamer_delta = ladder_id(0x98);
    put_envelope_claim(
        &vault,
        agent_state,
        subject,
        actor,
        EdgeActorClass::Agent,
        agent_provenance(),
    );
    // Same GATE-12 evidence floor on the Dreamer-surface DELTA; the forged
    // case summary and its assertions are untouched.
    put_envelope_claim_citing(
        &vault,
        dreamer_delta,
        subject,
        actor,
        EdgeActorClass::Agent,
        dreamer_provenance(),
        Some(subject),
    );

    let forged = magistrate_case(agent_state, dreamer_delta, CaseCriticality::Normal);
    let unattributable = magistrate_case(ladder_id(0x99), dreamer_delta, CaseCriticality::Normal);

    assert_eq!(
        decide_magistrate(&vault, &forged).expect("verdict"),
        MagistrateVerdict::Recused {
            reason: MagistrateRecusal::DreamerAuthoredState
        }
    );
    assert!(
        decide_magistrate(&vault, &unattributable).is_err(),
        "state with no recoverable attribution is not ruled on"
    );
}

/// The magistrate's whole write set is receipt + supersession + conflict
/// claim. It enqueues no work, schedules no outbound, and deletes nothing.
#[test]
fn applying_a_ruling_writes_only_reversible_records() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let subject = other_actor(&vault);
    let state = ladder_id(0x9A);
    let selected = ladder_id(0x9B);
    let competing = ladder_id(0x9C);
    for claim_ref in [state, selected, competing] {
        put_envelope_claim(
            &vault,
            claim_ref,
            subject,
            actor,
            EdgeActorClass::Agent,
            agent_provenance(),
        );
    }
    let mut case = magistrate_case(state, selected, CaseCriticality::Normal);
    case.candidate_delta_refs = vec![selected, competing];

    let attempts_before = AttemptQueue::new(&vault).list().expect("attempts").len();
    let conflicts_before = open_conflict_count(&vault);
    let verdict = decide_magistrate(&vault, &case).expect("verdict");
    let receipt = apply_magistrate_verdict(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        &case,
        &verdict,
    )
    .expect("ruling applies");
    let attempts_after = AttemptQueue::new(&vault).list().expect("attempts").len();

    assert_eq!(
        verdict,
        MagistrateVerdict::Rule {
            selected_delta_ref: selected,
            rationale_ref: ladder_id(0x92),
        }
    );
    assert!(receipt.reversible);
    assert_eq!(receipt.appeal_handle, case.task_ref);
    assert_eq!(
        attempts_after, attempts_before,
        "a ruling enqueues no work of any kind"
    );
    assert_eq!(
        vault
            .get_entity_type(&receipt.receipt_ref)
            .expect("receipt type"),
        Some(ENTITY_TYPE_TURN)
    );
    // The replaced head was superseded through the EXISTING claim API, and
    // the surviving competitor surfaced as the existing conflict predicate.
    assert_eq!(
        vault
            .get_claim(&state)
            .expect("state claim")
            .expect("stored")
            .lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(open_conflict_count(&vault) - conflicts_before, 1);
}

/// Advice is receipted but never applied: a critical case leaves the
/// contested head exactly where it was.
#[test]
fn a_critical_case_is_advised_and_never_applied() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let subject = other_actor(&vault);
    let state = ladder_id(0x9D);
    let delta = ladder_id(0x9E);
    for claim_ref in [state, delta] {
        put_envelope_claim(
            &vault,
            claim_ref,
            subject,
            actor,
            EdgeActorClass::Agent,
            agent_provenance(),
        );
    }
    let case = magistrate_case(state, delta, CaseCriticality::Critical);

    let verdict = decide_magistrate(&vault, &case).expect("verdict");
    apply_magistrate_verdict(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        &case,
        &verdict,
    )
    .expect("advice is receipted");

    assert_eq!(
        verdict,
        MagistrateVerdict::AdviceOnly {
            recommended_delta_ref: Some(delta),
            rationale_ref: ladder_id(0x92),
        }
    );
    assert_eq!(
        vault
            .get_claim(&state)
            .expect("state claim")
            .expect("stored")
            .lifecycle,
        ClaimLifecycleStatus::Active,
        "advice cannot terminalize the contested state"
    );
}

/// An overturn leaves the original receipt intact and writes exactly one
/// typed record — the complete ED handoff, with no ED call.
#[test]
fn an_overturn_preserves_the_original_receipt() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let subject = other_actor(&vault);
    let state = ladder_id(0x6A);
    let delta = ladder_id(0x6B);
    for claim_ref in [state, delta] {
        put_envelope_claim(
            &vault,
            claim_ref,
            subject,
            actor,
            EdgeActorClass::Agent,
            agent_provenance(),
        );
    }
    let case = magistrate_case(state, delta, CaseCriticality::Normal);
    let verdict = decide_magistrate(&vault, &case).expect("verdict");
    let receipt = apply_magistrate_verdict(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        &case,
        &verdict,
    )
    .expect("ruling applies");
    let receipt_bytes = vault
        .get_raw(&receipt.receipt_ref)
        .expect("receipt read")
        .expect("receipt stored");

    let overturn_ref = record_magistrate_overturn(
        &vault,
        &MagistrateOverturnRecord {
            original_receipt_ref: receipt.receipt_ref,
            overturning_verdict_ref: ladder_id(0xA3),
            corrected_delta_ref: Some(delta),
            rationale_ref: ladder_id(0xA4),
            occurred_at: LADDER_NOW + 10,
        },
    )
    .expect("overturn records");

    assert_ne!(overturn_ref, receipt.receipt_ref);
    assert_eq!(
        vault
            .get_raw(&receipt.receipt_ref)
            .expect("receipt read")
            .expect("receipt stored"),
        receipt_bytes,
        "the original receipt is never erased or rewritten"
    );
    assert_eq!(
        vault.get_entity_type(&overturn_ref).expect("overturn type"),
        Some(ENTITY_TYPE_TURN)
    );
}

/// Magistrate work rides the EXISTING Dreamer runner queue as a
/// payload-level attempt type under the unchanged outer kind.
#[test]
fn magistrate_work_enqueues_as_a_payload_level_attempt_type() {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let case = magistrate_case(ladder_id(0xB2), ladder_id(0xB3), CaseCriticality::Normal);

    let outcome = enqueue_magistrate(&store, &case, None, Some("run-magistrate".to_owned()))
        .expect("magistrate enqueues");
    let replay = enqueue_magistrate(&store, &case, None, Some("run-magistrate".to_owned()))
        .expect("magistrate re-enqueue");

    let EnqueueDreamerAttemptOutcome::Enqueued(status) = outcome else {
        panic!("the first enqueue is not a dedupe hit");
    };
    assert_eq!(status.payload.attempt_type, DREAMER_MAGISTRATE_ATTEMPT_TYPE);
    assert_eq!(status.attempt.kind, DREAMER_RUNNER_ATTEMPT_KIND);
    assert!(matches!(replay, EnqueueDreamerAttemptOutcome::Existing(_)));
}

/// The board reads the ladder outcome off the persisted row: a countered
/// original renders as an immutable rejected row naming its successor,
/// while the counter renders independently.
#[test]
fn a_countered_original_renders_as_rejected_with_its_counter() {
    let (_dir, vault) = open_vault();
    let fixture = cross_actor_fixture(&vault);
    let facade = vault.memory(fixture.proposer, EdgeActorClass::Agent);
    let delta = ladder_delta(
        fixture.target,
        fixture.delta_ref,
        fixture.proposer,
        fixture.owner,
    );
    let CrossActorRoute::ConsultOwner { receipt } = facade
        .route_entity_delta(delta.clone(), None, LADDER_DEADLINE, LADDER_NOW)
        .expect("cross-actor delta routes")
    else {
        panic!("expected an owner consult");
    };
    let original = receipt.task_ref.expect("consult minted");
    let counter = facade
        .mint_counter_task(original, delta, LADDER_DEADLINE, LADDER_NOW + 5)
        .expect("counter mints")
        .task_ref
        .expect("counter task minted");

    let section = facade.tasks_check().expect("board renders");
    let original_row = section
        .rows
        .iter()
        .find(|row| row.id == original.to_hex())
        .expect("the countered original stays on the board");
    let counter_row = section
        .rows
        .iter()
        .find(|row| row.id == counter.to_hex())
        .expect("the counter renders independently");

    assert_eq!(original_row.status, TaskBoardStatus::Failed);
    assert_eq!(
        original_row.ladder_disposition,
        Some(LadderTerminalDisposition::Countered)
    );
    assert_eq!(
        original_row.counter_task_ref.as_deref(),
        Some(counter.to_hex().as_str())
    );
    let tokens: Vec<&str> = original_row.line.split_whitespace().collect();
    assert!(tokens.contains(&"rejected"), "{}", original_row.line);
    assert!(tokens.contains(&"countered"), "{}", original_row.line);
    // The counter is its own row: no ladder outcome of its own yet, and
    // no counter link pointing anywhere.
    assert_eq!(counter_row.ladder_disposition, None);
    assert_eq!(counter_row.counter_task_ref, None);
    assert_ne!(counter_row.id, original_row.id);
}

/// An ESCALATED consult settled on the ladder axis while its TASK row stayed
/// live. The board reads the outcome off THAT half too: the escalation's
/// disposition and its durable receipt, on the queued lane where the ladder
/// projection puts it — not a bare pause whose stored refs have vanished.
///
/// The consult's own deadline is long past by the wall clock the board reads,
/// and derives nothing here: a settled ladder is an answer, which is the same
/// reading the expiry sweep takes of the row.
#[test]
fn an_escalated_consult_renders_its_escalation_rather_than_a_bare_pause() {
    let (_dir, vault) = open_vault();
    let asker = own_agent(&vault);
    let (task_ref, _peer, _question) = open_consult(&vault);
    let escalated = escalate_consult(&vault, task_ref, ladder_id(0xC6), LADDER_NOW + 1);

    let section = vault
        .memory(asker, EdgeActorClass::Agent)
        .tasks_check()
        .expect("board renders");
    let row = section
        .rows
        .iter()
        .find(|row| row.id == task_ref.to_hex())
        .expect("an escalated consult stays on the board");

    assert_eq!(
        row.ladder_disposition,
        Some(LadderTerminalDisposition::Escalated)
    );
    assert_eq!(
        row.result_ref.as_deref(),
        Some(escalated.result_ref.to_hex().as_str())
    );
    // An escalation names no successor task; only a counter does.
    assert_eq!(row.counter_task_ref, None);
    assert_eq!(row.status, TaskBoardStatus::Queued);
    assert_eq!(row.terminal_disposition, None);
    let tokens: Vec<&str> = row.line.split_whitespace().collect();
    assert!(tokens.contains(&"interrupted"), "{}", row.line);
    assert!(tokens.contains(&"escalated"), "{}", row.line);
}

/// A counter answers to the same attribution laws as the original ask:
/// a forged owner or an unattributed proposer never mints one.
#[test]
fn a_counter_cannot_forge_its_owner_or_proposer() {
    let (_dir, vault) = open_vault();
    let fixture = cross_actor_fixture(&vault);
    let facade = vault.memory(fixture.proposer, EdgeActorClass::Agent);
    let delta = ladder_delta(
        fixture.target,
        fixture.delta_ref,
        fixture.proposer,
        fixture.owner,
    );
    let CrossActorRoute::ConsultOwner { receipt } = facade
        .route_entity_delta(delta, None, LADDER_DEADLINE, LADDER_NOW)
        .expect("cross-actor delta routes")
    else {
        panic!("expected an owner consult");
    };
    let original = receipt.task_ref.expect("consult minted");

    let forged_owner = facade
        .mint_counter_task(
            original,
            ladder_delta(
                fixture.target,
                fixture.delta_ref,
                fixture.proposer,
                fixture.proposer,
            ),
            LADDER_DEADLINE,
            LADDER_NOW + 5,
        )
        .expect_err("a forged owner is refused");
    let forged_proposer = facade
        .mint_counter_task(
            original,
            ladder_delta(
                fixture.target,
                fixture.delta_ref,
                fixture.owner,
                fixture.owner,
            ),
            LADDER_DEADLINE,
            LADDER_NOW + 5,
        )
        .expect_err("an unattributed proposer is refused");
    let original_body = task_verb_body(&vault, original)
        .expect("decode original")
        .expect("original is typed");

    assert_eq!(forged_owner.code, MEMORY_CODE_FORBIDDEN);
    assert_eq!(forged_proposer.code, MEMORY_CODE_FORBIDDEN);
    assert_eq!(
        original_body.terminal(),
        None,
        "a refused counter never terminalizes the original"
    );
}

/// An UNSTAMPED ONE-1699 terminal projects its OWN disposition: `expired`
/// is not rounded to the nearest ladder word, and no interruption kind is
/// invented for a body that never recorded one.
#[test]
fn an_unstamped_legacy_terminal_projects_its_own_disposition() {
    let (_dir, vault) = open_vault();
    let (task_ref, _peer, _question) = open_consult(&vault);
    let facade = vault.memory(own_agent(&vault), EdgeActorClass::Agent);
    grant_outbound(&vault, own_agent(&vault), 0xC8);
    facade
        .settle_due_consults(CONSULT_DEADLINE + 1, &digest_route())
        .expect("the expiry sweep runs");

    let projection = project_consult_task_to_a2a(&vault, task_ref)
        .expect("projection reads")
        .expect("the expired consult projects");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode consult")
        .expect("consult is typed");

    assert_eq!(body.terminal().and_then(|record| record.ladder), None);
    assert_eq!(projection.state, A2aBaseTaskState::Cancelled);
    assert_eq!(
        projection.extensions.terminal_disposition.as_deref(),
        Some("expired")
    );
    assert_eq!(projection.extensions.interruption_kind, None);
    assert!(projection.extensions.result_ref.is_some());
}

/// The A2A projection reads a real persisted consult, including its
/// counter lineage. A counter is a decision that COMPLETED, never a
/// failure.
#[test]
fn a_persisted_counter_projects_with_its_counter_of_extension() {
    let (_dir, vault) = open_vault();
    let fixture = cross_actor_fixture(&vault);
    let facade = vault.memory(fixture.proposer, EdgeActorClass::Agent);
    let delta = ladder_delta(
        fixture.target,
        fixture.delta_ref,
        fixture.proposer,
        fixture.owner,
    );
    let CrossActorRoute::ConsultOwner { receipt } = facade
        .route_entity_delta(delta.clone(), None, LADDER_DEADLINE, LADDER_NOW)
        .expect("cross-actor delta routes")
    else {
        panic!("expected an owner consult");
    };
    let original = receipt.task_ref.expect("consult minted");
    let counter = facade
        .mint_counter_task(original, delta, LADDER_DEADLINE, LADDER_NOW + 5)
        .expect("counter mints")
        .task_ref
        .expect("counter task minted");

    let original_projection = project_consult_task_to_a2a(&vault, original)
        .expect("projection reads")
        .expect("the original projects");
    let counter_projection = project_consult_task_to_a2a(&vault, counter)
        .expect("projection reads")
        .expect("the counter projects");

    assert_eq!(original_projection.state, A2aBaseTaskState::Completed);
    assert_eq!(
        original_projection
            .extensions
            .terminal_disposition
            .as_deref(),
        Some("rejected")
    );
    assert_eq!(
        counter_projection.extensions.counter_of.as_deref(),
        Some(original.to_hex().as_str())
    );
}

/// Compatibility: a schema-v1 create — assignee absent entirely — still
/// mints exactly one `tasks.realize` attempt on the Dreamer lane.
#[test]
fn absent_assignee_routes_to_one_dreamer_realization() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let receipt = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(None))
        .expect("create");
    let task_ref = receipt.task_ref.expect("task ref");
    let attempts = attempts_for(&vault, task_ref);

    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].kind, TASK_REALIZE_ATTEMPT_KIND);
    assert_eq!(
        receipt.route.map(TaskRouteOutcome::lane),
        Some(TaskRouteLane::Dreamer)
    );
    assert_eq!(
        receipt.route.and_then(TaskRouteOutcome::local_attempt),
        Some(attempts[0].id)
    );
}

/// `Some(Dreamer)` and absent are the SAME lane: one realize attempt, and
/// the explicit spelling is what lands on the row.
#[test]
fn explicit_dreamer_assignee_routes_exactly_like_absent() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let receipt = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Dreamer)))
        .expect("create");
    let task_ref = receipt.task_ref.expect("task ref");
    let attempts = attempts_for(&vault, task_ref);
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].kind, TASK_REALIZE_ATTEMPT_KIND);
    assert_eq!(body.assignee, Some(TaskAssignee::Dreamer));
    assert_eq!(
        receipt.route.map(TaskRouteOutcome::lane),
        Some(TaskRouteLane::Dreamer)
    );
}

/// The agent-definition lane creates ONE in-process `agent.dispatch`
/// attempt, backlinked to the TASK, and never a `tasks.realize` row.
#[test]
fn agent_def_assignee_routes_to_one_in_process_dispatch() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let agent_def_ref = routable_agent_def(&vault, 0xC1);
    let receipt = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::AgentDef { agent_def_ref })))
        .expect("create");
    let task_ref = receipt.task_ref.expect("task ref");
    let attempts = attempts_for(&vault, task_ref);
    let payload = decode_dreamer_attempt_payload(&attempts[0].payload).expect("dispatch payload");

    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].kind, DREAMER_RUNNER_ATTEMPT_KIND);
    assert_eq!(payload.attempt_type, AGENT_DISPATCH_ATTEMPT_TYPE);
    assert_eq!(
        receipt.route,
        Some(TaskRouteOutcome::AgentDispatch {
            attempt_ref: attempts[0].id,
            agent_def_ref,
        })
    );
}

/// The dispatched child freezes the CURRENT definition snapshot and
/// addresses the ROW: no preset variant is persisted anywhere (ONE-1890
/// compatibility, proven from the stored bytes).
#[test]
fn agent_def_route_persists_a_row_ref_and_no_preset() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let agent_def_ref = routable_agent_def(&vault, 0xC2);
    let receipt = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::AgentDef { agent_def_ref })))
        .expect("create");
    let task_ref = receipt.task_ref.expect("task ref");
    let attempts = attempts_for(&vault, task_ref);
    let payload = decode_dreamer_attempt_payload(&attempts[0].payload).expect("dispatch payload");
    let dispatch_input =
        decode_agent_dispatch_input(&payload.input).expect("decode dispatch input");
    let stored_body = vault.get(&task_ref).expect("read task").expect("task row");
    let stored_text = String::from_utf8_lossy(&stored_body).to_ascii_lowercase();

    assert_eq!(
        dispatch_input.target,
        AgentDispatchTarget::Custom(agent_def_ref)
    );
    assert_eq!(
        dispatch_input.definition.agent_id.as_str(),
        format!("route-worker-{:02x}", 0xC2).as_str()
    );
    assert_eq!(usize::from(stored_text.contains("preset")), 0);
    assert_eq!(usize::from(stored_text.contains("system")), 0);
}

/// Re-routing the SAME task ref returns the existing dispatch instead of
/// minting a second one, and the dedupe row keeps its parent/run metadata.
#[test]
fn agent_def_route_is_idempotent_by_task_ref() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let agent_def_ref = routable_agent_def(&vault, 0xC3);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let receipt = facade
        .tasks_create(&route_spec(Some(TaskAssignee::AgentDef { agent_def_ref })))
        .expect("create");
    let task_ref = receipt.task_ref.expect("task ref");
    let first = attempts_for(&vault, task_ref);
    // A retried route on the SAME task: the dispatcher's namespaced dedupe
    // key resolves to the row already realizing it.
    let replayed = AgentDispatcher::new(&vault)
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(agent_def_ref),
            parent_attempt: None,
            dedupe_key: Some(task_route_dedupe_key(task_ref)),
            run_id: None,
            now: ROUTE_NOW,
        })
        .expect("replayed dispatch");
    let after = attempts_for(&vault, task_ref);

    assert_eq!(first.len(), 1);
    assert_eq!(after.len(), 1);
    assert_eq!(
        match replayed {
            AgentDispatchOutcome::Existing(status) => status.attempt.id,
            AgentDispatchOutcome::Dispatched(_) => panic!("a replayed route must dedupe"),
        },
        first[0].id
    );
}

/// The peer lane mints the synced TASK and NOTHING local: no realize row,
/// no dispatch row, no synthetic transport attempt.
#[test]
fn peer_assignee_routes_with_zero_local_attempts() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xC4);
    let receipt = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("create");
    let task_ref = receipt.task_ref.expect("task ref");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(attempts_for(&vault, task_ref).len(), 0);
    assert_eq!(
        AttemptQueue::new(&vault).list().expect("list").len(),
        0,
        "the peer lane mints no local attempt of any kind"
    );
    assert_eq!(body.assignee, Some(TaskAssignee::Peer { actor_ref }));
    assert_eq!(
        receipt.route,
        Some(TaskRouteOutcome::PeerSyncedOnly { actor_ref })
    );
}

/// A person the vault knows but cannot reach natively is refused in its own
/// name, and the refusal rolls the WHOLE create back (ONE-1708). The
/// reachability check lives inside the create transaction precisely so this
/// cannot leave a human task with nothing tracking it.
#[test]
fn unreachable_human_assignee_rolls_the_whole_create_back() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    // A bare PERSON row: a real entity the assignee validator admits, with
    // no connected channel behind it.
    let actor_ref = route_peer(&vault, 0xC5);
    let error = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Human { actor_ref })))
        .expect_err("an unreachable person is refused");

    assert_eq!(error.code, MEMORY_CODE_INVALID_STATE);
    assert_eq!(
        task_entity_census(&vault),
        0,
        "the TASK write rolls back with its follow-up cursor"
    );
    assert_eq!(
        task_authority_fact_census(&vault),
        0,
        "the owner proof rolls back with the task it proves"
    );
    assert!(
        crate::human_task::human_followup_records(&vault)
            .expect("cursors")
            .is_empty()
    );
    assert_eq!(AttemptQueue::new(&vault).list().expect("list").len(), 0);
}

/// An assignee that names no live row — or names the WRONG kind — is
/// refused before the TASK write, not compensated afterwards.
#[test]
fn agent_def_assignee_rejects_dangling_and_mistyped_rows_before_mutation() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let dangling = route_dangling(0xC6);
    let person = route_peer(&vault, 0xC7);

    let missing = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::AgentDef {
            agent_def_ref: dangling,
        })))
        .expect_err("a dangling agent definition is refused");
    let mistyped = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::AgentDef {
            agent_def_ref: person,
        })))
        .expect_err("a PERSON row is not an agent definition");

    assert_eq!(missing.code, mistyped.code);
    assert_eq!(task_entity_census(&vault), 0);
    assert_eq!(AttemptQueue::new(&vault).list().expect("list").len(), 0);
}

/// The synced TASK body carries the execution FACTS and none of the local
/// ACT mechanics: no lease owner, lock, trap id, or wait binding.
#[test]
fn task_body_carries_facts_and_never_local_lease_or_trap_state() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xC8);
    let peer_facade = vault.memory(actor_ref, EdgeActorClass::Agent);
    let receipt = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("create");
    let task_ref = receipt.task_ref.expect("task ref");
    peer_facade
        .mark_task_started(task_ref, ROUTE_NOW + 5)
        .expect("start");
    let result_ref = route_turn(&vault, 0xC9).entity_ref();
    peer_facade
        .land_task_result(
            task_ref,
            &TaskResultInput {
                result_ref,
                disposition: TaskTerminalDisposition::Abandoned,
                finished_at: ROUTE_NOW + 9,
            },
        )
        .expect("land result");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");
    let terminal = body.terminal().expect("terminal record").clone();
    let stored = vault.get(&task_ref).expect("read task").expect("task row");
    let stored_text = String::from_utf8_lossy(&stored).to_ascii_lowercase();

    assert_eq!(body.assignee, Some(TaskAssignee::Peer { actor_ref }));
    assert_eq!(terminal.disposition, TaskTerminalDisposition::Abandoned);
    assert_eq!(terminal.result_ref, Some(result_ref));
    for act_marker in [
        "lease_owner",
        "lease",
        "lock",
        "trap",
        "park_owner",
        "peer_wait",
    ] {
        assert_eq!(
            usize::from(stored_text.contains(act_marker)),
            0,
            "synced TASK body must not carry local ACT mechanics: {act_marker}"
        );
    }
}

/// `started_at` stamps once. A re-delivered start reports the FIRST
/// instant and mutates nothing — a redelivery is not a restart.
#[test]
fn mark_task_started_stamps_once_and_replays_idempotently() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xCA);
    let peer_facade = vault.memory(actor_ref, EdgeActorClass::Agent);
    let task_ref = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("create")
        .task_ref
        .expect("task ref");

    let first = peer_facade
        .mark_task_started(task_ref, ROUTE_NOW + 5)
        .expect("first start");
    let replay = peer_facade
        .mark_task_started(task_ref, ROUTE_NOW + 40)
        .expect("replayed start");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(first.started_at, ROUTE_NOW + 5);
    assert_eq!(usize::from(first.idempotent_replay), 0);
    assert_eq!(replay.started_at, ROUTE_NOW + 5);
    assert_eq!(usize::from(replay.idempotent_replay), 1);
    assert_eq!(
        body.state,
        Some(TaskExecutionState::Working {
            started_at: ROUTE_NOW + 5
        })
    );
}

/// Execution facts are ADDRESSED writes: an actor who is not the assignee
/// cannot start or settle someone else's task.
#[test]
fn execution_facts_refuse_an_unaddressed_writer() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xCB);
    let stranger = route_peer(&vault, 0xCC);
    let task_ref = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("create")
        .task_ref
        .expect("task ref");
    let result_ref = route_turn(&vault, 0xCD).entity_ref();
    let stranger_facade = vault.memory(stranger, EdgeActorClass::Agent);

    let start_error = stranger_facade
        .mark_task_started(task_ref, ROUTE_NOW + 5)
        .expect_err("a stranger cannot start an addressed task");
    let land_error = stranger_facade
        .land_task_result(
            task_ref,
            &TaskResultInput {
                result_ref,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: ROUTE_NOW + 9,
            },
        )
        .expect_err("a stranger cannot settle an addressed task");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(start_error.code, MEMORY_CODE_FORBIDDEN);
    assert_eq!(land_error.code, MEMORY_CODE_FORBIDDEN);
    assert_eq!(body.state, Some(TaskExecutionState::Queued));
}

/// The local Dreamer has no actor row, so its lane answers to the task
/// OWNER — the principal the engine drives realization under.
#[test]
fn dreamer_lane_execution_facts_answer_to_the_owner() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let task_ref = facade
        .tasks_create(&route_spec(Some(TaskAssignee::Dreamer)))
        .expect("create")
        .task_ref
        .expect("task ref");
    let result_ref = route_turn(&vault, 0xCE).entity_ref();

    let started = facade
        .mark_task_started(task_ref, ROUTE_NOW + 5)
        .expect("owner starts its own dreamer task");
    let landed = facade
        .land_task_result(
            task_ref,
            &TaskResultInput {
                result_ref,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: ROUTE_NOW + 9,
            },
        )
        .expect("owner settles its own dreamer task");

    assert_eq!(started.started_at, ROUTE_NOW + 5);
    assert_eq!(landed.terminal.result_ref, Some(result_ref));
    assert_eq!(usize::from(landed.idempotent_replay), 0);
}

/// Terminal records are immutable and always carry `result_ref`. A
/// byte-identical replay reports the winner; a CONFLICTING one is refused.
#[test]
fn terminal_results_are_immutable_and_always_carry_a_result_ref() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xCF);
    let peer_facade = vault.memory(actor_ref, EdgeActorClass::Agent);
    let task_ref = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("create")
        .task_ref
        .expect("task ref");
    let result_ref = route_turn(&vault, 0xD0).entity_ref();
    let other_ref = route_turn(&vault, 0xD1).entity_ref();
    let input = TaskResultInput {
        result_ref,
        disposition: TaskTerminalDisposition::Completed,
        finished_at: ROUTE_NOW + 9,
    };

    let landed = peer_facade
        .land_task_result(task_ref, &input)
        .expect("land result");
    let replay = peer_facade
        .land_task_result(task_ref, &input)
        .expect("identical replay reports the winner");
    let conflict = peer_facade
        .land_task_result(
            task_ref,
            &TaskResultInput {
                result_ref: other_ref,
                disposition: TaskTerminalDisposition::Failed,
                finished_at: ROUTE_NOW + 30,
            },
        )
        .expect_err("a converged terminal task is immutable");

    assert_eq!(landed.terminal.result_ref, Some(result_ref));
    assert_eq!(usize::from(landed.idempotent_replay), 0);
    assert_eq!(usize::from(replay.idempotent_replay), 1);
    assert_eq!(replay.terminal.result_ref, Some(result_ref));
    assert_eq!(conflict.code, MEMORY_CODE_INVALID_STATE);
}

/// A result whose `result_ref` names nothing is refused: a terminal record
/// without durable outputs is exactly what the floor forbids.
#[test]
fn land_task_result_requires_a_resolved_result_ref() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xD2);
    let task_ref = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("create")
        .task_ref
        .expect("task ref");

    let error = vault
        .memory(actor_ref, EdgeActorClass::Agent)
        .land_task_result(
            task_ref,
            &TaskResultInput {
                result_ref: route_dangling(0xD3),
                disposition: TaskTerminalDisposition::Completed,
                finished_at: ROUTE_NOW + 9,
            },
        )
        .expect_err("a dangling result ref is refused");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(usize::from(error.code.is_empty()), 0);
    assert_eq!(body.state, Some(TaskExecutionState::Queued));
}

/// Delegation returns the C9 durable wait keyed on the delegated TASK, and
/// refuses any assignee that is not a peer actor.
#[test]
fn delegate_task_and_wait_returns_a_peer_result_wait_on_the_task_ref() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xD4);
    let facade = vault.memory(own, EdgeActorClass::Agent);

    let (receipt, wait) = facade
        .delegate_task_and_wait(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("delegate");
    let not_a_peer = facade
        .delegate_task_and_wait(&route_spec(Some(TaskAssignee::Dreamer)))
        .expect_err("only a peer actor can be delegated to");

    assert_eq!(wait.wait_id, receipt.task_ref.expect("task ref"));
    assert_eq!(wait.effect, crate::code_run::SelfEffect::TaskDelegate);
    assert_eq!(
        wait.reason,
        crate::code_run::SelfDurableWaitReason::PeerResult
    );
    assert_eq!(wait.prompt, None);
    assert_eq!(usize::from(not_a_peer.code.is_empty()), 0);
}

/// A consult still routes as a peer task and still enforces ONE-1699's
/// evidence/abstention contract after general result routing landed.
#[test]
fn consult_regression_survives_general_result_routing() {
    let (_dir, vault) = open_vault();
    let (task_ref, peer, question) = open_consult(&vault);
    let peer_facade = vault.memory(peer, EdgeActorClass::Agent);

    let answer_ref = route_turn(&vault, 0xDA).entity_ref();
    let receipt = peer_facade
        .land_consult_result(task_ref, &answer_input(answer_ref, question))
        .expect("evidence answer still lands");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");
    let terminal = body.terminal().expect("terminal record");

    assert_eq!(attempts_for(&vault, task_ref).len(), 0);
    assert_eq!(usize::from(receipt.idempotent_replay), 0);
    assert_eq!(terminal.disposition, TaskTerminalDisposition::Completed);
    assert_eq!(
        usize::from(matches!(
            terminal.summary,
            Some(ConsultResultSummary::Answer { .. })
        )),
        1
    );
}

/// The general result door must NOT be a second way to settle a consult:
/// a consult's terminal record carries the ONE-1699 evidence-or-abstention
/// summary, and the general input cannot express one. Without this the
/// addressed peer could settle its consult with a bare result ref and no
/// evidence at all — weakening exactly the contract ONE-1700 must preserve.
#[test]
fn the_general_result_door_cannot_settle_a_consult() {
    let (_dir, vault) = open_vault();
    let (task_ref, peer, question) = open_consult(&vault);
    let peer_facade = vault.memory(peer, EdgeActorClass::Agent);
    let result_ref = route_turn(&vault, 0xDC).entity_ref();

    // The ADDRESSED peer — the one actor the terminal writer admits — is
    // still refused, so this is a contract door, not an actor check.
    let bypass = peer_facade
        .land_task_result(
            task_ref,
            &TaskResultInput {
                result_ref,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: CONSULT_NOW + 10,
            },
        )
        .expect_err("a consult cannot settle through the general door");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(bypass.code, MEMORY_CODE_INVALID_STATE);
    assert_eq!(usize::from(body.terminal().is_none()), 1);

    // The consult's own door still works and still carries the summary.
    let answer_ref = route_turn(&vault, 0xDD).entity_ref();
    let landed = peer_facade
        .land_consult_result(task_ref, &answer_input(answer_ref, question))
        .expect("the evidence door still lands");

    assert_eq!(
        usize::from(matches!(
            landed.terminal.summary,
            Some(ConsultResultSummary::Answer { .. })
        )),
        1
    );
}

/// The general terminal door refuses a non-consult body reader mismatch:
/// `land_consult_result` still rejects a standard task outright.
#[test]
fn land_consult_result_still_refuses_a_standard_task() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xD5);
    let task_ref = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("create")
        .task_ref
        .expect("task ref");
    let question = route_turn(&vault, 0xD6);
    let answer_ref = route_turn(&vault, 0xDB).entity_ref();

    let error = vault
        .memory(actor_ref, EdgeActorClass::Agent)
        .land_consult_result(task_ref, &answer_input(answer_ref, question))
        .expect_err("a standard task is not a consult");

    assert_eq!(usize::from(error.message.contains("consult")), 1);
}
