//! The host's start-up decisions and one real Dreamer pass on its own
//! trigger, against the local fake model server.
use std::time::Duration;

use oneiron::{ClaimApprovalStatus, EntityId, TimeRange};
use oneiron_driver::SessionHint;

use super::test_support::{
    capture_user_turn, eventually, extraction_reply, models, models_toml, name_claims,
    pin_every_role, rooted_vault, route_extraction, saved_agent,
};
use super::*;
use crate::fake_llm::FakeLlm;

#[tokio::test]
async fn the_dreamer_states_each_missing_prerequisite() {
    let fake = FakeLlm::start(vec![], None).await;
    let cases = [
        (false, "", Some(IdleReason::NoHostAuthority)),
        // Warm by default (ARCH-0026): a fresh vault's Dreamer needs no
        // grant step, only a model and the vault's route.
        (true, "", None),
        (
            true,
            "[dreamer]\nenabled = false",
            Some(IdleReason::Disabled),
        ),
    ];
    for (host_root, extra, reason) in cases {
        let (_dir, vault) = rooted_vault();
        route_extraction(&vault);
        let host = AiHost::start(vault, Some(&models(&fake.base_url, extra)), host_root).await;
        assert_eq!(host.handle().status().dreamer.reason, reason);
        // Chat and workflows only need the generative seat.
        assert_eq!(host.handle().status().chat.state, WorkState::Waiting);
        host.shutdown().await;
    }
    let (_dir, vault) = rooted_vault();
    route_extraction(&vault);
    let mut config = models(&fake.base_url, "");
    config.extraction_egress = false;
    let host = AiHost::start(vault, Some(&config), true).await;
    assert_eq!(
        host.handle().status().dreamer.reason,
        Some(IdleReason::ExtractionEgressNotAllowed)
    );
    host.shutdown().await;
    // Boot never routes extraction off the device by itself: the vault's
    // defaults are the owner's, and a restart leaves them as they are.
    let (_dir, vault) = rooted_vault();
    let before = vault.purpose_default_table().unwrap();
    let host = AiHost::start(vault.clone(), Some(&models(&fake.base_url, "")), true).await;
    assert_eq!(
        host.handle().status().dreamer.reason,
        Some(IdleReason::ExtractionRouteNotSet)
    );
    assert_eq!(vault.purpose_default_table().unwrap(), before);
    host.shutdown().await;
    // A manifest that pins the extraction teacher to a model this server does
    // not serve: every pass would be refused, so the Dreamer stays idle.
    let (_dir, vault) = rooted_vault();
    route_extraction(&vault);
    pin_every_role(
        &vault,
        "local/unserved@live",
        oneiron::ModelLocality::OwnServer,
    );
    let host = AiHost::start(vault, Some(&models(&fake.base_url, "")), true).await;
    assert_eq!(
        host.handle().status().dreamer.reason,
        Some(IdleReason::ExtractionModelNotServed)
    );
    host.shutdown().await;
}

#[tokio::test]
async fn captured_turns_dream_on_session_end_and_land_through_the_promotion_writer() {
    let fake = FakeLlm::start(vec![], None).await;
    // A fresh vault with a model route and no grant step: the Dreamer is
    // warm by default (ARCH-0026).
    let (_dir, vault) = rooted_vault();
    route_extraction(&vault);
    let host = AiHost::start(
        vault.clone(),
        Some(&models(&fake.base_url, "[dreamer]\nidle_floor_secs = 600")),
        true,
    )
    .await;
    let handle = host.handle();
    assert_eq!(handle.status().dreamer.state, WorkState::Waiting);

    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    fake.push(extraction_reply(subject, "Oleksii"));
    handle.session_hint(SessionHint::AppOpen);
    capture_user_turn(&vault, "call me Oleksii");
    // No call is made while the sitting is open: the end is the trigger.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(fake.seen().is_empty());
    handle.session_hint(SessionHint::ExplicitEnd);

    assert!(
        eventually(Duration::from_secs(30), || !name_claims(&vault, &subject)
            .is_empty())
        .await,
        "no claim landed; status {:?}",
        handle.status().dreamer
    );
    let claims = name_claims(&vault, &subject);
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].approval, ClaimApprovalStatus::Auto);
    // The Dreamer's write envelope: generated lineage, the Dreamer as writer.
    assert!(claims[0].evidence.is_some());
    assert!(
        eventually(Duration::from_secs(5), || handle.status().dreamer.completed
            >= 1)
        .await
    );
    let seen = fake.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].body["model"], serde_json::json!("test-model"));
    host.shutdown().await;
    assert_eq!(handle.status().dreamer.reason, Some(IdleReason::Stopped));
}

/// Greptile #1304 P1: with a model manifest, extraction is admitted as the
/// manifest's teacher model, but the Dreamer's backend still attested its
/// seat id, so admission refused every pass and no turn consolidated.
#[tokio::test]
async fn a_vault_model_manifest_names_the_model_the_dreamer_extracts_with() {
    let fake = FakeLlm::start(vec![], None).await;
    let (_dir, vault) = rooted_vault();
    route_extraction(&vault);
    let host = AiHost::start(
        vault.clone(),
        Some(&models(&fake.base_url, "[dreamer]\nidle_floor_secs = 600")),
        true,
    )
    .await;
    let handle = host.handle();
    assert_eq!(handle.status().dreamer.state, WorkState::Waiting);
    // The owner pins the model `[models]` serves after the Dreamer started:
    // each pass reads the live manifest.
    pin_every_role(
        &vault,
        "local/test-model@live",
        oneiron::ModelLocality::OwnServer,
    );

    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    fake.push(extraction_reply(subject, "Oleksii"));
    handle.session_hint(SessionHint::AppOpen);
    capture_user_turn(&vault, "call me Oleksii");
    handle.session_hint(SessionHint::ExplicitEnd);
    assert!(
        eventually(Duration::from_secs(30), || !name_claims(&vault, &subject)
            .is_empty())
        .await,
        "no claim landed; status {:?}",
        handle.status().dreamer
    );
    let seen = fake.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].body["model"], serde_json::json!("test-model"));
    host.shutdown().await;
}

/// Greptile #1304 P1 (re-review): the Dreamer's seat is a cloud rung, the
/// vault's manifest pins the extraction teacher to a local model this server
/// serves, and the owner routes extraction to `own_server`. Boot checked the
/// owner's route against the cloud seat and stayed idle with
/// `extraction_route_not_set`, though every pass extracts on the teacher.
#[tokio::test]
async fn a_manifest_pinned_local_teacher_starts_the_dreamer_beside_a_cloud_seat() {
    let local = FakeLlm::start(vec![], None).await;
    let cloud = FakeLlm::start(vec![], None).await;
    let (_dir, vault) = rooted_vault();
    route_extraction(&vault);
    pin_every_role(
        &vault,
        "local/teacher@live",
        oneiron::ModelLocality::OwnServer,
    );
    let config = models_toml(&format!(
        r#"
extraction_egress = true
[dreamer]
idle_floor_secs = 600
[providers.local]
kind = "local-openai-compat"
base_url = "{}"
[providers.cloud]
kind = "openai-compat"
base_url = "{}"
[roles.dreamer_current]
rungs = [{{ model = "cloud:big" }}]
[roles.extraction_teacher]
rungs = [{{ model = "local:teacher", prompt = "teacher rung rules" }}]
"#,
        local.base_url, cloud.base_url
    ));
    let host = AiHost::start(vault.clone(), Some(&config), true).await;
    let handle = host.handle();
    assert_eq!(
        handle.status().dreamer.state,
        WorkState::Waiting,
        "{:?}",
        handle.status().dreamer
    );

    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    local.push(extraction_reply(subject, "Oleksii"));
    handle.session_hint(SessionHint::AppOpen);
    capture_user_turn(&vault, "call me Oleksii");
    handle.session_hint(SessionHint::ExplicitEnd);
    assert!(
        eventually(Duration::from_secs(30), || !name_claims(&vault, &subject)
            .is_empty())
        .await,
        "no claim landed; status {:?}",
        handle.status().dreamer
    );
    // The teacher's own rung served the pass, with its prompt; nothing went
    // to the cloud seat.
    let seen = local.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].body["model"], serde_json::json!("teacher"));
    assert_eq!(
        seen[0].body["messages"][0]["content"],
        serde_json::json!("teacher rung rules")
    );
    assert!(cloud.seen().is_empty());
    host.shutdown().await;
}

#[tokio::test]
async fn a_saved_workflow_advances_every_step_through_the_pump_without_a_call() {
    use oneiron::agent_dispatch::{
        AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
    };
    let fake = FakeLlm::start(
        vec![
            crate::fake_llm::Reply::text("soil holds the seed"),
            crate::fake_llm::Reply::text("a seed in soil"),
        ],
        None,
    )
    .await;
    let (_dir, vault) = rooted_vault();
    let first = saved_agent(&vault, "first", "Write one line about soil.");
    let second = saved_agent(&vault, "second", "Shorten the line you are given.");
    let workflow = EntityId::now();
    vault
        .save_workflow(
            &workflow,
            &oneiron::agent_def::workflow::WorkflowDefinition::new("pair", vec![first, second])
                .unwrap(),
            2,
        )
        .unwrap();
    let host = AiHost::start(
        vault.clone(),
        Some(&models(&fake.base_url, "[dreamer]\nenabled = false")),
        true,
    )
    .await;
    let handle = host.handle();
    assert_eq!(handle.status().workflows.state, WorkState::Waiting);
    let dispatcher = AgentDispatcher::new(&vault);
    let root = match dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Workflow(workflow),
            parent_attempt: None,
            dedupe_key: Some("pump-test".into()),
            run_id: Some("pump-test".into()),
            now: 10,
        })
        .unwrap()
    {
        AgentDispatchOutcome::WorkflowDispatched(status)
        | AgentDispatchOutcome::WorkflowExisting(status) => status.attempt.id,
        other => panic!("workflow outcome expected: {other:?}"),
    };
    // Nobody calls a route: the pump sees the queued leaf and runs both.
    assert!(
        eventually(Duration::from_secs(30), || {
            dispatcher
                .workflow_status(root)
                .is_ok_and(|status| status.results.len() == 2)
        })
        .await,
        "workflow did not finish; status {:?}",
        handle.status().workflows
    );
    assert!(dispatcher.open_workflow_roots().unwrap().is_empty());
    let seen = fake.seen();
    assert_eq!(seen.len(), 2);
    let messages = |index: usize| -> Vec<String> {
        seen[index].body["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|message| message["content"].as_str().unwrap_or_default().to_owned())
            .collect()
    };
    assert_eq!(messages(0)[0], "Write one line about soil.");
    // The second step reads the first step's durable output.
    assert_eq!(
        messages(1),
        ["Shorten the line you are given.", "soil holds the seed"]
    );
    assert!(handle.status().workflows.completed >= 2);
    host.shutdown().await;
}

#[tokio::test]
async fn a_failing_step_is_tried_five_times_then_its_workflow_stops() {
    use oneiron::agent_dispatch::{AgentDispatchTarget, AgentDispatcher, DispatchAgent};
    use oneiron::attempt_queue::{AttemptQueue, AttemptState};
    let fake = FakeLlm::start(vec![], Some(crate::fake_llm::Reply::Status(500))).await;
    let (_dir, vault) = rooted_vault();
    let only = saved_agent(&vault, "always-failing", "Say one word.");
    let workflow = EntityId::now();
    vault
        .save_workflow(
            &workflow,
            &oneiron::agent_def::workflow::WorkflowDefinition::new("spent", vec![only]).unwrap(),
            2,
        )
        .unwrap();
    let host = AiHost::start(
        vault.clone(),
        Some(&models(
            &fake.base_url,
            "[dreamer]\nenabled = false\n[workflows]\nretry_backoff_secs = 0",
        )),
        true,
    )
    .await;
    let dispatcher = AgentDispatcher::new(&vault);
    dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Workflow(workflow),
            parent_attempt: None,
            dedupe_key: Some("spent-test".into()),
            run_id: Some("spent-test".into()),
            now: 10,
        })
        .unwrap();
    assert!(
        eventually(Duration::from_secs(20), || dispatcher
            .open_workflow_roots()
            .is_ok_and(|roots| roots.is_empty()))
        .await,
        "the workflow never stopped; status {:?}",
        host.handle().status().workflows
    );
    // Each retry is a fresh row; the tries are counted along the lineage.
    assert_eq!(fake.seen().len(), 5);
    assert_eq!(host.handle().status().workflows.failed, 5);
    let rows = AttemptQueue::new(&vault).list().unwrap();
    assert!(
        !rows.iter().any(|row| row.state == AttemptState::Leased),
        "{rows:?}"
    );
    host.shutdown().await;
}

/// Astra #1304 P1: every retry of a failing step got a fresh step budget,
/// so the step's budget never bounded what its retries spent.
#[tokio::test]
async fn a_failing_steps_retries_spend_one_step_budget() {
    use oneiron::agent_dispatch::{AgentDispatchTarget, AgentDispatcher, DispatchAgent};
    let fake = FakeLlm::start(vec![], Some(crate::fake_llm::Reply::Status(500))).await;
    let (_dir, vault) = rooted_vault();
    let only = saved_agent(&vault, "budget-bound", "Say one word.");
    let workflow = EntityId::now();
    vault
        .save_workflow(
            &workflow,
            &oneiron::agent_def::workflow::WorkflowDefinition::new("bounded", vec![only]).unwrap(),
            2,
        )
        .unwrap();
    // Three calls' reservations (8,000 units each).
    let host = AiHost::start(
        vault.clone(),
        Some(&models(
            &fake.base_url,
            "[dreamer]\nenabled = false\n[workflows]\nretry_backoff_secs = 0\nstep_budget_units = 24000",
        )),
        true,
    )
    .await;
    let dispatcher = AgentDispatcher::new(&vault);
    dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Workflow(workflow),
            parent_attempt: None,
            dedupe_key: Some("bounded-test".into()),
            run_id: Some("bounded-test".into()),
            now: 10,
        })
        .unwrap();
    assert!(
        eventually(Duration::from_secs(20), || dispatcher
            .open_workflow_roots()
            .is_ok_and(|roots| roots.is_empty()))
        .await,
        "the workflow never stopped; status {:?}",
        host.handle().status().workflows
    );
    // Each failed try is charged its reservation, so three tries spend the
    // step's budget and a fourth is never admitted.
    assert_eq!(fake.seen().len(), 3);
    host.shutdown().await;
}

/// Greptile #1304 P1: each retry of a failing step built a fresh meter, so a
/// policy row's cap (the agent's, the purpose's) renewed with every try.
#[tokio::test]
async fn a_failing_steps_retries_share_the_policy_rows_cap() {
    use oneiron::agent_dispatch::{AgentDispatchTarget, AgentDispatcher, DispatchAgent};
    let fake = FakeLlm::start(vec![], Some(crate::fake_llm::Reply::Status(500))).await;
    let (_dir, vault) = rooted_vault();
    // The owner caps workflow steps at one call's reservation (8,000 units).
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    oneiron::conversation_dag::test_support::put_test_policy_manifest(
        &vault,
        oneiron::WriteActor::new(owner, oneiron::EdgeActorClass::Human),
        EntityId::now(),
        &serde_json::json!({
            "schema_version": "1.2", "pack_id": "step-cap", "pack_version": "1",
            "min_engine_version": "0.0.0", "defaults": {}, "rules": [], "actor_ceilings": [],
            "budget_policy": [{"purpose": "workflow_step", "cap": 8000}],
        }),
    )
    .unwrap();
    let only = saved_agent(&vault, "capped", "Say one word.");
    let workflow = EntityId::now();
    vault
        .save_workflow(
            &workflow,
            &oneiron::agent_def::workflow::WorkflowDefinition::new("capped", vec![only]).unwrap(),
            2,
        )
        .unwrap();
    // The step's own budget would admit every try; the row's cap admits one.
    let host = AiHost::start(
        vault.clone(),
        Some(&models(
            &fake.base_url,
            "[dreamer]\nenabled = false\n[workflows]\nretry_backoff_secs = 0\nstep_budget_units = 64000",
        )),
        true,
    )
    .await;
    let dispatcher = AgentDispatcher::new(&vault);
    dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Workflow(workflow),
            parent_attempt: None,
            dedupe_key: Some("capped-test".into()),
            run_id: Some("capped-test".into()),
            now: 10,
        })
        .unwrap();
    assert!(
        eventually(Duration::from_secs(20), || dispatcher
            .open_workflow_roots()
            .is_ok_and(|roots| roots.is_empty()))
        .await,
        "the workflow never stopped; status {:?}",
        host.handle().status().workflows
    );
    assert_eq!(fake.seen().len(), 1);
    let stopped = host.handle().status().workflows.last_error;
    assert!(
        stopped
            .as_deref()
            .is_some_and(|error| error.contains("workflow step budget")),
        "{stopped:?}"
    );
    host.shutdown().await;
}

/// Astra #1304 P1: boot lease recovery requeued an attempt parked on its
/// budget trap, so a restart spent without the trap's resume signal.
#[tokio::test]
async fn a_budget_trapped_pass_stays_parked_across_a_restart() {
    use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, AttemptState};
    let fake = FakeLlm::start(vec![], None).await;
    let (_dir, vault) = rooted_vault();
    route_extraction(&vault);
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    // A pass budget below one call's reservation: the first extraction step
    // traps on its budget before any provider call.
    let tight = models(
        &fake.base_url,
        "[dreamer]\nidle_floor_secs = 600\npass_budget_units = 8500\n[workflows]\nenabled = false",
    );
    let host = AiHost::start(vault.clone(), Some(&tight), true).await;
    host.handle().session_hint(SessionHint::AppOpen);
    capture_user_turn(&vault, "call me Oleksii");
    host.handle().session_hint(SessionHint::ExplicitEnd);
    let runner = oneiron::DreamerRunnerStore::new(&vault);
    let on_trap = |row: &AttemptRecord| {
        runner
            .parked_attempt(row.id)
            .unwrap()
            .filter(|park| park.park_owner.starts_with("dreamer.trap:"))
            .map(|park| park.park_owner)
    };
    let trapped = || -> Vec<(AttemptRecord, String)> {
        AttemptQueue::new(&vault)
            .list()
            .unwrap()
            .into_iter()
            .filter_map(|row| on_trap(&row).map(|park| (row, park)))
            .collect()
    };
    assert!(
        eventually(Duration::from_secs(30), || !trapped().is_empty()).await,
        "no pass trapped; status {:?}",
        host.handle().status().dreamer
    );
    host.shutdown().await;
    assert!(fake.seen().is_empty());
    let parked = trapped();

    // A restart with room to spend is not the trap's resume signal. Other
    // passes may spend then: one still queued at the shutdown, or one the
    // restarted Dreamer schedules for the same turns. A pass parked on its
    // trap stays as it was: leased, on the same trap, never claimed again.
    fake.push(extraction_reply(subject, "Oleksii"));
    let roomy = models(
        &fake.base_url,
        "[dreamer]\nidle_floor_secs = 600\n[workflows]\nenabled = false",
    );
    let host = AiHost::start(vault.clone(), Some(&roomy), true).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let rows = AttemptQueue::new(&vault).list().unwrap();
    for (before, park) in &parked {
        let after = rows.iter().find(|row| row.id == before.id);
        assert_eq!(after, Some(before), "the trapped pass ran unsignalled");
        assert_eq!(on_trap(before).as_ref(), Some(park));
        assert_eq!(before.state, AttemptState::Leased);
    }
    host.shutdown().await;
}

/// The generative seat on two rungs, the first failing and the second
/// answering; each workflow step's line is `step_units`.
fn two_rung_steps(failing: &FakeLlm, answering: &FakeLlm, step_units: u64) -> ModelsConfig {
    models_toml(&format!(
        r#"
[providers.first]
kind = "local-openai-compat"
base_url = "{}"
[providers.second]
kind = "local-openai-compat"
base_url = "{}"
[roles.generative_reasoner]
rungs = [{{ model = "first:small" }}, {{ model = "second:big" }}]
[dreamer]
enabled = false
[workflows]
retry_backoff_secs = 0
step_budget_units = {step_units}
"#,
        failing.base_url, answering.base_url
    ))
}

/// Runs a one-step workflow under `config` until it stops, and returns the
/// run receipts its step wrote.
async fn one_step(config: &ModelsConfig) -> Vec<oneiron::llm::run_admission::RunReceipt> {
    use oneiron::agent_dispatch::{AgentDispatchTarget, AgentDispatcher, DispatchAgent};
    use oneiron::llm::run_admission::MemoryReceipts;
    let (_dir, vault) = rooted_vault();
    let only = saved_agent(&vault, "gated", "Say one word.");
    let workflow = EntityId::now();
    vault
        .save_workflow(
            &workflow,
            &oneiron::agent_def::workflow::WorkflowDefinition::new("gated", vec![only]).unwrap(),
            2,
        )
        .unwrap();
    let receipts = Arc::new(MemoryReceipts::default());
    let host = AiHost::start_receipted(vault.clone(), Some(config), true, receipts.clone()).await;
    let dispatcher = AgentDispatcher::new(&vault);
    dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Workflow(workflow),
            parent_attempt: None,
            dedupe_key: Some("gated-test".into()),
            run_id: Some("gated-test".into()),
            now: 10,
        })
        .unwrap();
    assert!(
        eventually(Duration::from_secs(20), || dispatcher
            .open_workflow_roots()
            .is_ok_and(|roots| roots.is_empty()))
        .await,
        "the workflow never stopped; status {:?}",
        host.handle().status().workflows
    );
    host.shutdown().await;
    receipts.rows()
}

fn run_events(rows: &[oneiron::llm::run_admission::RunReceipt]) -> Vec<&'static str> {
    use oneiron::llm::run_admission::RunEvent;
    rows.iter()
        .map(|row| match row.event {
            RunEvent::Admitted(_) => "admitted",
            RunEvent::Denied { .. } => "denied",
            RunEvent::Dispatched { .. } => "dispatched",
            RunEvent::Settled { .. } => "settled",
            RunEvent::Revised { .. } => "revised",
        })
        .collect()
}

/// A step's call falls through a failing rung to an answering one: two
/// provider calls, each admitted, dispatched and settled on its own permit.
#[tokio::test]
async fn a_workflow_step_writes_one_dispatched_row_per_provider_call() {
    let failing = FakeLlm::start(vec![], Some(crate::fake_llm::Reply::Status(500))).await;
    let answering = FakeLlm::start(vec![], Some(crate::fake_llm::Reply::text("word"))).await;
    let rows = one_step(&two_rung_steps(&failing, &answering, 100_000)).await;
    assert_eq!((failing.seen().len(), answering.seen().len()), (1, 1));
    let call = ["admitted", "dispatched", "settled"];
    assert_eq!(run_events(&rows), [call, call].concat());
}

/// A step line of one reservation: the failing rung spends it, so the
/// answering rung's admission is denied with a row and it is never sent.
#[tokio::test]
async fn a_step_rung_its_line_cannot_cover_is_denied_and_never_sent() {
    let failing = FakeLlm::start(vec![], Some(crate::fake_llm::Reply::Status(500))).await;
    let answering = FakeLlm::start(vec![], Some(crate::fake_llm::Reply::text("word"))).await;
    let reserve = oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS;
    let rows = one_step(&two_rung_steps(&failing, &answering, reserve)).await;
    assert_eq!(failing.seen().len(), 1);
    assert!(answering.seen().is_empty(), "the second rung went out");
    assert_eq!(
        run_events(&rows),
        ["admitted", "dispatched", "settled", "denied"]
    );
}

/// Runs the saved one-step workflow `workflow` in `world`, with `briefing`,
/// until it stops.
async fn step_in(
    vault: &Arc<Vault>,
    workflow: EntityId,
    (world, briefing): (EntityId, Option<&str>),
    host: &AiHost,
) {
    use oneiron::agent_dispatch::{
        AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
    };
    let dispatcher = AgentDispatcher::new(vault);
    let spawn = AgentSpawnContext {
        scope: Some(oneiron::llm::Scope {
            world: Some(world),
            ..oneiron::llm::Scope::default()
        }),
        context_spec: briefing.map(|text| oneiron::context_projection::ContextSpec {
            briefing: Some(text.to_owned()),
            ..oneiron::context_projection::ContextSpec::default()
        }),
        ..AgentSpawnContext::default()
    };
    let key = format!("world-step-{}-{}", world.to_hex(), briefing.is_some());
    dispatcher
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Workflow(workflow),
                parent_attempt: None,
                dedupe_key: Some(key.clone()),
                run_id: Some(key),
                now: 10,
            },
            spawn,
        )
        .unwrap();
    assert!(
        eventually(Duration::from_secs(20), || dispatcher
            .open_workflow_roots()
            .is_ok_and(|roots| roots.is_empty()))
        .await,
        "the workflow never stopped; status {:?}",
        host.handle().status().workflows
    );
}

/// Engine ruling 2026-10-15: a workflow step's call carries the world it was
/// dispatched in and follows that world's setting. A step in a world kept
/// on this machine never reaches a cloud fallback (each hold receipted); a
/// step in a world that may leave falls back to it, while that other world
/// stays here. Review repro (Astra R2 P1): a briefing is its dispatcher's
/// text, which the world does not vouch for, so a briefed step names no
/// world and stays on the device while that other world does.
#[tokio::test]
async fn a_workflow_step_follows_its_worlds_setting_for_a_cloud_fallback() {
    use oneiron::llm::run_admission::{MemoryReceipts, RunDenied, RunEvent};
    let device = FakeLlm::start(vec![], Some(crate::fake_llm::Reply::Status(500))).await;
    let cloud = FakeLlm::start(vec![], Some(crate::fake_llm::Reply::text("word"))).await;
    let config = models_toml(&format!(
        r#"
[providers.first]
kind = "local-openai-compat"
base_url = "{}"
[providers.second]
kind = "openai-compat"
base_url = "{}"
[roles.generative_reasoner]
rungs = [{{ model = "first:small" }}, {{ model = "second:big" }}]
[dreamer]
enabled = false
[workflows]
retry_backoff_secs = 0
"#,
        device.base_url, cloud.base_url
    ));
    let (_dir, vault) = rooted_vault();
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(
        super::test_support::TEST_SECRET.as_bytes(),
    )
    .unwrap();
    let world = |keep: bool| {
        let world = EntityId::now();
        vault
            .put_entity(
                &world,
                oneiron::registry::ENTITY_TYPE_WORLD,
                TimeRange { start: 1, end: 1 },
                1,
                b"world",
            )
            .unwrap();
        if keep {
            vault
                .keep_world_on_this_machine_under_for_test(&issuer, world, true)
                .unwrap();
        }
        world
    };
    let (private, portable) = (world(true), world(false));
    let only = saved_agent(&vault, "worldly", "Say one word.");
    let workflow = EntityId::now();
    vault
        .save_workflow(
            &workflow,
            &oneiron::agent_def::workflow::WorkflowDefinition::new("worldly", vec![only]).unwrap(),
            2,
        )
        .unwrap();
    let receipts = Arc::new(MemoryReceipts::default());
    let host = AiHost::start_receipted(vault.clone(), Some(&config), true, receipts.clone()).await;

    step_in(&vault, workflow, (private, None), &host).await;
    assert!(
        !device.seen().is_empty(),
        "the step was tried on the device"
    );
    assert!(
        cloud.seen().is_empty(),
        "the private world's step stayed here"
    );
    let held = receipts
        .rows()
        .iter()
        .filter(|row| {
            matches!(
                row.event,
                RunEvent::Denied {
                    reason: RunDenied::KeptOnDevice,
                    ..
                }
            )
        })
        .count();
    assert_eq!(held, device.seen().len(), "each held try is receipted");

    step_in(&vault, workflow, (portable, None), &host).await;
    assert_eq!(cloud.seen().len(), 1, "the portable world's step fell back");
    step_in(&vault, workflow, (portable, Some("a note")), &host).await;
    assert_eq!(cloud.seen().len(), 1, "the briefed step stayed here");
    host.shutdown().await;
}
