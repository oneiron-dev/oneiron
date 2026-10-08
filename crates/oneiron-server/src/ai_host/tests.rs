//! The host's start-up decisions and one real Dreamer pass on its own
//! trigger, against the local fake model server.
use std::time::Duration;

use oneiron::{ClaimApprovalStatus, EntityId, TimeRange};
use oneiron_driver::SessionHint;

use super::test_support::{
    capture_user_turn, eventually, extraction_reply, grant_dreamer, grant_dreamer_weave_only,
    models, name_claims, rooted_vault,
};
use super::*;
use crate::fake_llm::FakeLlm;

#[tokio::test]
async fn without_models_every_worker_is_idle_for_want_of_a_model() {
    let (_dir, vault) = rooted_vault();
    let host = AiHost::start(vault, None, true).await;
    let status = host.handle().status();
    for work in [&status.dreamer, &status.workflows, &status.chat] {
        assert_eq!(work.state, WorkState::Idle);
        assert_eq!(work.reason, Some(IdleReason::NoModelConfigured));
    }
    assert_eq!(status.health().dreamer, WorkState::Idle);
    host.shutdown().await;
}

#[tokio::test]
async fn the_dreamer_states_each_missing_prerequisite() {
    let fake = FakeLlm::start(vec![], None).await;
    let cases = [
        (false, true, "", IdleReason::NoHostAuthority),
        (true, false, "", IdleReason::NeedsOwnerGrant),
        (
            true,
            true,
            "[dreamer]\nenabled = false",
            IdleReason::Disabled,
        ),
    ];
    for (host_root, granted, extra, reason) in cases {
        let (_dir, vault) = rooted_vault();
        if granted {
            grant_dreamer(&vault);
        }
        let host = AiHost::start(vault, Some(&models(&fake.base_url, extra)), host_root).await;
        assert_eq!(host.handle().status().dreamer.reason, Some(reason));
        // Chat and workflows only need the generative seat.
        assert_eq!(host.handle().status().chat.state, WorkState::Waiting);
        host.shutdown().await;
    }
    let (_dir, vault) = rooted_vault();
    grant_dreamer(&vault);
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
    grant_dreamer_weave_only(&vault);
    let before = vault.purpose_default_table().unwrap();
    let host = AiHost::start(vault.clone(), Some(&models(&fake.base_url, "")), true).await;
    assert_eq!(
        host.handle().status().dreamer.reason,
        Some(IdleReason::ExtractionRouteNotSet)
    );
    assert_eq!(vault.purpose_default_table().unwrap(), before);
    host.shutdown().await;
}

#[tokio::test]
async fn captured_turns_dream_on_session_end_and_land_through_the_promotion_writer() {
    let fake = FakeLlm::start(vec![], None).await;
    let (_dir, vault) = rooted_vault();
    grant_dreamer(&vault);
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

fn agent(vault: &oneiron::Vault, name: &str, instructions: &str) -> EntityId {
    let (_, mut definition) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")
        .unwrap()
        .expect("seeded default");
    definition.logical_id = None;
    definition.agent_id = format!("test.pump.{name}");
    definition.instructions = Some(instructions.to_owned());
    definition.skills.clear();
    let id = EntityId::now();
    vault
        .put_agent_definition(&id, &definition, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    id
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
    let first = agent(&vault, "first", "Write one line about soil.");
    let second = agent(&vault, "second", "Shorten the line you are given.");
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
async fn shutdown_waits_for_a_turn_then_stops_one_that_outlives_its_grace() {
    let tracker = super::turns::TurnTracker::new();
    let quick = tracker.enter();
    let finishing = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(quick);
    });
    let started = std::time::Instant::now();
    tracker.shutdown(Duration::from_secs(5)).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "returned on drain"
    );
    finishing.await.unwrap();

    let tracker = super::turns::TurnTracker::new();
    let mut slow = tracker.enter();
    let stopped = tokio::spawn(async move {
        slow.stopping().await;
        drop(slow);
        true
    });
    tracker.shutdown(Duration::from_millis(50)).await;
    assert!(stopped.await.unwrap());
}

#[tokio::test]
async fn a_failed_step_gives_back_only_its_own_lease_and_waits_out_its_backoff() {
    use oneiron::agent_dispatch::{AgentDispatchTarget, AgentDispatcher, DispatchAgent};
    use oneiron::attempt_queue::{AttemptQueue, AttemptState};
    let fake = FakeLlm::start(vec![], Some(crate::fake_llm::Reply::Status(500))).await;
    let (_dir, vault) = rooted_vault();
    let only = agent(&vault, "failing", "Say one word.");
    let workflow = EntityId::now();
    vault
        .save_workflow(
            &workflow,
            &oneiron::agent_def::workflow::WorkflowDefinition::new("failing", vec![only]).unwrap(),
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
    AgentDispatcher::new(&vault)
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Workflow(workflow),
            parent_attempt: None,
            dedupe_key: Some("fail-test".into()),
            run_id: Some("fail-test".into()),
            now: 10,
        })
        .unwrap();
    assert!(
        eventually(Duration::from_secs(10), || handle.status().workflows.failed
            >= 1)
        .await,
        "the step never failed; status {:?}",
        handle.status().workflows
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The failed try is settled, not left leased; the next one is scheduled
    // past its backoff, so the model is not called again at once.
    let rows = AttemptQueue::new(&vault).list().unwrap();
    assert!(
        !rows.iter().any(|row| row.state == AttemptState::Leased),
        "{rows:?}"
    );
    assert!(
        rows.iter().any(|row| row.state == AttemptState::Scheduled),
        "{rows:?}"
    );
    assert_eq!(fake.seen().len(), 1);
    host.shutdown().await;
}

#[tokio::test]
async fn a_failing_step_is_tried_five_times_then_its_workflow_stops() {
    use oneiron::agent_dispatch::{AgentDispatchTarget, AgentDispatcher, DispatchAgent};
    use oneiron::attempt_queue::{AttemptQueue, AttemptState};
    let fake = FakeLlm::start(vec![], Some(crate::fake_llm::Reply::Status(500))).await;
    let (_dir, vault) = rooted_vault();
    let only = agent(&vault, "always-failing", "Say one word.");
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
