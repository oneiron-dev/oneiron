//! The host's start-up decisions and one real Dreamer pass on its own
//! trigger, against the local fake model server.
use std::time::Duration;

use oneiron::{ClaimApprovalStatus, EntityId, TimeRange};
use oneiron_driver::SessionHint;

use super::test_support::{
    capture_user_turn, eventually, extraction_reply, models, name_claims, pin_every_role,
    rooted_vault, route_extraction, saved_agent,
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
    let trapped = || -> Option<AttemptRecord> {
        AttemptQueue::new(&vault)
            .list()
            .unwrap()
            .into_iter()
            .find(|row| {
                runner
                    .parked_attempt(row.id)
                    .unwrap()
                    .is_some_and(|park| park.park_owner.starts_with("dreamer.trap:"))
            })
    };
    assert!(
        eventually(Duration::from_secs(30), || trapped().is_some()).await,
        "no pass trapped; status {:?}",
        host.handle().status().dreamer
    );
    host.shutdown().await;
    assert!(fake.seen().is_empty());

    // A restart with room to spend is not the trap's resume signal.
    fake.push(extraction_reply(subject, "Oleksii"));
    let roomy = models(
        &fake.base_url,
        "[dreamer]\nidle_floor_secs = 600\n[workflows]\nenabled = false",
    );
    let host = AiHost::start(vault.clone(), Some(&roomy), true).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(fake.seen().is_empty(), "the trapped pass ran unsignalled");
    let parked = trapped().expect("still parked on its trap");
    assert_eq!(parked.state, AttemptState::Leased);
    assert!(name_claims(&vault, &subject).is_empty());
    host.shutdown().await;
}
