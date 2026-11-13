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
    fake.push(extraction_reply(subject, "Owen"));
    let sitting = local_sitting(&vault);
    handle.session_hint(sitting, SessionHint::AppOpen, None);
    capture_user_turn(&vault, "call me Owen");
    // No call is made while the sitting is open: the end is the trigger.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(fake.seen().is_empty());
    handle.session_hint(sitting, SessionHint::ExplicitEnd, None);

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
    fake.push(extraction_reply(subject, "Owen"));
    let sitting = local_sitting(&vault);
    handle.session_hint(sitting, SessionHint::AppOpen, None);
    capture_user_turn(&vault, "call me Owen");
    handle.session_hint(sitting, SessionHint::ExplicitEnd, None);
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
    local.push(extraction_reply(subject, "Owen"));
    let sitting = local_sitting(&vault);
    handle.session_hint(sitting, SessionHint::AppOpen, None);
    capture_user_turn(&vault, "call me Owen");
    handle.session_hint(sitting, SessionHint::ExplicitEnd, None);
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
    // This fixture captures no chat turns; the default memory selection fills its cap.
    let omitted_memory = oneiron::config::context_spec::CONTEXT_SPEC_DEFAULT_MEMORY_LIMIT;
    let omitted_chat = 0;
    let omission_notice = format!(
        "{omitted_memory} memory rows and {omitted_chat} chat rows selected for this step's context are left out: \
         they could not be read for this run now, or they hold no text of their own."
    );
    // 16916daf0dc1 (FIX 6290 + 2315), 13cc092c9a92: count-only notice precedes earlier output.
    assert_eq!(
        messages(1),
        [
            "Shorten the line you are given.",
            omission_notice.as_str(),
            "soil holds the seed",
        ]
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
        Some(&metered_models(models(
            &fake.base_url,
            "[dreamer]\nenabled = false\n[workflows]\nretry_backoff_secs = 0\nstep_budget_units = 64000",
        ))),
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
    // 1820c118b76a (OF-541): exhaustion holds a Paused leaf under an open workflow.
    assert!(
        eventually(Duration::from_secs(20), || workflow_is_held_for_budget(
            &vault
        ))
        .await,
        "the workflow never held at its policy cap; status {:?}",
        host.handle().status().workflows
    );
    assert_eq!(fake.seen().len(), 1);
    let stopped = host.handle().status().workflows.last_error;
    // 1820c118b76a (OF-541): a held step is neither failed nor a failure last_error.
    assert!(
        stopped.is_none() && host.handle().status().workflows.failed == 0,
        "{stopped:?}"
    );
    host.shutdown().await;
}

/// Astra #1304 P1: boot lease recovery requeued an attempt parked on its
/// budget trap, so a restart spent without the trap's resume signal. Since
/// row B2 a pass budget trap's signal is a later pass with room for it.
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
    // The pass keeps a 10% landing reserve: 8,500 leaves 7,650 ordinary
    // units, below the paid call's reservation, so extraction traps before sending.
    let tight = metered_models(models(
        &fake.base_url,
        "[dreamer]\nidle_floor_secs = 600\npass_budget_units = 8500\n[workflows]\nenabled = false",
    ));
    let host = AiHost::start(vault.clone(), Some(&tight), true).await;
    let sitting = local_sitting(&vault);
    host.handle()
        .session_hint(sitting, SessionHint::AppOpen, None);
    capture_user_turn(&vault, "call me Owen");
    host.handle()
        .session_hint(sitting, SessionHint::ExplicitEnd, None);
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

    // A restart is not the trap's resume signal: under a pass budget that
    // still has no room for the trapped call, other passes may trap then (one
    // still queued at the shutdown, or one the restarted Dreamer schedules for
    // the same turns), but a pass parked on its trap stays as it was: leased,
    // on the same trap, never claimed again, and nothing is sent.
    let still_tight = metered_models(models(
        &fake.base_url,
        "[dreamer]\nidle_floor_secs = 600\npass_budget_units = 1000\n[workflows]\nenabled = false",
    ));
    let host = AiHost::start(vault.clone(), Some(&still_tight), true).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let rows = AttemptQueue::new(&vault).list().unwrap();
    for (before, park) in &parked {
        let after = rows.iter().find(|row| row.id == before.id);
        assert_eq!(after, Some(before), "the trapped pass ran unsignalled");
        assert_eq!(on_trap(before).as_ref(), Some(park));
        assert_eq!(before.state, AttemptState::Leased);
    }
    host.shutdown().await;
    assert!(fake.seen().is_empty(), "a restart with no room sent a call");

    // A pass budget trap's signal is a later pass whose budget has room for
    // its call (BUDGET-TRAP-UNTYPED-NO-SENDER row B2): a restart with room
    // wakes the trap, and its pass sends the extraction call.
    fake.push(extraction_reply(subject, "Owen"));
    let roomy = metered_models(models(
        &fake.base_url,
        "[dreamer]\nidle_floor_secs = 600\n[workflows]\nenabled = false",
    ));
    let host = AiHost::start(vault.clone(), Some(&roomy), true).await;
    assert!(
        eventually(Duration::from_secs(30), || parked
            .iter()
            .all(|(before, _)| on_trap(before).is_none()))
        .await,
        "a restart with room left the pass budget trap parked"
    );
    assert!(
        eventually(Duration::from_secs(30), || !fake.seen().is_empty()).await,
        "the woken pass sent no extraction call; status {:?}",
        host.handle().status().dreamer
    );
    host.shutdown().await;
}

/// Keep the configured own-server routes, but meter their simulated account work.
fn metered_models(mut config: ModelsConfig) -> ModelsConfig {
    for provider in config.providers.values_mut() {
        provider.payer = oneiron::llm::run_admission::Payer::CustomerAccount;
    }
    config
}

fn workflow_is_held_for_budget(vault: &Vault) -> bool {
    use oneiron::agent_dispatch::{AgentDispatcher, BudgetHoldState};
    use oneiron::attempt_queue::{AttemptQueue, AttemptState};
    let dispatcher = AgentDispatcher::new(vault);
    let queue = AttemptQueue::new(vault);
    dispatcher
        .open_workflow_roots()
        .unwrap()
        .iter()
        .any(|root| {
            dispatcher.plan_hold(*root).unwrap().is_some_and(|hold| {
                hold.state == BudgetHoldState::Held
                    && !hold.held.is_empty()
                    && hold.held.iter().all(|held| {
                        queue
                            .get(held.attempt)
                            .unwrap()
                            .is_some_and(|row| row.state == AttemptState::Paused)
                    })
            })
        })
}

fn first_generative_offer_is_resting(host: &AiHost) -> bool {
    host.handle()
        .model_runtime()
        .live_status()
        .seats
        .iter()
        .find(|seat| seat.role == "generative_reasoner")
        .and_then(|seat| seat.rungs.first())
        .and_then(|rung| rung.health)
        .is_some_and(|health| health.until.is_some())
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
    one_step_until(config, false).await
}

/// Waits for either normal completion or the paid-budget hold the fixture expects.
async fn one_step_until(
    config: &ModelsConfig,
    held_for_budget: bool,
) -> Vec<oneiron::llm::run_admission::RunReceipt> {
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
    let host =
        AiHost::start_receipted(vault.clone(), Some(config), true, receipts.clone(), None).await;
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
    // 1820c118b76a (OF-541): a paid denial holds; ordinary completion still stops.
    assert!(
        eventually(Duration::from_secs(20), || {
            if held_for_budget {
                workflow_is_held_for_budget(&vault)
            } else {
                dispatcher
                    .open_workflow_roots()
                    .is_ok_and(|roots| roots.is_empty())
            }
        })
        .await,
        "the workflow never reached its expected completion or budget hold; status {:?}",
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
            RunEvent::ResidentOverdraft { .. } => "resident_overdraft",
            RunEvent::PlanModelSubstituted { .. } => "plan_model_substituted",
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
    let config = metered_models(two_rung_steps(&failing, &answering, reserve));
    let rows = one_step_until(&config, true).await;
    assert_eq!(failing.seen().len(), 1);
    assert!(answering.seen().is_empty(), "the second rung went out");
    assert_eq!(
        run_events(&rows),
        ["admitted", "dispatched", "settled", "denied"]
    );
}

/// The local owner's sitting on this machine: the key an on-device app's
/// session hints carry (`bound_session_key`, locality OnDevice). Open and end
/// name the same sitting.
fn local_sitting(vault: &Vault) -> oneiron::session_lifecycle::SessionKey {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault.local_session_key(owner).expect("local session key")
}

/// Dispatches the saved workflow once more and observes whether it stops in the same window.
async fn step_once(vault: &Arc<Vault>, workflow: EntityId, key: &str) -> bool {
    use oneiron::agent_dispatch::{AgentDispatchTarget, AgentDispatcher, DispatchAgent};
    let dispatcher = AgentDispatcher::new(vault);
    dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Workflow(workflow),
            parent_attempt: None,
            dedupe_key: Some(key.to_owned()),
            run_id: Some(key.to_owned()),
            now: 10,
        })
        .unwrap();
    eventually(Duration::from_secs(20), || {
        dispatcher
            .open_workflow_roots()
            .is_ok_and(|roots| roots.is_empty())
    })
    .await
}

/// Engine ruling 2026-10-15 (world privacy, "Models"): a workflow step names
/// no world, since nothing proves which worlds its definition, briefing and
/// earlier outputs came from (Astra R3). With no world kept on the device
/// its call falls back to the cloud as before; once one is, the step never
/// reaches a cloud fallback, and each held try is receipted.
#[tokio::test]
async fn a_workflow_step_stays_on_the_device_while_any_world_does() {
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
    let host =
        AiHost::start_receipted(vault.clone(), Some(&config), true, receipts.clone(), None).await;

    // bf7c0817ad6c (OF-305): an available cloud fallback still completes the first run.
    assert!(
        step_once(&vault, workflow, "no-world-kept").await,
        "the workflow never stopped; status {:?}",
        host.handle().status().workflows
    );
    assert_eq!(cloud.seen().len(), 1, "the step fell back to the cloud");

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
    // The root the test host's install seed made (`rooted_vault`).
    let (issuer, _) = crate::test_credentials::rooting_host_issuer(
        &vault,
        super::test_support::TEST_SECRET.as_bytes(),
    );
    vault
        .keep_world_on_this_machine_under_for_test(&issuer, world, true)
        .unwrap();
    let tried = device.seen().len();
    // bf7c0817ad6c (OF-305): the device rests and this call stays open in the same window.
    assert!(
        !step_once(&vault, workflow, "a-world-kept").await
            && first_generative_offer_is_resting(&host),
        "the held workflow stopped or its device offer did not rest; status {:?}",
        host.handle().status().workflows
    );
    let tries = device.seen().len() - tried;
    assert!(tries > 0, "the step was tried on the device");
    assert_eq!(cloud.seen().len(), 1, "no held try reached the cloud");
    let held = receipts
        .rows()
        .iter()
        .filter(|row| {
            matches!(
                row.event,
                RunEvent::Denied {
                    reason: RunDenied::KeptOnDevice { .. },
                    ..
                }
            )
        })
        .count();
    // bf7c0817ad6c (OF-305): one Denied row per held fallback rung in this model call.
    assert_eq!(held, 1, "the held fallback decision is receipted once");
    host.shutdown().await;
}
