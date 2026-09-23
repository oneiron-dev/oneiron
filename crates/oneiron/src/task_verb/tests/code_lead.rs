use super::support::*;
use super::*;
use crate::agent_dispatch::AgentSpawnContext;
use crate::code_run::{
    HostSelfDispatcher, SelfAgentSpawnCall, SelfAgentSpawnResult, SelfCall, SelfDispatchOutcome,
    SelfDispatcher,
};
use crate::context_projection::{
    ContextSpec, LeadPanelSpec, PanelJudgeSpec, PanelMemberSpec, PanelSynthesisSpec,
    persist_lead_panel_spec, plan_lead_panel_tasks,
};

#[test]
fn code_mode_lead_spawns_bounded_worker_then_blind_panel_judge_synthesis() {
    let (_dir, vault) = open_vault();
    let (lead, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")
        .unwrap()
        .unwrap();
    // The definition is Auto-capable, but the owner's live manifest must also
    // grant this exact actor. The role label itself is not authorization.
    let mut policy = rmpv::decode::read_value(&mut std::io::Cursor::new(
        crate::gate::default_policy_manifest(),
    ))
    .unwrap();
    let Value::Map(entries) = &mut policy else {
        panic!("manifest map")
    };
    let Value::Array(ceilings) = &mut entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("actor_ceilings"))
        .unwrap()
        .1
    else {
        panic!("ceilings array")
    };
    ceilings.push(Value::Map(vec![
        (Value::from("actor_class"), Value::from("agent")),
        (Value::from("actor_ref"), Value::from(lead.to_hex())),
        (Value::from("ceiling"), Value::from("auto")),
    ]));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &policy).unwrap();
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id().unwrap(),
        &bytes,
    )
    .unwrap();
    let parent = match AgentDispatcher::new(&vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(lead),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some("headless-panel".to_owned()),
                now: unix_seconds_now(),
            },
            AgentSpawnContext::default().with_depth_remaining(1),
        )
        .unwrap()
    {
        AgentDispatchOutcome::Dispatched(status) => status.attempt.id,
        other => panic!("{other:?}"),
    };
    let originator = own_agent(&vault);
    let origin_question = consult_turn(&vault, 0xAC);
    let origin = vault
        .memory(originator, EdgeActorClass::Agent)
        .tasks_ask(&TaskAskSpec {
            intent_key: "panel-origin".to_owned(),
            ..crate::task_verb::TaskAskSpec::shorthand(
                Some(TaskAskTarget::Responder(TaskAssignee::Child {
                    actor_ref: lead,
                })),
                crate::task_verb::TaskAskQuestion {
                    reference: origin_question,
                    revision: 1,
                    options: Default::default(),
                    context_refs: vec![],
                    label: None,
                    outcome_binding: None,
                },
                Some(unix_seconds_now() + 3600),
                crate::task_verb::TaskAskDefault::AskMe,
            )
        })
        .unwrap();
    let dispatcher = HostSelfDispatcher::for_agent_attempt(
        &vault,
        WriteActor::new(lead, EdgeActorClass::Agent),
        parent,
    )
    .unwrap();
    let worker = routable_agent_def(&vault, 0xB1);
    let child = match dispatcher
        .dispatch(SelfCall::AgentsSpawn(SelfAgentSpawnCall {
            target: AgentDispatchTarget::Custom(worker),
            context: AgentSpawnContext::default(),
            intent_key: "worker".to_owned(),
        }))
        .unwrap()
    {
        SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::Queued { attempt_ref }) => {
            attempt_ref
        }
        other => panic!("{other:?}"),
    };
    let status = DreamerRunnerStore::new(&vault)
        .status(child)
        .unwrap()
        .unwrap();
    let child_input = decode_agent_dispatch_input(&status.payload.input).unwrap();
    assert_eq!(child_input.depth_remaining, Some(0));
    let worker_dispatcher = HostSelfDispatcher::for_agent_attempt(
        &vault,
        crate::agent_dispatch::agent_dispatch_actor(&child_input).unwrap(),
        child,
    )
    .unwrap();
    assert!(
        worker_dispatcher
            .dispatch(SelfCall::AgentsSpawn(SelfAgentSpawnCall {
                target: AgentDispatchTarget::Custom(worker),
                context: AgentSpawnContext::default(),
                intent_key: "too-deep".to_owned(),
            }))
            .is_err()
    );

    let peers: Vec<_> = [0xB2, 0xB3, 0xB4, 0xB5]
        .into_iter()
        .map(|seed| consult_peer(&vault, seed))
        .collect();
    let responder = |i: usize| TaskAssignee::Peer {
        actor_ref: peers[i],
    };
    let panel = LeadPanelSpec {
        members: vec![
            PanelMemberSpec {
                responder: responder(0),
                instructions: "a".to_owned(),
                context_spec: ContextSpec::default(),
            },
            PanelMemberSpec {
                responder: responder(1),
                instructions: "b".to_owned(),
                context_spec: ContextSpec::default(),
            },
        ],
        judge: PanelJudgeSpec {
            responder: responder(2),
            rubric: "judge".to_owned(),
            context_spec: ContextSpec::default(),
        },
        synthesis: PanelSynthesisSpec {
            responder: responder(3),
            instructions: "synthesize".to_owned(),
            context_spec: ContextSpec::default(),
        },
    };
    let panel_ref = persist_lead_panel_spec(&vault, &panel, unix_seconds_now()).unwrap();
    let question = consult_turn(&vault, 0xB6);
    let plan = plan_lead_panel_tasks(question, panel_ref, EntityId::now(), &panel).unwrap();
    let ask = |index: usize,
               planned: &crate::context_projection::LeadPanelTaskInputSpec,
               extra: &[ConsultPayloadRef]| {
        let mut context_refs = planned.consult.context_refs.clone();
        context_refs.extend_from_slice(extra);
        match dispatcher
            .dispatch(SelfCall::TasksAsk(TaskAskSpec {
                intent_key: format!("panel:{index}"),
                ..crate::task_verb::TaskAskSpec::shorthand(
                    Some(TaskAskTarget::Responder(planned.responder)),
                    crate::task_verb::TaskAskQuestion {
                        reference: question,
                        revision: 1,
                        options: Default::default(),
                        context_refs: context_refs,
                        label: None,
                        outcome_binding: None,
                    },
                    Some(unix_seconds_now() + 3600),
                    crate::task_verb::TaskAskDefault::AskMe,
                )
            }))
            .unwrap()
        {
            SelfDispatchOutcome::TaskAsk(receipt) => receipt,
            other => panic!("{other:?}"),
        }
    };
    let mut members = Vec::new();
    // Mint EVERY member before any answer exists; the member task inputs carry
    // only the question and panel spec. The code has no contextFrom channel.
    for (i, planned) in plan.member_tasks.iter().enumerate() {
        members.push(ask(i, planned, &[]));
    }
    let mut results = Vec::new();
    for (i, receipt) in members.iter().enumerate() {
        let body = task_verb_body(&vault, receipt.task_refs[0])
            .unwrap()
            .unwrap();
        assert_eq!(body.consult.unwrap().context_refs, vec![panel_ref]);
        let result = consult_turn(&vault, 0xA7 + i as u8);
        vault
            .memory(peers[i], EdgeActorClass::Human)
            .land_consult_result(
                receipt.task_refs[0],
                &answer_input(result.entity_ref(), result),
            )
            .unwrap();
        assert!(matches!(
            dispatcher
                .dispatch(SelfCall::TasksWait(receipt.handle))
                .unwrap(),
            SelfDispatchOutcome::TaskAskStatus(TaskAskStatus::Settled(_))
        ));
        results.push(result);
    }
    let judge = ask(2, &plan.judge_task, &results);
    let judgment = consult_turn(&vault, 0xA9);
    vault
        .memory(peers[2], EdgeActorClass::Human)
        .land_consult_result(
            judge.task_refs[0],
            &answer_input(judgment.entity_ref(), judgment),
        )
        .unwrap();
    results.push(judgment);
    let synthesis = ask(3, &plan.synthesis_task, &results);
    let report = consult_turn(&vault, 0xAB);
    vault
        .memory(peers[3], EdgeActorClass::Human)
        .land_consult_result(
            synthesis.task_refs[0],
            &answer_input(report.entity_ref(), report),
        )
        .unwrap();
    let SelfDispatchOutcome::TaskAskStatus(TaskAskStatus::Settled(result)) = dispatcher
        .dispatch(SelfCall::TasksWait(synthesis.handle))
        .unwrap()
    else {
        panic!("panel did not complete")
    };
    assert!(
        result
            .evidence
            .iter()
            .any(|entry| entry.answer.result_ref == report.entity_ref())
    );
    let TaskAskDecision::First(answer) = &result.decision else {
        panic!("the synthesis was submitted as a human word")
    };
    assert_eq!(answer.actor_ref, peers[3]);
    assert_eq!(answer.task_ref, synthesis.task_refs[0]);
    assert_eq!(answer.result_ref, report.entity_ref());
    assert!(result.coverage.met);
    assert!(result.fallback.is_none());
    vault
        .memory(lead, EdgeActorClass::Agent)
        .land_consult_result(
            origin.task_refs[0],
            &answer_input(report.entity_ref(), report),
        )
        .unwrap();
    let TaskAskWait::Ready(origin_result) = vault
        .memory(originator, EdgeActorClass::Agent)
        .tasks_wait(origin.handle, None)
        .unwrap()
    else {
        panic!("the lead's result is durable evidence")
    };
    assert_eq!(origin_result.decision, TaskAskDecision::Unknown);
    assert!(origin_result.coverage.responded.is_empty());
    assert!(origin_result.evidence.iter().any(|entry| {
        entry.source == TaskAskSource::Executor && entry.answer.result_ref == report.entity_ref()
    }));
    // Earlier member inputs remain blind after the downstream passes.
    for member in members {
        assert_eq!(
            task_verb_body(&vault, member.task_refs[0])
                .unwrap()
                .unwrap()
                .consult
                .unwrap()
                .context_refs,
            vec![panel_ref]
        );
    }
}
