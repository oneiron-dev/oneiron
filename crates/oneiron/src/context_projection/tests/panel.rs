//! Lead-panel codec, planner, blindness ordering, and `contextFrom` admission tests.

use super::test_support::*;
use super::*;

// ── contextFrom ─────────────────────────────────────────────────────

/// One facade-minted peer TASK plus a durable result TURN, landing its
/// terminal record through the ONE result door. Mints state exactly the
/// production way so the seen body is indistinguishable.
fn member_task(
    vault: &Vault,
    seed: u8,
    disposition: Option<crate::task_verb::TaskTerminalDisposition>,
) -> (EntityId, EntityId) {
    // The first-party connector actor id (0xE1), constructed EXPLICITLY as
    // test_util::entity documents: it is the one actor the default policy
    // admits at Auto ceiling, so `tasks_create` mints instead of parking
    // (the precedent is task_verb tests' `own_agent`).
    let actor = EntityId::from_bytes([0xE1; 16]).expect("first-party actor id");
    vault
        .put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
            b"actor",
        )
        .expect("store member actor");
    let result_ref = entity(seed + 1);
    vault
        .put_entity(
            &result_ref,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
            b"member result artifact",
        )
        .expect("store result artifact");
    let facade = vault.memory(actor, crate::edge::EdgeActorClass::Agent);
    let task_ref = facade
        .tasks_create(
            &crate::task_verb::TaskCreateSpec::new(
                rmpv::Value::from("member task"),
                None,
                None,
                Some(NOW),
            )
            .with_assignee(crate::task_verb::TaskAssignee::Peer { actor_ref: actor }),
        )
        .expect("member task mints")
        .task_ref
        .expect("member task is minted, not parked");
    if let Some(disposition) = disposition {
        facade
            .land_task_result(
                task_ref,
                &crate::task_verb::TaskResultInput {
                    result_ref,
                    disposition,
                    finished_at: NOW + 1,
                },
            )
            .expect("member task settles");
    }
    (task_ref, result_ref)
}

/// `contextFrom` injects SETTLED COMPLETED sibling TASK results and
/// nothing else: the durable-but-unsettled pre-settlement window, an
/// arbitrary existing non-TASK row, and a non-Completed settlement all
/// fail closed with a typed error.
#[test]
fn context_from_resolves_only_settled_completed_sibling_task_results() {
    let (_dir, vault) = open_vault();
    // The legacy-test vault ships with NO policy manifest, so every
    // facade create would park at Proposed; one minimal manifest with an
    // agent-Auto ceiling row lets the members mint through the real
    // `tasks_create` door (mirrors the gate-test fixture shape).
    let manifest = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("schema_version"),
            rmpv::Value::from("1.1"),
        ),
        (
            rmpv::Value::from("pack_id"),
            rmpv::Value::from("context-projection-test"),
        ),
        (rmpv::Value::from("pack_version"), rmpv::Value::from("v1")),
        (
            rmpv::Value::from("min_engine_version"),
            rmpv::Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            rmpv::Value::from("defaults"),
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::from("criticality"),
                    rmpv::Value::from("normal"),
                ),
                (
                    rmpv::Value::from("sensitivity"),
                    rmpv::Value::from("normal"),
                ),
            ]),
        ),
        (rmpv::Value::from("rules"), rmpv::Value::Array(Vec::new())),
        (
            rmpv::Value::from("actor_ceilings"),
            rmpv::Value::Array(vec![rmpv::Value::Map(vec![
                (rmpv::Value::from("actor_class"), rmpv::Value::from("agent")),
                (rmpv::Value::from("ceiling"), rmpv::Value::from("auto")),
            ])]),
        ),
    ]);
    let mut manifest_bytes = Vec::new();
    rmpv::encode::write_value(&mut manifest_bytes, &manifest).expect("encode policy manifest");
    put_policy_manifest_bytes(&vault, entity(0x15), &manifest_bytes)
        .expect("install agent-auto policy manifest");
    let (settled_task, result_a) = member_task(
        &vault,
        0x60,
        Some(crate::task_verb::TaskTerminalDisposition::Completed),
    );
    let (failed_task, _) = member_task(
        &vault,
        0x70,
        Some(crate::task_verb::TaskTerminalDisposition::Failed),
    );
    // A member whose result artifact is ALREADY durable while its TASK is
    // still unsettled (the require_resolved_entity pre-settlement window).
    let (unsettled_task, _) = member_task(&vault, 0x80, None);
    let arbitrary_row = put_turn(&vault, 0x90, NOW);

    let resolve = |context_from: Vec<EntityId>| {
        resolve_context_spec(
            &vault,
            ContextResolutionRequest {
                spec: ContextSpec::excluded(),
                parent: None,
                context_from,
                world_scope: None,
            },
        )
    };

    // A genuinely settled sibling TASK's terminal result resolves — to
    // the RESULT ref, not the TASK row.
    let resolved = resolve(vec![settled_task]).expect("settled sibling result resolves");
    assert_eq!(resolved.sibling_result_refs, [result_a]);

    let refusals = [
        vec![unsettled_task],             // pre-settlement window closed
        vec![arbitrary_row],              // arbitrary existing non-TASK row
        vec![failed_task],                // settled, but not Completed
        vec![entity(0x63)],               // unresolved
        vec![settled_task, settled_task], // same sibling result twice
    ]
    .into_iter()
    .filter(|context_from| resolve(context_from.clone()).is_err())
    .count();
    assert_eq!(refusals, 5);
}

// ── panel spec ──────────────────────────────────────────────────────

#[test]
fn panel_spec_round_trips_through_a_durable_ref() {
    let (_dir, vault) = open_vault();
    let spec = panel_spec();

    let spec_ref = persist_lead_panel_spec(&vault, &spec, NOW).expect("persist panel spec");

    // The ref is one of ONE-1699's already-legal payload-ref variants, and
    // it resolves as such against the vault.
    assert!(matches!(spec_ref, ConsultPayloadRef::Turn(_)));
    assert_eq!(
        ConsultPayloadRef::parse(&vault, &spec_ref.short_ref()).expect("ref parses"),
        spec_ref
    );
    assert_eq!(
        load_lead_panel_spec(&vault, spec_ref).expect("load panel spec"),
        spec
    );
    assert_eq!(
        decode_lead_panel_spec(&encode_lead_panel_spec(&spec).expect("encode")).expect("decode"),
        spec
    );
}

#[test]
fn panel_spec_rejects_non_peer_responders_before_planning() {
    let mut spec = panel_spec();
    spec.judge.responder = TaskAssignee::Human {
        actor_ref: entity(0xEE),
    };
    assert!(matches!(
        validate_lead_panel_spec(&spec),
        Err(Error::InvalidTaskBody(_))
    ));
}

#[test]
fn malformed_panel_specs_are_refused() {
    let mut no_members = panel_spec();
    no_members.members.clear();
    let mut duplicate_responder = panel_spec();
    duplicate_responder.members[1].responder = duplicate_responder.members[0].responder;
    let mut blank_rubric = panel_spec();
    blank_rubric.judge.rubric = "   ".to_owned();
    let mut blank_synthesis = panel_spec();
    blank_synthesis.synthesis.instructions = String::new();
    let mut malformed_member_context = panel_spec();
    malformed_member_context.members[0].context_spec = scoped(&["health"], 0);

    let rejects = [
        no_members,
        duplicate_responder,
        blank_rubric,
        blank_synthesis,
        malformed_member_context,
    ];
    let refusals = rejects
        .iter()
        .filter(|spec| validate_lead_panel_spec(spec).is_err())
        .count();
    assert_eq!(refusals, rejects.len());
}

/// The planner returns typed INPUTS. It allocates no entity id, and every
/// payload it plans carries ONE-1699 refs only — never the question text,
/// the member instructions, or the judge rubric.
#[test]
fn planner_returns_ref_only_task_inputs_with_no_preallocated_ids() {
    let (_dir, vault) = open_vault();
    let spec = panel_spec();
    let question_ref = ConsultPayloadRef::Turn(put_turn(&vault, 0x64, NOW));
    let spec_ref = persist_lead_panel_spec(&vault, &spec, NOW).expect("persist panel spec");
    let correlation_ref = entity(0x65);

    let plan = plan_lead_panel_tasks(question_ref, spec_ref, correlation_ref, &spec)
        .expect("plan panel tasks");

    assert_eq!(plan.member_tasks.len(), 3);
    let planned = plan
        .member_tasks
        .iter()
        .chain([&plan.judge_task, &plan.synthesis_task]);
    for input in planned {
        assert_eq!(input.consult.question_ref, question_ref);
        assert_eq!(input.consult.context_refs, [spec_ref]);
        assert_eq!(input.consult.correlation_ref, correlation_ref);
        // ONE-1888's optional additions stay absent for an ordinary panel.
        assert_eq!(input.consult.purpose, None);
        assert_eq!(input.consult.entity_delta, None);
        assert_eq!(input.consult.lineage, None);
        assert_eq!(input.consult.ref_count(), 2);
    }

    // Instruction/rubric text lives ONLY in the referenced spec entity.
    let rendered = format!("{plan:?}");
    for text in [
        "member 0 answers alone",
        "rank the answers",
        "write one final answer",
    ] {
        assert!(
            !rendered.contains(text),
            "free-form panel text must not ride the planned TASK payload"
        );
    }

    // A colliding question/spec ref is refused: a consult refuses duplicates.
    assert!(plan_lead_panel_tasks(spec_ref, spec_ref, correlation_ref, &spec).is_err());
}

/// Blindness is structural: no member input carries a sibling result, the
/// judge waits for ALL member results, and synthesis waits for the judge
/// plus the members.
#[test]
fn panel_members_are_blind_and_the_judge_runs_once_after_them() {
    let (_dir, vault) = open_vault();
    let spec = panel_spec();
    let question_ref = ConsultPayloadRef::Turn(put_turn(&vault, 0x66, NOW));
    let spec_ref = persist_lead_panel_spec(&vault, &spec, NOW).expect("persist panel spec");

    let plan = plan_lead_panel_tasks(question_ref, spec_ref, entity(0x67), &spec)
        .expect("plan panel tasks");

    let blind_members = plan
        .member_tasks
        .iter()
        .filter(|input| input.result_inputs == PanelResultInputs::None)
        .count();
    assert_eq!(blind_members, 3);
    assert_eq!(
        plan.judge_task.result_inputs,
        PanelResultInputs::AllMemberResults
    );
    assert_eq!(
        plan.synthesis_task.result_inputs,
        PanelResultInputs::AllMemberAndJudgeResults
    );

    // Distinct responders — three members means three answers.
    let mut responders: Vec<String> = plan
        .member_tasks
        .iter()
        .map(|input| format!("{:?}", input.responder))
        .collect();
    responders.sort();
    responders.dedup();
    assert_eq!(responders.len(), 3);
}
