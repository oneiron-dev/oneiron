//! Task verb tests: Consult payload, ladder states, durable CAS, escalation, cross-actor routing and human verdicts.

use super::support::*;
use super::*;

/// The purpose and the artifact must agree, and a self-owned "cross-actor"
/// delta is the auto path taking the wrong door.
#[test]
fn consult_payload_refuses_contradictory_purposes() {
    let question = ConsultPayloadRef::Turn(ladder_id(0xC1));
    let mut delta_without_artifact =
        ConsultPayload::question(question, Vec::new(), ladder_id(0xC2));
    delta_without_artifact.purpose = Some(ConsultPurpose::EntityDelta);

    let mut artifact_without_purpose =
        ConsultPayload::question(question, Vec::new(), ladder_id(0xC2));
    artifact_without_purpose.entity_delta = Some(ladder_delta(
        ladder_id(0xC3),
        ladder_id(0xC4),
        ladder_id(0xC5),
        ladder_id(0xC6),
    ));

    let same_actor = ConsultPayload::question(question, Vec::new(), ladder_id(0xC2))
        .with_entity_delta(ladder_delta(
            ladder_id(0xC3),
            ladder_id(0xC4),
            ladder_id(0xC5),
            ladder_id(0xC5),
        ));

    for (index, payload) in [delta_without_artifact, artifact_without_purpose, same_actor]
        .into_iter()
        .enumerate()
    {
        assert!(
            decode_consult_payload(&consult_payload_value(&payload)).is_err(),
            "case {index} must be refused"
        );
    }
}

/// A LIVE `interrupted` register may carry only a ladder terminal that DEFERS
/// to a follow-on. Every other settled disposition is refused at the wire: the
/// projection never writes one there, and a peer that ships one would freeze
/// every ladder write door on a row the projections read as settled.
///
/// The `terminal` arm is unchanged — that is where a non-deferring ladder
/// belongs, and all seven still decode there.
#[test]
fn an_interrupted_register_admits_only_a_deferring_ladder_terminal() {
    let (_dir, vault) = open_vault();
    let (task_ref, _peer, _question) = open_consult(&vault);
    let body = task_verb_body(&vault, task_ref)
        .expect("decode consult")
        .expect("consult is typed");
    let dispositions = [
        LadderTerminalDisposition::Approved,
        LadderTerminalDisposition::Overridden,
        LadderTerminalDisposition::Rejected,
        LadderTerminalDisposition::Failed,
        LadderTerminalDisposition::Escalated,
        LadderTerminalDisposition::Countered,
        LadderTerminalDisposition::Abandoned,
    ];

    for disposition in dispositions {
        let counter_task_ref =
            matches!(disposition, LadderTerminalDisposition::Countered).then(|| ladder_id(0xB2));
        let mut live = body.clone();
        live.state = Some(TaskExecutionState::Interrupted {
            ladder: Some(LadderTerminalState {
                disposition,
                result_ref: ladder_id(0xB1),
                counter_task_ref,
                finished_at: LADDER_NOW + 1,
            }),
        });
        let live_state = live.state.clone();
        let decoded = decode_task_verb_body(&encode_task_verb_body(live));

        if disposition.defers_to_follow_on() {
            assert_eq!(
                decoded
                    .expect("a deferring ladder terminal is the one live register")
                    .state,
                live_state,
                "{} defers to a follow-on, so it rides on the live row",
                disposition.as_str()
            );
        } else {
            assert!(
                matches!(
                    decoded,
                    Err(crate::error::Error::Record(
                        crate::error::RecordError::InvalidTaskBody("tasks.terminal.ladder")
                    ))
                ),
                "{} settles without deferring and has no place on a live row",
                disposition.as_str()
            );
        }

        let mut settled = body.clone();
        settled.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
            disposition: TaskTerminalDisposition::Completed,
            result_ref: Some(ladder_id(0xB1)),
            summary: None,
            finished_at: LADDER_NOW + 1,
            ladder: Some(disposition),
            counter_task_ref,
        }));
        let settled_state = settled.state.clone();
        assert_eq!(
            decode_task_verb_body(&encode_task_verb_body(settled))
                .expect("a terminal record admits every ladder disposition")
                .state,
            settled_state,
            "{} still decodes on the terminal arm",
            disposition.as_str()
        );

        // ...but only with a COHERENT counter link. The terminal arm takes all
        // seven dispositions; the link belongs to exactly one of them, which is
        // what `LadderTerminalState::is_well_formed` says on the ladder's own
        // type. Flip it and the row is a state no internal door can mint — a
        // counter projected for a task nobody replaced, or the lineage of one
        // that was, silently dropped.
        let mut incoherent = body.clone();
        incoherent.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
            disposition: TaskTerminalDisposition::Completed,
            result_ref: Some(ladder_id(0xB1)),
            summary: None,
            finished_at: LADDER_NOW + 1,
            ladder: Some(disposition),
            counter_task_ref: match counter_task_ref {
                Some(_) => None,
                None => Some(ladder_id(0xB3)),
            },
        }));
        assert!(
            matches!(
                decode_task_verb_body(&encode_task_verb_body(incoherent)),
                Err(crate::error::Error::Record(
                    crate::error::RecordError::InvalidTaskBody("tasks.terminal.ladder")
                ))
            ),
            "{} paired with the wrong counter link has no coherent reading",
            disposition.as_str()
        );
    }

    // Deferring is necessary but not sufficient. The counter link belongs to
    // `Countered` alone, so an escalation naming a successor is a state no
    // internal door can mint — and the wire does not mint it either.
    let mut ill_formed = body;
    ill_formed.state = Some(TaskExecutionState::Interrupted {
        ladder: Some(LadderTerminalState {
            disposition: LadderTerminalDisposition::Escalated,
            result_ref: ladder_id(0xB1),
            counter_task_ref: Some(ladder_id(0xB2)),
            finished_at: LADDER_NOW + 1,
        }),
    });
    assert!(
        matches!(
            decode_task_verb_body(&encode_task_verb_body(ill_formed)),
            Err(crate::error::Error::Record(
                crate::error::RecordError::InvalidTaskBody("tasks.terminal.ladder")
            ))
        ),
        "an escalation that names a successor is not a well-formed ladder terminal"
    );

    // The same rule where there is no ladder at all: a ONE-1699 terminal that
    // names a successor is naming one for a ladder it never ran.
    let mut unladdered = task_verb_body(&vault, task_ref)
        .expect("decode consult")
        .expect("consult is typed");
    unladdered.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
        disposition: TaskTerminalDisposition::Completed,
        result_ref: Some(ladder_id(0xB1)),
        summary: None,
        finished_at: LADDER_NOW + 1,
        ladder: None,
        counter_task_ref: Some(ladder_id(0xB3)),
    }));
    assert!(
        matches!(
            decode_task_verb_body(&encode_task_verb_body(unladdered)),
            Err(crate::error::Error::Record(
                crate::error::RecordError::InvalidTaskBody("tasks.terminal.ladder")
            ))
        ),
        "a counter link with no ladder disposition names a successor to nothing",
    );
}

/// Two replicas converge on the same terminal register in either merge
/// order: later `finished_at` wins, and a SUBSTANTIVE decision beats an
/// expiry-like sweep on an exact tie.
#[test]
fn substantive_terminals_dominate_expiry_like_ones_on_an_exact_tie() {
    let record = |disposition, finished_at| TaskTerminalRecord {
        disposition,
        result_ref: Some(ladder_id(0xE1)),
        summary: None,
        finished_at,
        ladder: None,
        counter_task_ref: None,
    };
    let cases = [
        // A rejection that landed at the deadline instant is still an
        // answer: it beats the expiry sweep.
        (
            record(TaskTerminalDisposition::Rejected, 150),
            record(TaskTerminalDisposition::Expired, 150),
            record(TaskTerminalDisposition::Rejected, 150),
        ),
        (
            record(TaskTerminalDisposition::Rejected, 150),
            record(TaskTerminalDisposition::Abandoned, 150),
            record(TaskTerminalDisposition::Rejected, 150),
        ),
        (
            record(TaskTerminalDisposition::Completed, 150),
            record(TaskTerminalDisposition::Abandoned, 150),
            record(TaskTerminalDisposition::Completed, 150),
        ),
        // Time still dominates class.
        (
            record(TaskTerminalDisposition::Rejected, 100),
            record(TaskTerminalDisposition::Expired, 200),
            record(TaskTerminalDisposition::Expired, 200),
        ),
    ];

    for (index, (left, right, expected)) in cases.into_iter().enumerate() {
        let forward = merge_task_terminal_register(Some(&left), Some(&right));
        let backward = merge_task_terminal_register(Some(&right), Some(&left));
        assert_eq!(forward, backward, "case {index} must be order-free");
        assert_eq!(forward, Some(expected), "case {index} winner");
    }

    // Two substantive terminals at one instant fall to canonical bytes,
    // which both replicas compute identically.
    let completed = record(TaskTerminalDisposition::Completed, 150);
    let rejected = record(TaskTerminalDisposition::Rejected, 150);
    assert_eq!(
        merge_task_terminal_register(Some(&completed), Some(&rejected)),
        merge_task_terminal_register(Some(&rejected), Some(&completed))
    );
}

/// A target the acting actor owns routes auto and writes nothing; a target
/// owned by another actor mints exactly ONE owner-assigned consult and
/// leaves the target byte-untouched.
#[test]
fn own_writes_route_auto_and_cross_actor_writes_mint_one_owner_consult() {
    let (_dir, vault) = open_vault();
    let fixture = cross_actor_fixture(&vault);
    let facade = vault.memory(fixture.proposer, EdgeActorClass::Agent);
    let own_task = facade
        .tasks_create(&spec(LADDER_NOW))
        .expect("own task create effects")
        .task_ref
        .expect("own task minted");

    let own_route = facade
        .route_entity_delta(
            ladder_delta(
                own_task,
                fixture.delta_ref,
                fixture.proposer,
                fixture.proposer,
            ),
            None,
            LADDER_DEADLINE,
            LADDER_NOW,
        )
        .expect("own delta routes");
    assert_eq!(own_route, CrossActorRoute::AutoOwn);

    let tasks_before = task_entity_census(&vault);
    let target_before = vault
        .get_raw(&fixture.target)
        .expect("target read")
        .expect("target stored");
    let cross_route = facade
        .route_entity_delta(
            ladder_delta(
                fixture.target,
                fixture.delta_ref,
                fixture.proposer,
                fixture.owner,
            ),
            None,
            LADDER_DEADLINE,
            LADDER_NOW,
        )
        .expect("cross-actor delta routes");
    let tasks_after = task_entity_census(&vault);

    let CrossActorRoute::ConsultOwner { receipt } = cross_route else {
        panic!("a non-graduated cross-actor write consults the owner");
    };
    let consult_ref = receipt.task_ref.expect("consult minted");
    let body = task_verb_body(&vault, consult_ref)
        .expect("decode consult")
        .expect("consult is typed");
    let payload = body.consult.as_ref().expect("consult payload");

    assert_eq!(tasks_after - tasks_before, 1, "exactly one TASK is written");
    assert_eq!(body.task_kind(), TaskKind::Consult);
    assert_eq!(
        body.assignee,
        Some(TaskAssignee::Peer {
            actor_ref: fixture.owner
        }),
        "the OWNING actor is the first adjudicator"
    );
    assert_eq!(payload.consult_purpose(), ConsultPurpose::EntityDelta);
    assert_eq!(
        payload
            .entity_delta
            .as_ref()
            .map(|delta| delta.proposer_actor_ref),
        Some(fixture.proposer)
    );
    // Routing proposes; it never writes the state it is asking about.
    assert_eq!(
        vault
            .get_raw(&fixture.target)
            .expect("target read")
            .expect("target stored"),
        target_before
    );
}

/// Ownership is resolved from durable state, never asserted: a forged
/// owning actor and an unattributed proposer are both refused.
#[test]
fn a_forged_owner_or_proposer_is_refused() {
    let (_dir, vault) = open_vault();
    let fixture = cross_actor_fixture(&vault);
    let facade = vault.memory(fixture.proposer, EdgeActorClass::Agent);

    let forged_owner = facade
        .route_entity_delta(
            // Claims the proposer owns state the vault attributes to
            // another actor.
            ladder_delta(
                fixture.target,
                fixture.delta_ref,
                fixture.proposer,
                fixture.proposer,
            ),
            None,
            LADDER_DEADLINE,
            LADDER_NOW,
        )
        .expect_err("a forged owner is refused");
    let forged_proposer = facade
        .route_entity_delta(
            ladder_delta(
                fixture.target,
                fixture.delta_ref,
                fixture.owner,
                fixture.owner,
            ),
            None,
            LADDER_DEADLINE,
            LADDER_NOW,
        )
        .expect_err("an unattributed proposer is refused");
    let unresolvable = facade
        .route_entity_delta(
            ladder_delta(
                fixture.delta_ref,
                fixture.delta_ref,
                fixture.proposer,
                fixture.owner,
            ),
            None,
            LADDER_DEADLINE,
            LADDER_NOW,
        )
        .expect_err("a target with no recorded owner is refused");

    assert_eq!(forged_owner.code, MEMORY_CODE_FORBIDDEN);
    assert_eq!(forged_proposer.code, MEMORY_CODE_FORBIDDEN);
    assert_eq!(unresolvable.code, MEMORY_CODE_INVALID_STATE);
}

/// A graduated pair on an already-receipted shape rides its existing
/// standing grant instead of minting a second consult.
#[test]
fn a_graduated_known_shape_routes_through_its_standing_grant() {
    let (_dir, vault) = open_vault();
    let fixture = cross_actor_fixture(&vault);
    let facade = vault.memory(fixture.proposer, EdgeActorClass::Agent);
    let scope = ladder_scope(fixture.proposer, fixture.owner);

    let before = task_entity_census(&vault);
    let route = facade
        .route_entity_delta(
            ladder_delta(
                fixture.target,
                fixture.delta_ref,
                fixture.proposer,
                fixture.owner,
            ),
            Some((&AlwaysGraduated, &scope)),
            LADDER_DEADLINE,
            LADDER_NOW,
        )
        .expect("graduated delta routes");
    let after = task_entity_census(&vault);

    assert_eq!(
        route,
        CrossActorRoute::AutoViaStandingGrant {
            standing_grant_ref: ladder_id(0xB1)
        }
    );
    assert_eq!(after, before, "an auto route mints no consult");

    // A grant for a DIFFERENT pair cannot be borrowed.
    let wrong_pair = ladder_scope(fixture.owner, fixture.proposer);
    let borrowed = facade
        .route_entity_delta(
            ladder_delta(
                fixture.target,
                fixture.delta_ref,
                fixture.proposer,
                fixture.owner,
            ),
            Some((&AlwaysGraduated, &wrong_pair)),
            LADDER_DEADLINE,
            LADDER_NOW,
        )
        .expect("mismatched grant still routes");
    assert!(matches!(borrowed, CrossActorRoute::ConsultOwner { .. }));
}

/// A counter is a NEW task with `Counter` lineage. The open original
/// terminalizes as rejected-with-counter-lineage in the same transaction;
/// a second counter preserves the original terminal decision and linkage.
#[test]
fn counter_mints_a_new_task_and_never_reopens_the_original() {
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
        .mint_counter_task(original, delta.clone(), LADDER_DEADLINE, LADDER_NOW + 5)
        .expect("counter mints")
        .task_ref
        .expect("counter task minted");
    let original_body = task_verb_body(&vault, original)
        .expect("decode original")
        .expect("original is typed");
    let counter_body = task_verb_body(&vault, counter)
        .expect("decode counter")
        .expect("counter is typed");

    assert_ne!(counter, original);
    assert_eq!(
        counter_body
            .consult
            .as_ref()
            .and_then(|payload| payload.lineage),
        Some(ConsultLineage {
            relation: ConsultLineageRelation::Counter,
            parent_task_ref: original,
        })
    );
    let terminal = original_body.terminal().expect("original terminalized");
    assert_eq!(terminal.disposition, TaskTerminalDisposition::Rejected);
    assert_eq!(terminal.ladder, Some(LadderTerminalDisposition::Countered));
    assert_eq!(terminal.counter_task_ref, Some(counter));
    assert!(terminal.result_ref.is_some(), "counter lineage is durable");

    let second = facade
        .mint_counter_task(original, delta, LADDER_DEADLINE, LADDER_NOW + 9)
        .expect("a second counter still mints")
        .task_ref
        .expect("second counter minted");
    let after_body = task_verb_body(&vault, original)
        .expect("decode original after second counter")
        .expect("original is typed");
    let after = after_body.terminal().expect("original remains terminal");

    assert_ne!(second, counter);
    assert_ne!(second, original);
    assert_eq!(after.disposition, TaskTerminalDisposition::Rejected);
    assert_eq!(after.ladder, Some(LadderTerminalDisposition::Countered));
    assert_eq!(after.counter_task_ref, Some(counter));
    assert_eq!(after.result_ref, terminal.result_ref);
}

/// A counter mints beside an escalated original without changing its
/// settled decision, durable links, or live TASK state.
#[test]
fn counter_leaves_an_escalated_original_byte_identical() {
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
    let working = ConsultLadderState::Working(WorkingState {
        started_at: LADDER_NOW,
        decision_round: 0,
    });
    seed_ladder_state(&vault, original, &working);
    facade
        .compare_and_set_consult_ladder(
            original,
            &working,
            LadderTransition::Finish(LadderTerminalState {
                disposition: LadderTerminalDisposition::Escalated,
                result_ref: ladder_id(0xE5),
                counter_task_ref: None,
                finished_at: LADDER_NOW + 1,
            }),
        )
        .expect("a working ladder may escalate");

    facade
        .mint_counter_task(original, delta, LADDER_DEADLINE, LADDER_NOW + 5)
        .expect("counter mints")
        .task_ref
        .expect("counter task minted");

    let body = task_verb_body(&vault, original)
        .expect("decode original after counter")
        .expect("original is typed");
    assert!(body.terminal().is_none(), "the task remains live");
    let Some(TaskExecutionState::Interrupted {
        ladder: Some(persisted),
    }) = body.state.as_ref()
    else {
        panic!("the task retains its settled escalation");
    };
    assert_eq!(persisted.disposition, LadderTerminalDisposition::Escalated);
    assert_eq!(persisted.result_ref, ladder_id(0xE5));
    assert_eq!(persisted.counter_task_ref, None);
}

/// The CAS decides against the PERSISTED projection, not the caller's
/// optimism: a freshly-minted `Queued` consult has no ladder row yet.
#[test]
fn the_durable_ladder_cas_refuses_a_stale_expectation() {
    let (_dir, vault) = open_vault();
    let (task_ref, _peer, _question) = open_consult(&vault);
    let facade = vault.memory(own_agent(&vault), EdgeActorClass::Agent);

    let conflict = facade
        .compare_and_set_consult_ladder(
            task_ref,
            &ConsultLadderState::Working(WorkingState {
                started_at: LADDER_NOW,
                decision_round: 0,
            }),
            LadderTransition::Interrupt(InterruptedState {
                kind: InterruptionKind::Contested,
                consent_required: false,
                case_ref: ladder_id(0xF1),
                interrupted_at: LADDER_NOW + 1,
            }),
        )
        .expect_err("a stale expectation is refused");

    assert_eq!(conflict.code, MEMORY_CODE_INVALID_STATE);
}

/// An escalated ladder is settled even though its TASK row stays live, so a
/// caller naming the state the row PROJECTS onto — a plain interruption —
/// still cannot resume or finish it.
///
/// The projection alone cannot tell the two apart, which is exactly why the
/// settled ladder is persisted beside it.
#[test]
fn an_escalated_ladder_refuses_a_cas_that_expects_a_plain_interruption() {
    let (_dir, vault) = open_vault();
    let (task_ref, _peer, _question) = open_consult(&vault);
    let facade = vault.memory(own_agent(&vault), EdgeActorClass::Agent);
    let working = ConsultLadderState::Working(WorkingState {
        started_at: LADDER_NOW,
        decision_round: 0,
    });
    seed_ladder_state(&vault, task_ref, &working);
    facade
        .compare_and_set_consult_ladder(
            task_ref,
            &working,
            LadderTransition::Finish(LadderTerminalState {
                disposition: LadderTerminalDisposition::Escalated,
                result_ref: ladder_id(0xE1),
                counter_task_ref: None,
                finished_at: LADDER_NOW + 1,
            }),
        )
        .expect("a working ladder may escalate");

    let masquerading = ConsultLadderState::Interrupted(InterruptedState {
        kind: InterruptionKind::Contested,
        consent_required: false,
        case_ref: ladder_id(0xE2),
        interrupted_at: LADDER_NOW + 1,
    });
    let resumed = facade
        .compare_and_set_consult_ladder(
            task_ref,
            &masquerading,
            LadderTransition::Resume(WorkingState {
                started_at: LADDER_NOW + 2,
                decision_round: 1,
            }),
        )
        .expect_err("a settled ladder does not resume");
    let finished = facade
        .compare_and_set_consult_ladder(
            task_ref,
            &masquerading,
            LadderTransition::Finish(LadderTerminalState {
                disposition: LadderTerminalDisposition::Approved,
                result_ref: ladder_id(0xE3),
                counter_task_ref: None,
                finished_at: LADDER_NOW + 3,
            }),
        )
        .expect_err("a settled ladder does not settle twice");

    assert_eq!(resumed.code, MEMORY_CODE_INVALID_STATE);
    assert_eq!(finished.code, MEMORY_CODE_INVALID_STATE);
    let body = task_verb_body(&vault, task_ref)
        .expect("decode consult")
        .expect("consult is typed");
    assert_eq!(
        body.state,
        Some(TaskExecutionState::Interrupted {
            ladder: Some(LadderTerminalState {
                disposition: LadderTerminalDisposition::Escalated,
                result_ref: ladder_id(0xE1),
                counter_task_ref: None,
                finished_at: LADDER_NOW + 1,
            }),
        })
    );
}

/// A late peer answer is refused without changing the settled escalation,
/// its durable result, its counter linkage, or the live TASK state.
#[test]
fn a_late_consult_result_refuses_to_overwrite_a_settled_ladder() {
    let (_dir, vault) = open_vault();
    let (task_ref, peer, question) = open_consult(&vault);
    let escalated = escalate_consult(&vault, task_ref, ladder_id(0xC1), LADDER_NOW + 1);
    let late_result = consult_turn(&vault, 0x82).entity_ref();

    let late = vault
        .memory(peer, EdgeActorClass::Agent)
        .land_consult_result(task_ref, &answer_input(late_result, question))
        .expect_err("an escalated consult refuses a late answer");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode consult")
        .expect("consult is typed");

    assert_eq!(late.code, MEMORY_CODE_INVALID_STATE);
    assert!(body.terminal().is_none(), "the task remains live");
    let Some(TaskExecutionState::Interrupted {
        ladder: Some(persisted),
    }) = body.state.as_ref()
    else {
        panic!("the task retains its settled escalation");
    };
    assert_eq!(persisted.disposition, LadderTerminalDisposition::Escalated);
    assert_eq!(persisted.result_ref, escalated.result_ref);
    assert_eq!(persisted.counter_task_ref, escalated.counter_task_ref);
}

/// The general result door refuses a synced settled ladder without
/// flattening its escalation or losing its durable result and counter link.
#[test]
fn a_late_generic_result_refuses_to_overwrite_a_settled_ladder() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xC2);
    let task_ref = vault
        .memory(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("create")
        .task_ref
        .expect("task ref");
    let escalated = LadderTerminalState {
        disposition: LadderTerminalDisposition::Escalated,
        result_ref: ladder_id(0xC3),
        counter_task_ref: None,
        finished_at: ROUTE_NOW + 1,
    };
    seed_ladder_state(&vault, task_ref, &ConsultLadderState::Terminal(escalated));
    let late_result = route_turn(&vault, 0xC4).entity_ref();

    let late = vault
        .memory(actor_ref, EdgeActorClass::Agent)
        .land_task_result(
            task_ref,
            &TaskResultInput {
                result_ref: late_result,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: ROUTE_NOW + 9,
            },
        )
        .expect_err("an escalated row refuses a late result");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(late.code, MEMORY_CODE_INVALID_STATE);
    assert!(body.terminal().is_none(), "the task remains live");
    let Some(TaskExecutionState::Interrupted {
        ladder: Some(persisted),
    }) = body.state.as_ref()
    else {
        panic!("the task retains its settled escalation");
    };
    assert_eq!(persisted.disposition, LadderTerminalDisposition::Escalated);
    assert_eq!(persisted.result_ref, ladder_id(0xC3));
    assert_eq!(persisted.counter_task_ref, None);
}

/// An escalated consult is settled, not overdue: the sweep neither expires
/// it nor schedules a digest, and preserves its durable decision and links.
#[test]
fn the_deadline_sweep_leaves_an_escalated_consult_settled() {
    let (_dir, vault) = open_vault();
    let asker = own_agent(&vault);
    grant_outbound(&vault, asker, 0xD1);
    let (task_ref, _peer, _question) = open_consult(&vault);
    let escalated = escalate_consult(&vault, task_ref, ladder_id(0xC5), LADDER_NOW + 1);

    let report = vault
        .memory(asker, EdgeActorClass::Agent)
        .settle_due_consults(CONSULT_DEADLINE + 1, &digest_route())
        .expect("the sweep runs past the deadline");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode consult")
        .expect("consult is typed");

    assert_eq!(report.expired_task_refs.len(), 0);
    assert_eq!(report.digest_intent_refs.len(), 0);
    assert_eq!(
        vault.connector_send_tasks().expect("connector sends").len(),
        0
    );
    assert!(body.terminal().is_none(), "the task remains live");
    let Some(TaskExecutionState::Interrupted {
        ladder: Some(persisted),
    }) = body.state.as_ref()
    else {
        panic!("the task retains its settled escalation");
    };
    assert_eq!(persisted.disposition, LadderTerminalDisposition::Escalated);
    assert_eq!(persisted.result_ref, escalated.result_ref);
    assert_eq!(persisted.counter_task_ref, escalated.counter_task_ref);
}

/// A consent-required interruption resumes only through a human verdict —
/// enforced on the durable path, not just the pure one.
#[test]
fn a_consent_required_interruption_cannot_be_resumed_durably() {
    let (_dir, vault) = open_vault();
    let (task_ref, _peer, _question) = open_consult(&vault);
    let facade = vault.memory(own_agent(&vault), EdgeActorClass::Agent);
    let waiting = ConsultLadderState::Interrupted(InterruptedState {
        kind: InterruptionKind::Critical,
        consent_required: true,
        case_ref: ladder_id(0xF5),
        interrupted_at: LADDER_NOW,
    });
    seed_ladder_state(&vault, task_ref, &waiting);

    let refused = facade
        .compare_and_set_consult_ladder(
            task_ref,
            &waiting,
            LadderTransition::Resume(WorkingState {
                started_at: LADDER_NOW + 1,
                decision_round: 1,
            }),
        )
        .expect_err("consent-required work does not resume itself");
    // The human verdict path DOES settle it.
    let approved = facade
        .compare_and_set_consult_ladder(
            task_ref,
            &waiting,
            LadderTransition::Finish(LadderTerminalState {
                disposition: terminal_for_human_verdict(HumanVerdict::Approve {
                    rationale_ref: Some(ladder_id(0xF6)),
                }),
                result_ref: ladder_id(0xF7),
                counter_task_ref: None,
                finished_at: LADDER_NOW + 2,
            }),
        )
        .expect("a human verdict settles the case");

    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN);
    assert_eq!(
        approved
            .ladder_state
            .terminal()
            .map(|state| state.disposition),
        Some(LadderTerminalDisposition::Approved)
    );
}
