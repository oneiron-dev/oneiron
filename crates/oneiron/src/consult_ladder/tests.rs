//! Pure ladder, novelty-guard, magistrate, and A2A-projection tests
//! (ONE-1888). Everything here runs without a vault by construction.

use super::*;

fn id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("test entity id")
}

fn working(started_at: u64) -> ConsultLadderState {
    ConsultLadderState::Working(WorkingState {
        started_at,
        decision_round: 0,
    })
}

fn interrupted(kind: InterruptionKind, consent_required: bool) -> ConsultLadderState {
    ConsultLadderState::Interrupted(InterruptedState {
        kind,
        consent_required,
        case_ref: id(0x21),
        interrupted_at: 500,
    })
}

fn terminal(disposition: LadderTerminalDisposition) -> LadderTerminalState {
    LadderTerminalState {
        disposition,
        result_ref: id(0x31),
        counter_task_ref: matches!(disposition, LadderTerminalDisposition::Countered)
            .then(|| id(0x32)),
        finished_at: 900,
    }
}

const ALL_DISPOSITIONS: [LadderTerminalDisposition; 7] = [
    LadderTerminalDisposition::Approved,
    LadderTerminalDisposition::Overridden,
    LadderTerminalDisposition::Rejected,
    LadderTerminalDisposition::Failed,
    LadderTerminalDisposition::Escalated,
    LadderTerminalDisposition::Countered,
    LadderTerminalDisposition::Abandoned,
];

// ── terminal immutability ───────────────────────────────────────────────

/// Every generated terminal state refuses every transition and survives
/// field-for-field. A settled consult is a record, not a mutable row.
#[test]
fn every_terminal_state_refuses_every_transition_and_is_preserved() {
    let transitions = [
        LadderTransition::Interrupt(InterruptedState {
            kind: InterruptionKind::Pathology,
            consent_required: true,
            case_ref: id(0x41),
            interrupted_at: 1_000,
        }),
        LadderTransition::Resume(WorkingState {
            started_at: 1_000,
            decision_round: 3,
        }),
        LadderTransition::Finish(terminal(LadderTerminalDisposition::Approved)),
    ];

    for disposition in ALL_DISPOSITIONS {
        let settled = ConsultLadderState::Terminal(terminal(disposition));
        for transition in transitions {
            let before = settled;
            let refused = transition_ladder(&settled, transition);
            assert_eq!(
                refused,
                Err(LadderTransitionError::TerminalImmutable),
                "{} must refuse every transition",
                disposition.as_str()
            );
            // The pure function took `&self`, so the original is untouched —
            // asserted rather than assumed.
            assert_eq!(settled, before);
            assert_eq!(
                settled.terminal().map(|state| state.disposition),
                Some(disposition)
            );
        }
    }
}

/// Every accepted terminal state carries a durable result. `result_ref` is a
/// plain `EntityId`, so a result-less terminal is unrepresentable rather than
/// merely rejected — and `EntityId` already refuses the empty sentinel.
#[test]
fn accepted_terminal_states_always_carry_a_result_ref() {
    for disposition in ALL_DISPOSITIONS {
        let settled = transition_ladder(
            &working(100),
            LadderTransition::Finish(terminal(disposition)),
        )
        .expect("a working ladder may finish");
        let state = settled.terminal().expect("finish lands terminal");
        assert_eq!(state.result_ref, id(0x31));
        assert!(EntityId::from_bytes([0; 16]).is_err());
    }
}

/// A counter names its successor and nothing else may. A `Countered` terminal
/// without the link — or any other disposition carrying one — is refused.
#[test]
fn counter_link_must_match_the_disposition() {
    let orphan_counter = LadderTerminalState {
        disposition: LadderTerminalDisposition::Countered,
        result_ref: id(0x31),
        counter_task_ref: None,
        finished_at: 900,
    };
    let stray_link = LadderTerminalState {
        disposition: LadderTerminalDisposition::Approved,
        result_ref: id(0x31),
        counter_task_ref: Some(id(0x32)),
        finished_at: 900,
    };

    for malformed in [orphan_counter, stray_link] {
        assert_eq!(
            transition_ladder(&working(100), LadderTransition::Finish(malformed)),
            Err(LadderTransitionError::InvalidTransition)
        );
    }
}

// ── rejected is not failed ──────────────────────────────────────────────

/// `Rejected` never renders, projects, or compares as `Failed` on ANY of the
/// surfaces this module owns. A completed decision is not a broken machine.
#[test]
fn rejected_never_reads_as_failed_on_any_surface() {
    let rejected = ConsultLadderState::Terminal(terminal(LadderTerminalDisposition::Rejected));
    let failed = ConsultLadderState::Terminal(terminal(LadderTerminalDisposition::Failed));

    assert_ne!(rejected, failed);
    assert_ne!(
        LadderTerminalDisposition::Rejected.as_str(),
        LadderTerminalDisposition::Failed.as_str()
    );
    let rejected_a2a = project_to_a2a(id(0x01), &rejected, None);
    let failed_a2a = project_to_a2a(id(0x01), &failed, None);
    assert_eq!(rejected_a2a.state, A2aBaseTaskState::Completed);
    assert_eq!(failed_a2a.state, A2aBaseTaskState::Failed);
    assert_eq!(
        rejected_a2a.extensions.terminal_disposition.as_deref(),
        Some("rejected")
    );
    assert_eq!(
        failed_a2a.extensions.terminal_disposition.as_deref(),
        Some("failed")
    );
    // Tokens round-trip one-to-one, so no decoder can fold them together.
    for disposition in ALL_DISPOSITIONS {
        assert_eq!(
            LadderTerminalDisposition::from_token(disposition.as_str()),
            Some(disposition)
        );
    }
}

// ── non-terminal transitions ────────────────────────────────────────────

/// A consent-required interruption resumes only through a human verdict; an
/// ordinary one resumes freely; and a re-interrupt must actually change state.
#[test]
fn interruption_transitions_follow_the_consent_rule() {
    let contested = interrupted(InterruptionKind::Contested, false);
    let critical = interrupted(InterruptionKind::Critical, true);
    let resumed = WorkingState {
        started_at: 600,
        decision_round: 1,
    };
    let resume = LadderTransition::Resume(resumed);

    assert_eq!(
        transition_ladder(&contested, resume),
        Ok(ConsultLadderState::Working(resumed)),
        "an ordinary interruption resumes into its next decision round"
    );
    assert_eq!(
        transition_ladder(&critical, resume),
        Err(LadderTransitionError::ConsentRequired)
    );
    assert_eq!(
        transition_ladder(&working(100), resume),
        Err(LadderTransitionError::InvalidTransition),
        "a working ladder cannot resume"
    );

    // A recusal turns a contested case into a consent-required one.
    let ConsultLadderState::Interrupted(critical_state) = critical else {
        panic!("critical fixture is an interruption");
    };
    assert_eq!(
        transition_ladder(&contested, LadderTransition::Interrupt(critical_state)),
        Ok(critical)
    );
    assert_eq!(
        transition_ladder(&critical, LadderTransition::Interrupt(critical_state)),
        Err(LadderTransitionError::InvalidTransition),
        "a re-interrupt to the same state is a no-op, not a transition"
    );
}

// ── OF-399 novelty guard ────────────────────────────────────────────────

struct StubLookup {
    graduated: std::result::Result<bool, String>,
    approved: std::result::Result<bool, String>,
}

impl StubLookup {
    fn graduated_with(approved: bool) -> Self {
        Self {
            graduated: Ok(true),
            approved: Ok(approved),
        }
    }
}

impl GraduationLookup for StubLookup {
    fn scope_is_graduated(&self, _scope: &GraduationScope) -> std::result::Result<bool, String> {
        self.graduated.clone()
    }

    fn shape_was_approved(
        &self,
        _scope: &GraduationScope,
        _fingerprint: DeltaShapeFingerprint,
    ) -> std::result::Result<bool, String> {
        self.approved.clone()
    }
}

fn shape(paths: &[&str]) -> EntityDeltaShape {
    EntityDeltaShape {
        operation_kind: "claim.replace".to_owned(),
        target_entity_type: 4,
        normalized_paths: paths.iter().map(|path| (*path).to_owned()).collect(),
    }
}

fn scope() -> GraduationScope {
    GraduationScope {
        proposer_actor_ref: id(0x51),
        owning_actor_ref: id(0x52),
        operation_kind: "claim.replace".to_owned(),
        target_entity_type: 4,
        skill_or_agent_ref: None,
        standing_grant_ref: id(0x53),
    }
}

/// A graduated pair reuses its standing grant only for an already-receipted
/// shape. The same pair proposing a new field, operation family, or target
/// class returns to consult.
#[test]
fn graduation_admits_a_known_shape_and_returns_a_novel_one_to_consult() {
    let known = novelty_guard(
        &StubLookup::graduated_with(true),
        &scope(),
        &shape(&["person.email"]),
    );
    assert_eq!(
        known,
        NoveltyDecision::AutoKnownShape {
            standing_grant_ref: id(0x53)
        }
    );

    let novel_field = shape(&["person.email", "person.home_address"]);
    assert_eq!(
        novelty_guard(&StubLookup::graduated_with(false), &scope(), &novel_field),
        NoveltyDecision::ConsultNovelShape {
            fingerprint: delta_shape_fingerprint(&novel_field)
        }
    );

    // A new OPERATION family under the same paths is a different bound, so the
    // graduated scope no longer covers it at all.
    let mut novel_operation = shape(&["person.email"]);
    novel_operation.operation_kind = "claim.retract".to_owned();
    assert_eq!(
        novelty_guard(
            &StubLookup::graduated_with(true),
            &scope(),
            &novel_operation
        ),
        NoveltyDecision::ConsultUncertainShape
    );

    // A new TARGET class likewise.
    let mut novel_class = shape(&["person.email"]);
    novel_class.target_entity_type = 17;
    assert_eq!(
        novelty_guard(&StubLookup::graduated_with(true), &scope(), &novel_class),
        NoveltyDecision::ConsultUncertainShape
    );
}

/// Every failure direction is consult. A missing grant, a malformed shape, and
/// a lookup that cannot answer all mint the owner-agent ask; none of them can
/// produce the auto arm.
#[test]
fn novelty_guard_fails_toward_consult_and_never_toward_auto() {
    let no_grant = StubLookup {
        graduated: Ok(false),
        approved: Ok(true),
    };
    assert_eq!(
        novelty_guard(&no_grant, &scope(), &shape(&["person.email"])),
        NoveltyDecision::ConsultNoGrant
    );

    let broken_scope_lookup = StubLookup {
        graduated: Err("index unavailable".to_owned()),
        approved: Ok(true),
    };
    let broken_shape_lookup = StubLookup {
        graduated: Ok(true),
        approved: Err("receipt history unreadable".to_owned()),
    };
    for lookup in [broken_scope_lookup, broken_shape_lookup] {
        assert_eq!(
            novelty_guard(&lookup, &scope(), &shape(&["person.email"])),
            NoveltyDecision::ConsultUncertainShape
        );
    }

    let malformed = [
        shape(&[]),
        shape(&["", "person.email"]),
        shape(&["person.email", "person.email"]),
        shape(&["person.email\u{7}injected"]),
        shape(&[" person.email"]),
        EntityDeltaShape {
            operation_kind: String::new(),
            target_entity_type: 4,
            normalized_paths: vec!["person.email".to_owned()],
        },
    ];
    for (index, entry) in malformed.into_iter().enumerate() {
        assert!(!entry.is_decodable(), "case {index} must not decode");
        assert_eq!(
            novelty_guard(&StubLookup::graduated_with(true), &scope(), &entry),
            NoveltyDecision::ConsultUncertainShape,
            "case {index} must fall back to consult"
        );
    }
}

/// The fingerprint hashes STRUCTURE. Path order is not structure; a new path
/// is.
#[test]
fn delta_shape_fingerprint_is_order_free_but_structure_sensitive() {
    let forward = shape(&["person.email", "person.phone"]);
    let reversed = shape(&["person.phone", "person.email"]);
    let extended = shape(&["person.email", "person.phone", "person.address"]);

    assert_eq!(
        delta_shape_fingerprint(&forward),
        delta_shape_fingerprint(&reversed)
    );
    assert_ne!(
        delta_shape_fingerprint(&forward),
        delta_shape_fingerprint(&extended)
    );
}

// ── human-entry matrix ──────────────────────────────────────────────────

/// The complete list of branches that may reach a person. Ordinary owner-agent
/// decisions never do; normal-class contested goes to the Dreamer first; only
/// critical-contested and pathology admit a human.
#[test]
fn human_entry_matrix_is_exactly_contested_critical_and_pathology() {
    let matrix = [
        (
            OwnerAgentOutcome::Approved,
            CaseCriticality::Normal,
            LadderRoute::Terminal(LadderTerminalDisposition::Approved),
        ),
        (
            OwnerAgentOutcome::Approved,
            CaseCriticality::Critical,
            LadderRoute::Terminal(LadderTerminalDisposition::Approved),
        ),
        (
            OwnerAgentOutcome::Rejected,
            CaseCriticality::Normal,
            LadderRoute::Terminal(LadderTerminalDisposition::Rejected),
        ),
        (
            OwnerAgentOutcome::Overridden,
            CaseCriticality::Normal,
            LadderRoute::Terminal(LadderTerminalDisposition::Overridden),
        ),
        (
            OwnerAgentOutcome::Contested,
            CaseCriticality::Normal,
            LadderRoute::DreamerMagistrate,
        ),
        (
            OwnerAgentOutcome::Contested,
            CaseCriticality::Critical,
            LadderRoute::HumanConsent(InterruptionKind::Critical),
        ),
        (
            OwnerAgentOutcome::Pathological,
            CaseCriticality::Normal,
            LadderRoute::HumanConsent(InterruptionKind::Pathology),
        ),
        (
            OwnerAgentOutcome::Pathological,
            CaseCriticality::Critical,
            LadderRoute::HumanConsent(InterruptionKind::Pathology),
        ),
    ];

    let mut human_entries = 0_usize;
    for (index, (outcome, criticality, expected)) in matrix.into_iter().enumerate() {
        let route = route_owner_agent_outcome(outcome, criticality);
        assert_eq!(route, expected, "case {index}");
        if matches!(route, LadderRoute::HumanConsent(_)) {
            human_entries += 1;
        }
    }
    // Exactly the three admitted rows above; no ordinary decision reaches one.
    assert_eq!(human_entries, 3);
}

/// Every human verdict settles on exactly one ladder outcome, and escalation
/// reuses ONE-1699's assignee wire rather than minting a second one.
#[test]
fn human_verdicts_map_onto_ladder_outcomes() {
    let cases = [
        (
            HumanVerdict::Approve {
                rationale_ref: None,
            },
            LadderTerminalDisposition::Approved,
        ),
        (
            HumanVerdict::Reject {
                rationale_ref: Some(id(0x61)),
            },
            LadderTerminalDisposition::Rejected,
        ),
        (
            HumanVerdict::OverrideWithDiff {
                delta_ref: id(0x62),
                rationale_ref: id(0x63),
            },
            LadderTerminalDisposition::Overridden,
        ),
        (
            HumanVerdict::Escalate {
                assignee: TaskAssignee::Human {
                    actor_ref: id(0x64),
                },
                rationale_ref: id(0x65),
            },
            LadderTerminalDisposition::Escalated,
        ),
    ];
    for (verdict, expected) in cases {
        assert_eq!(terminal_for_human_verdict(verdict), expected);
    }
    // Escalation goes to a follow-on, so it is NOT a terminal TASK record.
    assert!(LadderTerminalDisposition::Escalated.defers_to_follow_on());
    assert!(
        !ALL_DISPOSITIONS
            .iter()
            .filter(|disposition| **disposition != LadderTerminalDisposition::Escalated)
            .any(|disposition| disposition.defers_to_follow_on())
    );
}

// ── magistrate ──────────────────────────────────────────────────────────

fn case(criticality: CaseCriticality) -> MagistrateCase {
    MagistrateCase {
        task_ref: id(0x71),
        contested_state_ref: id(0x72),
        contested_delta_ref: id(0x73),
        criticality,
        policy: Vec::new(),
        authority: Vec::new(),
        temporal: Vec::new(),
        candidate_delta_refs: vec![id(0x73), id(0x74)],
        dreamer_attempt_ref: None,
        now: 1_000,
    }
}

fn deciding_policy() -> Vec<PolicyEvidence> {
    vec![PolicyEvidence {
        policy_ref: id(0x76),
        selected_delta_ref: Some(id(0x73)),
    }]
}

/// The decision order is strict, not weighted: compiled policy beats contrary
/// authority AND temporal evidence.
#[test]
fn compiled_policy_outranks_contrary_authority_and_temporal_evidence() {
    let mut policy_wins = case(CaseCriticality::Normal);
    policy_wins.policy = deciding_policy();
    policy_wins.authority = vec![AuthorityEvidence {
        authoritative_actor_ref: id(0x75),
        state_ref: id(0x72),
        selected_delta_ref: Some(id(0x74)),
    }];
    policy_wins.temporal = vec![TemporalEvidence {
        occurred_at: 9_999,
        learned_at: 9_999,
        supersedes_ref: None,
        selected_delta_ref: Some(id(0x74)),
    }];

    let verdict =
        decide_magistrate_from_derived_authorship(&policy_wins, StateAuthorship::OtherAgent);

    assert_eq!(
        verdict,
        MagistrateVerdict::Rule {
            selected_delta_ref: id(0x73),
            rationale_ref: id(0x76),
        },
        "the freshest fact in the world cannot outvote explicit policy"
    );
    assert_eq!(
        magistrate_decision_layer(&policy_wins, verdict),
        MagistrateDecisionLayer::CompiledPolicy
    );
}

/// With policy silent, authoritative ownership decides — still ahead of
/// contrary temporal evidence.
#[test]
fn authority_outranks_contrary_temporal_evidence_when_policy_is_silent() {
    let mut authority_wins = case(CaseCriticality::Normal);
    authority_wins.authority = vec![AuthorityEvidence {
        authoritative_actor_ref: id(0x75),
        state_ref: id(0x72),
        selected_delta_ref: Some(id(0x73)),
    }];
    authority_wins.temporal = vec![TemporalEvidence {
        occurred_at: 9_999,
        learned_at: 9_999,
        supersedes_ref: None,
        selected_delta_ref: Some(id(0x74)),
    }];

    let verdict =
        decide_magistrate_from_derived_authorship(&authority_wins, StateAuthorship::Human);

    assert_eq!(
        verdict,
        MagistrateVerdict::Rule {
            selected_delta_ref: id(0x73),
            rationale_ref: id(0x72),
        }
    );
    assert_eq!(
        magistrate_decision_layer(&authority_wins, verdict),
        MagistrateDecisionLayer::AuthorityOverState
    );
}

/// Only with both silent does time decide: supersession first, then freshness.
#[test]
fn temporal_decides_only_when_policy_and_authority_are_silent() {
    let mut temporal_only = case(CaseCriticality::Normal);
    temporal_only.temporal = vec![
        TemporalEvidence {
            occurred_at: 10,
            learned_at: 10,
            supersedes_ref: None,
            selected_delta_ref: Some(id(0x74)),
        },
        TemporalEvidence {
            occurred_at: 20,
            learned_at: 20,
            supersedes_ref: Some(id(0x74)),
            selected_delta_ref: Some(id(0x73)),
        },
    ];

    let verdict =
        decide_magistrate_from_derived_authorship(&temporal_only, StateAuthorship::System);

    assert_eq!(
        verdict,
        MagistrateVerdict::Rule {
            selected_delta_ref: id(0x73),
            rationale_ref: id(0x74),
        }
    );
    assert_eq!(
        magistrate_decision_layer(&temporal_only, verdict),
        MagistrateDecisionLayer::Temporal
    );
}

/// An explicitly-applicable policy that selects NOTHING is a decision, not
/// silence: it rejects rather than falling through to the next layer.
#[test]
fn an_applicable_policy_selecting_nothing_rejects() {
    let mut refusing = case(CaseCriticality::Normal);
    refusing.policy = vec![PolicyEvidence {
        policy_ref: id(0x76),
        selected_delta_ref: None,
    }];
    refusing.authority = vec![AuthorityEvidence {
        authoritative_actor_ref: id(0x75),
        state_ref: id(0x72),
        selected_delta_ref: Some(id(0x73)),
    }];

    assert_eq!(
        decide_magistrate_from_derived_authorship(&refusing, StateAuthorship::OtherAgent),
        MagistrateVerdict::Reject {
            rationale_ref: id(0x76)
        }
    );
}

/// Dreamer-authored state recuses BEFORE any evidence is weighed — even when
/// the evidence would otherwise produce a clean ruling, and even on a critical
/// case where advice would otherwise be the outcome.
#[test]
fn dreamer_authored_state_recuses_before_any_ruling() {
    let mut decisive = case(CaseCriticality::Normal);
    decisive.policy = deciding_policy();
    let recused = MagistrateVerdict::Recused {
        reason: MagistrateRecusal::DreamerAuthoredState,
    };

    assert_eq!(
        decide_magistrate_from_derived_authorship(&decisive, StateAuthorship::Dreamer),
        recused
    );
    assert_eq!(
        magistrate_decision_layer(&decisive, recused),
        MagistrateDecisionLayer::Recused
    );
    // A recusal is not a ruling, so it cannot terminalize the TASK.
    assert_eq!(terminal_for_magistrate_verdict(recused), None);

    let mut critical = decisive;
    critical.criticality = CaseCriticality::Critical;
    assert_eq!(
        decide_magistrate_from_derived_authorship(&critical, StateAuthorship::Dreamer),
        recused
    );
    assert_eq!(
        MagistrateRecusal::DreamerAuthoredState.as_str(),
        "dreamer_authored_state"
    );
}

/// The case type carries no authorship field at all, so there is nothing for a
/// caller to forge: the ONLY input is the derived argument. Two byte-identical
/// cases decide differently purely on what the vault said.
#[test]
fn authorship_is_an_argument_not_a_forgeable_case_field() {
    let mut decisive = case(CaseCriticality::Normal);
    decisive.policy = deciding_policy();
    let forged_view = decisive.clone();

    assert_eq!(decisive, forged_view);
    assert_eq!(
        decide_magistrate_from_derived_authorship(&forged_view, StateAuthorship::OtherAgent),
        MagistrateVerdict::Rule {
            selected_delta_ref: id(0x73),
            rationale_ref: id(0x76),
        }
    );
    assert_eq!(
        decide_magistrate_from_derived_authorship(&decisive, StateAuthorship::Dreamer),
        MagistrateVerdict::Recused {
            reason: MagistrateRecusal::DreamerAuthoredState
        }
    );
}

/// A critical case yields advice with a recommendation, and advice can never
/// become a terminal state without a human verdict. Criticality is the only
/// difference from the ruling case.
#[test]
fn critical_cases_return_advice_that_cannot_terminalize() {
    let mut critical = case(CaseCriticality::Critical);
    critical.policy = deciding_policy();

    let verdict = decide_magistrate_from_derived_authorship(&critical, StateAuthorship::OtherAgent);

    assert_eq!(
        verdict,
        MagistrateVerdict::AdviceOnly {
            recommended_delta_ref: Some(id(0x73)),
            rationale_ref: id(0x76),
        }
    );
    assert_eq!(terminal_for_magistrate_verdict(verdict), None);
    assert_eq!(
        magistrate_decision_layer(&critical, verdict),
        MagistrateDecisionLayer::AdviceOnly
    );

    let mut normal = critical;
    normal.criticality = CaseCriticality::Normal;
    assert_eq!(
        terminal_for_magistrate_verdict(decide_magistrate_from_derived_authorship(
            &normal,
            StateAuthorship::OtherAgent
        )),
        Some(LadderTerminalDisposition::Approved)
    );
}

/// Typed invariant failures escalate instead of being ruled on: no candidates,
/// a contested delta outside the candidate set, evidence selecting an unknown
/// delta, contradictory layers, an exact bitemporal tie, and no evidence at
/// all.
#[test]
fn malformed_and_contradictory_cases_escalate_as_pathology() {
    let cases = [
        MagistrateCase {
            candidate_delta_refs: Vec::new(),
            ..case(CaseCriticality::Normal)
        },
        MagistrateCase {
            candidate_delta_refs: vec![id(0x74)],
            ..case(CaseCriticality::Normal)
        },
        MagistrateCase {
            policy: vec![PolicyEvidence {
                policy_ref: id(0x76),
                selected_delta_ref: Some(id(0x7F)),
            }],
            ..case(CaseCriticality::Normal)
        },
        MagistrateCase {
            policy: vec![
                PolicyEvidence {
                    policy_ref: id(0x76),
                    selected_delta_ref: Some(id(0x73)),
                },
                PolicyEvidence {
                    policy_ref: id(0x77),
                    selected_delta_ref: Some(id(0x74)),
                },
            ],
            ..case(CaseCriticality::Normal)
        },
        MagistrateCase {
            temporal: vec![
                TemporalEvidence {
                    occurred_at: 50,
                    learned_at: 50,
                    supersedes_ref: None,
                    selected_delta_ref: Some(id(0x73)),
                },
                TemporalEvidence {
                    occurred_at: 50,
                    learned_at: 50,
                    supersedes_ref: None,
                    selected_delta_ref: Some(id(0x74)),
                },
            ],
            ..case(CaseCriticality::Normal)
        },
        case(CaseCriticality::Normal),
    ];

    for (index, entry) in cases.into_iter().enumerate() {
        let verdict =
            decide_magistrate_from_derived_authorship(&entry, StateAuthorship::OtherAgent);
        assert_eq!(
            verdict,
            MagistrateVerdict::EscalatePathology {
                rationale_ref: id(0x72)
            },
            "case {index} must escalate"
        );
        assert_eq!(terminal_for_magistrate_verdict(verdict), None);
        assert_eq!(
            magistrate_decision_layer(&entry, verdict),
            MagistrateDecisionLayer::Pathology
        );
    }
}

// ── A2A projection ──────────────────────────────────────────────────────

/// The projection, in full. It is a wire PROJECTION: Oneiron's richer terminal
/// vocabulary rides the extensions rather than collapsing into A2A's five
/// base states.
#[test]
fn a2a_projection_maps_every_ladder_state() {
    let task = id(0x81);

    let working_projection = project_to_a2a(task, &working(10), None);
    assert_eq!(working_projection.id, task.to_hex());
    assert_eq!(working_projection.state, A2aBaseTaskState::Working);
    assert_eq!(
        working_projection.extensions,
        OneironA2aExtensions::default()
    );

    let consent = project_to_a2a(task, &interrupted(InterruptionKind::Critical, true), None);
    assert_eq!(consent.state, A2aBaseTaskState::InputRequired);
    assert_eq!(
        consent.extensions.interruption_kind.as_deref(),
        Some("critical")
    );

    // A contested case is still progressing: no human input is awaited, so the
    // base state stays `working` and the reason rides the extension.
    let contested = project_to_a2a(task, &interrupted(InterruptionKind::Contested, false), None);
    assert_eq!(contested.state, A2aBaseTaskState::Working);
    assert_eq!(
        contested.extensions.interruption_kind.as_deref(),
        Some("contested")
    );

    let expected = [
        (
            LadderTerminalDisposition::Approved,
            A2aBaseTaskState::Completed,
            "approved",
        ),
        (
            LadderTerminalDisposition::Overridden,
            A2aBaseTaskState::Completed,
            "overridden",
        ),
        (
            LadderTerminalDisposition::Rejected,
            A2aBaseTaskState::Completed,
            "rejected",
        ),
        (
            LadderTerminalDisposition::Failed,
            A2aBaseTaskState::Failed,
            "failed",
        ),
        (
            LadderTerminalDisposition::Escalated,
            A2aBaseTaskState::InputRequired,
            "escalated",
        ),
        (
            LadderTerminalDisposition::Countered,
            A2aBaseTaskState::Completed,
            "rejected",
        ),
        (
            LadderTerminalDisposition::Abandoned,
            A2aBaseTaskState::Cancelled,
            "abandoned",
        ),
    ];
    for (disposition, base, token) in expected {
        let projection = project_to_a2a(
            task,
            &ConsultLadderState::Terminal(terminal(disposition)),
            None,
        );
        assert_eq!(projection.state, base, "{}", disposition.as_str());
        assert_eq!(
            projection.extensions.terminal_disposition.as_deref(),
            Some(token),
            "{}",
            disposition.as_str()
        );
        assert_eq!(
            projection.extensions.result_ref.as_deref(),
            Some(id(0x31).to_hex().as_str())
        );
        assert_eq!(projection.extensions.counter_of, None);
    }
}

/// A counter is a NEW projected task carrying `oneiron.counter_of`; there is
/// no invented in-place mutation on the base A2A task.
#[test]
fn a2a_counter_is_a_new_task_carrying_counter_of() {
    let parent = id(0x82);
    let counter_task = id(0x83);
    let lineage = ConsultLineage {
        relation: ConsultLineageRelation::Counter,
        parent_task_ref: parent,
    };

    let counter = project_to_a2a(counter_task, &working(10), Some(lineage));

    assert_eq!(counter.id, counter_task.to_hex());
    assert_eq!(counter.state, A2aBaseTaskState::Working);
    assert_eq!(
        counter.extensions.counter_of.as_deref(),
        Some(parent.to_hex().as_str())
    );

    // Appeal and escalation lineage do NOT mint a counter link.
    for relation in [
        ConsultLineageRelation::Appeal,
        ConsultLineageRelation::Escalation,
    ] {
        let other = project_to_a2a(
            counter_task,
            &working(10),
            Some(ConsultLineage {
                relation,
                parent_task_ref: parent,
            }),
        );
        assert_eq!(other.extensions.counter_of, None);
        assert_eq!(
            ConsultLineageRelation::from_token(relation.as_str()),
            Some(relation)
        );
    }
}

/// The A2A base tokens are the protocol's own strings, not Oneiron's, and the
/// consult purpose round-trips with absent meaning ONE-1699's question shape.
#[test]
fn wire_tokens_are_pinned_and_round_trip() {
    let a2a = [
        (A2aBaseTaskState::Working, "working"),
        (A2aBaseTaskState::InputRequired, "input-required"),
        (A2aBaseTaskState::Completed, "completed"),
        (A2aBaseTaskState::Failed, "failed"),
        (A2aBaseTaskState::Cancelled, "cancelled"),
    ];
    for (state, token) in a2a {
        assert_eq!(state.as_str(), token);
    }
    for purpose in [ConsultPurpose::Question, ConsultPurpose::EntityDelta] {
        assert_eq!(ConsultPurpose::from_token(purpose.as_str()), Some(purpose));
    }
    assert_eq!(ConsultPurpose::from_token("counter"), None);
    for kind in [
        InterruptionKind::Contested,
        InterruptionKind::Critical,
        InterruptionKind::Pathology,
    ] {
        assert!(!kind.as_str().is_empty());
    }
    assert_eq!(DREAMER_MAGISTRATE_ATTEMPT_TYPE, "dreamer.magistrate");
}
