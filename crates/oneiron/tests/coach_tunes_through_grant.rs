//! The Coach tunes the engine's knobs through public verbs behind its
//! `engine.controls` grant (untangle 6.6d; Engine S66-CALLS = A; owner 9 Nov
//! 22:47, every substrate control is a public verb behind a grant). Each
//! knob verb answers a holder's call with the engine-control receipt, and
//! the knob is in force. The learning dials and the wake policy take the
//! holder through their existing verbs. An agent without the grant changes
//! nothing. A sieve raise is refused. The owner calls the same verbs under
//! its proof, and its receipts say so. On the base the verbs do not exist.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test coach_tunes_through_grant`.
#![cfg(oneiron_test_support)]

use oneiron::EntityId;
use oneiron::dreamer_consolidation::strength::ConsolidationStrengthPolicy;
use oneiron::dreamer_runner::{FreeTimeCadence, FreeTimeSchedule};
use oneiron::dreamer_wake::ProjectorPolicy;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{EngineControlActor, EngineControlClass};
use oneiron::learning_setting::{AUDIT_RATE, setting_value};
use oneiron::learning_setting_doors::{
    LearningSettingClear, LearningSettingMode, LearningSettingPut, clear_learning_setting_as_holder,
    put_learning_setting_as_holder,
};
use oneiron::policy_setting_doors::{WakePolicySetRequest, wake_policy_set_as_holder};
use oneiron::task_verb::sdk::{
    ConsolidationSelectionTimingSetRequest, ConsolidationStrengthSetRequest,
    CuratorCadenceSetRequest, DreamerProjectorSetRequest, FreeTimeScheduleSetRequest,
    ProactivityPeriodSetRequest, RetuneThresholdsSetRequest, SieveBudgetsLowerRequest,
    StewardshipRulePeriodSetRequest, lower_sieve_budgets_as,
    set_consolidation_selection_timing_as, set_consolidation_strength_as,
    set_curator_cadence_as, set_dreamer_projector_as, set_free_time_schedule_as,
    set_proactivity_period_as, set_retune_thresholds_as, set_stewardship_rule_period_as,
};
use oneiron::test_doors::coach::{coach, define_agent};
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::write_envelope::WriteActor;

fn pin(key: &str, value: f64) -> LearningSettingPut {
    LearningSettingPut {
        key: key.to_owned(),
        mode: LearningSettingMode::Pin,
        value: Some(value),
        choice: None,
        weight_runs: None,
        why: "tuning".to_owned(),
        goal: None,
        project: None,
        task_type: None,
    }
}

#[test]
fn the_coach_tunes_each_knob_through_its_verb() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let coach = coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");
    let holder = || EngineControlActor::Holder(coach);

    // The seven knob setters: each answers with its receipt, and the knob is
    // in force where the vault reads it back.
    let before = vault.consolidation_selection().expect("selection");
    let selection = set_consolidation_selection_timing_as(
        &vault,
        holder(),
        ConsolidationSelectionTimingSetRequest {
            soak_ms: 60_000,
            recency_window_ms: before.recency_window_ms * 2,
        },
    )
    .expect("selection timing");
    assert_eq!(selection.change.knob, "DREAMER_CONSOLIDATION_SELECTION");
    let after = vault.consolidation_selection().expect("selection");
    assert_eq!(after.soak_ms, 60_000);
    assert_eq!(after.recency_window_ms, before.recency_window_ms * 2);

    let strength = set_consolidation_strength_as(
        &vault,
        holder(),
        ConsolidationStrengthSetRequest {
            archive_below: 0.2,
            quiet_ms: 86_400_000,
        },
    )
    .expect("strength");
    assert_eq!(strength.change.knob, "DREAMER_CONSOLIDATION_STRENGTH_POLICY");
    assert_eq!(
        vault.consolidation_strength_policy().expect("strength"),
        ConsolidationStrengthPolicy {
            archive_below: 0.2,
            quiet_ms: 86_400_000,
        }
    );

    let curator = set_curator_cadence_as(
        &vault,
        holder(),
        CuratorCadenceSetRequest {
            minimum_age_secs: 3_600,
            cadence_secs: 7_200,
        },
    )
    .expect("curator cadence");
    assert_eq!(curator.change.knob, "DREAMER_CURATOR_RUBRIC");
    let rubric = vault.curator_rubric_as(&owner).expect("rubric");
    assert_eq!((rubric.minimum_age_secs, rubric.cadence_secs), (3_600, 7_200));

    let period = set_proactivity_period_as(
        &vault,
        holder(),
        ProactivityPeriodSetRequest { period_secs: 7_200 },
    )
    .expect("proactivity period");
    assert_eq!(period.change.knob, "DREAMER_PROACTIVITY_CADENCE");

    let thresholds = set_retune_thresholds_as(
        &vault,
        holder(),
        RetuneThresholdsSetRequest {
            prompts_score_regression: 0.1,
            weights_score_regression: 0.2,
            manifest_thresholds_score_regression: 0.3,
        },
    )
    .expect("retune thresholds");
    assert_eq!(thresholds.change.knob, "DREAMER_HARNESS_THRESHOLDS");

    let projector = set_dreamer_projector_as(
        &vault,
        holder(),
        DreamerProjectorSetRequest {
            min_new_statements: 3,
        },
    )
    .expect("projector");
    assert_eq!(projector.change.knob, "DREAMER_PROJECTOR_POLICY");
    assert_eq!(
        vault.dreamer_projector_policy().expect("projector"),
        ProjectorPolicy {
            min_new_statements: 3,
        }
    );

    // A rule the rule set does not name is refused, with no receipt.
    assert!(
        set_stewardship_rule_period_as(
            &vault,
            holder(),
            StewardshipRulePeriodSetRequest {
                rule: "no-such-rule".to_owned(),
                every_secs: 3_600,
            },
        )
        .is_err()
    );

    // The sieve: lower works, a raise is refused and changes nothing.
    let held = vault.dreamer_sieve_policy().expect("sieve");
    let lowered = lower_sieve_budgets_as(
        &vault,
        holder(),
        SieveBudgetsLowerRequest {
            max_turns_per_pass: held.max_turns_per_pass / 2,
            max_scan_per_pass: held.max_scan_per_pass,
            max_text_bytes_per_pass: held.max_text_bytes_per_pass,
        },
    )
    .expect("a lower budget");
    assert_eq!(lowered.change.class, EngineControlClass::WorkBudget);
    let sieve = vault.dreamer_sieve_policy().expect("sieve");
    assert_eq!(sieve.max_turns_per_pass, held.max_turns_per_pass / 2);
    assert!(
        lower_sieve_budgets_as(
            &vault,
            holder(),
            SieveBudgetsLowerRequest {
                max_turns_per_pass: held.max_turns_per_pass,
                max_scan_per_pass: held.max_scan_per_pass,
                max_text_bytes_per_pass: held.max_text_bytes_per_pass,
            },
        )
        .is_err(),
        "raising a sieve budget is the owner's act"
    );
    assert_eq!(vault.dreamer_sieve_policy().expect("sieve"), sieve);

    // The learning dials through vault.settings.learning.put and .clear.
    let reader = WriteActor::new(coach, EdgeActorClass::Agent);
    let view = put_learning_setting_as_holder(&vault, reader, pin(AUDIT_RATE.key, 0.25))
        .expect("the Coach's dial");
    assert!(view.rows.iter().any(|row| row.key == AUDIT_RATE.key));
    assert_eq!(setting_value(&vault, &AUDIT_RATE).expect("value"), 0.25);
    assert!(
        put_learning_setting_as_holder(&vault, reader, pin("health.card.owner_copy", 1.0))
            .is_err(),
        "a dial the owner keeps"
    );
    clear_learning_setting_as_holder(
        &vault,
        reader,
        LearningSettingClear {
            key: AUDIT_RATE.key.to_owned(),
            mode: LearningSettingMode::Pin,
            goal: None,
            project: None,
            task_type: None,
        },
    )
    .expect("the Coach clears its pin");

    // The wake policy through vault.settings.wake_policy.set.
    let mut wake = vault.dreamer_wake_policy().expect("wake policy");
    wake.longest_wait_secs += 60;
    let outcome = wake_policy_set_as_holder(
        &vault,
        reader,
        WakePolicySetRequest {
            policy: serde_json::to_value(wake).expect("policy"),
            idempotency_key: "coach-wake-1".to_owned(),
        },
    )
    .expect("wake policy");
    assert!(outcome.outcome["receipt"].is_string());
    assert_eq!(vault.dreamer_wake_policy().expect("wake policy"), wake);

    // Every change has its receipt, each naming the Coach as a holder.
    let changes = vault.engine_control_changes(&owner).expect("receipts");
    assert_eq!(changes.len(), 10, "{changes:?}");
    assert!(
        changes
            .iter()
            .all(|(_, change)| change.by == coach && !change.owner)
    );
    for answer in [&selection, &strength, &curator, &period, &thresholds, &projector] {
        assert!(changes.iter().any(|(id, _)| *id == answer.id));
    }
}

#[test]
fn an_agent_without_engine_controls_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    coach(&vault).expect("the Coach");
    vault.provision_system_agent_grants().expect("first mint");
    let agent = define_agent(&vault).expect("an agent");
    let stranger = EngineControlActor::Holder(agent);

    let projector = vault.dreamer_projector_policy().expect("projector");
    assert!(
        set_dreamer_projector_as(
            &vault,
            stranger,
            DreamerProjectorSetRequest {
                min_new_statements: projector.min_new_statements + 7,
            },
        )
        .is_err()
    );
    assert_eq!(vault.dreamer_projector_policy().expect("projector"), projector);
    assert!(
        set_proactivity_period_as(
            &vault,
            stranger,
            ProactivityPeriodSetRequest { period_secs: 60 },
        )
        .is_err()
    );
    let held = vault.dreamer_sieve_policy().expect("sieve");
    assert!(
        lower_sieve_budgets_as(
            &vault,
            stranger,
            SieveBudgetsLowerRequest {
                max_turns_per_pass: 1,
                max_scan_per_pass: 1,
                max_text_bytes_per_pass: 1,
            },
        )
        .is_err()
    );
    assert_eq!(vault.dreamer_sieve_policy().expect("sieve"), held);
    let reader = WriteActor::new(agent, EdgeActorClass::Agent);
    assert!(put_learning_setting_as_holder(&vault, reader, pin(AUDIT_RATE.key, 0.25)).is_err());
    let wake = vault.dreamer_wake_policy().expect("wake policy");
    assert!(
        wake_policy_set_as_holder(
            &vault,
            reader,
            WakePolicySetRequest {
                policy: serde_json::to_value(wake).expect("policy"),
                idempotency_key: "stranger-wake-1".to_owned(),
            },
        )
        .is_err()
    );
    assert!(
        set_free_time_schedule_as(
            &vault,
            stranger,
            FreeTimeScheduleSetRequest {
                agent: agent.to_hex(),
                expected_revision: 0,
                schedule: FreeTimeSchedule {
                    cadence: FreeTimeCadence::Nightly,
                    hour: 2,
                    minute: 0,
                    zone: "Asia/Tokyo".to_owned(),
                },
            },
        )
        .is_err()
    );
    assert!(
        vault
            .engine_control_changes(&owner)
            .expect("receipts")
            .is_empty(),
        "nothing changed"
    );
}

#[test]
fn the_owner_tunes_through_the_same_verbs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner = owner(&vault).expect("owner proof");
    let person = vault.ensure_embedded_owner_actor().expect("owner");

    let answer = set_dreamer_projector_as(
        &vault,
        EngineControlActor::Owner(&owner),
        DreamerProjectorSetRequest {
            min_new_statements: 5,
        },
    )
    .expect("the owner's projector");
    assert!(answer.change.owner);
    assert_eq!(answer.change.by, person);
    assert_eq!(
        vault.dreamer_projector_policy().expect("projector"),
        ProjectorPolicy {
            min_new_statements: 5,
        }
    );

    // The owner sets free time as a whole policy at its own verb.
    assert!(
        set_free_time_schedule_as(
            &vault,
            EngineControlActor::Owner(&owner),
            FreeTimeScheduleSetRequest {
                agent: EntityId::now().to_hex(),
                expected_revision: 0,
                schedule: FreeTimeSchedule {
                    cadence: FreeTimeCadence::Nightly,
                    hour: 2,
                    minute: 0,
                    zone: "Asia/Tokyo".to_owned(),
                },
            },
        )
        .is_err()
    );
    let changes = vault.engine_control_changes(&owner).expect("receipts");
    let [(id, change)] = changes.as_slice() else {
        panic!("one receipt, found {}", changes.len());
    };
    assert_eq!(*id, answer.id);
    assert!(change.owner);
}
