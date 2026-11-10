//! Direct calls into the items `oneiron-model` made `pub` so `oneiron` can reach them across
//! the crate split. Called from outside the engine, the checks still refuse bad input
//! exactly as they did when they were crate-private.

use oneiron_contracts::EntityId;
use oneiron_contracts::edge::EdgeActorClass;
use oneiron_contracts::write_envelope::WriteActor;
use oneiron_model::extraction_eval::{
    OF360_GOLD_DATASET_ID, OF360_GOLD_DATASET_REVISION, OF360_SCHEMA_VERSION, Of360Ar3MetricTier,
    Of360EvalError, Of360ExtractionRun, of360_builtin_ar3_metric_tier,
};
use oneiron_model::llm::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetPolicyRow, BudgetPolicySelector, BudgetPolicyTable,
    CallPurpose, DreamerFailureClass, DreamerFailurePrecedence, DreamerFailureRule, FinishReason,
    LlmMessage, LlmMessageRole, LlmResponse, LlmUsage, decide_failure, dynamic_model_id,
    fallback_failure_class, parse_failure_rules,
};
use rmpv::Value;

fn actor() -> WriteActor {
    WriteActor::new(
        EntityId::from_bytes([0x11; 16]).expect("a valid entity id"),
        EdgeActorClass::Agent,
    )
}

/// The shipped AR-3 tier for a run that extracted nothing.
fn metric_tier() -> Of360Ar3MetricTier {
    of360_builtin_ar3_metric_tier(&Of360ExtractionRun {
        schema_version: OF360_SCHEMA_VERSION,
        run_id: "seam".to_owned(),
        system_id: "seam".to_owned(),
        dataset_id: OF360_GOLD_DATASET_ID.to_owned(),
        dataset_revision: OF360_GOLD_DATASET_REVISION.to_owned(),
        cases: Vec::new(),
    })
    .expect("an empty run scores against the shipped subset")
}

const OPEN_FATAL: DreamerFailureRule = DreamerFailureRule {
    class: DreamerFailureClass::Fatal,
    consolidation_eligible: true,
    effector_eligible: true,
    default_consolidation_eligible: true,
    default_effector_eligible: true,
};

#[test]
fn failure_rules_parser_refuses_malformed_tables() {
    assert!(parse_failure_rules(&Value::from("fatal")).is_none());
    assert!(parse_failure_rules(&Value::Array(vec![Value::from(1); 4])).is_none());
    assert!(parse_failure_rules(&Value::Array(vec![Value::from("row")])).is_none());
}

#[test]
#[should_panic(expected = "addressable by a u16 row index")]
fn policy_guard_refuses_a_table_past_the_u16_row_index() {
    let row = BudgetPolicyRow::new(BudgetPolicySelector::Purpose(CallPurpose::Eval), None, None);
    let table = BudgetPolicyTable::from_rows(vec![row; usize::from(u16::MAX) + 2]);
    let _ = BudgetGuard::with_policy_table(
        "seam",
        1_000,
        10,
        BudgetExhaustionPolicy::Suspend,
        actor(),
        &table,
    );
}

#[test]
fn an_actor_cap_row_still_refuses_admission() {
    let actor = actor();
    let cap = BudgetPolicyRow::new(
        BudgetPolicySelector::Actor(actor.entity_ref()),
        None,
        Some(0),
    );
    let table = BudgetPolicyTable::from_rows(vec![cap]);
    let guard = BudgetGuard::with_policy_table(
        "seam",
        1_000,
        10,
        BudgetExhaustionPolicy::Suspend,
        actor,
        &table,
    );
    assert!(guard.admit().is_err());
}

#[test]
fn failure_decisions_never_grant_past_a_vault_ceiling() {
    // A class no trusted pack configures has no ceiling, so nothing is eligible.
    let unconfigured = decide_failure(
        &[],
        DreamerFailureClass::Fatal,
        DreamerFailurePrecedence::HolderOverrideCappedAtVault,
    );
    assert!(!unconfigured.consolidation_with_stage(Some(true)));
    assert!(!unconfigured.effector_with_stage(Some(true)));

    // One pack's false ceiling caps the class whatever the holder chooses.
    let capped = DreamerFailureRule {
        consolidation_eligible: false,
        effector_eligible: false,
        ..OPEN_FATAL
    };
    let decision = decide_failure(
        &[OPEN_FATAL, capped],
        DreamerFailureClass::Fatal,
        DreamerFailurePrecedence::HolderOverrideCappedAtVault,
    );
    assert!(!decision.consolidation_with_stage(Some(true)));
    assert!(!decision.effector_with_stage(Some(true)));

    // Under nested narrowing a holder choice only narrows the default.
    let closed_default = DreamerFailureRule {
        default_effector_eligible: false,
        ..OPEN_FATAL
    };
    let nested = decide_failure(
        &[closed_default],
        DreamerFailureClass::Fatal,
        DreamerFailurePrecedence::NestedNarrowing,
    );
    assert!(!nested.effector_with_stage(Some(true)));
    assert!(nested.consolidation_with_stage(Some(true)));
    assert!(!nested.consolidation_with_stage(Some(false)));
}

#[test]
fn failure_precedence_parses_strictly_and_restricts_to_nested_narrowing() {
    for value in ["", "Nested_Narrowing", "holder_override"] {
        assert_eq!(DreamerFailurePrecedence::parse(value), None, "{value:?}");
    }
    let nested = DreamerFailurePrecedence::NestedNarrowing;
    let holder = DreamerFailurePrecedence::HolderOverrideCappedAtVault;
    assert_eq!(holder.restrict(nested), nested);
    assert_eq!(nested.restrict(holder), nested);
    assert_eq!(holder.restrict(holder), holder);
}

#[test]
fn metric_tier_check_refuses_foreign_versions_and_mismatched_reports() {
    assert!(metric_tier().validate().is_ok());

    let mut version = metric_tier();
    version.interface_version += 1;
    let mut report_schema = metric_tier();
    report_schema.report.schema_version += 1;
    let mut metric_set = metric_tier();
    metric_set.report.metric_set_id.push_str("-forged");
    let mut duplicate_case = metric_tier();
    let first = duplicate_case.report.cases[0].clone();
    duplicate_case.report.cases.push(first);
    for refused in [version, report_schema, metric_set, duplicate_case] {
        let result = refused.validate();
        assert!(
            matches!(result, Err(Of360EvalError::InvalidMetricTier { .. })),
            "{result:?}"
        );
    }
}

#[test]
fn only_a_fallback_finish_marks_an_output_as_failed() {
    let response = |finish_reason| LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: Vec::new(),
        },
        usage: LlmUsage::zero(),
        finish_reason,
    };
    let fallback = FinishReason::Other {
        name: "fallback:deterministic".to_owned(),
    };
    assert_eq!(
        fallback_failure_class(&response(fallback)),
        Some(DreamerFailureClass::Fatal)
    );
    for finish in [
        FinishReason::Stop,
        FinishReason::Length,
        FinishReason::Other {
            name: "provider:fallback".to_owned(),
        },
    ] {
        assert_eq!(fallback_failure_class(&response(finish)), None);
    }
}

#[test]
fn dynamic_model_ids_join_sanitized_segments() {
    let id = dynamic_model_id("local", "guard-3".to_owned(), "2026-10");
    assert_eq!(id.as_str(), "local/guard-3@2026-10");
}

#[test]
#[should_panic(expected = "sanitized safeguard model binding")]
fn dynamic_model_ids_refuse_an_unsanitized_segment() {
    let _ = dynamic_model_id("local", "guard 3".to_owned(), "2026-10");
}
