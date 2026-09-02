//! ONE-1961 regressions over the trust tables.

use std::collections::BTreeSet;

use super::*;

/// THE rule, evaluated over the whole table rather than asserted about one
/// case: a blocking check may never rest on operator-declared evidence.
///
/// This is the static half of the enforcement described in the module
/// documentation. A future check that grows an operator-declared input fails
/// here, at compile-and-test time, rather than at publication time.
#[test]
fn no_blocking_check_rests_on_operator_declared_evidence() {
    let violations = blocking_evidence_violations();
    assert!(
        violations.is_empty(),
        "blocking checks resting on operator-declared evidence: {violations:?}"
    );

    // The rule has to be capable of failing, or the assertion above proves
    // nothing. Evaluate it directly against the classifier.
    assert!(!TrustInput::OperatorDeclared.admissible_as_blocking_evidence());
    for admissible in [
        TrustInput::Measured,
        TrustInput::CompileDeclared,
        TrustInput::Derived,
    ] {
        assert!(
            admissible.admissible_as_blocking_evidence(),
            "{} must remain admissible as blocking evidence",
            admissible.as_str()
        );
    }
}

/// Every operator-declared input must be consumed only by advisory checks, and
/// the cache stream must actually be one of them. Stated from the INPUT side so
/// the two tables are cross-checked in both directions.
#[test]
fn every_operator_declared_input_is_consumed_only_by_advisory_checks() {
    let mut operator_declared = Vec::new();
    for input in &INPUTS {
        if input.class != TrustInput::OperatorDeclared {
            continue;
        }
        operator_declared.push(input.name);
        for consumer in consumers(input.name) {
            let spec = check_spec(consumer).expect("a consumer is a declared check");
            assert_eq!(
                spec.scope,
                CheckScope::Advisory,
                "`{consumer}` consumes operator-declared `{}` and must be advisory",
                input.name
            );
        }
    }
    assert_eq!(
        operator_declared,
        vec!["cache_events"],
        "the cache-event stream is the operator-declared input this design turns on"
    );
    assert_eq!(consumers("cache_events"), vec!["cache_rungs_complete"]);
}

/// The tables must be internally complete: every declared input is consumed by
/// something, every consumed input is declared, and no name is duplicated.
#[test]
fn the_trust_tables_are_complete_and_unambiguous() {
    let mut check_names = BTreeSet::new();
    for check in &CHECKS {
        assert!(
            check_names.insert(check.name),
            "duplicate check `{}`",
            check.name
        );
        assert!(
            !check.inputs.is_empty(),
            "`{}` must name the evidence it rests on",
            check.name
        );
        for input in check.inputs {
            assert!(
                input_spec(input).is_some(),
                "`{}` consumes undeclared input `{input}`",
                check.name
            );
        }
    }

    let mut input_names = BTreeSet::new();
    for input in &INPUTS {
        assert!(
            input_names.insert(input.name),
            "duplicate input `{}`",
            input.name
        );
        assert!(
            !consumers(input.name).is_empty(),
            "input `{}` is declared but consumed by no check; an unused trust row is a claim \
             nobody checks",
            input.name
        );
        assert!(
            !input.source.is_empty(),
            "input `{}` must name a concrete origin",
            input.name
        );
    }

    assert_eq!(CHECKS.len(), 22);
    assert_eq!(INPUTS.len(), 21);
}

/// Exactly one check is advisory, and it is the cache rung check. Everything
/// else withholds candidacy when it fails.
#[test]
fn cache_rungs_complete_is_the_only_advisory_check() {
    let advisory: Vec<&str> = CHECKS
        .iter()
        .filter(|check| !check.scope.is_blocking())
        .map(|check| check.name)
        .collect();
    assert_eq!(advisory, vec!["cache_rungs_complete"]);

    let cache = check_spec("cache_rungs_complete").expect("the cache check is declared");
    assert_eq!(cache.scope, CheckScope::Advisory);
    assert_eq!(cache.inputs, &["cache_events"]);
    assert_eq!(
        input_spec("cache_events").map(|spec| spec.class),
        Some(TrustInput::OperatorDeclared),
        "the cache stream is a file the operator pointed at; its rows describing themselves is \
         not evidence of origin"
    );
}

/// ONE-1963's new check is present, blocking, and rests on the two measured
/// digests it compares. It must not have quietly landed as advisory.
#[test]
fn the_child_program_check_is_blocking_and_rests_on_measured_digests() {
    let spec = check_spec("child_program_matches_build_revision")
        .expect("ONE-1963 adds the child-program check");
    assert_eq!(spec.scope, CheckScope::Blocking);
    assert_eq!(
        spec.inputs,
        &["child_program_blake3", "build_revision_blake3"]
    );
    for input in spec.inputs {
        assert_eq!(
            input_spec(input).map(|spec| spec.class),
            Some(TrustInput::Measured),
            "`{input}` must be measured, or the check compares two declarations"
        );
    }
    assert_eq!(CHECKS.last().expect("non-empty").name, spec.name);
}

/// The classes render as the snake-case strings the eval-side contract reads.
#[test]
fn trust_classes_and_scopes_render_as_their_contract_strings() {
    for (class, expected) in [
        (TrustInput::Measured, "measured"),
        (TrustInput::CompileDeclared, "compile_declared"),
        (TrustInput::OperatorDeclared, "operator_declared"),
        (TrustInput::Derived, "derived"),
    ] {
        assert_eq!(class.as_str(), expected);
        assert_eq!(
            serde_json::to_value(class).expect("class renders"),
            serde_json::Value::String(expected.to_owned())
        );
    }
    for (scope, expected) in [
        (CheckScope::Blocking, "blocking"),
        (CheckScope::Advisory, "advisory"),
    ] {
        assert_eq!(scope.as_str(), expected);
        assert_eq!(
            serde_json::to_value(scope).expect("scope renders"),
            serde_json::Value::String(expected.to_owned())
        );
    }
}
