//! Regressions for ONE-1579 compiled-settings attribution.
//!
//! Split out of `build_profile.rs` so the module itself stays well under the
//! repository's giant-file bar; nothing here is reachable outside `cfg(test)`.

use super::*;

/// The collected profile describes THIS artifact: the level the build script
/// captured from Cargo, the debug assertions compiled into the crate, and
/// overflow checks observed from the code the compiler emitted.
#[test]
fn the_collected_profile_reads_this_artifacts_own_compilation() {
    let profile = BuildProfile::collect();
    assert_eq!(profile.debug_assertions, cfg!(debug_assertions));
    assert_eq!(profile.declared_profile_source, BUILD_PROFILE_ENV);
    assert_eq!(profile.publishable_opt_levels, PUBLISHABLE_OPT_LEVELS);
    assert_eq!(profile.rule, PROFILE_RULE);
    assert!(
        profile.compiled_opt_level.is_measured(),
        "build.rs publishes Cargo's own OPT_LEVEL into every build of this crate"
    );
    assert!(
        profile.cargo_profile_name.is_measured(),
        "build.rs publishes Cargo's own PROFILE name as provenance"
    );
    assert_eq!(
        profile.opt_level_publishable,
        profile
            .compiled_opt_level
            .value()
            .is_some_and(|level| PUBLISHABLE_OPT_LEVELS.contains(&level.as_str()))
    );
    assert_eq!(
        profile.approved_for_publication,
        profile.opt_level_publishable
            && !profile.debug_assertions
            && profile.overflow_checks == OverflowChecks::Off
    );
    // `cargo test` compiles with debug assertions on, so the harness under
    // test must not be publication-approved from here.
    if cfg!(debug_assertions) {
        assert!(!profile.approved_for_publication);
    }
}

/// The reported overflow-check state must describe the ARITHMETIC this
/// artifact actually emitted, not a profile name or a declared flag. The test
/// reproduces the observation independently and requires the two to agree, so
/// a build that turned the checks on cannot report them off.
#[test]
fn the_overflow_check_state_matches_this_artifacts_own_arithmetic() {
    let profile = BuildProfile::collect();
    if !cfg!(panic = "unwind") {
        // A `panic=abort` artifact cannot be asked to demonstrate a trapping
        // overflow without dying, so the observation is not attempted and the
        // fail-closed fallback stands.
        assert!(profile.overflow_checks_source.contains("cannot unwind"));
        return;
    }
    assert_ne!(
        profile.overflow_checks,
        OverflowChecks::Unknown,
        "this artifact unwinds, so its own arithmetic answers the question: {}",
        profile.overflow_checks_source
    );

    // A different type and a different overflow from the module's own probe,
    // so the two agree about the artifact rather than about one expression.
    let traps = silently(|| {
        let left = std::hint::black_box(u32::MAX);
        let right = std::hint::black_box(1_u32);
        std::hint::black_box(left + right)
    })
    .is_err();

    let observed = if traps {
        OverflowChecks::On
    } else {
        OverflowChecks::Off
    };
    assert_eq!(
        profile.overflow_checks, observed,
        "an overflowing addition traps={traps} in this artifact, so the report must say so"
    );
    assert!(
        profile.overflow_checks_source.contains("emitted code"),
        "{}",
        profile.overflow_checks_source
    );
    assert_eq!(
        observe_compiled_overflow_checks(),
        Some(traps),
        "the observation is made once and stays stable across calls"
    );
}
