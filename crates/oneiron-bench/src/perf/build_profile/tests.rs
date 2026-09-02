//! Regressions for ONE-1579 compiled-settings attribution.
//!
//! Split out of `build_profile.rs` so the module itself stays well under the
//! repository's giant-file bar; nothing here is reachable outside `cfg(test)`.

use super::*;

fn settings(
    opt_level: Option<&str>,
    debug_assertions: bool,
    checks: OverflowChecks,
) -> CompiledSettings {
    CompiledSettings {
        opt_level: opt_level.map(str::to_owned),
        debug_assertions,
        overflow_checks: checks,
        overflow_checks_source: "injected by a test".to_owned(),
    }
}

/// A profile built from injected compiled settings, under names that claim an
/// optimised build in every case, so only the settings can decide.
fn named_release(settings: CompiledSettings) -> BuildProfile {
    BuildProfile::from_parts(Some("release"), Some("release"), settings)
}

/// The verdict rests on the settings that were COMPILED. A publishable
/// optimisation level with both debug-only checks out publishes; every other
/// combination — including one the build could not establish — is refused.
#[test]
fn only_a_measured_optimized_artifact_may_publish() {
    for level in PUBLISHABLE_OPT_LEVELS {
        let approved = named_release(settings(Some(level), false, OverflowChecks::Off));
        assert!(
            approved.approved_for_publication,
            "opt-level {level} with no debug assertions and no overflow checks publishes"
        );
        assert!(approved.optimized_artifact && approved.opt_level_publishable);
        assert_eq!(
            approved.compiled_opt_level.value().map(String::as_str),
            Some(level)
        );
    }

    // An optimisation level that is not publishable: unoptimised, lightly
    // optimised, size-optimised, or never embedded at all.
    for level in [Some("0"), Some("1"), Some("s"), Some("z"), Some(""), None] {
        let refused = named_release(settings(level, false, OverflowChecks::Off));
        assert!(
            !refused.approved_for_publication,
            "{level:?} is not a publishable optimisation level"
        );
        assert!(!refused.opt_level_publishable && !refused.optimized_artifact);
        let detail = refused.publication_detail();
        assert!(
            detail.contains("approved for publication=false"),
            "{detail}"
        );
    }

    let unembedded = named_release(settings(None, false, OverflowChecks::Off));
    assert!(
        !unembedded.compiled_opt_level.is_measured(),
        "an artifact that embedded no optimisation level cannot show what it was compiled at"
    );
    let detail = unembedded.publication_detail();
    assert!(detail.contains("opt_level=<none>"), "{detail}");

    // Debug assertions disqualify a fully optimised artifact on their own.
    let asserted = named_release(settings(Some("3"), true, OverflowChecks::Off));
    assert!(!asserted.approved_for_publication && !asserted.optimized_artifact);
    let detail = asserted.publication_detail();
    assert!(detail.contains("debug_assertions=true"), "{detail}");

    // So do overflow checks — and a setting that could not be established
    // fails closed exactly as a compiled-in one does.
    for checks in [OverflowChecks::On, OverflowChecks::Unknown] {
        let refused = named_release(settings(Some("3"), false, checks));
        assert!(
            !refused.approved_for_publication,
            "overflow checks `{}` must not publish",
            checks.as_str()
        );
        let detail = refused.publication_detail();
        let expected = format!("overflow_checks={}", checks.as_str());
        assert!(detail.contains(&expected), "{detail}");
    }
}

/// The profile NAME is provenance. A binary that calls itself `release` while
/// carrying opt-level 0 or overflow checks must not publish, and an artifact
/// whose compiled settings are publishable must not be blocked by the name it
/// happens to carry — or by carrying no name at all.
#[test]
fn the_profile_name_is_provenance_and_never_the_publication_predicate() {
    for lie in [
        settings(Some("0"), false, OverflowChecks::Off),
        settings(Some("3"), false, OverflowChecks::On),
        settings(Some("3"), true, OverflowChecks::Off),
        settings(Some("3"), false, OverflowChecks::Unknown),
    ] {
        let claimed = named_release(lie.clone());
        assert!(
            !claimed.approved_for_publication,
            "`release` must not cover for compiled settings {lie:?}"
        );
        assert_eq!(
            claimed.declared_profile.value().map(String::as_str),
            Some("release"),
            "the name is still reported, as provenance"
        );
        assert!(claimed.profile_names_are_provenance_only);
    }

    // Names that are on no approved list, and no name at all, cannot block an
    // artifact whose compiled settings are publishable.
    for (declared, cargo) in [
        (Some("dev"), Some("debug")),
        (Some("perf-experiment"), Some("release")),
        (None, None),
        (Some("   "), Some("")),
    ] {
        let compiled = settings(Some("3"), false, OverflowChecks::Off);
        let profile = BuildProfile::from_parts(declared, cargo, compiled);
        assert!(
            profile.approved_for_publication,
            "{declared:?}/{cargo:?}: the compiled settings decide, not the name"
        );
    }

    let approved = named_release(settings(Some("3"), false, OverflowChecks::Off));
    let rendered = serde_json::to_string(&approved).expect("profile renders");
    for field in [
        "compiled_opt_level",
        "overflow_checks",
        "profile_names_are_provenance_only",
        "approved_for_publication",
    ] {
        assert!(rendered.contains(field), "profile dropped `{field}`");
    }
}

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
