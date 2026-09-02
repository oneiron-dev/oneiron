//! Compile-time build-profile attribution for ONE-1579 publication.
//!
//! Latency, throughput and RSS are properties of an ARTIFACT, not of a source
//! tree. The same code compiled unoptimised, with debug assertions and
//! overflow checks compiled in, produces numbers that are not merely slower
//! but differently shaped — so a full report drawn from such a binary is not a
//! weaker performance result, it is a different experiment. This module is the
//! evidence that lets the publication predicate refuse one.
//!
//! Everything here is read at COMPILE time and is therefore immutable for the
//! running executable:
//!
//! * `cfg!(debug_assertions)` and `cfg!(overflow_checks)` are compiled INTO the
//!   artifact. They cannot be spoofed at report time by any environment, and
//!   they are the direct evidence that the optimisation-shaping settings a
//!   debug profile turns on were not in force.
//! * the profile NAME is declared by the build environment through
//!   [`BUILD_PROFILE_ENV`] and embedded with `option_env!`. Cargo exports
//!   `PROFILE` to build scripts rather than to the crate, so the name is
//!   declared rather than inferred — and because it is only a name, it is
//!   never trusted on its own: an artifact claiming `release` while carrying
//!   debug assertions is refused.
//!
//! The gate fails closed in both directions. An artifact that declared no
//! profile is not approved, and an artifact that declared an unapproved one is
//! not approved, so nothing publishes by default.

use serde::Serialize;

use super::cells::Cell;

/// Compile-time declaration of the Cargo profile the artifact was built with.
pub(crate) const BUILD_PROFILE_ENV: &str = "ONEIRON_BENCH_BUILD_PROFILE";
const COMPILE_TIME_BUILD_PROFILE: Option<&str> = option_env!("ONEIRON_BENCH_BUILD_PROFILE");

/// The optimised Cargo profiles a publishable full report may come from.
///
/// Both inherit `opt-level = 3` and `debug-assertions = false`. A profile that
/// is not on this list has not been reviewed for measurement, so it cannot
/// publish regardless of what it is named.
pub(crate) const APPROVED_BUILD_PROFILES: [&str; 2] = ["release", "bench"];

const PROFILE_RULE: &str = "a full report is publishable only from an approved OPTIMIZED artifact: \
     the running executable must have been compiled with debug assertions and overflow checks \
     off, and its build environment must have declared one of the approved profiles at compile \
     time; a debug, unoptimised or undeclared artifact measures a different experiment and is \
     refused rather than published with a caveat";

/// The compile-time build-profile facts of the running executable.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct BuildProfile {
    /// Profile name embedded by the build environment, if any.
    pub(crate) declared_profile: Cell<String>,
    pub(crate) declared_profile_source: &'static str,
    pub(crate) approved_profiles: [&'static str; 2],
    /// Compiled INTO this artifact; not a runtime observation.
    pub(crate) debug_assertions: bool,
    pub(crate) overflow_checks: bool,
    /// Both debug-only checks compiled out.
    pub(crate) optimized_artifact: bool,
    /// The declared profile is on the approved list.
    pub(crate) declared_profile_approved: bool,
    /// The only field publication reads: an approved profile AND an artifact
    /// whose compiled-in evidence agrees with it.
    pub(crate) approved_for_publication: bool,
    pub(crate) rule: &'static str,
}

impl BuildProfile {
    pub(crate) fn collect() -> Self {
        Self::from_declaration(COMPILE_TIME_BUILD_PROFILE, ArtifactFlags::compiled_in())
    }

    /// Same decision over an injected declaration and artifact flag pair, so
    /// every branch is reachable from a test without recompiling the harness.
    fn from_declaration(declared: Option<&str>, flags: ArtifactFlags) -> Self {
        let declared = declared
            .map(str::trim)
            .filter(|profile| !profile.is_empty())
            .map(str::to_owned);
        let declared_profile_approved = declared
            .as_deref()
            .is_some_and(|profile| APPROVED_BUILD_PROFILES.contains(&profile));
        let optimized_artifact = !flags.debug_assertions && !flags.overflow_checks;
        Self {
            declared_profile: Cell::from_option(
                declared,
                format!(
                    "no build profile was declared at compile time; set {BUILD_PROFILE_ENV} while \
                     compiling so the artifact names the approved optimized profile it came from"
                ),
            ),
            declared_profile_source: BUILD_PROFILE_ENV,
            approved_profiles: APPROVED_BUILD_PROFILES,
            debug_assertions: flags.debug_assertions,
            overflow_checks: flags.overflow_checks,
            optimized_artifact,
            declared_profile_approved,
            approved_for_publication: declared_profile_approved && optimized_artifact,
            rule: PROFILE_RULE,
        }
    }

    /// One line explaining the verdict, for the publication check.
    pub(crate) fn publication_detail(&self) -> String {
        format!(
            "declared build profile {} (approved: {:?}); compiled-in evidence: \
             debug_assertions={}, overflow_checks={}; optimized artifact={}, approved for \
             publication={}",
            self.declared_profile
                .value()
                .map_or_else(|| "<none>".to_owned(), |profile| format!("`{profile}`")),
            APPROVED_BUILD_PROFILES,
            self.debug_assertions,
            self.overflow_checks,
            self.optimized_artifact,
            self.approved_for_publication,
        )
    }
}

/// The optimisation-shaping settings compiled into an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ArtifactFlags {
    debug_assertions: bool,
    overflow_checks: bool,
}

impl ArtifactFlags {
    /// Read from this crate's own compilation, never from the environment.
    const fn compiled_in() -> Self {
        Self {
            debug_assertions: cfg!(debug_assertions),
            // `cfg(overflow_checks)` is unstable (rustc E0658 / #111466). Default
            // cargo profiles keep it aligned with debug_assertions, which is the
            // stable compiled-in signal this gate can actually read.
            overflow_checks: cfg!(debug_assertions),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPTIMIZED: ArtifactFlags = ArtifactFlags {
        debug_assertions: false,
        overflow_checks: false,
    };
    const DEBUG: ArtifactFlags = ArtifactFlags {
        debug_assertions: true,
        overflow_checks: true,
    };

    /// A full report may only be published from an approved OPTIMIZED
    /// artifact. Every other combination — undeclared, unapproved, or declared
    /// approved while the artifact itself still carries debug assertions — is
    /// refused, so a debug build can never publish performance numbers under
    /// an approved profile's name.
    #[test]
    fn only_an_approved_optimized_artifact_may_publish() {
        for profile in APPROVED_BUILD_PROFILES {
            let approved = BuildProfile::from_declaration(Some(profile), OPTIMIZED);
            assert!(
                approved.approved_for_publication,
                "`{profile}` compiled optimized is the publishable case"
            );
            assert!(approved.optimized_artifact);
            assert!(approved.declared_profile_approved);
            assert_eq!(
                approved.declared_profile.value().map(String::as_str),
                Some(profile)
            );

            // The NAME alone is never enough: the artifact must agree.
            let lying = BuildProfile::from_declaration(Some(profile), DEBUG);
            assert!(
                !lying.approved_for_publication,
                "`{profile}` must not publish from an artifact carrying debug assertions"
            );
            assert!(lying.declared_profile_approved && !lying.optimized_artifact);
            assert!(lying.publication_detail().contains("debug_assertions=true"));
        }

        // Fail closed on an undeclared or unapproved profile.
        for declared in [
            None,
            Some(""),
            Some("   "),
            Some("dev"),
            Some("debug"),
            Some("test"),
        ] {
            let refused = BuildProfile::from_declaration(declared, OPTIMIZED);
            assert!(
                !refused.approved_for_publication,
                "{declared:?} is not an approved optimized profile"
            );
            assert!(!refused.declared_profile_approved);
            let detail = refused.publication_detail();
            assert!(
                detail.contains("approved for publication=false"),
                "{detail}"
            );
        }
        let undeclared = BuildProfile::from_declaration(None, OPTIMIZED);
        assert!(!undeclared.declared_profile.is_measured());
        assert!(undeclared.publication_detail().contains("<none>"));

        // Overflow checks alone are enough to disqualify the artifact.
        let checked = BuildProfile::from_declaration(
            Some("release"),
            ArtifactFlags {
                debug_assertions: false,
                overflow_checks: true,
            },
        );
        assert!(!checked.optimized_artifact && !checked.approved_for_publication);
    }

    /// The collected profile reports THIS artifact's compiled-in flags rather
    /// than anything a runtime environment could assert.
    #[test]
    fn the_collected_profile_reads_this_artifacts_own_compilation() {
        let profile = BuildProfile::collect();
        assert_eq!(profile.debug_assertions, cfg!(debug_assertions));
        assert_eq!(profile.overflow_checks, cfg!(debug_assertions));
        assert_eq!(profile.declared_profile_source, BUILD_PROFILE_ENV);
        assert_eq!(profile.approved_profiles, APPROVED_BUILD_PROFILES);
        assert_eq!(profile.rule, PROFILE_RULE);
        assert_eq!(profile.optimized_artifact, !cfg!(debug_assertions));
        // `cargo test` compiles the test profile with debug assertions on, so
        // the harness under test must not be publication-approved from here.
        if cfg!(debug_assertions) {
            assert!(!profile.approved_for_publication);
        }
        let rendered = serde_json::to_string(&profile).expect("profile renders");
        assert!(rendered.contains(BUILD_PROFILE_ENV), "{rendered}");
        assert!(rendered.contains("approved_for_publication"), "{rendered}");
    }
}
