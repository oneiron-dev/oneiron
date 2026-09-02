//! Compiled-settings attribution for ONE-1579 publication.
//!
//! Latency, throughput and RSS are properties of an ARTIFACT, not of a source
//! tree. The same code compiled unoptimised, or with overflow checks compiled
//! in, produces numbers that are not merely slower but differently shaped — so
//! a full report drawn from such a binary is not a weaker performance result,
//! it is a different experiment. This module is the evidence that lets the
//! publication predicate refuse one.
//!
//! The predicate reads what was COMPILED, never what was declared:
//!
//! * the OPTIMISATION LEVEL is the value Cargo compiled this crate at, handed
//!   to `build.rs` as `OPT_LEVEL` and embedded with `option_env!`. A profile
//!   named `release` that carries `opt-level = 0` reports `0` here, so the name
//!   cannot cover for the setting;
//! * DEBUG ASSERTIONS are read from this crate's own compilation with
//!   `cfg!(debug_assertions)`, which is compiled into the artifact;
//! * OVERFLOW CHECKS are observed from the code the compiler actually emitted:
//!   an unguarded overflowing addition panics if and only if the checks are
//!   compiled in. `cfg!(overflow_checks)` is unstable (rustc E0658 /
//!   rust-lang#111466) and is deliberately not used; when the observation
//!   cannot be made the build script's explicit-rustflags declaration is the
//!   fallback, and an artifact that establishes neither is `unknown` — which
//!   fails closed exactly as `on` does.
//!
//! The profile NAME survives only as PROVENANCE: both the name a build
//! environment declared through [`BUILD_PROFILE_ENV`] and the name Cargo used
//! are reported, and neither is part of [`BuildProfile::approved_for_publication`].
//!
//! The gate fails closed in every direction. An artifact whose optimisation
//! level was not embedded is not approved, and an artifact whose overflow
//! checks could not be established is not approved, so nothing publishes by
//! default.

use std::panic::UnwindSafe;
use std::sync::{Mutex, OnceLock, PoisonError};

use serde::Serialize;

use super::cells::Cell;

/// Compile-time declaration of the Cargo profile the artifact was built with.
/// Reported as provenance; never a publication predicate.
pub(crate) const BUILD_PROFILE_ENV: &str = "ONEIRON_BENCH_BUILD_PROFILE";
const COMPILE_TIME_BUILD_PROFILE: Option<&str> = option_env!("ONEIRON_BENCH_BUILD_PROFILE");

/// Settings captured by `build.rs` from the compilation of THIS crate.
const COMPILED_OPT_LEVEL_ENV: &str = "OPT_LEVEL (via build.rs)";
const COMPILED_OPT_LEVEL: Option<&str> = option_env!("ONEIRON_BENCH_COMPILED_OPT_LEVEL");
const COMPILED_PROFILE_ENV: &str = "PROFILE (via build.rs)";
const COMPILED_PROFILE: Option<&str> = option_env!("ONEIRON_BENCH_COMPILED_PROFILE");
const COMPILED_OVERFLOW_CHECKS: Option<&str> =
    option_env!("ONEIRON_BENCH_COMPILED_OVERFLOW_CHECKS");
const COMPILED_OVERFLOW_CHECKS_SOURCE: Option<&str> =
    option_env!("ONEIRON_BENCH_COMPILED_OVERFLOW_CHECKS_SOURCE");

/// The optimisation levels a publishable full report may be measured at.
///
/// `release` and `bench` inherit `opt-level = 3`; `2` is the other genuinely
/// optimised level. The size levels `s` and `z` trade speed for size, so a
/// report measured at one of them describes a different experiment and is
/// refused rather than published with a caveat.
pub(crate) const PUBLISHABLE_OPT_LEVELS: [&str; 2] = ["2", "3"];

const PROFILE_RULE: &str = "a full report is publishable only from an artifact whose COMPILED \
     settings were measured and are publishable: an optimisation level Cargo actually compiled \
     this crate at (one of the publishable levels), debug assertions compiled out, and overflow \
     checks observed to be compiled out; the declared and Cargo profile NAMES ride along as \
     provenance and gate nothing, because a binary can be named `release` while carrying \
     opt-level 0 or overflow checks, and an unestablished setting fails closed exactly as a \
     disqualifying one does";

/// Whether arithmetic overflow checks were compiled into the artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OverflowChecks {
    /// Compiled in: an overflowing addition traps.
    On,
    /// Compiled out: an overflowing addition wraps.
    Off,
    /// Could not be established. Treated exactly as `on` by the predicate.
    Unknown,
}

impl OverflowChecks {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
            Self::Unknown => "unknown",
        }
    }

    const fn is_off(self) -> bool {
        matches!(self, Self::Off)
    }
}

/// The compiled settings of the running executable, and the verdict they
/// produce.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct BuildProfile {
    /// Profile name embedded by the build environment, if any. PROVENANCE.
    pub(crate) declared_profile: Cell<String>,
    pub(crate) declared_profile_source: &'static str,
    /// Profile name Cargo itself used, captured by the build script. PROVENANCE.
    pub(crate) cargo_profile_name: Cell<String>,
    pub(crate) cargo_profile_name_source: &'static str,
    /// Pinned so a reader cannot mistake either name for the predicate.
    pub(crate) profile_names_are_provenance_only: bool,
    /// The optimisation level this crate was COMPILED at.
    pub(crate) compiled_opt_level: Cell<String>,
    pub(crate) compiled_opt_level_source: &'static str,
    pub(crate) publishable_opt_levels: [&'static str; 2],
    pub(crate) opt_level_publishable: bool,
    /// Compiled INTO this artifact; not a runtime observation.
    pub(crate) debug_assertions: bool,
    /// Observed from this artifact's own emitted code where possible.
    pub(crate) overflow_checks: OverflowChecks,
    pub(crate) overflow_checks_source: String,
    /// A publishable optimisation level with both debug-only checks out.
    pub(crate) optimized_artifact: bool,
    /// The only field publication reads.
    pub(crate) approved_for_publication: bool,
    pub(crate) rule: &'static str,
}

impl BuildProfile {
    pub(crate) fn collect() -> Self {
        Self::from_parts(
            COMPILE_TIME_BUILD_PROFILE,
            COMPILED_PROFILE,
            CompiledSettings::observe(),
        )
    }

    /// The same decision over injected settings, so every branch is reachable
    /// from a test without recompiling the harness.
    fn from_parts(
        declared: Option<&str>,
        cargo_profile: Option<&str>,
        settings: CompiledSettings,
    ) -> Self {
        let opt_level_publishable = settings
            .opt_level
            .as_deref()
            .is_some_and(|level| PUBLISHABLE_OPT_LEVELS.contains(&level));
        let optimized_artifact = opt_level_publishable
            && !settings.debug_assertions
            && settings.overflow_checks.is_off();
        Self {
            declared_profile: Cell::from_option(
                declared_name(declared),
                format!(
                    "no build profile name was declared at compile time via \
                     {BUILD_PROFILE_ENV}; this is provenance only and does not affect the \
                     publication verdict"
                ),
            ),
            declared_profile_source: BUILD_PROFILE_ENV,
            cargo_profile_name: Cell::from_option(
                declared_name(cargo_profile),
                "the build script embedded no Cargo profile name; this is provenance only and \
                 does not affect the publication verdict",
            ),
            cargo_profile_name_source: COMPILED_PROFILE_ENV,
            profile_names_are_provenance_only: true,
            compiled_opt_level: Cell::from_option(
                settings.opt_level,
                format!(
                    "the artifact embedded no compiled optimisation level; `build.rs` publishes \
                     Cargo's {COMPILED_OPT_LEVEL_ENV} into the crate, and an artifact that \
                     carries none cannot show what it was compiled at"
                ),
            ),
            compiled_opt_level_source: COMPILED_OPT_LEVEL_ENV,
            publishable_opt_levels: PUBLISHABLE_OPT_LEVELS,
            opt_level_publishable,
            debug_assertions: settings.debug_assertions,
            overflow_checks: settings.overflow_checks,
            overflow_checks_source: settings.overflow_checks_source,
            optimized_artifact,
            approved_for_publication: optimized_artifact,
            rule: PROFILE_RULE,
        }
    }

    /// One line explaining the verdict, for the publication check.
    pub(crate) fn publication_detail(&self) -> String {
        format!(
            "compiled settings: opt_level={} (publishable: {:?}), debug_assertions={}, \
             overflow_checks={} ({}); optimized artifact={}, approved for publication={}; \
             profile names (provenance only): declared={}, cargo={}",
            describe(&self.compiled_opt_level),
            PUBLISHABLE_OPT_LEVELS,
            self.debug_assertions,
            self.overflow_checks.as_str(),
            self.overflow_checks_source,
            self.optimized_artifact,
            self.approved_for_publication,
            describe(&self.declared_profile),
            describe(&self.cargo_profile_name),
        )
    }
}

fn describe(cell: &Cell<String>) -> String {
    cell.value()
        .map_or_else(|| "<none>".to_owned(), |value| format!("`{value}`"))
}

fn declared_name(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

/// The optimisation-shaping settings an artifact was compiled with.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CompiledSettings {
    opt_level: Option<String>,
    debug_assertions: bool,
    overflow_checks: OverflowChecks,
    overflow_checks_source: String,
}

impl CompiledSettings {
    /// Read from this crate's own compilation and from its own emitted code,
    /// never from the environment the report is produced in.
    fn observe() -> Self {
        let (overflow_checks, overflow_checks_source) = observed_overflow_checks();
        Self {
            opt_level: declared_name(COMPILED_OPT_LEVEL),
            debug_assertions: cfg!(debug_assertions),
            overflow_checks,
            overflow_checks_source,
        }
    }
}

/// Overflow checks as this artifact can actually establish them.
///
/// The behavioural observation comes first because it describes the emitted
/// code rather than the flags that were meant to produce it; the build
/// script's explicit-rustflags declaration is the fallback for a `panic=abort`
/// artifact, where the observation cannot be made safely.
fn observed_overflow_checks() -> (OverflowChecks, String) {
    if let Some(compiled_in) = observe_compiled_overflow_checks() {
        return (
            if compiled_in {
                OverflowChecks::On
            } else {
                OverflowChecks::Off
            },
            "observed in this artifact's own emitted code: an unguarded overflowing addition \
             traps only when the checks were compiled in"
                .to_owned(),
        );
    }
    let declared = match COMPILED_OVERFLOW_CHECKS.map(str::trim) {
        Some("on") => OverflowChecks::On,
        Some("off") => OverflowChecks::Off,
        _ => OverflowChecks::Unknown,
    };
    (
        declared,
        format!(
            "this artifact cannot unwind, so its emitted code was not exercised; falling back to \
             the build script's declaration ({}), which fails closed when the build environment \
             did not name the setting either",
            COMPILED_OVERFLOW_CHECKS_SOURCE
                .unwrap_or("no build-script declaration was embedded at all")
        ),
    )
}

/// Whether overflow checks are compiled into THIS artifact, observed once.
///
/// `None` means the observation was not attempted: with `panic = "abort"` a
/// trapping overflow would take the process down instead of unwinding into
/// [`std::panic::catch_unwind`], and a bench harness must not abort itself to
/// answer a provenance question.
static OBSERVED_OVERFLOW_CHECKS: OnceLock<bool> = OnceLock::new();

fn observe_compiled_overflow_checks() -> Option<bool> {
    if !cfg!(panic = "unwind") {
        return None;
    }
    Some(
        *OBSERVED_OVERFLOW_CHECKS.get_or_init(|| silently(|| overflowing_sum(u8::MAX, 1)).is_err()),
    )
}

/// Serializes the hook swap, so two probes cannot interleave and leave the
/// silent hook installed behind them.
static PROBE_HOOK: Mutex<()> = Mutex::new(());

/// Runs `probe` with panic output silenced and the previous hook restored.
///
/// The probe below panics BY DESIGN when overflow checks are compiled in, so
/// the hook is silenced for exactly that window rather than letting a
/// provenance question print a panic the operator did not cause.
fn silently<T>(probe: impl FnOnce() -> T + UnwindSafe) -> std::thread::Result<T> {
    let _guard = PROBE_HOOK.lock().unwrap_or_else(PoisonError::into_inner);
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = std::panic::catch_unwind(probe);
    std::panic::set_hook(previous);
    outcome
}

/// A deliberately unguarded addition over values the optimiser cannot fold.
///
/// With overflow checks compiled in this traps; without them it wraps to zero.
/// The operands arrive as parameters through [`std::hint::black_box`], so the
/// constant-propagation lint never sees a constant overflow and the compiler
/// cannot answer the question at compile time.
#[inline(never)]
fn overflowing_sum(left: u8, right: u8) -> u8 {
    std::hint::black_box(std::hint::black_box(left) + std::hint::black_box(right))
}

#[cfg(test)]
mod tests;
