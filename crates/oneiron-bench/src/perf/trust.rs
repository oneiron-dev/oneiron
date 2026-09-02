//! ONE-1961 trust classes for publication evidence.
//!
//! A publication check is only as good as WHERE its inputs came from. This
//! module names that origin for every input the predicate reads, and turns the
//! naming into an enforced rule rather than a comment.
//!
//! Four origins, and the difference between them is who could have chosen the
//! value:
//!
//! * [`TrustInput::Measured`] — this process observed it: `/proc/*`, a
//!   completed TCP `accept`, BLAKE3 over `/proc/self/exe`, the compiled
//!   settings the build script read back out of the compiler, `/sys/class/block`.
//!   The operator running the bench cannot choose it without changing what is
//!   physically true on the box or in the artifact.
//! * [`TrustInput::CompileDeclared`] — the BUILD environment embedded it into
//!   the artifact with `option_env!`. The measuring process cannot rewrite it,
//!   but it is still a declaration, so it stays PROVISIONAL until an external
//!   verifier matches it against a build record (`perf-verify` V4/V5).
//! * [`TrustInput::OperatorDeclared`] — whoever launched the run chose it: a
//!   runtime environment variable, a field in the plan JSON they wrote, or the
//!   contents of a file they pointed at. A cache-event stream whose rows say
//!   `"source": "real_traffic"` is exactly this: the stream describing itself.
//! * [`TrustInput::Derived`] — computed by the harness from inputs already
//!   pinned by a hash (`plan_hash`, `corpus_hash`, `cache_events_hash`,
//!   `sample_counts`).
//!
//! ## The rule
//!
//! **No blocking check may rest on operator-declared evidence.** A check whose
//! satisfaction can be arranged by the party who benefits from it is not
//! evidence, it is a self-declaration, and this harness emits CANDIDATES only
//! precisely so that no self-declaration can become a published number.
//!
//! Compile-declared evidence IS admissible on a blocking check, because the
//! measuring process cannot forge it — but it is provisional, and the external
//! verifier is what converts it into a fact by matching the build record.
//!
//! The rule is enforced twice:
//!
//! 1. statically, by a unit test over [`CHECKS`] × [`INPUTS`], so a check that
//!    grows an operator-declared input fails the build's test suite;
//! 2. dynamically, in `publication::decide`, for inputs whose class depends on
//!    HOW they resolved in this particular run (see below).
//!
//! ## Evidence versus restriction
//!
//! [`CheckSpec::inputs`] lists a check's EVIDENCE: the inputs whose value can
//! make it SATISFIED. An operator declaration that can only make a check FAIL
//! is a restriction, not evidence, and is deliberately not listed — refusing to
//! publish unless the operator ALSO says `ONEIRON_BENCH_NODE=tokyo-1` subtracts
//! from what a run can claim and can never add to it.
//!
//! Two checks are shaped that way and it is worth being explicit about them:
//!
//! * `designated_first_tokyo_node` rests on the OBSERVED hostname/machine-id
//!   pair matching the allowlist compiled into the artifact. The operator's
//!   `ONEIRON_BENCH_NODE` / `ONEIRON_BENCH_NODE_LOCATION` declarations are
//!   additionally required, so they can only ever block;
//! * `run_mode_is_full` rests on the harness's own admission verdict over plan
//!   bytes pinned by `plan_hash`. Declaring `mode: full` does not satisfy any
//!   measurement — it SUBJECTS the run to every other check — and the external
//!   verifier re-derives it (`perf-verify` V1) rather than trusting this field.
//!
//! ## Dynamic classes
//!
//! Some inputs are measured in the ordinary case and operator-declared in a
//! specific one. `child_program_blake3` is BLAKE3 over the program the harness
//! resolved for itself, unless `ONEIRON_BENCH_PERF_CHILD` named a different
//! one — in which case the operator chose the bytes being hashed. The predicate
//! is told about that at runtime and fails the dependent checks closed; a full
//! run refuses the override outright, before any axis runs, so the dynamic path
//! is a second net under a closed door rather than the only lock.

use serde::Serialize;

/// Where a publication input came from, and therefore who could have chosen it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TrustInput {
    /// Observed by this process on this machine or in this artifact.
    Measured,
    /// Embedded into the artifact by the build environment. Provisional until
    /// an external verifier matches it against a build record.
    CompileDeclared,
    /// Chosen by whoever launched the run: runtime environment, plan JSON, or
    /// the contents of a file the plan pointed at.
    OperatorDeclared,
    /// Computed by the harness from inputs already pinned by a hash.
    Derived,
}

impl TrustInput {
    #[cfg(test)]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::CompileDeclared => "compile_declared",
            Self::OperatorDeclared => "operator_declared",
            Self::Derived => "derived",
        }
    }

    /// Whether a BLOCKING check may rest on evidence of this class. This is
    /// the whole rule in one place: everything except an operator declaration.
    pub(crate) const fn admissible_as_blocking_evidence(self) -> bool {
        !matches!(self, Self::OperatorDeclared)
    }
}

/// Whether a check can withhold candidacy or only annotate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CheckScope {
    /// A failure means the report is not a publication candidate.
    Blocking,
    /// A failure is reported and carried forward, but does not withhold
    /// candidacy. Used where the evidence is operator-declared.
    Advisory,
}

impl CheckScope {
    #[cfg(test)]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Blocking => "blocking",
            Self::Advisory => "advisory",
        }
    }

    pub(crate) const fn is_blocking(self) -> bool {
        matches!(self, Self::Blocking)
    }
}

/// One named input the publication predicate reads, and where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InputSpec {
    pub(crate) name: &'static str,
    pub(crate) class: TrustInput,
    /// The concrete origin, named precisely enough that a reader can go and
    /// look at it. This string is emitted in the run certificate.
    pub(crate) source: &'static str,
}

/// Every input, with the class the rule is evaluated against.
///
/// Order is the emitted order of the certificate's trust manifest, so it is
/// part of the hashed payload and is deliberately stable.
pub(crate) const INPUTS: [InputSpec; 21] = [
    InputSpec {
        name: "run_mode",
        class: TrustInput::Derived,
        source: "PerfPlan::validate() admission verdict over the plan bytes pinned by plan_hash",
    },
    InputSpec {
        name: "plan_hash",
        class: TrustInput::Derived,
        source: "blake3 over the exact plan bytes this run was admitted from",
    },
    InputSpec {
        name: "corpus_hash",
        class: TrustInput::Derived,
        source: "blake3 over the corpus this run generated from the plan seed",
    },
    InputSpec {
        name: "corpus_marker_evidence",
        class: TrustInput::Derived,
        source: "counted over the generated corpus markers",
    },
    InputSpec {
        name: "corpus_query_evidence",
        class: TrustInput::Derived,
        source: "counted over the generated corpus queries and their anchors",
    },
    InputSpec {
        name: "sample_counts",
        class: TrustInput::Derived,
        source: "COMPLETED operation counts tallied from the measured axes",
    },
    InputSpec {
        name: "recall_latency_axis",
        class: TrustInput::Measured,
        source: "wall-clock cold and warm retrieval calls against an open vault",
    },
    InputSpec {
        name: "wake_axis",
        class: TrustInput::Measured,
        source: "the parent's completed TCP accept for each spawned ready child",
    },
    InputSpec {
        name: "sessions_axis",
        class: TrustInput::Measured,
        source: "wall-clock concurrent-session curve against one open vault",
    },
    InputSpec {
        name: "resident_memory_axis",
        class: TrustInput::Measured,
        source: "/proc/<pid>/status VmRSS across the ready children",
    },
    InputSpec {
        name: "gated_writes_axis",
        class: TrustInput::Measured,
        source: "wall-clock ClaimCandidate commits and the gate ledger read back",
    },
    InputSpec {
        name: "precision_axis",
        class: TrustInput::Measured,
        source: "wall-clock scans over the bench representations",
    },
    InputSpec {
        name: "acceptance_evidence",
        class: TrustInput::Derived,
        source: "copied from measured axis cells; no acceptance number is re-measured",
    },
    InputSpec {
        name: "cache_events",
        class: TrustInput::OperatorDeclared,
        source: "plan.cache.events_path — a file the operator wrote or pointed at, whose rows \
                 declare their own `source`",
    },
    InputSpec {
        name: "build_revision_blake3",
        class: TrustInput::Measured,
        source: "BLAKE3 over the running executable image (/proc/self/exe)",
    },
    InputSpec {
        name: "build_tree_dirty",
        class: TrustInput::CompileDeclared,
        source: "option_env!(ONEIRON_BENCH_BUILD_GIT_DIRTY)",
    },
    InputSpec {
        name: "build_settings",
        class: TrustInput::Measured,
        source: "cfg!(debug_assertions) plus the opt-level and overflow-check settings the build \
                 script read back out of the compiler's own environment",
    },
    InputSpec {
        name: "node_observed_identity",
        class: TrustInput::Measured,
        source: "/proc/sys/kernel/hostname and /etc/machine-id as the kernel reports them",
    },
    InputSpec {
        name: "tokyo_node_allowlist",
        class: TrustInput::CompileDeclared,
        source: "option_env!(ONEIRON_BENCH_TOKYO_NODE_ALLOWLIST)",
    },
    InputSpec {
        name: "nvme_device_evidence",
        class: TrustInput::Measured,
        source: "/proc/self/mounts and /sys/class/block for the mount the vault lived on",
    },
    InputSpec {
        name: "child_program_blake3",
        class: TrustInput::Measured,
        source: "BLAKE3 over the resolved ready-child program, hashed before the first spawn",
    },
];

/// One publication check: its scope, and the evidence it rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CheckSpec {
    pub(crate) name: &'static str,
    pub(crate) scope: CheckScope,
    /// The inputs whose value can make this check SATISFIED. Restrictions that
    /// can only make it fail are not evidence and are not listed; see the
    /// module documentation.
    pub(crate) inputs: &'static [&'static str],
}

/// Every publication check, in the order the predicate emits them.
///
/// This table is the contract: `publication::evaluate_checks` must emit exactly
/// these names, in exactly this order, and a unit test enforces that so a check
/// can never be added without also declaring where its evidence came from.
pub(crate) const CHECKS: [CheckSpec; 22] = [
    CheckSpec {
        name: "run_mode_is_full",
        scope: CheckScope::Blocking,
        inputs: &["run_mode"],
    },
    CheckSpec {
        name: "recall_latency_plan_floor",
        scope: CheckScope::Blocking,
        inputs: &["plan_hash"],
    },
    CheckSpec {
        name: "recall_latency_completed_sample_floor",
        scope: CheckScope::Blocking,
        inputs: &["recall_latency_axis", "sample_counts"],
    },
    CheckSpec {
        name: "recall_latency_measurements_complete",
        scope: CheckScope::Blocking,
        inputs: &["recall_latency_axis"],
    },
    CheckSpec {
        name: "wake_axis_complete",
        scope: CheckScope::Blocking,
        inputs: &["wake_axis"],
    },
    CheckSpec {
        name: "session_curve_complete",
        scope: CheckScope::Blocking,
        inputs: &["sessions_axis"],
    },
    CheckSpec {
        name: "ten_child_rss_complete",
        scope: CheckScope::Blocking,
        inputs: &["resident_memory_axis"],
    },
    CheckSpec {
        name: "gated_write_measurements_complete",
        scope: CheckScope::Blocking,
        inputs: &["gated_writes_axis"],
    },
    CheckSpec {
        name: "gated_write_floor",
        scope: CheckScope::Blocking,
        inputs: &["gated_writes_axis", "plan_hash"],
    },
    CheckSpec {
        name: "gated_write_commits_all_succeeded",
        scope: CheckScope::Blocking,
        inputs: &["gated_writes_axis"],
    },
    CheckSpec {
        name: "gate_ledger_one_decision_per_commit",
        scope: CheckScope::Blocking,
        inputs: &["gated_writes_axis"],
    },
    CheckSpec {
        name: "precision_axis_complete",
        scope: CheckScope::Blocking,
        inputs: &["precision_axis", "plan_hash"],
    },
    // The one advisory check, and it is advisory BECAUSE of the rule above,
    // not as a policy preference: its only evidence is a file the operator
    // pointed at, whose rows declare their own provenance.
    CheckSpec {
        name: "cache_rungs_complete",
        scope: CheckScope::Advisory,
        inputs: &["cache_events"],
    },
    CheckSpec {
        name: "corpus_markers_collision_free",
        scope: CheckScope::Blocking,
        inputs: &["corpus_marker_evidence", "corpus_hash"],
    },
    CheckSpec {
        name: "corpus_query_anchors_distinct",
        scope: CheckScope::Blocking,
        inputs: &["corpus_query_evidence", "corpus_hash"],
    },
    CheckSpec {
        name: "measured_qps_acceptance_traceable",
        scope: CheckScope::Blocking,
        inputs: &["acceptance_evidence", "sessions_axis"],
    },
    CheckSpec {
        name: "build_revision_identified",
        scope: CheckScope::Blocking,
        inputs: &["build_revision_blake3"],
    },
    CheckSpec {
        name: "build_tree_clean_at_compile_time",
        scope: CheckScope::Blocking,
        inputs: &["build_tree_dirty"],
    },
    CheckSpec {
        name: "measured_optimized_build_settings",
        scope: CheckScope::Blocking,
        inputs: &["build_settings"],
    },
    CheckSpec {
        name: "designated_first_tokyo_node",
        scope: CheckScope::Blocking,
        inputs: &["node_observed_identity", "tokyo_node_allowlist"],
    },
    CheckSpec {
        name: "nvme_sanity",
        scope: CheckScope::Blocking,
        inputs: &["nvme_device_evidence"],
    },
    // ONE-1963: the artifact that measured the run must also be the artifact
    // that was spawned as its ready child.
    CheckSpec {
        name: "child_program_matches_build_revision",
        scope: CheckScope::Blocking,
        inputs: &["child_program_blake3", "build_revision_blake3"],
    },
];

/// The check spec for `name`, or `None` if the predicate emitted a check this
/// table does not know about. Callers treat `None` as fail-closed.
pub(crate) fn check_spec(name: &str) -> Option<&'static CheckSpec> {
    CHECKS.iter().find(|spec| spec.name == name)
}

/// The input spec for `name`, or `None` for an undeclared input.
pub(crate) fn input_spec(name: &str) -> Option<&'static InputSpec> {
    INPUTS.iter().find(|spec| spec.name == name)
}

/// Every check that consumes `input` as evidence, in table order.
pub(crate) fn consumers(input: &'static str) -> Vec<&'static str> {
    CHECKS
        .iter()
        .filter(|spec| spec.inputs.contains(&input))
        .map(|spec| spec.name)
        .collect()
}

/// Every `(check, input)` pair that breaks the rule, computed over the static
/// tables. An empty result is the invariant; the unit test asserts it, and the
/// certificate builder refuses to seal a run when it is non-empty.
pub(crate) fn blocking_evidence_violations() -> Vec<(&'static str, &'static str)> {
    let mut violations = Vec::new();
    for check in &CHECKS {
        if !check.scope.is_blocking() {
            continue;
        }
        for input in check.inputs {
            let admissible =
                input_spec(input).is_some_and(|spec| spec.class.admissible_as_blocking_evidence());
            if !admissible {
                violations.push((check.name, *input));
            }
        }
    }
    violations
}

/// The rule, pinned into the emitted certificate so a reader never has to go
/// looking for what "blocking" was allowed to rest on.
pub(crate) const TRUST_RULE: &str = "no blocking check may rest on operator-declared evidence: a condition the party who \
     benefits from it can arrange is a self-declaration, not evidence. Compile-declared evidence \
     is admissible but PROVISIONAL, and becomes fact only when an external verifier matches it \
     against the build record. Inputs that can only make a check FAIL are restrictions rather \
     than evidence and are not listed as inputs";

#[cfg(test)]
mod tests;
