//! ONE-1579 plan admission.
//!
//! A plan is refused at the door rather than quietly reshaped. Admission is
//! where the harness makes sure the report it is about to produce can mean
//! what it says:
//!
//! * a FULL run must walk exactly the `[1, 10, 100, 300]` session curve, clear
//!   the doc/query and gated-write floors, and name a cache-event stream. That
//!   stream is OPERATOR-DECLARED evidence and the report treats it as advisory
//!   (ONE-1961), so naming it is a completeness requirement rather than a
//!   claim the plan gets to make about the numbers;
//! * a FULL run may NOT name its own ready-child program (ONE-1963). A full run
//!   measures the artifact it was built from, and a plan-supplied child would
//!   make the wake and ready-children axes describe some other binary;
//! * `corpus.k` and `corpus.queries` may not exceed `corpus.indexed_docs`, and
//!   the binary-prefix breadth must stay inside `[k, indexed_docs]`. Clamping
//!   any of them in one axis while the plan hash kept the caller's request
//!   would describe a different experiment, and more queries than documents
//!   could only be answered by re-probing documents already queried;
//! * `wake.hold_ms` must outlast the accept timeout by the ready-children
//!   sampling margin, so the FIRST child cannot expire while the parent is
//!   still accepting the tenth.

use serde::{Deserialize, Serialize};

use super::axes::{
    FULL_RUN_MIN_GATED_WRITE_MEASURED, FULL_RUN_MIN_GATED_WRITE_WARMUP, FULL_RUN_MIN_INDEXED_DOCS,
    FULL_RUN_MIN_QUERIES, REQUIRED_FULL_SESSION_CURVE, REQUIRED_READY_CHILDREN,
};
use super::cells::{EvidenceKind, RunMode};
use super::child_process::{ChildCommandPlan, ChildSettings, minimum_child_hold_ms};
use super::nvme::NvmeProbe;
use super::precision::{PrecisionCandidate, default_binary_prefix_breadth};

/// Plan schema id. A plan that does not name it is refused.
pub(crate) const PERF_PLAN_SCHEMA: &str = "oneiron.bench.perf_plan.v1";

/// Which contract a plan is asking to be held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PlanMode {
    Full,
    SyntheticSmoke,
}

impl PlanMode {
    pub(crate) const fn run_mode(self) -> RunMode {
        match self {
            Self::Full => RunMode::Full,
            Self::SyntheticSmoke => RunMode::SyntheticSmoke,
        }
    }

    pub(crate) const fn evidence_kind(self) -> EvidenceKind {
        match self {
            Self::Full => EvidenceKind::MeasuredWallClock,
            Self::SyntheticSmoke => EvidenceKind::SyntheticSmoke,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CorpusPlan {
    pub(crate) indexed_docs: usize,
    pub(crate) queries: usize,
    pub(crate) k: usize,
    pub(crate) dimensions: usize,
    pub(crate) warm_passes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionsPlan {
    pub(crate) curve: Vec<usize>,
    pub(crate) queries_per_session: usize,
}

impl SessionsPlan {
    pub(crate) fn max_sessions(&self) -> usize {
        self.curve.iter().copied().max().unwrap_or(1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WakePlan {
    pub(crate) samples: usize,
    pub(crate) timeout_ms: u64,
    pub(crate) hold_ms: u64,
    /// The program a full run spawns as its ready child. Absent means the
    /// harness spawns its own `perf wake-child` process.
    #[serde(default)]
    pub(crate) child: Option<ChildCommandPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResidentMemoryPlan {
    pub(crate) ready_children: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GatedWritePlan {
    pub(crate) warmup: usize,
    pub(crate) measured: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrecisionPlan {
    pub(crate) candidates: Vec<PrecisionCandidate>,
    /// Defaults to `4 * k` (40 at the contract k=10) and is always recorded.
    #[serde(default)]
    pub(crate) binary_prefix_breadth: Option<usize>,
}

impl PrecisionPlan {
    pub(crate) fn breadth(&self, k: usize) -> usize {
        self.binary_prefix_breadth
            .unwrap_or_else(|| default_binary_prefix_breadth(k))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CachePlan {
    /// Only rungs that actually exist for this run. A rung with no rows must
    /// be OMITTED from the plan rather than listed and zeroed.
    pub(crate) rungs: Vec<String>,
    /// JSONL cache-event stream, resolved relative to the plan file.
    ///
    /// Whoever runs the bench chooses this file and its rows declare their own
    /// `source`, so it is OPERATOR-DECLARED evidence (see `perf/trust.rs`) and
    /// the cache axis it feeds is advisory. No signature is asked for here,
    /// because a signature the same operator produces would not change that.
    #[serde(default)]
    pub(crate) events_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NvmePlan {
    pub(crate) sequential_ops: usize,
    pub(crate) random_ops: usize,
    pub(crate) block_bytes: usize,
}

impl NvmePlan {
    pub(crate) const fn probe(self, seed: u64) -> NvmeProbe {
        NvmeProbe {
            sequential_ops: self.sequential_ops,
            random_ops: self.random_ops,
            block_bytes: self.block_bytes,
            seed,
        }
    }
}

/// One performance-bench plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PerfPlan {
    pub(crate) schema: String,
    pub(crate) label: String,
    pub(crate) mode: PlanMode,
    pub(crate) seed: u64,
    pub(crate) corpus: CorpusPlan,
    pub(crate) sessions: SessionsPlan,
    pub(crate) wake: WakePlan,
    pub(crate) resident_memory: ResidentMemoryPlan,
    pub(crate) gated_writes: GatedWritePlan,
    pub(crate) precision: PrecisionPlan,
    pub(crate) cache: CachePlan,
    pub(crate) nvme: NvmePlan,
}

/// Why a plan was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum PlanError {
    #[error("plan schema `{found}` is not `oneiron.bench.perf_plan.v1`")]
    Schema { found: String },
    #[error("the concurrent-session curve must be non-empty and carry no zero-session point")]
    EmptySessionCurve,
    #[error(
        "a full run must walk exactly the concurrent-session curve {expected:?} against one \
         vault; `{found:?}` omits or reorders it and is not a valid full-run plan"
    )]
    SessionCurve {
        expected: Vec<usize>,
        found: Vec<usize>,
    },
    #[error(
        "a full run needs >=1000 indexed docs and >=100 queries for latency/recall; the plan asks \
         for {indexed_docs} docs and {queries} queries"
    )]
    LatencyFloor { indexed_docs: usize, queries: usize },
    #[error(
        "a full run needs >=1000 warmup and >=10000 measured gated writes; the plan asks for \
         {warmup} warmup and {measured} measured"
    )]
    GatedWriteFloor { warmup: usize, measured: usize },
    #[error(
        "the resident-memory axis is defined at exactly {expected} ready children, not {found}"
    )]
    ReadyChildren { expected: usize, found: usize },
    #[error(
        "the precision axis needs exactly the four candidates f32, f16, int8_sq and \
         binary_prefix_rescore, got {found:?}"
    )]
    PrecisionCandidates { found: Vec<String> },
    #[error("the plan must list at least one cache rung, or the cache axis has nothing to report")]
    EmptyCacheRungs,
    #[error("cache rung `{rung}` is listed more than once")]
    DuplicateCacheRung { rung: String },
    #[error("a full run must name a real-traffic cache event stream (`cache.events_path`)")]
    MissingCacheEvents,
    #[error(
        "a full run may not name its own ready-child program (`wake.child` is `{program}`); a \
         full run measures the artifact it was built from, and the wake and ready-children axes \
         would otherwise report the spawn latency and resident memory of some other binary under \
         this artifact's build revision. Run a separate-binary comparison as a synthetic smoke"
    )]
    ChildOverrideNotAllowedInFullRun { program: String },
    #[error(
        "`corpus.queries` is {queries} but the plan only indexes {indexed_docs} documents; every \
         query anchors on a document of its own, so a plan asking for more queries than documents \
         is refused rather than answered with queries that wrap back onto documents already \
         probed and re-score the same rows as fresh samples"
    )]
    QueriesExceedCorpus { queries: usize, indexed_docs: usize },
    #[error(
        "`corpus.k` is {k} but the plan only indexes {indexed_docs} documents; the retrieval and \
         precision axes describe the same plan, so a k larger than the corpus is refused rather \
         than clamped in one axis and left alone in the other"
    )]
    KExceedsCorpus { k: usize, indexed_docs: usize },
    #[error(
        "`precision.binary_prefix_breadth` resolves to {breadth}, but an admitted plan requires \
         it inside [{k}, {indexed_docs}]; the harness refuses an out-of-range breadth rather than \
         silently measuring a clamped experiment under the caller's original plan hash"
    )]
    BinaryPrefixBreadthOutOfRange {
        breadth: usize,
        k: usize,
        indexed_docs: usize,
    },
    #[error(
        "`wake.hold_ms` is {hold_ms} but a ready child must stay up for at least {minimum_ms} ms \
         ({timeout_ms} ms accept timeout plus the resident-memory sampling margin); a shorter \
         hold lets the first child expire while the parent is still accepting the rest of the \
         cohort, which would turn the ten-children measurement into not_ready"
    )]
    ChildHoldTooShort {
        hold_ms: u64,
        minimum_ms: u64,
        timeout_ms: u64,
    },
    #[error("`{field}` must be greater than zero")]
    NonPositive { field: &'static str },
}

impl PerfPlan {
    /// Fail-closed plan admission. A full run is held to every floor; a
    /// synthetic smoke may use smaller fixtures but still has to be coherent.
    pub(crate) fn validate(&self) -> Result<(), PlanError> {
        if self.schema != PERF_PLAN_SCHEMA {
            return Err(PlanError::Schema {
                found: self.schema.clone(),
            });
        }
        self.validate_shape()?;
        self.validate_child_hold()?;
        self.validate_precision()?;
        self.validate_cache()?;
        if self.resident_memory.ready_children != REQUIRED_READY_CHILDREN {
            return Err(PlanError::ReadyChildren {
                expected: REQUIRED_READY_CHILDREN,
                found: self.resident_memory.ready_children,
            });
        }
        if self.mode == PlanMode::Full {
            self.validate_full_run()?;
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), PlanError> {
        for (field, value) in [
            ("corpus.indexed_docs", self.corpus.indexed_docs),
            ("corpus.queries", self.corpus.queries),
            ("corpus.k", self.corpus.k),
            ("corpus.dimensions", self.corpus.dimensions),
            (
                "sessions.queries_per_session",
                self.sessions.queries_per_session,
            ),
            ("wake.samples", self.wake.samples),
            ("gated_writes.measured", self.gated_writes.measured),
            ("nvme.block_bytes", self.nvme.block_bytes),
        ] {
            if value == 0 {
                return Err(PlanError::NonPositive { field });
            }
        }
        if self.wake.timeout_ms == 0 {
            return Err(PlanError::NonPositive {
                field: "wake.timeout_ms",
            });
        }
        if self.sessions.curve.is_empty() || self.sessions.curve.contains(&0) {
            return Err(PlanError::EmptySessionCurve);
        }
        if self.corpus.k > self.corpus.indexed_docs {
            return Err(PlanError::KExceedsCorpus {
                k: self.corpus.k,
                indexed_docs: self.corpus.indexed_docs,
            });
        }
        if self.corpus.queries > self.corpus.indexed_docs {
            return Err(PlanError::QueriesExceedCorpus {
                queries: self.corpus.queries,
                indexed_docs: self.corpus.indexed_docs,
            });
        }
        Ok(())
    }

    fn validate_child_hold(&self) -> Result<(), PlanError> {
        let minimum_ms = minimum_child_hold_ms(self.wake.timeout_ms);
        if self.wake.hold_ms < minimum_ms {
            return Err(PlanError::ChildHoldTooShort {
                hold_ms: self.wake.hold_ms,
                minimum_ms,
                timeout_ms: self.wake.timeout_ms,
            });
        }
        Ok(())
    }

    fn validate_precision(&self) -> Result<(), PlanError> {
        if self.precision.candidates.as_slice() != PrecisionCandidate::ALL.as_slice() {
            return Err(PlanError::PrecisionCandidates {
                found: self
                    .precision
                    .candidates
                    .iter()
                    .map(|candidate| candidate.as_str().to_owned())
                    .collect(),
            });
        }
        let breadth = self.precision.breadth(self.corpus.k);
        if !(self.corpus.k..=self.corpus.indexed_docs).contains(&breadth) {
            return Err(PlanError::BinaryPrefixBreadthOutOfRange {
                breadth,
                k: self.corpus.k,
                indexed_docs: self.corpus.indexed_docs,
            });
        }
        Ok(())
    }

    fn validate_cache(&self) -> Result<(), PlanError> {
        if self.cache.rungs.is_empty() {
            return Err(PlanError::EmptyCacheRungs);
        }
        let mut seen: Vec<&str> = Vec::with_capacity(self.cache.rungs.len());
        for rung in &self.cache.rungs {
            if seen.contains(&rung.as_str()) {
                return Err(PlanError::DuplicateCacheRung { rung: rung.clone() });
            }
            seen.push(rung.as_str());
        }
        Ok(())
    }

    fn validate_full_run(&self) -> Result<(), PlanError> {
        if self.sessions.curve.as_slice() != REQUIRED_FULL_SESSION_CURVE.as_slice() {
            return Err(PlanError::SessionCurve {
                expected: REQUIRED_FULL_SESSION_CURVE.to_vec(),
                found: self.sessions.curve.clone(),
            });
        }
        if self.corpus.indexed_docs < FULL_RUN_MIN_INDEXED_DOCS
            || self.corpus.queries < FULL_RUN_MIN_QUERIES
        {
            return Err(PlanError::LatencyFloor {
                indexed_docs: self.corpus.indexed_docs,
                queries: self.corpus.queries,
            });
        }
        if self.gated_writes.warmup < FULL_RUN_MIN_GATED_WRITE_WARMUP
            || self.gated_writes.measured < FULL_RUN_MIN_GATED_WRITE_MEASURED
        {
            return Err(PlanError::GatedWriteFloor {
                warmup: self.gated_writes.warmup,
                measured: self.gated_writes.measured,
            });
        }
        if self.cache.events_path.is_none() {
            return Err(PlanError::MissingCacheEvents);
        }
        // ONE-1963. Refused at admission rather than downgraded at report
        // time: an axis that measured the wrong binary is not weaker evidence,
        // it is evidence about something else.
        if let Some(child) = &self.wake.child {
            return Err(PlanError::ChildOverrideNotAllowedInFullRun {
                program: child.program.clone(),
            });
        }
        Ok(())
    }

    pub(crate) fn child_settings(&self) -> ChildSettings {
        ChildSettings {
            samples: self.wake.samples,
            timeout_ms: self.wake.timeout_ms,
            hold_ms: self.wake.hold_ms,
            child: self.wake.child.clone(),
        }
    }
}

#[cfg(test)]
pub(crate) fn full_plan_fixture() -> PerfPlan {
    PerfPlan {
        schema: PERF_PLAN_SCHEMA.to_owned(),
        label: "full-run fixture".to_owned(),
        mode: PlanMode::Full,
        seed: 1579,
        corpus: CorpusPlan {
            indexed_docs: FULL_RUN_MIN_INDEXED_DOCS,
            queries: FULL_RUN_MIN_QUERIES,
            k: 10,
            dimensions: 256,
            warm_passes: 2,
        },
        sessions: SessionsPlan {
            curve: REQUIRED_FULL_SESSION_CURVE.to_vec(),
            queries_per_session: 20,
        },
        wake: WakePlan {
            samples: 5,
            timeout_ms: 20_000,
            hold_ms: 30_000,
            child: None,
        },
        resident_memory: ResidentMemoryPlan {
            ready_children: REQUIRED_READY_CHILDREN,
        },
        gated_writes: GatedWritePlan {
            warmup: FULL_RUN_MIN_GATED_WRITE_WARMUP,
            measured: FULL_RUN_MIN_GATED_WRITE_MEASURED,
        },
        precision: PrecisionPlan {
            candidates: PrecisionCandidate::ALL.to_vec(),
            binary_prefix_breadth: None,
        },
        cache: CachePlan {
            rungs: vec!["embedding".to_owned(), "posting_list".to_owned()],
            events_path: Some("cache.jsonl".to_owned()),
        },
        nvme: NvmePlan {
            sequential_ops: 64,
            random_ops: 64,
            block_bytes: 4096,
        },
    }
}

#[cfg(test)]
mod tests;
