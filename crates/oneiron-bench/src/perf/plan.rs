//! ONE-1579 plan admission.
//!
//! A plan is refused at the door rather than quietly reshaped. Admission is
//! where the harness makes sure the report it is about to produce can mean
//! what it says:
//!
//! * a FULL run must walk exactly the `[1, 10, 100, 300]` session curve, clear
//!   the doc/query and gated-write floors, and name a real-traffic cache
//!   stream;
//! * `corpus.k` may not exceed `corpus.indexed_docs`, and the binary-prefix
//!   breadth must stay inside `[k, indexed_docs]`. Clamping either value in one
//!   axis while the plan hash kept the caller's request would describe a
//!   different experiment;
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
mod tests {
    use super::*;

    /// A full run is defined at exactly `[1, 10, 100, 300]`. Omitting a rung,
    /// reordering it, padding it or emptying it are all invalid full-run
    /// plans; a synthetic smoke may use a smaller curve.
    #[test]
    fn perf_plan_requires_exact_full_scale_curve() {
        full_plan_fixture()
            .validate()
            .expect("the exact curve validates");

        for broken in [
            vec![1, 10, 100],
            vec![1, 10, 300],
            vec![1, 10, 300, 100],
            vec![300, 100, 10, 1],
            vec![1, 10, 100, 300, 1000],
            vec![1, 10, 100, 200],
        ] {
            let mut plan = full_plan_fixture();
            plan.sessions.curve = broken.clone();
            let error = plan
                .validate()
                .expect_err("a full run must refuse a curve that is not exactly [1,10,100,300]");
            match error {
                PlanError::SessionCurve { expected, found } => {
                    assert_eq!(expected.as_slice(), REQUIRED_FULL_SESSION_CURVE.as_slice());
                    assert_eq!(found, broken);
                }
                other => panic!("expected a session-curve refusal for {broken:?}, got {other}"),
            }
        }

        let mut empty = full_plan_fixture();
        empty.sessions.curve = Vec::new();
        assert_eq!(
            empty.validate().expect_err("an empty curve is refused"),
            PlanError::EmptySessionCurve
        );

        // The smoke contract is explicitly allowed smaller fixtures.
        let mut smoke = full_plan_fixture();
        smoke.mode = PlanMode::SyntheticSmoke;
        smoke.sessions.curve = vec![1, 4];
        smoke.corpus.indexed_docs = 48;
        smoke.corpus.queries = 8;
        smoke.gated_writes = GatedWritePlan {
            warmup: 2,
            measured: 6,
        };
        smoke.cache.events_path = None;
        smoke
            .validate()
            .expect("a synthetic smoke may use smaller fixtures");
    }

    #[test]
    fn full_run_floors_and_axis_shape_are_enforced() {
        let mut under = full_plan_fixture();
        under.corpus.indexed_docs = 999;
        assert!(matches!(
            under.validate(),
            Err(PlanError::LatencyFloor { .. })
        ));

        let mut writes = full_plan_fixture();
        writes.gated_writes.measured = 9_999;
        assert!(matches!(
            writes.validate(),
            Err(PlanError::GatedWriteFloor { .. })
        ));

        let mut children = full_plan_fixture();
        children.resident_memory.ready_children = 9;
        assert!(matches!(
            children.validate(),
            Err(PlanError::ReadyChildren { .. })
        ));

        let mut candidates = full_plan_fixture();
        candidates.precision.candidates = vec![PrecisionCandidate::F32, PrecisionCandidate::F16];
        assert!(matches!(
            candidates.validate(),
            Err(PlanError::PrecisionCandidates { .. })
        ));

        let mut rungs = full_plan_fixture();
        rungs.cache.rungs = vec!["embedding".to_owned(), "embedding".to_owned()];
        assert!(matches!(
            rungs.validate(),
            Err(PlanError::DuplicateCacheRung { .. })
        ));

        let mut events = full_plan_fixture();
        events.cache.events_path = None;
        assert_eq!(
            events.validate().expect_err("a full run needs real events"),
            PlanError::MissingCacheEvents
        );

        let mut schema = full_plan_fixture();
        schema.schema = "something.else".to_owned();
        assert!(matches!(schema.validate(), Err(PlanError::Schema { .. })));
    }

    /// The retrieval and precision axes describe the SAME plan. A `k` larger
    /// than the indexed corpus is refused at the door, so one axis can never
    /// report a clamped k while the other keeps the original.
    #[test]
    fn a_k_larger_than_the_indexed_corpus_is_refused() {
        let mut plan = full_plan_fixture();
        plan.corpus.k = plan.corpus.indexed_docs + 1;
        let error = plan.validate().expect_err("k > indexed_docs is refused");
        assert_eq!(
            error,
            PlanError::KExceedsCorpus {
                k: FULL_RUN_MIN_INDEXED_DOCS + 1,
                indexed_docs: FULL_RUN_MIN_INDEXED_DOCS,
            }
        );

        // The same refusal applies to a smoke, whose corpus is small.
        let mut smoke = full_plan_fixture();
        smoke.mode = PlanMode::SyntheticSmoke;
        smoke.sessions.curve = vec![1, 4];
        smoke.corpus.indexed_docs = 8;
        smoke.corpus.queries = 4;
        smoke.corpus.k = 10;
        smoke.gated_writes = GatedWritePlan {
            warmup: 1,
            measured: 2,
        };
        smoke.cache.events_path = None;
        assert!(matches!(
            smoke.validate(),
            Err(PlanError::KExceedsCorpus { .. })
        ));

        // k exactly at the corpus size is admissible.
        let mut edge = full_plan_fixture();
        edge.corpus.k = edge.corpus.indexed_docs;
        edge.precision.binary_prefix_breadth = Some(edge.corpus.indexed_docs);
        edge.validate().expect("k == indexed_docs is a valid plan");
    }

    /// The binary-prefix stage must run at exactly the breadth named by the
    /// plan. Values below k or past the indexed corpus are refused before the
    /// plan hash can identify one request while the axis silently measures
    /// another.
    #[test]
    fn an_out_of_range_binary_prefix_breadth_is_refused_at_admission() {
        for breadth in [9, FULL_RUN_MIN_INDEXED_DOCS + 1] {
            let mut plan = full_plan_fixture();
            plan.precision.binary_prefix_breadth = Some(breadth);
            assert_eq!(
                plan.validate()
                    .expect_err("an out-of-range breadth must be refused"),
                PlanError::BinaryPrefixBreadthOutOfRange {
                    breadth,
                    k: 10,
                    indexed_docs: FULL_RUN_MIN_INDEXED_DOCS,
                }
            );
        }

        for breadth in [10, FULL_RUN_MIN_INDEXED_DOCS] {
            let mut plan = full_plan_fixture();
            plan.precision.binary_prefix_breadth = Some(breadth);
            plan.validate()
                .expect("both inclusive breadth boundaries are admissible");
        }

        // An omitted breadth still resolves to 4*k. A tiny smoke that cannot
        // hold that default must name a smaller in-range breadth explicitly;
        // it is never clamped behind the plan's back.
        let mut smoke = full_plan_fixture();
        smoke.mode = PlanMode::SyntheticSmoke;
        smoke.sessions.curve = vec![1];
        smoke.corpus.indexed_docs = 20;
        smoke.corpus.queries = 4;
        smoke.gated_writes = GatedWritePlan {
            warmup: 1,
            measured: 2,
        };
        smoke.cache.events_path = None;
        assert_eq!(
            smoke
                .validate()
                .expect_err("the 4*k default exceeds this smoke corpus"),
            PlanError::BinaryPrefixBreadthOutOfRange {
                breadth: 40,
                k: 10,
                indexed_docs: 20,
            }
        );
        smoke.precision.binary_prefix_breadth = Some(20);
        smoke
            .validate()
            .expect("an explicit in-range smoke breadth is admissible");
    }

    /// A ready child arms its hold the moment it connects, which can be at the
    /// very start of the parent's accept window. A hold that does not outlast
    /// that window plus the sampling margin is refused.
    #[test]
    fn a_child_hold_that_cannot_outlast_the_sampling_phase_is_refused() {
        let mut plan = full_plan_fixture();
        plan.wake.timeout_ms = 20_000;
        plan.wake.hold_ms = 20_000;
        let error = plan
            .validate()
            .expect_err("a hold equal to the accept timeout is refused");
        match error {
            PlanError::ChildHoldTooShort {
                hold_ms,
                minimum_ms,
                timeout_ms,
            } => {
                assert_eq!(hold_ms, 20_000);
                assert_eq!(timeout_ms, 20_000);
                assert_eq!(minimum_ms, minimum_child_hold_ms(20_000));
                assert!(minimum_ms > hold_ms);
            }
            other => panic!("expected a child-hold refusal, got {other}"),
        }

        let mut exact = full_plan_fixture();
        exact.wake.timeout_ms = 20_000;
        exact.wake.hold_ms = minimum_child_hold_ms(20_000);
        exact
            .validate()
            .expect("a hold exactly at the floor is admissible");

        let mut short = full_plan_fixture();
        short.wake.hold_ms = 1;
        assert!(matches!(
            short.validate(),
            Err(PlanError::ChildHoldTooShort { .. })
        ));
    }
}
