//! ONE-1579 axis 7: real-traffic cache hit rates per listed rung.
//!
//! These events are BENCH-OWNED rows read from a JSONL stream the harness
//! owns. No retrieval internal in `vault.rs` or `ppr.rs` is instrumented or
//! mutated to produce them.
//!
//! Three fail-closed rules the ingest enforces rather than documents: a FULL
//! run admits `real_traffic` events only; a rung the plan does not list is
//! refused rather than invented; and a listed rung with no admissible event is
//! `not_ready`, never a zero hit rate.
//!
//! ## This axis is ADVISORY, and the shape checks are why
//!
//! A row's `source` field is the STREAM DESCRIBING ITSELF. Refusing a row that
//! admits to being synthetic is worth doing — it keeps an obviously
//! inadmissible stream out of a full run — but it is a shape check, not
//! evidence of origin, and no amount of shape checking turns a file the
//! operator pointed at into something they did not choose.
//!
//! ONE-1961 draws the conclusion rather than papering over it: `cache_events`
//! is OPERATOR-DECLARED (see [`super::trust`]), so `cache_rungs_complete` is an
//! ADVISORY check and the cache axis is an ADVISORY axis. It is still measured,
//! still emitted, still hashed into `provenance.cache_events_hash`, and a
//! silent rung is still a reported failure — it just cannot withhold
//! publication candidacy, because a condition the operator can arrange is not
//! evidence. A signature over these bytes was considered and rejected: the same
//! operator would hold the key, so it would authenticate the same declaration.
//!
//! Future re-gate path (not implemented): replace this operator-supplied stream
//! with engine-produced, engine-signed cache telemetry from the measured run.
//! An independent verifier must authenticate the engine's signer and bind the
//! events to that run and its rungs before any cache check can become blocking.
//! An operator-held signature on today's JSONL file, or its BLAKE3 hash in the
//! report, cannot establish the origin of real traffic. Until that separate
//! telemetry and verification path exists, the cache axis stays advisory.
//!
//! `sessions` counts DISTINCT session ids, not rows that happened to carry
//! one. One session emitting four events is one session; counting the events
//! instead would misdescribe the traffic scope the hit rate was measured over.
//! The row keeps `events_with_session` beside it so both numbers are visible.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::cells::{Cell, EvidenceKind, RunMode};

/// Where a cache event came from. Only `real_traffic` is admissible in a full
/// run; the other two exist so a smoke can say what it is out loud.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CacheEventSource {
    RealTraffic,
    SyntheticSmoke,
    Simulated,
}

impl CacheEventSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RealTraffic => "real_traffic",
            Self::SyntheticSmoke => "synthetic_smoke",
            Self::Simulated => "simulated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CacheOutcome {
    Hit,
    Miss,
}

/// One bench-owned cache event row. These are produced OUTSIDE the engine:
/// `vault.rs` and `ppr.rs` retrieval internals are never instrumented.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheEvent {
    rung: String,
    outcome: CacheOutcome,
    source: CacheEventSource,
    #[serde(default)]
    observed_at_unix_ms: Option<u64>,
    #[serde(default)]
    session: Option<String>,
}

/// Why a cache-event stream was refused.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CacheIngestError {
    #[error("cache event row {row} is malformed: {reason}")]
    Malformed { row: usize, reason: String },
    #[error(
        "cache event row {row} carries source `{reason}`: a full run accepts real-traffic cache \
         events only, never a synthetic or simulated source"
    )]
    SyntheticSourceInFullRun { row: usize, reason: String },
    #[error(
        "cache event row {row} names rung `{rung}`, which the plan does not list; a rung the plan \
         omits must stay omitted rather than be invented from an event"
    )]
    UnlistedRung { row: usize, rung: String },
}

/// One reported cache rung.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct CacheRungRow {
    pub(crate) rung: String,
    pub(crate) events: usize,
    pub(crate) hits: usize,
    pub(crate) misses: usize,
    /// `not_ready` when the rung saw no admissible event. NEVER `0.0`.
    pub(crate) hit_rate: Cell<f64>,
    /// DISTINCT session ids seen on this rung.
    pub(crate) sessions: usize,
    /// Events that carried a session id at all, so the distinction between
    /// "rows with a session" and "how many sessions" stays visible.
    pub(crate) events_with_session: usize,
    /// Newest admissible observation for this rung, when the events carried
    /// one. Absent rather than zeroed when no row was timestamped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) latest_observed_at_unix_ms: Option<u64>,
}

/// Axis 7: real-traffic cache hit rates per listed rung.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct CacheAxis {
    pub(crate) source_kind: &'static str,
    pub(crate) rungs_listed: Vec<String>,
    pub(crate) rows: Vec<CacheRungRow>,
    pub(crate) events_admitted: usize,
    pub(crate) rejects_synthetic_source_for_full_run: bool,
    /// The trust class of this axis's evidence, stated in the axis itself so a
    /// reader never has to infer it: the rows' own `source` field is a shape
    /// check on a stream the operator chose, which is why the axis is advisory.
    pub(crate) evidence_trust_class: &'static str,
    pub(crate) publication_scope: &'static str,
    /// Future evidence needed before this advisory axis can be considered for
    /// re-gating; this is a design path, not evidence accepted by this run.
    pub(crate) future_re_gate_path: &'static str,
    pub(crate) session_counting_rule: &'static str,
    pub(crate) evidence_kind: EvidenceKind,
    pub(crate) note: &'static str,
}

const CACHE_NOTE: &str = "cache events are BENCH-OWNED rows: they are read from a JSONL stream the \
     harness owns, and no retrieval internal in vault.rs or ppr.rs is instrumented or mutated to \
     produce them; the stream is chosen by whoever runs the bench and its rows declare their own \
     source, so this axis is OPERATOR-DECLARED evidence and is ADVISORY — it is measured, emitted \
     and hashed, and it never withholds publication candidacy; a listed rung with no admissible \
     event stays not_ready and never reads as a zero hit rate. Future re-gate requires engine-signed \
     cache telemetry produced by the engine during the measured run, with its signer, run binding \
     and rung evidence independently verified; an operator-held signature on this JSONL stream \
     or its report hash does not prove real-traffic origin, so this axis remains advisory";
/// The ONE-1961 trust class of every cache row, stated on the axis.
const CACHE_TRUST_CLASS: &str = "operator_declared";
/// The ONE-1961 publication scope of this axis.
const CACHE_PUBLICATION_SCOPE: &str = "advisory";
const CACHE_FUTURE_RE_GATE_PATH: &str = "engine_signed_cache_telemetry";
const SESSION_RULE: &str = "`sessions` is the number of DISTINCT non-empty session ids seen on the \
     rung, not the number of rows that carried one; `events_with_session` reports the latter \
     separately so neither can be mistaken for the other";

impl CacheAxis {
    /// Ingests a bench-owned JSONL cache-event stream.
    ///
    /// A full run accepts `real_traffic` events ONLY. A rung the plan does not
    /// list is refused rather than invented, and a listed rung with no
    /// admissible event is reported `not_ready`.
    pub(crate) fn ingest(
        mode: RunMode,
        rungs: &[String],
        jsonl: &str,
    ) -> Result<Self, CacheIngestError> {
        let mut tallies: BTreeMap<&str, RungTally> = rungs
            .iter()
            .map(|rung| (rung.as_str(), RungTally::default()))
            .collect();
        let mut admitted = 0_usize;
        for (offset, line) in jsonl.lines().enumerate() {
            let row = offset + 1;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let event: CacheEvent =
                serde_json::from_str(trimmed).map_err(|error| CacheIngestError::Malformed {
                    row,
                    reason: error.to_string(),
                })?;
            if mode.is_full() && event.source != CacheEventSource::RealTraffic {
                return Err(CacheIngestError::SyntheticSourceInFullRun {
                    row,
                    reason: event.source.as_str().to_owned(),
                });
            }
            let Some(tally) = tallies.get_mut(event.rung.as_str()) else {
                return Err(CacheIngestError::UnlistedRung {
                    row,
                    rung: event.rung,
                });
            };
            tally.record(&event);
            admitted += 1;
        }

        let rows = rungs
            .iter()
            .map(|rung| {
                tallies
                    .get(rung.as_str())
                    .map_or_else(|| RungTally::default().row(rung), |tally| tally.row(rung))
            })
            .collect();
        Ok(Self {
            source_kind: if mode.is_full() {
                "real_traffic_only"
            } else {
                "synthetic_smoke_fixture"
            },
            rungs_listed: rungs.to_vec(),
            rows,
            events_admitted: admitted,
            rejects_synthetic_source_for_full_run: true,
            evidence_trust_class: CACHE_TRUST_CLASS,
            publication_scope: CACHE_PUBLICATION_SCOPE,
            future_re_gate_path: CACHE_FUTURE_RE_GATE_PATH,
            session_counting_rule: SESSION_RULE,
            evidence_kind: if mode.is_full() {
                EvidenceKind::IngestedRealTrafficEvents
            } else {
                EvidenceKind::SyntheticSmoke
            },
            note: CACHE_NOTE,
        })
    }
}

#[derive(Debug, Clone, Default)]
struct RungTally {
    hits: usize,
    misses: usize,
    /// Distinct non-empty session ids. A set, not a counter: one session that
    /// emits four events is still one session.
    sessions: BTreeSet<String>,
    events_with_session: usize,
    latest_observed_at_unix_ms: Option<u64>,
}

impl RungTally {
    fn record(&mut self, event: &CacheEvent) {
        match event.outcome {
            CacheOutcome::Hit => self.hits += 1,
            CacheOutcome::Miss => self.misses += 1,
        }
        if let Some(session) = event.session.as_deref() {
            let session = session.trim();
            if !session.is_empty() {
                self.events_with_session += 1;
                self.sessions.insert(session.to_owned());
            }
        }
        if let Some(observed) = event.observed_at_unix_ms {
            self.latest_observed_at_unix_ms = Some(
                self.latest_observed_at_unix_ms
                    .map_or(observed, |latest| latest.max(observed)),
            );
        }
    }

    fn row(&self, rung: &str) -> CacheRungRow {
        let events = self.hits + self.misses;
        CacheRungRow {
            rung: rung.to_owned(),
            events,
            hits: self.hits,
            misses: self.misses,
            hit_rate: if events == 0 {
                Cell::not_ready(format!(
                    "rung `{rung}` is listed in the plan but saw no admissible cache event in this \
                     run; a required rung with no real event is not_ready, never a zero hit rate"
                ))
            } else {
                Cell::measured(self.hits as f64 / events as f64)
            },
            sessions: self.sessions.len(),
            events_with_session: self.events_with_session,
            latest_observed_at_unix_ms: self.latest_observed_at_unix_ms,
        }
    }
}
