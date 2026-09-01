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
    pub(crate) session_counting_rule: &'static str,
    pub(crate) evidence_kind: EvidenceKind,
    pub(crate) note: &'static str,
}

const CACHE_NOTE: &str = "cache events are BENCH-OWNED rows: they are read from a JSONL stream the \
     harness owns, and no retrieval internal in vault.rs or ppr.rs is instrumented or mutated to \
     produce them; a listed rung with no admissible event stays not_ready and never reads as a \
     zero hit rate";
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rungs(names: &[&str]) -> Vec<String> {
        names.iter().copied().map(String::from).collect()
    }

    /// A full run must refuse a synthetic or simulated cache source outright,
    /// accept the same rows for a smoke, and never turn a listed-but-silent
    /// rung into a zero hit rate.
    #[test]
    fn cache_events_reject_synthetic_source_for_full_run() {
        let listed = rungs(&["embedding", "posting_list", "context_pack"]);
        let synthetic = concat!(
            r#"{"rung":"embedding","outcome":"hit","source":"synthetic_smoke"}"#,
            "\n",
            r#"{"rung":"embedding","outcome":"miss","source":"synthetic_smoke"}"#,
            "\n"
        );

        let refused = CacheAxis::ingest(RunMode::Full, &listed, synthetic)
            .expect_err("a full run must refuse a synthetic cache source");
        match refused {
            CacheIngestError::SyntheticSourceInFullRun { row, reason } => {
                assert_eq!(row, 1);
                assert_eq!(reason, "synthetic_smoke");
            }
            other => panic!("expected a synthetic-source refusal, got {other}"),
        }

        let simulated = r#"{"rung":"embedding","outcome":"hit","source":"simulated"}"#;
        assert!(
            matches!(
                CacheAxis::ingest(RunMode::Full, &listed, simulated),
                Err(CacheIngestError::SyntheticSourceInFullRun { .. })
            ),
            "a simulated source is refused for a full run too"
        );

        // The same rows are admissible for a synthetic smoke, which says what
        // it is out loud.
        let smoke = CacheAxis::ingest(RunMode::SyntheticSmoke, &listed, synthetic)
            .expect("a smoke admits its own fixture");
        assert_eq!(smoke.events_admitted, 2);
        assert!(smoke.rejects_synthetic_source_for_full_run);
        assert_eq!(smoke.evidence_kind, EvidenceKind::SyntheticSmoke);
        let embedding = &smoke.rows[0];
        assert_eq!(embedding.events, 2);
        assert!(
            (embedding.hit_rate.value().copied().unwrap_or(-1.0) - 0.5).abs() < f64::EPSILON,
            "one hit of two events is a 0.5 hit rate"
        );

        // A listed rung with no event is not_ready, never zero.
        for silent in &smoke.rows[1..] {
            assert!(
                matches!(silent.hit_rate, Cell::NotReady { .. }),
                "rung `{}` saw no event and must be not_ready, not 0",
                silent.rung
            );
            assert_eq!(silent.events, 0);
        }

        // Real traffic passes a full run and reports a real rate.
        let real = concat!(
            r#"{"rung":"posting_list","outcome":"hit","source":"real_traffic"}"#,
            "\n",
            r#"{"rung":"posting_list","outcome":"hit","source":"real_traffic"}"#,
            "\n",
            r#"{"rung":"posting_list","outcome":"miss","source":"real_traffic"}"#
        );
        let full =
            CacheAxis::ingest(RunMode::Full, &listed, real).expect("real traffic is admitted");
        assert_eq!(full.evidence_kind, EvidenceKind::IngestedRealTrafficEvents);
        let posting = &full.rows[1];
        assert_eq!(posting.rung, "posting_list");
        assert!((posting.hit_rate.value().copied().unwrap_or(-1.0) - (2.0 / 3.0)).abs() < 1e-12);

        // An unlisted rung is refused rather than invented.
        let stray = r#"{"rung":"not_in_plan","outcome":"hit","source":"real_traffic"}"#;
        assert!(matches!(
            CacheAxis::ingest(RunMode::Full, &listed, stray),
            Err(CacheIngestError::UnlistedRung { .. })
        ));
    }

    /// One session emitting several events is ONE session. Counting rows that
    /// carried a session id instead would report four sessions for a rung that
    /// only ever saw two, corrupting the traffic scope the hit rate describes.
    #[test]
    fn a_rung_counts_distinct_sessions_not_events() {
        let listed = rungs(&["embedding", "posting_list"]);
        // Four embedding events from exactly two sessions, three of them from
        // the same one — the bundled smoke fixture has this same shape.
        let stream = concat!(
            r#"{"rung":"embedding","outcome":"hit","source":"real_traffic","session":"smoke-a"}"#,
            "\n",
            r#"{"rung":"embedding","outcome":"hit","source":"real_traffic","session":"smoke-a"}"#,
            "\n",
            r#"{"rung":"embedding","outcome":"miss","source":"real_traffic","session":"smoke-a"}"#,
            "\n",
            r#"{"rung":"embedding","outcome":"hit","source":"real_traffic","session":"smoke-b"}"#,
            "\n",
            r#"{"rung":"posting_list","outcome":"hit","source":"real_traffic"}"#,
            "\n",
            r#"{"rung":"posting_list","outcome":"miss","source":"real_traffic","session":"  "}"#
        );
        let axis = CacheAxis::ingest(RunMode::Full, &listed, stream).expect("stream is admitted");

        let embedding = &axis.rows[0];
        assert_eq!(embedding.events, 4, "four events landed on the rung");
        assert_eq!(
            embedding.events_with_session, 4,
            "all four carried a session id"
        );
        assert_eq!(
            embedding.sessions, 2,
            "but they came from only two DISTINCT sessions, not four"
        );

        let posting = &axis.rows[1];
        assert_eq!(posting.events, 2);
        assert_eq!(
            posting.sessions, 0,
            "an absent or blank session id is not a session"
        );
        assert_eq!(posting.events_with_session, 0);

        let rendered = serde_json::to_string(&axis).expect("axis renders");
        assert!(rendered.contains("session_counting_rule"), "{rendered}");
    }

    /// The bundled smoke fixture keeps its repeated `smoke-a` rows, so the
    /// distinct-session correction stays exercised by the shipped smoke.
    #[test]
    fn the_bundled_fixture_exercises_repeated_sessions() {
        let fixture = include_str!("../../fixtures/perf_smoke.cache.jsonl");
        let listed = rungs(&["embedding", "posting_list", "context_pack"]);
        let axis =
            CacheAxis::ingest(RunMode::SyntheticSmoke, &listed, fixture).expect("fixture ingests");

        let embedding = &axis.rows[0];
        assert!(
            embedding.events_with_session > embedding.sessions,
            "the fixture must keep repeated events from one session ({} events with a session, \
             {} distinct sessions)",
            embedding.events_with_session,
            embedding.sessions
        );
        assert_eq!(embedding.events, 4);
        assert_eq!(embedding.sessions, 2, "smoke-a and smoke-b");
    }
}
