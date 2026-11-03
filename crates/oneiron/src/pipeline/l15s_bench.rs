//! L15-S temporal micro-bench (bench only, never merges): score_temporal_candidate +
//! sort over a widened candidate set (2,400 rows: the corpus entity count the widen
//! bound can reach), corpus-shaped timestamps. Prints median ms per set and a hash of
//! (id, score bits) in sorted order.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Instant;

use super::channels::{
    TemporalScoringContext, score_temporal_candidate, sort_temporal_candidate_scores,
};
use super::types::{EntityMetadata, TemporalSearchConfig};
use crate::entity_id::EntityId;
use crate::temporal::TemporalAnchorMode;

const T0: u64 = 1_793_047_302; // corpus first `at`
const T1: u64 = 1_793_313_700; // corpus last `at` (approx)

pub(crate) fn run() -> String {
    let sets: usize = std::env::var("L15S_SETS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let rows: Vec<(EntityId, EntityMetadata)> = (0..2400u64)
        .map(|i| {
            let at = T0 + (i * 265_443_576_1 % (T1 - T0));
            (
                crate::l15s_bench::det_id(&format!("l15s-row-{i}")),
                EntityMetadata {
                    entity_type: 1,
                    occurred_start: at,
                    occurred_end: at + 60,
                    learned_at: at + 30,
                },
            )
        })
        .collect();
    let mid = (T0 + T1) / 2;
    let config = TemporalSearchConfig {
        anchor_start: mid - 86_400,
        anchor_end: mid + 86_400,
        learned_start: None,
        learned_end: None,
        sigma_secs: 86_400 * 7,
        anchor_mode: TemporalAnchorMode::Both,
        adaptive: false,
        limit: 80,
        widened: None,
        query_occurred_range: None,
        effort_anchor: false,
    };
    let (alpha, one_minus_alpha) =
        TemporalScoringContext::blend_weights(T1 + 3600, config.anchor_end);
    let scoring = TemporalScoringContext {
        sigma: config.sigma_secs,
        now: T1 + 3600,
        anchor_mid: mid,
        learned_anchor: (config.anchor_start, config.anchor_end),
        learned_anchor_mid: mid,
        alpha,
        one_minus_alpha,
    };
    let run_set = |hash: &mut u64| {
        let mut scored: Vec<_> = rows
            .iter()
            .map(|(id, meta)| score_temporal_candidate(*id, *meta, &config, &scoring))
            .collect();
        sort_temporal_candidate_scores(&mut scored);
        let mut hasher = DefaultHasher::new();
        for s in &scored {
            s.id.as_bytes().hash(&mut hasher);
            s.score.to_bits().hash(&mut hasher);
        }
        *hash = hasher.finish();
    };
    let mut hash = 0u64;
    for _ in 0..3 {
        run_set(&mut hash);
    }
    let mut times = Vec::with_capacity(sets);
    for _ in 0..sets {
        let start = Instant::now();
        run_set(&mut hash);
        times.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    times.sort_by(|a, b| a.total_cmp(b));
    let med = times[times.len() / 2];
    format!(
        "L15S-BENCH temporal ms_per_set={med:.3} us_per_row={:.3} hash={hash:016x} rows={} sets={sets}",
        med * 1000.0 / rows.len() as f64,
        rows.len()
    )
}
