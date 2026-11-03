//! L15-S secret-match micro-bench (bench only, never merges): KnownValues::spans +
//! growing over every corpus message text, with 64 corpus note values as the known
//! set (they occur inside the companion "Note saved:" texts, so hits are real).
//! Prints median ms per set and a hash of every span (range, custody, handle) and
//! every Growing{opens, held}.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Instant;

use zeroize::Zeroizing;

use super::*;
use crate::store::{KnownEntry, KnownHistory};

pub(crate) fn run(dir: &str) -> String {
    let sets: usize = std::env::var("L15S_SETS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let rows = crate::l15s_bench::claim_rows(dir);
    let values: Vec<String> = rows
        .iter()
        .step_by(8)
        .map(|(_, _, value)| value.clone())
        .filter(|value| value.len() >= 4)
        .take(64)
        .collect();
    let master = [7u8; 32];
    let keys = Keys::derive(&master);
    let holders: Vec<(EntityId, Vec<KnownEntry>)> = values
        .iter()
        .enumerate()
        .map(|(i, value)| {
            let bytes = value.as_bytes();
            let window = &bytes[..bytes.len().min(TAG_WINDOW)];
            (
                crate::l15s_bench::det_id(&format!("l15s-custody-{i}")),
                vec![KnownEntry {
                    len: bytes.len() as u32,
                    tag: keys.tag(window),
                    rolling: keys.rolling.value(window),
                    fingerprint: keys.fingerprint(bytes),
                }],
            )
        })
        .collect();
    let history = KnownHistory {
        master: Zeroizing::new(master),
        holders,
    };
    let known = match KnownValues::of(&history, |id| {
        Ok(Some(format!("handle-{}", id.as_bytes()[15])))
    }) {
        Ok(Some(known)) => known,
        Ok(None) => return "L15S-BENCH secret ERR empty index".to_string(),
        Err(e) => return format!("L15S-BENCH secret ERR of: {e}"),
    };
    let texts: Vec<String> = crate::l15s_bench::read_inputs(dir, "texts.txt")
        .lines()
        .map(str::to_string)
        .collect();
    let total_bytes: usize = texts.iter().map(String::len).sum();
    let run_set = |hash: &mut u64| {
        let mut hasher = DefaultHasher::new();
        for text in &texts {
            let data = text.as_bytes();
            for span in known.spans(data) {
                span.span.start.hash(&mut hasher);
                span.span.end.hash(&mut hasher);
                span.custody.as_bytes().hash(&mut hasher);
                span.handle.hash(&mut hasher);
            }
            let growing = known.growing(data);
            growing.opens.hash(&mut hasher);
            growing.held.hash(&mut hasher);
        }
        *hash = hasher.finish();
    };
    let mut hash = 0u64;
    run_set(&mut hash);
    let mut times = Vec::with_capacity(sets);
    for _ in 0..sets {
        let start = Instant::now();
        run_set(&mut hash);
        times.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    times.sort_by(|a, b| a.total_cmp(b));
    let med = times[times.len() / 2];
    format!(
        "L15S-BENCH secret ms_per_set={med:.3} us_per_kb={:.2} hash={hash:016x} texts={} bytes={total_bytes} knowns={} sets={sets}",
        med * 1000.0 / (total_bytes as f64 / 1024.0),
        texts.len(),
        values.len()
    )
}
