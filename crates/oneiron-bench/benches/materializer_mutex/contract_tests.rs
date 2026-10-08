//! Deterministic workload, report, bounds, and rejection contracts.

use std::collections::BTreeMap;
use std::sync::Arc;

use loro::LoroDoc;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{TimeRange, Vault, VaultConfig};

use super::configuration::*;
use super::observers::*;
use super::worker::*;

// This module is compiled into BOTH targets that share `materializer_mutex.rs`
// (`crates/oneiron-bench/Cargo.toml`): both carry `cfg(test)`, but only the
// libtest target gets `--test`, so in the `harness = false` bench binary every
// `#[test]` fn below is stripped. Imports that only those fns consume therefore
// live inside the fn that uses them; at module level they would be unused
// imports in the bench binary.

/// Deliberately tiny: the 1/4/16 x 32 x 100 x 1,000 matrix is a BENCH run,
/// not a unit test. These fixtures assert contracts, not timings.
fn fixture_case(workers: usize) -> MaterializerCase {
    MaterializerCase {
        workers,
        updates_per_burst: 4,
        warmup_bursts: 2,
        measured_bursts: 8,
    }
}

/// Drives one shadow adapter over a fixed delta containing four valid
/// entity ops, one op under a non-hex key, and one op whose blob is too
/// short to carry a header. Returns the committed rows plus the adapter's
/// (committed_ops, errors) counters.
fn shadow_fixture<L: BenchLock>() -> (BTreeMap<String, Vec<u8>>, u64, u64) {
    let dir = tempfile::tempdir().expect("fixture temp vault directory");
    let vault =
        Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("fixture temp vault opens"));
    let lock = Arc::new(L::new());
    let counters = Arc::new(ShadowCounters::default());
    let doc = LoroDoc::new();
    let _subscriptions = register_shadow_observer(&doc, &vault, &lock, &counters);
    let entities = doc.get_map("entities");

    let occurred = TimeRange {
        start: BASE_LEARNED_AT,
        end: BASE_LEARNED_AT,
    };
    let mut valid_ids = Vec::new();
    for update in 0..4 {
        let id = bench_entity_id(0, 0, update);
        let blob = encode_entity_blob(ENTITY_TYPE_PERSON, occurred, BASE_LEARNED_AT, ENTITY_BODY);
        entities
            .insert(&id.to_hex(), blob.as_slice())
            .expect("fixture entity insert succeeds");
        valid_ids.push(id);
    }
    // Rejected op 1: key is not 32-char hex.
    entities
        .insert("not-a-hex-entity-key", b"rejected".as_slice())
        .expect("fixture entity insert succeeds");
    // Rejected op 2: canonical key, but the blob is shorter than a header.
    entities
        .insert(&bench_entity_id(0, 0, 9).to_hex(), b"short".as_slice())
        .expect("fixture entity insert succeeds");
    doc.commit();

    let mut rows = BTreeMap::new();
    for id in &valid_ids {
        if let Some(raw) = vault.get_raw(id).expect("fixture entity read succeeds") {
            rows.insert(id.to_hex(), raw);
        }
    }
    let (committed_ops, errors) = counters.snapshot();
    (rows, committed_ops, errors)
}

/// The parse-time dimension gate.
///
/// The blueprint defaults and the exact `u16` boundary are accepted; a
/// count the entity id space cannot encode, and a zero-sized workload, are
/// refused with a message naming the variable, the value and the range.
/// Refusing here is what keeps the old failure mode — `narrow_u16`
/// panicking inside a worker and parking the fleet on a barrier forever —
/// unreachable.
#[test]
fn materializer_mutex_dimension_bounds_are_enforced() {
    for workers in DEFAULT_WORKER_MATRIX {
        let raw = workers.to_string();
        assert_eq!(parse_dimension(ENV_WORKERS, &raw), Ok(workers));
    }
    let updates = DEFAULT_UPDATES_PER_BURST.to_string();
    let default_updates = parse_dimension(ENV_UPDATES, &updates);
    assert_eq!(default_updates, Ok(DEFAULT_UPDATES_PER_BURST));
    assert_eq!(
        parse_dimension(ENV_UPDATES, "65536"),
        Ok(MAX_WORKLOAD_DIMENSION),
        "the widest index of a 65536-count dimension is still a u16"
    );

    // Every refusal has to name the variable, the value and the range.
    let over = parse_dimension(ENV_UPDATES, "65537").expect_err("65537 is refused");
    for expected in [ENV_UPDATES, "65537", "1..=65536"] {
        assert!(over.contains(expected), "{over} must name {expected}");
    }
    let zero = parse_dimension(ENV_WORKERS, "0").expect_err("0 is refused");
    for expected in [ENV_WORKERS, "=0 ", "1..=65536"] {
        assert!(zero.contains(expected), "{zero} must name {expected}");
    }

    // A set-but-unparseable override is a named error too, never a silent
    // fallback to the default it was meant to replace.
    assert!(parse_dimension(ENV_WORKERS, "four").is_err());
}

/// Independent expected final state for a short run or a wrapped slot space.
/// Build it by replaying rounds, rather than duplicating the validator's
/// last-round arithmetic.
fn workload_rows(case: &MaterializerCase, rounds: u64) -> BTreeMap<String, Vec<u8>> {
    let mut rows = BTreeMap::new();
    for round in 0..rounds {
        let slot = (round % KEY_SLOTS as u64) as usize;
        let learned_at = BASE_LEARNED_AT + round;
        let occurred = TimeRange {
            start: learned_at,
            end: learned_at,
        };
        let blob = encode_entity_blob(ENTITY_TYPE_PERSON, occurred, learned_at, ENTITY_BODY);
        for worker in 0..case.workers {
            for update in 0..case.updates_per_burst {
                rows.insert(bench_entity_id(worker, slot, update).to_hex(), blob.clone());
            }
        }
    }
    rows
}

#[test]
fn materializer_mutex_requires_complete_current_materialization() {
    let case = fixture_case(2);
    for rounds in [2, KEY_SLOTS as u64, KEY_SLOTS as u64 + 2] {
        let rows = workload_rows(&case, rounds);
        let found = validate_workload_rows(&case, rounds, |id| Ok(rows.get(&id.to_hex()).cloned()))
            .expect("every visited slot has its latest blob");
        assert_eq!(found, rows.len());

        let missing_id = bench_entity_id(1, 1, 3).to_hex();
        let mut incomplete = rows;
        incomplete.remove(&missing_id);
        let error = validate_workload_rows(&case, rounds, |id| {
            Ok(incomplete.get(&id.to_hex()).cloned())
        })
        .expect_err("one missing row must invalidate the whole workload");
        assert!(error.contains("missing materialized entity"), "{error}");
        assert!(error.contains(&missing_id), "{error}");
    }

    // All slots still exist after warmup, but they cannot stand in for the
    // newer measured writes. This defeated a presence-only row census.
    let stale = workload_rows(&case, KEY_SLOTS as u64);
    let error = validate_workload_rows(&case, KEY_SLOTS as u64 + 2, |id| {
        Ok(stale.get(&id.to_hex()).cloned())
    })
    .expect_err("warmup rows must not mask failed measured writes");
    assert!(error.contains("does not match round"), "{error}");
}

struct EmptyObserverFactory;

impl ObserverFactory for EmptyObserverFactory {
    fn register(
        &self,
        _doc: &LoroDoc,
        _vault: &Arc<Vault>,
        _window_key: &str,
    ) -> Vec<loro::Subscription> {
        Vec::new()
    }
}
