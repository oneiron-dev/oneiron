//! The fold's ancestor index holds each row's claimed ancestry as sorted
//! runs of topological ids (row [ROSTER-KEY-LOG-FLOOD], PR 1; Engine RULINGs
//! 16 Nov 13:32 and 13:44 = A). It must answer every fold reader exactly as
//! the per-row set index it replaced: the same rows indexed (a claimed
//! parent the log lacks has no ancestry), the same members, membership and
//! counts, the same pairs and counted pairs, and the same memory floor
//! verdict at every pair limit.
//!
//! Through `test_doors::authority_ancestor_index`, each test builds both
//! indexes of synthetic logs (hashes drawn at random, so hash order is not
//! claim order) and compares every answer:
//! - random DAGs, with repeated and missing parent claims;
//! - chains, stars, grids, braids and diamond stacks;
//! - chains whose rows claim parents the log lacks;
//! - hand-built claim cycles and self parents (a row on a cycle is its own
//!   ancestor, as before);
//! - pair limits just under, at and over each log's pairs;
//! - the marked pass (PR 3, `AncestorIndex::marks`): whether each row, each
//!   claimed parent and each probe hash has a probe hash among its
//!   ancestors, against the set index's intersection.
//!
//! Each test prints one `EQUIV` line. Green on the head only: the door is
//! new (the index it tests is a rewrite, exact by construction).
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test ancestor_index_equivalence`.

#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};

use oneiron::test_doors::authority_ancestor_index::{IndexedAncestry, by_runs, by_sets};

type Hash = [u8; 32];
type Log = BTreeMap<Hash, Vec<Hash>>;

/// A splitmix64 stream: the same seed draws the same logs on every host.
struct Draws(u64);

impl Draws {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn hash(&mut self) -> Hash {
        let mut hash = [0_u8; 32];
        for chunk in hash.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes());
        }
        hash
    }

    fn hashes(&mut self, count: usize) -> Vec<Hash> {
        (0..count).map(|_| self.hash()).collect()
    }
}

/// Builds `log` both ways with no limit and at limits around its pairs, and
/// asserts every answer equal. Returns the log's pairs.
fn assert_equivalent(label: &str, log: &Log, draws: &mut Draws) -> u64 {
    let rows: Vec<_> = log.keys().copied().collect();
    let uncounted: BTreeSet<Hash> = rows
        .iter()
        .filter(|_| draws.below(5) == 0)
        .copied()
        .collect();
    let claimed: Vec<Hash> = log.values().flatten().copied().collect();
    let mut probe: BTreeSet<Hash> = draws.hashes(3).into_iter().collect();
    for _ in 0..4 {
        if !rows.is_empty() {
            probe.insert(rows[draws.below(rows.len())]);
        }
        if !claimed.is_empty() {
            probe.insert(claimed[draws.below(claimed.len())]);
        }
    }
    let by_set_index = by_sets(log, &uncounted, u64::MAX, &probe)
        .unwrap_or_else(|| panic!("{label}: no limit refuses"));
    assert_ancestry_eq(
        label,
        "no limit",
        by_runs(log, &uncounted, u64::MAX, &probe).as_ref(),
        Some(&by_set_index),
    );
    let pairs = by_set_index.pairs;
    for limit in [0, pairs / 2, pairs.saturating_sub(1), pairs, pairs + 1] {
        let runs = by_runs(log, &uncounted, limit, &probe);
        let sets = by_sets(log, &uncounted, limit, &probe);
        assert_eq!(
            runs.is_some(),
            pairs <= limit,
            "{label}: limit {limit}, pairs {pairs}: the run index refuses exactly past the limit"
        );
        assert_ancestry_eq(
            label,
            &format!("limit {limit}"),
            runs.as_ref(),
            sets.as_ref(),
        );
    }
    pairs
}

fn assert_ancestry_eq(
    label: &str,
    limit: &str,
    runs: Option<&IndexedAncestry>,
    sets: Option<&IndexedAncestry>,
) {
    let (Some(runs), Some(sets)) = (runs, sets) else {
        assert_eq!(
            runs.is_some(),
            sets.is_some(),
            "{label}, {limit}: one index refused and the other did not"
        );
        return;
    };
    assert_eq!(runs.indexed, sets.indexed, "{label}, {limit}: indexed rows");
    assert_eq!(runs.members, sets.members, "{label}, {limit}: members");
    assert_eq!(runs.walked, sets.walked, "{label}, {limit}: walked members");
    assert_eq!(
        runs.contained, sets.contained,
        "{label}, {limit}: membership"
    );
    assert_eq!(runs.lens, sets.lens, "{label}, {limit}: counts");
    assert_eq!(
        runs.meets_probe, sets.meets_probe,
        "{label}, {limit}: probe"
    );
    assert_eq!(runs.marked, sets.marked, "{label}, {limit}: marked pass");
    assert_eq!(runs.pairs, sets.pairs, "{label}, {limit}: pairs");
    assert_eq!(
        runs.counted_pairs, sets.counted_pairs,
        "{label}, {limit}: counted pairs"
    );
    assert_eq!(runs, sets, "{label}, {limit}: every answer");
}

/// A random DAG of `count` rows: each claims up to `most_parents` earlier
/// rows (repeats allowed) and, one time in `missing_one_in`, a parent the
/// log lacks.
fn random_dag(draws: &mut Draws, count: usize, most_parents: usize, missing_one_in: usize) -> Log {
    let hashes = draws.hashes(count);
    let mut log = Log::new();
    for (place, hash) in hashes.iter().enumerate() {
        let mut parents = Vec::new();
        if place > 0 {
            for _ in 0..draws.below(most_parents + 1) {
                parents.push(hashes[draws.below(place)]);
            }
        }
        if draws.below(missing_one_in) == 0 {
            parents.push(draws.hash());
        }
        log.insert(*hash, parents);
    }
    log
}

/// Each row claims the one before it.
fn chain(draws: &mut Draws, count: usize) -> Log {
    let hashes = draws.hashes(count);
    hashes
        .iter()
        .enumerate()
        .map(|(place, hash)| {
            let parents = if place == 0 {
                Vec::new()
            } else {
                vec![hashes[place - 1]]
            };
            (*hash, parents)
        })
        .collect()
}

/// Every row but the first claims the first.
fn star(draws: &mut Draws, count: usize) -> Log {
    let hashes = draws.hashes(count);
    hashes
        .iter()
        .enumerate()
        .map(|(place, hash)| {
            let parents = if place == 0 {
                Vec::new()
            } else {
                vec![hashes[0]]
            };
            (*hash, parents)
        })
        .collect()
}

/// A `side` x `side` grid: each row claims the row to its left and the row
/// above it.
fn grid(draws: &mut Draws, side: usize) -> Log {
    let hashes = draws.hashes(side * side);
    let mut log = Log::new();
    for row in 0..side {
        for column in 0..side {
            let mut parents = Vec::new();
            if column > 0 {
                parents.push(hashes[row * side + column - 1]);
            }
            if row > 0 {
                parents.push(hashes[(row - 1) * side + column]);
            }
            log.insert(hashes[row * side + column], parents);
        }
    }
    log
}

/// Two chains A and B; row C_k claims A_k and B_k, and A_{k+1} and B_{k+1}
/// claim A_k and B_k alone.
fn braid(draws: &mut Draws, length: usize) -> Log {
    let a = draws.hashes(length);
    let b = draws.hashes(length);
    let c = draws.hashes(length);
    let mut log = Log::new();
    for k in 0..length {
        let before = |line: &[Hash]| {
            if k == 0 {
                Vec::new()
            } else {
                vec![line[k - 1]]
            }
        };
        log.insert(a[k], before(a.as_slice()));
        log.insert(b[k], before(b.as_slice()));
        log.insert(c[k], vec![a[k], b[k]]);
    }
    log
}

/// A stack of diamonds: each top claims two middles, each middle the last
/// top, so every row reaches the first top along two paths.
fn diamonds(draws: &mut Draws, count: usize) -> Log {
    let mut log = Log::new();
    let mut top = draws.hash();
    log.insert(top, Vec::new());
    for _ in 0..count {
        let (left, right, next) = (draws.hash(), draws.hash(), draws.hash());
        log.insert(left, vec![top]);
        log.insert(right, vec![top, top]);
        log.insert(next, vec![right, left]);
        top = next;
    }
    log
}

/// A chain whose every row also claims `missing` parents the log lacks,
/// before or after the row below it.
fn chain_naming_missing_parents(draws: &mut Draws, count: usize, missing: usize) -> Log {
    let hashes = draws.hashes(count);
    let mut log = Log::new();
    for (place, hash) in hashes.iter().enumerate() {
        let mut parents = draws.hashes(missing);
        if place > 0 {
            parents.insert(draws.below(missing + 1), hashes[place - 1]);
        }
        log.insert(*hash, parents);
    }
    log
}

#[test]
fn run_index_matches_set_index_on_random_dags() {
    let mut draws = Draws(0x5EED_0001);
    let (mut logs, mut pairs) = (0, 0);
    for count in [0, 1, 2, 3, 5, 8, 30, 120] {
        for most_parents in [1, 2, 4] {
            for missing_one_in in [2, 9] {
                for _ in 0..12 {
                    let log = random_dag(&mut draws, count, most_parents, missing_one_in);
                    let label = format!(
                        "random dag {count} rows, {most_parents} parents, 1/{missing_one_in} missing"
                    );
                    pairs += assert_equivalent(&label, &log, &mut draws);
                    logs += 1;
                }
            }
        }
    }
    println!("EQUIV shape=random-dag logs={logs} pairs={pairs}");
}

#[test]
fn run_index_matches_set_index_on_chains_stars_grids_braids_and_diamonds() {
    let mut draws = Draws(0x5EED_0002);
    let (mut logs, mut pairs) = (0, 0);
    for count in [1, 2, 3, 17, 250] {
        let log = chain(&mut draws, count);
        pairs += assert_equivalent(&format!("chain {count}"), &log, &mut draws);
        let log = star(&mut draws, count);
        pairs += assert_equivalent(&format!("star {count}"), &log, &mut draws);
        logs += 2;
    }
    for side in [1, 2, 3, 6, 14] {
        let log = grid(&mut draws, side);
        pairs += assert_equivalent(&format!("grid {side}x{side}"), &log, &mut draws);
        logs += 1;
    }
    for length in [1, 2, 9, 40] {
        let log = braid(&mut draws, length);
        pairs += assert_equivalent(&format!("braid {length}"), &log, &mut draws);
        let log = diamonds(&mut draws, length);
        pairs += assert_equivalent(&format!("diamonds {length}"), &log, &mut draws);
        logs += 2;
    }
    println!("EQUIV shape=chain-star-grid-braid-diamond logs={logs} pairs={pairs}");
}

#[test]
fn run_index_matches_set_index_with_missing_parents() {
    let mut draws = Draws(0x5EED_0003);
    let (mut logs, mut pairs) = (0, 0);
    for count in [1, 2, 12, 64] {
        for missing in [1, 3, 31] {
            let log = chain_naming_missing_parents(&mut draws, count, missing);
            let label = format!("chain {count} naming {missing} missing parents a row");
            pairs += assert_equivalent(&label, &log, &mut draws);
            logs += 1;
        }
    }
    // Two rows naming one missing parent, and a row naming only missing ones.
    let (shared, first, second, lone) = (draws.hash(), draws.hash(), draws.hash(), draws.hash());
    let log: Log = [
        (first, vec![shared]),
        (second, vec![shared, first]),
        (lone, draws.hashes(4)),
    ]
    .into_iter()
    .collect();
    pairs += assert_equivalent("shared missing parent", &log, &mut draws);
    logs += 1;
    println!("EQUIV shape=missing-parents logs={logs} pairs={pairs}");
}

#[test]
fn run_index_matches_set_index_on_claim_cycles() {
    let mut draws = Draws(0x5EED_0004);
    let h = draws.hashes(10);
    let missing = draws.hash();
    let logs: Vec<(&str, Log)> = vec![
        ("self parent", [(h[0], vec![h[0]])].into_iter().collect()),
        (
            "self parent above a root",
            [(h[0], Vec::new()), (h[1], vec![h[1], h[0]])]
                .into_iter()
                .collect(),
        ),
        (
            "two-row cycle",
            [(h[0], vec![h[1]]), (h[1], vec![h[0]])]
                .into_iter()
                .collect(),
        ),
        (
            "three-row cycle with a tail above and below",
            [
                (h[0], Vec::new()),
                (h[1], vec![h[3], h[0]]),
                (h[2], vec![h[1]]),
                (h[3], vec![h[2]]),
                (h[4], vec![h[3]]),
                (h[5], vec![h[4], h[2]]),
            ]
            .into_iter()
            .collect(),
        ),
        (
            "cycle reaching a missing parent",
            [
                (h[0], vec![h[1], missing]),
                (h[1], vec![h[0]]),
                (h[2], vec![h[1]]),
            ]
            .into_iter()
            .collect(),
        ),
        (
            "two cycles joined by a row",
            [
                (h[0], vec![h[1]]),
                (h[1], vec![h[0]]),
                (h[2], vec![h[3]]),
                (h[3], vec![h[2], h[2]]),
                (h[4], vec![h[0], h[3]]),
                (h[5], vec![h[4], h[5]]),
            ]
            .into_iter()
            .collect(),
        ),
        (
            "nested cycles",
            [
                (h[0], vec![h[1]]),
                (h[1], vec![h[2], h[0]]),
                (h[2], vec![h[0], h[3]]),
                (h[3], vec![h[1]]),
                (h[4], vec![h[2]]),
            ]
            .into_iter()
            .collect(),
        ),
    ];
    let mut pairs = 0;
    for (label, log) in &logs {
        pairs += assert_equivalent(label, log, &mut draws);
    }
    // A row on a cycle is its own ancestor; a row above one is not.
    let probe = BTreeSet::new();
    let two = by_runs(&logs[2].1, &BTreeSet::new(), u64::MAX, &probe).expect("no limit");
    assert_eq!(two.members[&h[0]], {
        let mut both = vec![h[0], h[1]];
        both.sort_unstable();
        both
    });
    let tail = by_runs(&logs[3].1, &BTreeSet::new(), u64::MAX, &probe).expect("no limit");
    assert!(
        tail.members[&h[2]].contains(&h[2]),
        "a cycle's row holds itself"
    );
    assert!(
        !tail.members[&h[5]].contains(&h[5]),
        "a row above a cycle does not"
    );
    assert!(
        !tail.members[&h[0]].contains(&h[0]),
        "a root below a cycle does not"
    );
    println!("EQUIV shape=claim-cycles logs={} pairs={pairs}", logs.len());
}

#[test]
fn run_index_refuses_where_the_set_index_refuses() {
    let mut draws = Draws(0x5EED_0005);
    let log = chain(&mut draws, 300);
    let probe = BTreeSet::new();
    let none = BTreeSet::new();
    let pairs = by_sets(&log, &none, u64::MAX, &probe)
        .expect("no limit")
        .pairs;
    assert_eq!(
        pairs,
        300 * 299 / 2,
        "a chain of n rows holds n(n-1)/2 pairs"
    );
    for limit in [0, 1, pairs / 3, pairs - 1] {
        assert!(
            by_runs(&log, &none, limit, &probe).is_none(),
            "limit {limit} refuses"
        );
        assert!(
            by_sets(&log, &none, limit, &probe).is_none(),
            "limit {limit} refuses"
        );
    }
    for limit in [pairs, pairs + 1, u64::MAX] {
        assert!(
            by_runs(&log, &none, limit, &probe).is_some(),
            "limit {limit} builds"
        );
    }
    // A log with no pair builds at limit 0 either way.
    let roots: Log = draws
        .hashes(5)
        .into_iter()
        .map(|hash| (hash, Vec::new()))
        .collect();
    assert!(by_runs(&roots, &none, 0, &probe).is_some());
    assert!(by_sets(&roots, &none, 0, &probe).is_some());
    println!("EQUIV shape=floor pairs={pairs}");
}
