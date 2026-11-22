//! FIX [ADOPTED-FOLD-TAIL-WALK-SIGNER-COST] (found while fixing
//! [ADOPTED-FOLD-GATE-SIGNER-COST]): past the gate, the adopted fold's tail
//! checks ask whether the tail moves a covered row's sequence floor
//! (`adopted_fold::rows_floors_unmoved`) and, where it does, which covered
//! rows it floors (`adopted_fold::covered_floors::floored_covered_rows`).
//! They walked the ancestry once per tail signer with a fresh visited set:
//! the first from each signer's lowest tail row down to its covered top,
//! the second the whole ancestry of that row. Tail signers whose tops sit
//! below one long spine each walked all of it: s signers beside an n-row
//! spine cost about s*n row visits. The checks now pass over the rows once.
//!
//! Each test sets the covered row summaries of the image a rooted vault
//! builds to rows of its own, adds tail rows, and asks the tail checks
//! through the door, gate first, as the fold past the image asks them. The
//! checks read those summaries, the rows the image holds rejected and the
//! tail rows alone; no signature is checked.
//!
//! 1. `tail_signers_above_one_spine_check_within_budget`: 4000 tail signers
//!    whose rows rise from their covered tops across one 4000-row spine. The
//!    tail moves no floor, and the answer must come within `CHECK_BUDGET`.
//!    RED at #10034's head (about 30 million row visits), GREEN on the head.
//! 2. `forked_tail_signers_beside_one_spine_floor_within_budget`: 4000 tail
//!    signers whose tail rows sit on a 4000-row spine their covered rows are
//!    no ancestors of. The tail floors each covered row, and the answer must
//!    come within `CHECK_BUDGET`. RED at #10034's head (about 16 million row
//!    visits), GREEN on the head.
//! 3. `the_tail_checks_answer_as_the_walks_did`: named logs, and seeded
//!    random logs, each answered as the old walks' rule (`walk_rule`, written
//!    out here) answers it. GREEN at both heads.
//!
//! One `TAIL-COST` line is printed per budget case, and one `TAIL-ANSWERS`
//! line for the random logs. The budget is for the test profile, whose
//! workspace crates build at opt-level 0.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test adopted_fold_tail_walk_signer_cost -- --nocapture`.
#![cfg(all(oneiron_test_support, feature = "sync", feature = "test-support"))]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityCheckpointRow, AuthorityCheckpointV2,
    AuthorityEntryHash, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
    MachineRole,
};
use oneiron::test_doors::authority_adopted_fold::tail_floored_rows;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_authority::authority::{FrontierJoin, FrontierJoinFamily, FrontierJoinScope};

/// The tail signers beside the spine, and the spine's rows.
const SIGNERS: usize = 4000;
const SPINE: usize = 4000;
/// The time the checks may take over each budget case's rows. On the head
/// they pass about 16000 rows a few times; at #10034's head they walked the
/// spine once per tail signer.
const CHECK_BUDGET: Duration = Duration::from_secs(3);
/// The seeded random logs the differential case answers.
const RANDOM_LOGS: usize = 4000;

/// A self-host vault as its own server starts one, rooted and with this
/// install profiled under the host root, and the image it builds of its log.
fn rooted_image() -> (AuthorityCheckpointV2, Vault, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("self-host vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("setup: this install's machine profile under the host root")
        .roster
        .expect("setup: this install has a roster chain");
    let image = vault
        .build_authority_checkpoint_v2()
        .expect("setup: the held log builds a checkpoint image");
    (image, vault, dir)
}

fn numbered<const WIDTH: usize>(tag: u8, n: usize) -> [u8; WIDTH] {
    let mut bytes = [tag; WIDTH];
    bytes[WIDTH - 8..].copy_from_slice(&(n as u64).to_be_bytes());
    bytes
}

fn signer(n: usize) -> AuthorityKey {
    AuthorityKey::Ed25519(numbered(0x5a, n))
}

fn world(n: usize) -> EntityId {
    EntityId::from_bytes(numbered(0x77, n)).expect("a world id")
}

/// A row neither covered nor in the tail.
const ABSENT: AuthorityEntryHash = [0xee; 32];

fn summary(
    signer: AuthorityKey,
    seq: u64,
    mut parents: Vec<AuthorityEntryHash>,
    world: Option<EntityId>,
) -> AuthorityCheckpointRow {
    // A signed row's parent list is in canonical hash order.
    parents.sort_unstable();
    AuthorityCheckpointRow {
        signer,
        seq,
        parents,
        world,
        slip_op: false,
        body_required: false,
        body: None,
    }
}

/// One test log: the covered row summaries, the ones the image holds
/// rejected, and the tail rows, each as a summary of the row.
#[derive(Debug, Default)]
struct Log {
    covered: BTreeMap<AuthorityEntryHash, AuthorityCheckpointRow>,
    rejected: BTreeSet<AuthorityEntryHash>,
    tail: BTreeMap<AuthorityEntryHash, AuthorityCheckpointRow>,
}

/// A tail row as `row` summarises it: a frontier join of the main log or
/// of its world, the one op a sequence scope reads for either
/// (`world_privacy::side_world`). The signature is never checked.
fn tail_entry(image: &AuthorityCheckpointV2, row: &AuthorityCheckpointRow) -> AuthorityLogEntry {
    let scope = row
        .world
        .map_or(FrontierJoinScope::Main, FrontierJoinScope::World);
    AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(image.vault_id),
        seq: row.seq,
        parent_hashes: row.parents.clone(),
        op: AuthorityOp::FrontierJoin(FrontierJoin {
            family: FrontierJoinFamily::Host,
            scope,
        }),
        signer: AuthoritySignature {
            suite: row.signer.suite(),
            public_key: row.signer.clone(),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: row.seq,
        overlay_seed: None,
    }
}

/// The tail checks' answer on `log` through the door, past `image` with its
/// covered rows replaced by `log`'s.
fn door_answer(
    image: &mut AuthorityCheckpointV2,
    log: &Log,
) -> Option<BTreeSet<AuthorityEntryHash>> {
    image.rows = log.covered.clone();
    let tail = log
        .tail
        .iter()
        .map(|(hash, row)| (*hash, tail_entry(image, row)))
        .collect();
    tail_floored_rows(image, &log.rejected, &tail)
}

/// The covered rows of both budget cases, all in the main scope: a root row
/// `P` and each tail signer `S_i`'s row `A_i` (sequence 1) on it; with
/// `joined`, `Z`'s rows `J_1` on `A_1` and `J_i` on `J_(i-1)` and `A_i`, at
/// sequence i, and `Z`'s spine `C_1..C_n` on `J_s`; without, the spine on
/// `P`. The spine's top is `C_n`.
fn signers_beside_one_spine(signers: usize, spine: usize, joined: bool) -> Log {
    let zed = signer(0);
    let root: AuthorityEntryHash = numbered(b'p', 0);
    let mut log = Log::default();
    log.covered.insert(
        root,
        summary(AuthorityKey::Ed25519([0x52; 32]), 1, Vec::new(), None),
    );
    let mut below = root;
    for i in 1..=signers {
        log.covered
            .insert(numbered(b'a', i), summary(signer(i), 1, vec![root], None));
        if joined {
            let mut parents = vec![numbered(b'a', i)];
            if i > 1 {
                parents.push(numbered(b'j', i - 1));
            }
            below = numbered(b'j', i);
            log.covered
                .insert(below, summary(zed.clone(), i as u64, parents, None));
        }
    }
    for k in 1..=spine {
        let at = numbered(b'c', k);
        log.covered.insert(
            at,
            summary(zed.clone(), (signers + k) as u64, vec![below], None),
        );
        below = at;
    }
    for i in 1..=signers {
        log.tail
            .insert(numbered(b'b', i), summary(signer(i), 2, vec![below], None));
    }
    log
}

/// Runs the door on a budget case's log, prints one `TAIL-COST` line and
/// returns the answer and the time it took.
fn timed_answer(
    case: &str,
    image: &mut AuthorityCheckpointV2,
    log: &Log,
) -> (Option<BTreeSet<AuthorityEntryHash>>, Duration) {
    image.rows = log.covered.clone();
    let tail = log
        .tail
        .iter()
        .map(|(hash, row)| (*hash, tail_entry(image, row)))
        .collect();
    // testkit-lint: allow(wall-clock) the elapsed time is the budget under test
    let started = Instant::now();
    let answer = tail_floored_rows(image, &log.rejected, &tail);
    let elapsed = started.elapsed();
    println!(
        "TAIL-COST case={case} signers={SIGNERS} spine={SPINE} covered={} tail={} \
         answer_rows={:?} elapsed_ms={}",
        log.covered.len(),
        log.tail.len(),
        answer.as_ref().map(BTreeSet::len),
        elapsed.as_millis()
    );
    (answer, elapsed)
}

/// Each tail signer's row `B_i` (sequence 2) sits on the spine's top, which
/// descends from every `A_i` through the joins: the tail moves no floor. At
/// #10034's head, each `B_i`'s check walked the whole spine back to its
/// `A_i`.
#[test]
fn tail_signers_above_one_spine_check_within_budget() {
    let (mut image, _vault, _dir) = rooted_image();
    let log = signers_beside_one_spine(SIGNERS, SPINE, true);
    let (answer, elapsed) = timed_answer("unmoved", &mut image, &log);
    assert_eq!(
        answer,
        Some(BTreeSet::new()),
        "every tail row rises from its signer's covered top, so the tail moves no floor"
    );
    assert!(
        elapsed <= CHECK_BUDGET,
        "the tail checks took {elapsed:?}, past the budget {CHECK_BUDGET:?}: they walk the \
         spine once per tail signer"
    );
}

/// Each tail signer's row `B_i` (sequence 2) sits on the spine's top, which
/// no `A_i` is an ancestor of: each `B_i` floors its signer's `A_i`. At
/// #10034's head, each signer's floored rows came from a walk of `B_i`'s
/// whole ancestry, the spine included.
#[test]
fn forked_tail_signers_beside_one_spine_floor_within_budget() {
    let (mut image, _vault, _dir) = rooted_image();
    let log = signers_beside_one_spine(SIGNERS, SPINE, false);
    let (answer, elapsed) = timed_answer("floored", &mut image, &log);
    let every_a: BTreeSet<AuthorityEntryHash> = (1..=SIGNERS).map(|i| numbered(b'a', i)).collect();
    assert_eq!(
        answer,
        Some(every_a),
        "each tail row floors its signer's covered row, and no row vouches one away"
    );
    assert!(
        elapsed <= CHECK_BUDGET,
        "the tail checks took {elapsed:?}, past the budget {CHECK_BUDGET:?}: they walk the \
         spine once per tail signer"
    );
}

/// Whether `lower` is among the ancestors of a row with `parents` along
/// rows of `world`, as `row` gives a row's parents and scope where the walk
/// may pass through it: the old `rows_floor::descends_within_scope`.
fn descends(
    lower: &AuthorityEntryHash,
    parents: &[AuthorityEntryHash],
    world: Option<EntityId>,
    row: &impl Fn(&AuthorityEntryHash) -> Option<(Vec<AuthorityEntryHash>, Option<EntityId>)>,
) -> bool {
    let mut seen = BTreeSet::new();
    let mut stack = parents.to_vec();
    while let Some(at) = stack.pop() {
        if at == *lower {
            return true;
        }
        if !seen.insert(at) {
            continue;
        }
        if let Some((row_parents, row_world)) = row(&at)
            && row_world == world
        {
            stack.extend(row_parents);
        }
    }
    false
}

/// The old walks' rule, over a test log: the gate over the tail's signers
/// (each one's covered rows per sequence scope rise strictly and descend
/// each from the one below it, along covered rows of that scope that name
/// no side row of another world, as the covered rows alone tell it); then,
/// per tail signer and scope, the walk from the lowest tail row down to the
/// covered top and from each tail row to the one below it; and where that
/// fails, the floored rows from the whole judged ancestry of each lowest
/// tail row, and the vouch check.
fn walk_rule(log: &Log) -> Option<BTreeSet<AuthorityEntryHash>> {
    let covered_world = |hash: &AuthorityEntryHash| log.covered.get(hash).and_then(|row| row.world);
    let world_of = |hash: &AuthorityEntryHash| match log.tail.get(hash) {
        Some(row) => row.world,
        None => covered_world(hash),
    };
    let names_other =
        |row: &AuthorityCheckpointRow,
         world_of: &dyn Fn(&AuthorityEntryHash) -> Option<EntityId>| {
            row.parents.iter().any(|parent| {
                world_of(parent).is_some_and(|parent_world| row.world != Some(parent_world))
            })
        };
    let violates = |row: &AuthorityCheckpointRow| names_other(row, &world_of);
    // The gate, over the covered rows alone.
    let signers: BTreeSet<_> = log.tail.values().map(|row| &row.signer).collect();
    let gate_row = |hash: &AuthorityEntryHash| {
        let row = log.covered.get(hash)?;
        (!names_other(row, &covered_world)).then(|| (row.parents.clone(), row.world))
    };
    let mut chains = BTreeMap::<_, Vec<(u64, AuthorityEntryHash)>>::new();
    for (hash, row) in &log.covered {
        if signers.contains(&row.signer) && !names_other(row, &covered_world) {
            chains
                .entry((&row.signer, row.world))
                .or_default()
                .push((row.seq, *hash));
        }
    }
    for chain in chains.values_mut() {
        chain.sort_unstable();
        let chained = chain.windows(2).all(|pair| {
            pair[0].0 < pair[1].0
                && descends(
                    &pair[0].1,
                    &log.covered[&pair[1].1].parents,
                    log.covered[&pair[1].1].world,
                    &gate_row,
                )
        });
        if !chained {
            return None;
        }
    }
    // The tail's rows per signer and scope, the covered rows of those, and
    // the walk's rows: a tail row, and a covered row neither held rejected,
    // each naming no side row of another world.
    let mut scopes = BTreeMap::<_, Vec<(u64, AuthorityEntryHash)>>::new();
    for (hash, row) in &log.tail {
        if !violates(row) {
            scopes
                .entry((&row.signer, row.world))
                .or_default()
                .push((row.seq, *hash));
        }
    }
    let mut covered = BTreeMap::<_, Vec<(u64, AuthorityEntryHash)>>::new();
    for (hash, row) in &log.covered {
        let key = (&row.signer, row.world);
        if scopes.contains_key(&key) && !violates(row) {
            covered.entry(key).or_default().push((row.seq, *hash));
        }
    }
    let judged_parents = |hash: &AuthorityEntryHash| match log.tail.get(hash) {
        Some(row) => (!violates(row)).then(|| row.parents.clone()),
        None => log
            .covered
            .get(hash)
            .filter(|row| !log.rejected.contains(hash) && !violates(row))
            .map(|row| row.parents.clone()),
    };
    let walk_row = |hash: &AuthorityEntryHash| Some((judged_parents(hash)?, world_of(hash)));
    let tail_parents = |hash: &AuthorityEntryHash| log.tail[hash].parents.clone();
    for rows in scopes.values_mut() {
        rows.sort_unstable();
    }
    let unmoved = scopes.iter().all(|(key, rows)| {
        let top = covered
            .get(key)
            .and_then(|rows| rows.iter().map(|(seq, _)| *seq).max());
        let tops: Vec<_> = covered
            .get(key)
            .into_iter()
            .flatten()
            .filter(|(seq, _)| Some(*seq) == top)
            .map(|(_, hash)| *hash)
            .collect();
        let mut below_seq = top;
        let mut below = tops;
        rows.iter().all(|(seq, hash)| {
            let rises = below_seq.is_none_or(|below_seq| *seq > below_seq)
                && below
                    .iter()
                    .all(|lower| descends(lower, &tail_parents(hash), key.1, &walk_row));
            (below_seq, below) = (Some(*seq), vec![*hash]);
            rises
        })
    });
    if unmoved {
        return Some(BTreeSet::new());
    }
    let mut floored = BTreeSet::new();
    for (key, rows) in &scopes {
        let top = covered
            .get(key)
            .and_then(|rows| rows.iter().map(|(seq, _)| *seq).max());
        let rises = top.is_none_or(|top| rows[0].0 > top)
            && rows.windows(2).all(|pair| {
                pair[0].0 < pair[1].0
                    && descends(&pair[0].1, &tail_parents(&pair[1].1), key.1, &walk_row)
            });
        if !rises {
            return None;
        }
        let Some(below) = covered.get(key) else {
            continue;
        };
        let mut past = BTreeSet::new();
        let mut stack = tail_parents(&rows[0].1);
        while let Some(at) = stack.pop() {
            if past.insert(at) {
                stack.extend(judged_parents(&at)?);
            }
        }
        floored.extend(
            below
                .iter()
                .map(|(_, hash)| *hash)
                .filter(|hash| !past.contains(hash)),
        );
    }
    (!floored.is_empty() && vouch_tip_free(log, &floored)).then_some(floored)
}

/// The vouch check as the fold past the image runs it: no row of a floored
/// row's signer above that signer's lowest floored row descends from a
/// floored row, the floored rows aside.
fn vouch_tip_free(log: &Log, floored: &BTreeSet<AuthorityEntryHash>) -> bool {
    let signer_seq = |hash: &AuthorityEntryHash| {
        log.tail
            .get(hash)
            .or_else(|| log.covered.get(hash))
            .map(|row| (&row.signer, row.seq))
    };
    let mut lowest = BTreeMap::<&AuthorityKey, u64>::new();
    for (signer, seq) in floored.iter().filter_map(signer_seq) {
        let low = lowest.entry(signer).or_insert(seq);
        *low = (*low).min(seq);
    }
    let mut children = BTreeMap::<_, Vec<_>>::new();
    for (hash, row) in log.covered.iter().chain(&log.tail) {
        for parent in &row.parents {
            children.entry(*parent).or_default().push(*hash);
        }
    }
    let mut seen = BTreeSet::new();
    let mut stack: Vec<_> = floored.iter().copied().collect();
    while let Some(at) = stack.pop() {
        for child in children.get(&at).into_iter().flatten() {
            if seen.insert(*child) {
                stack.push(*child);
            }
        }
    }
    seen.iter()
        .filter(|hash| !floored.contains(*hash))
        .filter_map(signer_seq)
        .all(|(signer, seq)| lowest.get(signer).is_none_or(|low| seq <= *low))
}

/// Where a named row sits: covered, covered and held rejected, or in the
/// tail.
#[derive(Clone, Copy)]
enum Place {
    Covered,
    Rejected,
    Tail,
}

use Place::{Covered, Rejected, Tail};

/// One row of a named log: where it sits, its signer, sequence, parents by
/// index (`None` for a row neither covered nor in the tail) and world.
type NamedRow = (Place, usize, u64, &'static [Option<usize>], Option<usize>);

fn named_log(rows: &[NamedRow]) -> Log {
    let mut log = Log::default();
    for (index, (place, signer_number, seq, parents, world_number)) in rows.iter().enumerate() {
        let hash = numbered(b'n', index);
        let parents = parents
            .iter()
            .map(|parent| parent.map_or(ABSENT, |parent| numbered(b'n', parent)))
            .collect();
        let row = summary(
            signer(*signer_number),
            *seq,
            parents,
            world_number.map(world),
        );
        match place {
            Place::Covered => {
                log.covered.insert(hash, row);
            }
            Place::Rejected => {
                log.covered.insert(hash, row);
                log.rejected.insert(hash);
            }
            Place::Tail => {
                log.tail.insert(hash, row);
            }
        }
    }
    log
}

/// The named logs and the answer each must get: None for the whole
/// history, else the floored rows by index (none where the tail moves no
/// floor).
const NAMED_LOGS: &[(&str, &[NamedRow], Option<&[usize]>)] = &[
    (
        "a tail row on its signer's covered top",
        &[
            (Covered, 9, 1, &[], None),
            (Covered, 1, 1, &[Some(0)], None),
            (Tail, 1, 2, &[Some(1)], None),
        ],
        Some(&[]),
    ),
    (
        "a tail row on a sibling branch floors its signer's covered row",
        &[
            (Covered, 9, 1, &[], None),
            (Covered, 1, 1, &[Some(0)], None),
            (Covered, 2, 1, &[Some(0)], None),
            (Tail, 1, 2, &[Some(2)], None),
        ],
        Some(&[1]),
    ),
    (
        "a tail row at its signer's covered top sequence",
        &[
            (Covered, 9, 1, &[], None),
            (Covered, 1, 1, &[Some(0)], None),
            (Tail, 1, 1, &[Some(1)], None),
        ],
        None,
    ),
    (
        "a tail row reaching its top only through a row held rejected",
        &[
            (Covered, 9, 1, &[], None),
            (Covered, 1, 1, &[Some(0)], None),
            (Rejected, 2, 1, &[Some(1)], None),
            (Tail, 1, 2, &[Some(2)], None),
        ],
        None,
    ),
    (
        "a top held rejected is found as a parent",
        &[
            (Covered, 9, 1, &[], None),
            (Rejected, 1, 1, &[Some(0)], None),
            (Tail, 1, 2, &[Some(1)], None),
        ],
        Some(&[]),
    ),
    (
        "tail rows chained through another signer's tail row",
        &[
            (Covered, 9, 1, &[], None),
            (Covered, 1, 1, &[Some(0)], None),
            (Tail, 1, 2, &[Some(1)], None),
            (Tail, 2, 1, &[Some(2)], None),
            (Tail, 1, 3, &[Some(3)], None),
        ],
        Some(&[]),
    ),
    (
        "a later tail row not descending from the one below it",
        &[
            (Covered, 9, 1, &[], None),
            (Covered, 1, 1, &[Some(0)], None),
            (Tail, 1, 2, &[Some(1)], None),
            (Tail, 1, 3, &[Some(1)], None),
        ],
        None,
    ),
    (
        "a side tail row on its world's top",
        &[
            (Covered, 9, 1, &[], None),
            (Covered, 1, 1, &[Some(0)], Some(1)),
            (Tail, 1, 2, &[Some(1)], Some(1)),
        ],
        Some(&[]),
    ),
    (
        "a side tail row on a main row floors its world's covered row",
        &[
            (Covered, 9, 1, &[], None),
            (Covered, 1, 1, &[Some(0)], Some(1)),
            (Covered, 2, 1, &[Some(0)], None),
            (Tail, 1, 2, &[Some(2)], Some(1)),
        ],
        Some(&[1]),
    ),
    (
        "a floored row whose ancestry holds a row neither covered nor in the tail",
        &[
            (Covered, 9, 1, &[], None),
            (Covered, 1, 1, &[Some(0)], None),
            (Covered, 2, 1, &[Some(0)], None),
            (Tail, 1, 2, &[Some(2), None], None),
        ],
        None,
    ),
    (
        "a later row of the floored row's signer descends from it",
        &[
            (Covered, 9, 1, &[], None),
            (Covered, 1, 1, &[Some(0)], None),
            (Tail, 1, 2, &[Some(0)], None),
            (Tail, 1, 3, &[Some(1), Some(2)], None),
        ],
        None,
    ),
    (
        "one tail signer on its top, another floored",
        &[
            (Covered, 9, 1, &[], None),
            (Covered, 1, 1, &[Some(0)], None),
            (Covered, 2, 1, &[Some(0)], None),
            (Tail, 1, 2, &[Some(1)], None),
            (Tail, 2, 2, &[Some(3)], None),
        ],
        Some(&[2]),
    ),
    (
        "the floored row's chain lies below a covered row the tail descends from",
        &[
            (Covered, 9, 1, &[], None),
            (Covered, 1, 1, &[Some(0)], None),
            (Covered, 1, 2, &[Some(1)], None),
            (Covered, 1, 3, &[Some(2)], None),
            (Covered, 2, 1, &[Some(2)], None),
            (Tail, 1, 4, &[Some(4)], None),
        ],
        Some(&[3]),
    ),
    (
        "the gate refuses a tail signer's covered rows on sibling branches",
        &[
            (Covered, 9, 1, &[], None),
            (Covered, 1, 1, &[Some(0)], None),
            (Covered, 1, 2, &[Some(0)], None),
            (Tail, 1, 3, &[Some(1), Some(2)], None),
        ],
        None,
    ),
    (
        "a tail row naming another world's side row is none of the tail's rows",
        &[
            (Covered, 9, 1, &[], None),
            (Covered, 3, 1, &[Some(0)], Some(2)),
            (Covered, 1, 1, &[Some(0)], None),
            (Tail, 1, 2, &[Some(1)], None),
        ],
        Some(&[]),
    ),
];

/// xorshift64: the differential case's seeded draws.
struct Xorshift64(u64);

impl Xorshift64 {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// A random log of 1 to 8 covered rows and then 1 to 5 tail rows, over 3
/// signers and 3 scopes (the main log with probability 2/3). Each row names
/// its signer's top row in its scope so far with probability 1/2, else the
/// row drawn before it with probability 1/4, and up to 2 more rows drawn
/// before it, now and then one neither covered nor in the tail. Its sequence
/// is one above that top with probability 3/4, else drawn from 1 to 4. A
/// covered row is held rejected with probability 1/10.
fn random_log(draws: &mut Xorshift64) -> Log {
    let covered_count = 1 + draws.below(8) as usize;
    let tail_count = 1 + draws.below(5) as usize;
    let mut hashes: Vec<AuthorityEntryHash> = Vec::new();
    let mut tops = BTreeMap::<(usize, Option<usize>), (u64, AuthorityEntryHash)>::new();
    let mut log = Log::default();
    for index in 0..covered_count + tail_count {
        let mut hash = [0u8; 32];
        for chunk in hash.chunks_mut(8) {
            chunk.copy_from_slice(&draws.next().to_be_bytes());
        }
        let signer_number = draws.below(3) as usize;
        let world_number = match draws.below(6) {
            0 => Some(1),
            1 => Some(2),
            _ => None,
        };
        let key = (signer_number, world_number);
        let mut parents = BTreeSet::new();
        match draws.below(4) {
            0 | 1 => {
                if let Some((_, top)) = tops.get(&key) {
                    parents.insert(*top);
                }
            }
            2 => {
                if let Some(previous) = hashes.last() {
                    parents.insert(*previous);
                }
            }
            _ => {}
        }
        for _ in 0..draws.below(3) {
            if hashes.is_empty() || draws.below(10) == 0 {
                parents.insert(ABSENT);
            } else {
                parents.insert(hashes[draws.below(hashes.len() as u64) as usize]);
            }
        }
        let seq = if draws.below(4) != 0 {
            tops.get(&key).map_or(1, |(seq, _)| seq + 1)
        } else {
            1 + draws.below(4)
        };
        if tops.get(&key).is_none_or(|(top, _)| seq >= *top) {
            tops.insert(key, (seq, hash));
        }
        let row = summary(
            signer(signer_number),
            seq,
            parents.into_iter().collect(),
            world_number.map(world),
        );
        if index < covered_count {
            log.covered.insert(hash, row);
            if draws.below(10) == 0 {
                log.rejected.insert(hash);
            }
        } else {
            log.tail.insert(hash, row);
        }
        hashes.push(hash);
    }
    log
}

/// The class of an answer the differential case counts.
fn answer_class(answer: Option<&BTreeSet<AuthorityEntryHash>>) -> &'static str {
    match answer {
        None => "history",
        Some(floored) if floored.is_empty() => "unmoved",
        Some(_) => "floored",
    }
}

#[test]
fn the_tail_checks_answer_as_the_walks_did() {
    let (mut image, _vault, _dir) = rooted_image();
    for (name, rows, expected) in NAMED_LOGS {
        let log = named_log(rows);
        let expected: Option<BTreeSet<AuthorityEntryHash>> =
            expected.map(|floored| floored.iter().map(|index| numbered(b'n', *index)).collect());
        assert_eq!(walk_rule(&log), expected, "the walk rule on: {name}");
        assert_eq!(
            door_answer(&mut image, &log),
            expected,
            "the tail checks on: {name}"
        );
    }
    let mut draws = Xorshift64(0x2545_f491_4f6c_dd1d);
    let mut answers = BTreeMap::<&str, usize>::new();
    for case in 0..RANDOM_LOGS {
        let log = random_log(&mut draws);
        let expected = walk_rule(&log);
        assert_eq!(
            door_answer(&mut image, &log),
            expected,
            "random log {case} answered apart from the walk rule: {log:?}"
        );
        *answers.entry(answer_class(expected.as_ref())).or_default() += 1;
    }
    println!("TAIL-ANSWERS random logs {RANDOM_LOGS}: {answers:?}");
    for class in ["history", "unmoved", "floored"] {
        assert!(
            answers.get(class).copied().unwrap_or(0) >= RANDOM_LOGS / 50,
            "the random logs answer {class} at least a fiftieth of the time: {answers:?}"
        );
    }
}
