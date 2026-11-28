//! FIX [ADOPTED-FOLD-TAIL-WALK-SIGNER-COST], the resumed fold's site: a fold
//! past a base takes the new rows only where none moves a row's sequence
//! floor (`fold_resume::scope_tops`, `ScopeTops::past`). For each new side
//! row whose signer already has a top in its world, it walked that world's
//! rows down from the row to each row at the top, with a fresh visited set.
//! Side signers whose tops sit below one long spine of their world each
//! walked all of it: s signers beside an n-row spine cost about s*(n+s) row
//! visits on every resume. The fold now reads each signer's top rows from
//! maps the base keeps at its frontier side rows, which each tail extends.
//!
//! Each test asks the scope-tops door whether a fold past a base takes each
//! of a sequence of tails. The door reads each row's signer, sequence, op
//! scope and parents alone; no signature is checked.
//!
//! 1. `side_signers_above_one_spine_resume_within_budget`: 4000 side signers
//!    whose new rows rise from their tops across one 4000-row spine of their
//!    world. The fold takes the tail, and the answer must come within
//!    `RESUME_BUDGET`. RED at #10052's head (about 32 million row visits),
//!    GREEN on the head.
//! 2. `the_scope_tops_take_tails_as_the_walk_did`: named logs, each with the
//!    answers it must get, and seeded random logs, each answered as the old
//!    walk's rule (`walk_rule`, written out here) answers it. GREEN at both
//!    heads.
//!
//! One `SCOPE-TOPS-COST` line is printed for the budget case, and one
//! `SCOPE-TOPS-ANSWERS` line for the random logs. The budget is for the test
//! profile, whose workspace crates build at opt-level 0.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test fold_resume_scope_tops_signer_cost -- --nocapture`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry, AuthorityOp,
    AuthoritySignature,
};
use oneiron::test_doors::authority_sequence_floor::scope_tops_tails_taken;
use oneiron_authority::authority::{FrontierJoin, FrontierJoinFamily, FrontierJoinScope};

/// The side signers beside the spine, and the spine's rows.
const SIGNERS: usize = 4000;
const SPINE: usize = 4000;
/// The time the door may take over the budget case: capture the base's
/// tops and fold past it once. On the head that is a few passes over about
/// 16000 rows; at #10052's head each new row walked the spine.
const RESUME_BUDGET: Duration = Duration::from_secs(3);
/// The seeded random logs the differential case answers.
const RANDOM_LOGS: usize = 4000;

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

/// A row as the test builds it: its signer's number, its sequence, its
/// parents, and its world's number (None for the main log).
#[derive(Clone, Debug)]
struct Row {
    signer: usize,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    world: Option<usize>,
}

type Rows = BTreeMap<AuthorityEntryHash, Row>;

/// One test log: the first base's rows, and each tail's rows in turn.
#[derive(Debug, Default)]
struct Log {
    base: Rows,
    tails: Vec<Rows>,
}

fn row(signer: usize, seq: u64, parents: &[AuthorityEntryHash], world: Option<usize>) -> Row {
    // A signed row's parent list is in canonical hash order.
    let mut parents = parents.to_vec();
    parents.sort_unstable();
    parents.dedup();
    Row {
        signer,
        seq,
        parents,
        world,
    }
}

/// `row` as a log entry: a frontier join of the main log or of its world,
/// the one op a sequence scope reads for either
/// (`world_privacy::side_world`). The signature is never checked.
fn entry(row: &Row) -> AuthorityLogEntry {
    let key = signer(row.signer);
    let scope = row.world.map_or(FrontierJoinScope::Main, |n| {
        FrontierJoinScope::World(world(n))
    });
    AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: row.seq,
        parent_hashes: row.parents.clone(),
        op: AuthorityOp::FrontierJoin(FrontierJoin {
            family: FrontierJoinFamily::Host,
            scope,
        }),
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: row.seq,
        overlay_seed: None,
    }
}

fn entries(rows: &Rows) -> BTreeMap<AuthorityEntryHash, AuthorityLogEntry> {
    rows.iter().map(|(hash, row)| (*hash, entry(row))).collect()
}

/// The door's answers on `log`: whether the fold takes each tail.
fn door_answers(log: &Log) -> Vec<bool> {
    let tails: Vec<_> = log.tails.iter().map(entries).collect();
    scope_tops_tails_taken(&entries(&log.base), &tails)
}

/// The rows of the budget case, all but the root in one world `W`: a main
/// root `P`; each side signer `S_i`'s row `A_i` (sequence 1) on it; `Z`'s
/// joins `J_1` on `A_1` and `J_i` on `J_(i-1)` and `A_i`, at sequence i;
/// `Z`'s spine `C_1..C_n` on `J_s`, at sequences s+1..s+n. The spine's top
/// `C_n` is the base's one frontier side row. The tail is each `S_i`'s row
/// `B_i` (sequence 2) on `C_n`.
fn signers_beside_one_spine(signers: usize, spine: usize) -> Log {
    const W: Option<usize> = Some(1);
    let zed = 0;
    let root: AuthorityEntryHash = numbered(b'p', 0);
    let mut log = Log::default();
    log.base.insert(root, row(signers + 1, 1, &[], None));
    let mut below = root;
    for i in 1..=signers {
        let a = numbered(b'a', i);
        log.base.insert(a, row(i, 1, &[root], W));
        let parents = if i == 1 {
            vec![a]
        } else {
            vec![numbered(b'j', i - 1), a]
        };
        below = numbered(b'j', i);
        log.base.insert(below, row(zed, i as u64, &parents, W));
    }
    for k in 1..=spine {
        let at = numbered(b'c', k);
        log.base
            .insert(at, row(zed, (signers + k) as u64, &[below], W));
        below = at;
    }
    let mut tail = Rows::new();
    for i in 1..=signers {
        tail.insert(numbered(b'b', i), row(i, 2, &[below], W));
    }
    log.tails.push(tail);
    log
}

/// Each side signer's row `B_i` sits on the spine's top, which descends from
/// every `A_i` through the joins: the fold takes the tail. At #10052's head,
/// each `B_i`'s check walked the whole spine and the joins above `J_i`.
#[test]
fn side_signers_above_one_spine_resume_within_budget() {
    let log = signers_beside_one_spine(SIGNERS, SPINE);
    let base = entries(&log.base);
    let tails: Vec<_> = log.tails.iter().map(entries).collect();
    // testkit-lint: allow(wall-clock) the elapsed time is the budget under test
    let started = Instant::now();
    let answers = scope_tops_tails_taken(&base, &tails);
    let elapsed = started.elapsed();
    println!(
        "SCOPE-TOPS-COST signers={SIGNERS} spine={SPINE} base={} tail={} answers={answers:?} \
         elapsed_ms={}",
        base.len(),
        tails[0].len(),
        elapsed.as_millis()
    );
    assert_eq!(
        answers,
        vec![true],
        "every new row rises from its signer's top through the spine, so the fold takes the tail"
    );
    assert!(
        elapsed <= RESUME_BUDGET,
        "the fold past the base took {elapsed:?}, past the budget {RESUME_BUDGET:?}: it walks \
         the spine once per side signer"
    );
}

/// Whether `lower` is among the ancestors of a row with `parents` along
/// rows of `world`, as `row` gives a held row's parents and world: the old
/// `rows_floor::descends_within_scope`.
fn descends(
    lower: &AuthorityEntryHash,
    parents: &[AuthorityEntryHash],
    world: Option<usize>,
    row: &impl Fn(&AuthorityEntryHash) -> Option<(Vec<AuthorityEntryHash>, Option<usize>)>,
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

/// `rows`' hashes, each after its parents among `rows`, ties by hash.
fn parents_first(rows: &Rows) -> Vec<AuthorityEntryHash> {
    let mut waiting = BTreeMap::new();
    let mut children = BTreeMap::<_, Vec<_>>::new();
    let mut ready = BTreeSet::new();
    for (hash, row) in rows {
        let parents: BTreeSet<_> = row
            .parents
            .iter()
            .filter(|parent| rows.contains_key(*parent))
            .collect();
        for parent in &parents {
            children.entry(**parent).or_default().push(*hash);
        }
        if parents.is_empty() {
            ready.insert(*hash);
        } else {
            waiting.insert(*hash, parents.len());
        }
    }
    let mut order = Vec::new();
    while let Some(hash) = ready.pop_first() {
        order.push(hash);
        for child in children.get(&hash).into_iter().flatten() {
            if let Some(count) = waiting.get_mut(child) {
                *count -= 1;
                if *count == 0 {
                    waiting.remove(child);
                    ready.insert(*child);
                }
            }
        }
    }
    order.extend(waiting.into_keys());
    order
}

/// Each signer's top per scope: the highest sequence and the rows at it.
type Tops = BTreeMap<(usize, Option<usize>), (u64, Vec<AuthorityEntryHash>)>;

fn tops_of(rows: &Rows) -> Tops {
    let mut tops = Tops::new();
    for (hash, row) in rows {
        let top = tops
            .entry((row.signer, row.world))
            .or_insert((row.seq, Vec::new()));
        if row.seq > top.0 {
            *top = (row.seq, Vec::new());
        }
        if row.seq == top.0 {
            top.1.push(*hash);
        }
    }
    tops
}

/// How the old rule answered one tail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Answer {
    /// Taken, and some new side row's signer had a top it had to descend
    /// from.
    TakenOnDescent,
    /// Taken, with no such row.
    Taken,
    /// Declined: a new row was not above its signer's top.
    BelowTop,
    /// Declined: a new side row was above its signer's top but did not
    /// descend from every row at it.
    NoDescent,
}

/// The old rule over one tail past `held` with `tops`: each new row, parents
/// first, must rise above its signer's top in its scope, and a new side row
/// must descend from every row at that top along its world's rows.
fn tail_rule(tops: &Tops, held: &Rows, new: &Rows) -> (Answer, Option<Tops>) {
    let mut tops = tops.clone();
    let mut descended = false;
    let at = |hash: &AuthorityEntryHash| {
        new.get(hash)
            .or_else(|| held.get(hash))
            .map(|row| (row.parents.clone(), row.world))
    };
    for hash in parents_first(new) {
        let row = &new[&hash];
        let key = (row.signer, row.world);
        if let Some((top_seq, top_rows)) = tops.get(&key) {
            if row.seq <= *top_seq {
                return (Answer::BelowTop, None);
            }
            if row.world.is_some() {
                if !top_rows
                    .iter()
                    .all(|top| descends(top, &row.parents, row.world, &at))
                {
                    return (Answer::NoDescent, None);
                }
                descended = true;
            }
        }
        tops.insert(key, (row.seq, vec![hash]));
    }
    let answer = if descended {
        Answer::TakenOnDescent
    } else {
        Answer::Taken
    };
    (answer, Some(tops))
}

/// The old walk's rule over a whole log: each tail in turn, and past a tail
/// it declines, the tops of every row so far.
fn walk_rule(log: &Log) -> Vec<Answer> {
    let mut held = log.base.clone();
    let mut tops = tops_of(&held);
    let mut answers = Vec::new();
    for tail in &log.tails {
        let new: Rows = tail
            .iter()
            .filter(|(hash, _)| !held.contains_key(*hash))
            .map(|(hash, row)| (*hash, row.clone()))
            .collect();
        let (answer, next) = tail_rule(&tops, &held, &new);
        answers.push(answer);
        held.extend(new);
        tops = next.unwrap_or_else(|| tops_of(&held));
    }
    answers
}

fn taken(answers: &[Answer]) -> Vec<bool> {
    answers
        .iter()
        .map(|answer| matches!(answer, Answer::TakenOnDescent | Answer::Taken))
        .collect()
}

fn h(tag: u8) -> AuthorityEntryHash {
    numbered(tag, 0)
}

/// Named logs, each with the answers it must get. Signers: `Z` 0, `A` 1,
/// `B` 2; worlds `W` 1 and `V` 2; `P` is a main root.
fn named_logs() -> Vec<(&'static str, Log, Vec<bool>)> {
    const W: Option<usize> = Some(1);
    const V: Option<usize> = Some(2);
    let p = h(b'p');
    let base = |rows: &[(u8, Row)]| -> Rows {
        let mut base: Rows = rows
            .iter()
            .map(|(tag, row)| (h(*tag), row.clone()))
            .collect();
        base.insert(p, row(0, 1, &[], None));
        base
    };
    let tail = |rows: &[(u8, Row)]| -> Rows {
        rows.iter()
            .map(|(tag, row)| (h(*tag), row.clone()))
            .collect()
    };
    let log = |base: Rows, tails: Vec<Rows>| Log { base, tails };
    vec![
        (
            "a side row on the spine above its top",
            log(
                base(&[
                    (b'a', row(1, 1, &[p], W)),
                    (b'c', row(0, 2, &[h(b'a')], W)),
                    (b'd', row(0, 3, &[h(b'c')], W)),
                ]),
                vec![tail(&[(b'b', row(1, 2, &[h(b'd')], W))])],
            ),
            vec![true],
        ),
        (
            "a side row on a branch beside its top",
            log(
                base(&[(b'a', row(1, 1, &[p], W)), (b'c', row(0, 2, &[p], W))]),
                vec![tail(&[(b'b', row(1, 2, &[h(b'c')], W))])],
            ),
            vec![false],
        ),
        (
            "a side row not above its top",
            log(
                base(&[(b'a', row(1, 2, &[p], W))]),
                vec![tail(&[(b'b', row(1, 2, &[h(b'a')], W))])],
            ),
            vec![false],
        ),
        (
            "two tied tops, both below the new row",
            log(
                base(&[
                    (b'a', row(1, 1, &[p], W)),
                    (b'e', row(1, 1, &[p], W)),
                    (b'j', row(0, 2, &[h(b'a'), h(b'e')], W)),
                ]),
                vec![tail(&[(b'b', row(1, 2, &[h(b'j')], W))])],
            ),
            vec![true],
        ),
        (
            "two tied tops, one below the new row",
            log(
                base(&[
                    (b'a', row(1, 1, &[p], W)),
                    (b'e', row(1, 1, &[p], W)),
                    (b'j', row(0, 2, &[h(b'a')], W)),
                ]),
                vec![tail(&[(b'b', row(1, 2, &[h(b'j')], W))])],
            ),
            vec![false],
        ),
        (
            "two tied tops, one through each parent",
            log(
                base(&[
                    (b'a', row(1, 1, &[p], W)),
                    (b'e', row(1, 1, &[p], W)),
                    (b'j', row(0, 2, &[h(b'a')], W)),
                    (b'k', row(2, 2, &[h(b'e')], W)),
                ]),
                vec![tail(&[(b'b', row(1, 2, &[h(b'j'), h(b'k')], W))])],
            ),
            vec![true],
        ),
        (
            "the top only through a main row",
            log(
                base(&[
                    (b'a', row(1, 1, &[p], W)),
                    (b'm', row(0, 2, &[h(b'a')], None)),
                    (b'y', row(0, 3, &[h(b'm')], W)),
                ]),
                vec![tail(&[(b'b', row(1, 2, &[h(b'y')], W))])],
            ),
            vec![false],
        ),
        (
            "the top only through another world's row",
            log(
                base(&[
                    (b'a', row(1, 1, &[p], W)),
                    (b'x', row(0, 2, &[h(b'a')], V)),
                    (b'y', row(0, 3, &[h(b'x')], W)),
                ]),
                vec![tail(&[(b'b', row(1, 2, &[h(b'y')], W))])],
            ),
            vec![false],
        ),
        (
            "a base row on a row the base does not hold",
            log(
                base(&[
                    (b'a', row(1, 1, &[p], W)),
                    (b'c', row(0, 2, &[h(b'a'), h(0xee)], W)),
                ]),
                vec![tail(&[(b'b', row(1, 2, &[h(b'c')], W))])],
            ),
            vec![true],
        ),
        (
            "two new rows of one signer, one on the other",
            log(
                base(&[(b'a', row(1, 1, &[p], W))]),
                vec![tail(&[
                    (b'b', row(1, 2, &[h(b'a')], W)),
                    (b'd', row(1, 3, &[h(b'b')], W)),
                ])],
            ),
            vec![true],
        ),
        (
            "two new rows of one signer, side by side",
            log(
                base(&[(b'a', row(1, 1, &[p], W))]),
                vec![tail(&[
                    (b'b', row(1, 2, &[h(b'a')], W)),
                    (b'd', row(1, 3, &[h(b'a')], W)),
                ])],
            ),
            vec![false],
        ),
        (
            "a new main row above its top, then one not above",
            log(
                base(&[(b'm', row(1, 1, &[p], None))]),
                vec![
                    tail(&[(b'n', row(1, 2, &[h(b'm')], None))]),
                    tail(&[(b'o', row(1, 2, &[h(b'n')], None))]),
                ],
            ),
            vec![true, false],
        ),
        (
            "a signer's first row in a world",
            log(
                base(&[(b'a', row(1, 1, &[p], W))]),
                vec![tail(&[(b'b', row(2, 1, &[h(b'a')], W))])],
            ),
            vec![true],
        ),
        (
            "four tails on the leaves the ones before left",
            log(
                base(&[(b'a', row(1, 1, &[p], W)), (b'c', row(0, 2, &[h(b'a')], W))]),
                vec![
                    tail(&[(b'b', row(1, 2, &[h(b'c')], W))]),
                    tail(&[(b'd', row(1, 3, &[h(b'b')], W))]),
                    tail(&[(b'e', row(2, 1, &[h(b'd')], W))]),
                    tail(&[(b'f', row(1, 4, &[h(b'e')], W))]),
                ],
            ),
            vec![true, true, true, true],
        ),
        (
            "a frontier row a tail leaves unnamed, named by the next",
            log(
                base(&[
                    (b'a', row(1, 1, &[p], W)),
                    (b'l', row(0, 2, &[h(b'a')], W)),
                    (b'k', row(2, 1, &[p], W)),
                ]),
                vec![
                    tail(&[(b'b', row(2, 2, &[h(b'k')], W))]),
                    tail(&[(b'd', row(1, 2, &[h(b'l')], W))]),
                ],
            ),
            vec![true, true],
        ),
        (
            "a declined tail, then a tail on it past the whole log's base",
            log(
                base(&[(b'a', row(1, 1, &[p], W)), (b'c', row(0, 2, &[p], W))]),
                vec![
                    tail(&[(b'b', row(1, 2, &[h(b'c')], W))]),
                    tail(&[(b'd', row(1, 3, &[h(b'b')], W))]),
                ],
            ),
            vec![false, true],
        ),
        (
            "rows of two worlds in one tail",
            log(
                base(&[(b'a', row(1, 1, &[p], W)), (b'v', row(1, 1, &[p], V))]),
                vec![tail(&[
                    (b'b', row(1, 2, &[h(b'a')], W)),
                    (b'u', row(1, 2, &[h(b'v'), p], V)),
                ])],
            ),
            vec![true],
        ),
    ]
}

/// A seeded xorshift stream.
struct Stream(u64);

impl Stream {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    fn below(&mut self, bound: usize) -> usize {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        (x % bound as u64) as usize
    }
}

/// A random log: a base of 6 to 14 rows of 3 signers in the main log and
/// two worlds, on any earlier rows and now and then a row the log does not
/// hold; then 1 to 3 tails of 1 to 5 rows each. A tail's main row stands on
/// one main row; its side row on 1 to 3 rows among the tail's own main and
/// same-world rows, the held main rows, and the held side rows of its world
/// no held row names (the frontier, as `side_tail::shape` admits them).
fn random_log(seed: u64) -> Log {
    let mut stream = Stream::new(seed);
    let mut count = 0;
    let mut fresh = |tag: u8| {
        count += 1;
        numbered::<32>(tag, count)
    };
    let mut log = Log::default();
    let mut held = Rows::new();
    let scope = |stream: &mut Stream| [None, Some(1), Some(2)][stream.below(3)];
    for _ in 0..6 + stream.below(9) {
        let world = scope(&mut stream);
        let signer = stream.below(3);
        let seq = 1 + stream.below(5) as u64;
        let candidates: Vec<_> = held.keys().copied().collect();
        let mut parents = Vec::new();
        for _ in 0..stream.below(4) {
            if !candidates.is_empty() {
                parents.push(candidates[stream.below(candidates.len())]);
            }
        }
        if stream.below(8) == 0 {
            parents.push(fresh(b'x'));
        }
        let hash = fresh(b'r');
        let new = row(signer, seq, &parents, world);
        log.base.insert(hash, new.clone());
        held.insert(hash, new);
    }
    for _ in 0..1 + stream.below(3) {
        let named: BTreeSet<_> = held.values().flat_map(|row| row.parents.clone()).collect();
        let mut tail = Rows::new();
        for _ in 0..1 + stream.below(5) {
            let world = scope(&mut stream);
            let signer = stream.below(3);
            let seq = 1 + stream.below(8) as u64;
            let parents = match world {
                None => {
                    let mains: Vec<_> = held
                        .iter()
                        .chain(&tail)
                        .filter(|(_, row)| row.world.is_none())
                        .map(|(hash, _)| *hash)
                        .collect();
                    if mains.is_empty() {
                        Vec::new()
                    } else {
                        vec![mains[stream.below(mains.len())]]
                    }
                }
                Some(_) => {
                    let candidates: Vec<_> = tail
                        .iter()
                        .filter(|(_, row)| row.world.is_none() || row.world == world)
                        .chain(held.iter().filter(|(hash, row)| {
                            row.world.is_none() || (row.world == world && !named.contains(*hash))
                        }))
                        .map(|(hash, _)| *hash)
                        .collect();
                    let mut parents = Vec::new();
                    for _ in 0..1 + stream.below(3) {
                        if !candidates.is_empty() {
                            parents.push(candidates[stream.below(candidates.len())]);
                        }
                    }
                    parents
                }
            };
            tail.insert(fresh(b'r'), row(signer, seq, &parents, world));
        }
        held.extend(tail.clone());
        log.tails.push(tail);
    }
    log
}

/// Named logs get their answers, the old walk's rule among them; seeded
/// random logs get the old walk's answers, with every kind of answer among
/// them.
#[test]
fn the_scope_tops_take_tails_as_the_walk_did() {
    for (name, log, expected) in named_logs() {
        assert_eq!(
            taken(&walk_rule(&log)),
            expected,
            "the old walk's rule answers the named log `{name}`"
        );
        assert_eq!(
            door_answers(&log),
            expected,
            "the fold past the base answers the named log `{name}`"
        );
    }
    let mut kinds = BTreeMap::<Answer, usize>::new();
    for seed in 0..RANDOM_LOGS as u64 {
        let log = random_log(seed);
        let answers = walk_rule(&log);
        for answer in &answers {
            *kinds.entry(*answer).or_default() += 1;
        }
        assert_eq!(
            door_answers(&log),
            taken(&answers),
            "seed {seed}: the fold past the base answers as the old walk did, on {log:?}"
        );
    }
    println!("SCOPE-TOPS-ANSWERS logs={RANDOM_LOGS} kinds={kinds:?}");
    for kind in [
        Answer::TakenOnDescent,
        Answer::Taken,
        Answer::BelowTop,
        Answer::NoDescent,
    ] {
        assert!(
            kinds.get(&kind).copied().unwrap_or(0) >= 100,
            "the random logs hold at least 100 tails answered {kind:?}: {kinds:?}"
        );
    }
}
