//! FIX [ADOPTED-FOLD-GATE-SIGNER-COST] (Astra seq-floor round 2b F1; Engine
//! RULING SEQ-FLOOR-GATE-COST = A): the adopted-fold gate asks whether each
//! signer's covered rows form one chain in each sequence scope
//! (`adopted_fold::covered_floors::covered_rows_unfloored`). It walked the
//! ancestry once for each pair of a signer's rows, with a fresh visited set,
//! so signers whose rows sit either side of one long spine each walked all of
//! it: s signers beside an n-row spine cost about s*n row visits. The check
//! now passes over the covered rows once.
//!
//! Each test sets the covered row summaries of the image a rooted vault
//! builds to rows of its own and asks the gate's check through the door; the
//! check reads those summaries alone.
//!
//! 1. `signers_beside_one_spine_check_within_budget`: Astra's rows, 4000
//!    signers beside a 4000-row spine. The answer is true, and it must come
//!    within `CHECK_BUDGET`. RED on main (about 40 million row visits), GREEN
//!    on the head. One `GATE-COST` line is printed.
//! 2. `the_check_answers_as_the_pair_walks_did`: named logs, and seeded random
//!    logs, each answered as the old pair walks' rule (`walk_rule`, written
//!    out here) answers it. GREEN at both heads.
//!
//! The budget is for the test profile, whose workspace crates build at
//! opt-level 0.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test adopted_fold_gate_signer_cost -- --nocapture`.
#![cfg(all(oneiron_test_support, feature = "sync", feature = "test-support"))]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::authority::{
    AuthorityCheckpointRow, AuthorityCheckpointV2, AuthorityEntryHash, AuthorityKey, MachineRole,
};
use oneiron::test_doors::authority_adopted_fold::covered_rows_unfloored;
use oneiron::{EntityId, Vault, VaultConfig};

/// The signers beside the spine, and the spine's rows.
const SIGNERS: usize = 4000;
const SPINE: usize = 4000;
/// The time the check may take over Astra's rows. On the head it passes
/// about 12000 rows once; on main it walked the spine once per signer.
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

/// A row the image does not hold.
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

/// Astra round 2b F1's rows, all in the main scope: a root row `P`; each
/// signer `S_i`'s row `A_i` (sequence 1) on it; `Z`'s rows `J_1` on `A_1`
/// and `J_i` on `J_(i-1)` and `A_i`, at sequence i; `Z`'s spine `C_1..C_n`
/// on `J_s`, at s+1..s+n; and each signer's row `B_i` (sequence 2) on `C_n`.
/// Every signer's rows form one chain, so the check answers true; on main,
/// each `B_i` walked the whole spine back to its `A_i`.
fn signers_beside_one_spine(
    signers: usize,
    spine: usize,
) -> BTreeMap<AuthorityEntryHash, AuthorityCheckpointRow> {
    let zed = signer(0);
    let root: AuthorityEntryHash = numbered(b'p', 0);
    let mut rows = BTreeMap::new();
    rows.insert(
        root,
        summary(AuthorityKey::Ed25519([0x52; 32]), 1, Vec::new(), None),
    );
    for i in 1..=signers {
        rows.insert(numbered(b'a', i), summary(signer(i), 1, vec![root], None));
        let mut parents = vec![numbered(b'a', i)];
        if i > 1 {
            parents.push(numbered(b'j', i - 1));
        }
        rows.insert(
            numbered(b'j', i),
            summary(zed.clone(), i as u64, parents, None),
        );
    }
    let mut below: AuthorityEntryHash = numbered(b'j', signers);
    for k in 1..=spine {
        let at = numbered(b'c', k);
        rows.insert(
            at,
            summary(zed.clone(), (signers + k) as u64, vec![below], None),
        );
        below = at;
    }
    for i in 1..=signers {
        rows.insert(numbered(b'b', i), summary(signer(i), 2, vec![below], None));
    }
    rows
}

#[test]
fn signers_beside_one_spine_check_within_budget() {
    let (mut image, _vault, _dir) = rooted_image();
    image.rows = signers_beside_one_spine(SIGNERS, SPINE);
    let rows = image.rows.len();
    let started = Instant::now();
    let answer = covered_rows_unfloored(&image);
    let elapsed = started.elapsed();
    println!(
        "GATE-COST signers={SIGNERS} spine={SPINE} rows={rows} answer={answer} elapsed_ms={}",
        elapsed.as_millis()
    );
    assert!(
        answer,
        "every signer's covered rows form one chain, so the gate passes"
    );
    assert!(
        elapsed <= CHECK_BUDGET,
        "the covered-row check took {elapsed:?} over {rows} rows, past the budget \
         {CHECK_BUDGET:?}: it walks the spine once per signer"
    );
}

/// The old pair walks' rule, over the covered row summaries: per signer and
/// sequence scope, the rows naming no side row of another world, by
/// sequence; each next row above the one below it, and descending from it
/// along held rows of that scope that name no side row of another world.
fn walk_rule(rows: &BTreeMap<AuthorityEntryHash, AuthorityCheckpointRow>) -> bool {
    let violates = |row: &AuthorityCheckpointRow| {
        row.parents.iter().any(|parent| {
            rows.get(parent)
                .and_then(|parent| parent.world)
                .is_some_and(|parent_world| row.world != Some(parent_world))
        })
    };
    let descends = |lower: &AuthorityEntryHash, upper: &AuthorityEntryHash| {
        let world = rows[upper].world;
        let mut seen = BTreeSet::new();
        let mut stack = rows[upper].parents.clone();
        while let Some(at) = stack.pop() {
            if at == *lower {
                return true;
            }
            if !seen.insert(at) {
                continue;
            }
            if let Some(row) = rows.get(&at)
                && row.world == world
                && !violates(row)
            {
                stack.extend(row.parents.iter().copied());
            }
        }
        false
    };
    let mut scopes = BTreeMap::<_, Vec<(u64, AuthorityEntryHash)>>::new();
    for (hash, row) in rows {
        if !violates(row) {
            scopes
                .entry((&row.signer, row.world))
                .or_default()
                .push((row.seq, *hash));
        }
    }
    scopes.into_values().all(|mut chain| {
        chain.sort_unstable();
        chain
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0 && descends(&pair[0].1, &pair[1].1))
    })
}

/// One row of a named log: its signer, sequence, parents by index (`None`
/// for a row the image does not hold) and world.
type NamedRow = (usize, u64, &'static [Option<usize>], Option<usize>);

fn named_rows(log: &[NamedRow]) -> BTreeMap<AuthorityEntryHash, AuthorityCheckpointRow> {
    log.iter()
        .enumerate()
        .map(|(index, (signer_number, seq, parents, world_number))| {
            let parents = parents
                .iter()
                .map(|parent| parent.map_or(ABSENT, |parent| numbered(b'n', parent)))
                .collect();
            (
                numbered(b'n', index),
                summary(
                    signer(*signer_number),
                    *seq,
                    parents,
                    world_number.map(world),
                ),
            )
        })
        .collect()
}

/// The named logs and the answer each must get.
const NAMED_LOGS: &[(&str, &[NamedRow], bool)] = &[
    (
        "one signer's rows chained across a join",
        &[
            (9, 1, &[], None),
            (1, 1, &[Some(0)], None),
            (2, 1, &[Some(0)], None),
            (3, 1, &[Some(1), Some(2)], None),
            (1, 2, &[Some(3)], None),
        ],
        true,
    ),
    (
        "one signer's rows on sibling branches",
        &[
            (9, 1, &[], None),
            (1, 1, &[Some(0)], None),
            (1, 2, &[Some(0)], None),
        ],
        false,
    ),
    (
        "two rows of one signer at one sequence",
        &[(1, 1, &[], None), (1, 1, &[Some(0)], None)],
        false,
    ),
    (
        "a later row at a lower sequence",
        &[(1, 2, &[], None), (1, 1, &[Some(0)], None)],
        false,
    ),
    (
        "a side scope's rows chained through another signer's side row",
        &[
            (1, 1, &[], Some(1)),
            (2, 1, &[Some(0)], Some(1)),
            (1, 2, &[Some(1)], Some(1)),
        ],
        true,
    ),
    (
        "a side scope's rows linked only through a main row",
        &[
            (1, 1, &[], Some(1)),
            (2, 1, &[Some(0)], None),
            (1, 2, &[Some(1)], Some(1)),
        ],
        false,
    ),
    (
        "a main row naming another world's side row is no row of its scope",
        &[
            (2, 1, &[], Some(2)),
            (1, 1, &[], None),
            (1, 2, &[Some(1), Some(0)], None),
        ],
        true,
    ),
    (
        "no walk passes a main row naming another world's side row",
        &[
            (2, 1, &[], Some(2)),
            (1, 1, &[], None),
            (3, 1, &[Some(1), Some(0)], None),
            (1, 2, &[Some(2)], None),
        ],
        false,
    ),
    (
        "each world's rows chained apart",
        &[
            (1, 1, &[], Some(1)),
            (1, 2, &[Some(0)], Some(1)),
            (1, 1, &[], Some(2)),
            (1, 2, &[Some(2)], Some(2)),
            (1, 1, &[], None),
        ],
        true,
    ),
    (
        "a link through a row the image does not hold",
        &[(1, 1, &[], None), (1, 2, &[None], None)],
        false,
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

/// A random log of 2 to 10 rows over 3 signers and 3 scopes. Each row
/// names its predecessor in draw order with probability 3/4, and up to 2
/// more rows drawn before it, now and then one the image does not hold. Its
/// sequence is its draw index plus one with probability 3/4, else drawn
/// from 1 to 4; its scope is the main log with probability 2/3.
fn random_rows(draws: &mut Xorshift64) -> BTreeMap<AuthorityEntryHash, AuthorityCheckpointRow> {
    let count = 2 + draws.below(9) as usize;
    let mut hashes: Vec<AuthorityEntryHash> = Vec::with_capacity(count);
    let mut rows = BTreeMap::new();
    for index in 0..count {
        let mut hash = [0u8; 32];
        for chunk in hash.chunks_mut(8) {
            chunk.copy_from_slice(&draws.next().to_be_bytes());
        }
        let mut parents = BTreeSet::new();
        if let Some(previous) = hashes.last()
            && draws.below(4) != 0
        {
            parents.insert(*previous);
        }
        for _ in 0..draws.below(3) {
            if hashes.is_empty() || draws.below(8) == 0 {
                parents.insert(ABSENT);
            } else {
                parents.insert(hashes[draws.below(hashes.len() as u64) as usize]);
            }
        }
        let seq = if draws.below(4) != 0 {
            index as u64 + 1
        } else {
            1 + draws.below(4)
        };
        let scope = match draws.below(6) {
            0 => Some(world(1)),
            1 => Some(world(2)),
            _ => None,
        };
        let row = summary(
            signer(draws.below(3) as usize),
            seq,
            parents.into_iter().collect(),
            scope,
        );
        rows.insert(hash, row);
        hashes.push(hash);
    }
    rows
}

#[test]
fn the_check_answers_as_the_pair_walks_did() {
    let (mut image, _vault, _dir) = rooted_image();
    for (name, log, expected) in NAMED_LOGS {
        image.rows = named_rows(log);
        assert_eq!(
            walk_rule(&image.rows),
            *expected,
            "the walk rule on: {name}"
        );
        assert_eq!(
            covered_rows_unfloored(&image),
            *expected,
            "the gate's check on: {name}"
        );
    }
    let mut draws = Xorshift64(0x9e37_79b9_7f4a_7c15);
    let mut answers = BTreeMap::<bool, usize>::new();
    for case in 0..RANDOM_LOGS {
        image.rows = random_rows(&mut draws);
        let expected = walk_rule(&image.rows);
        assert_eq!(
            covered_rows_unfloored(&image),
            expected,
            "random log {case} answered apart from the walk rule: {:?}",
            image.rows
        );
        *answers.entry(expected).or_default() += 1;
    }
    println!("GATE-ANSWERS random logs {RANDOM_LOGS}: {answers:?}");
    for answer in [true, false] {
        assert!(
            answers.get(&answer).copied().unwrap_or(0) >= RANDOM_LOGS / 10,
            "the random logs answer {answer} at least a tenth of the time: {answers:?}"
        );
    }
}
