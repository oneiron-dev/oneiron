//! Measures what the authority fold holds and how long it takes on long logs
//! that one live roster key signs ([ROSTER-KEY-LOG-FLOOD] PLAN v2, step one;
//! root FIX-LIST 25305). A counting global allocator weighs each phase: the
//! rows by hash, the ancestor index, every row's state, the deepest row's
//! state, the merge, the whole vault fold, and the causal floors pass under
//! three arrival orders. Each run prints one `FOLD-MEASURE` line and one
//! `FOLD-FLOORS` line per arrival order; nothing here asserts a number.
//!
//! Op families (each row adds one entry to a per-row state map): `confirm`
//! (federation confirms), `critical` (critical write confirms), `enroll`
//! (roster), `residence` (residence directives), `agents` (enrol, then bind;
//! chain only). Shapes: `chain` (each row on the one before), `star` (each
//! row on genesis), `grid` (rows in a square of side ceil(sqrt n), each on
//! its left and lower neighbours).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron
//! --all-features --test fold_memory_measure -- --nocapture`. Times are of
//! the test profile (the oneiron crate at opt-level 0). `ONEIRON_FOLD_MEASURE`
//! narrows the runs: `family:shape:rows[,rows...]` items separated by `;`.

// The test door is compiled only under `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::EntityId;
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityConfirmAction,
    AuthorityConfirmKind, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry, AuthorityOp,
    AuthoritySignature, AuthorityTier, AuthorityVaultId, CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION,
    CriticalWriteConfirmAction, CriticalWriteConfirmDisposition, CriticalWriteConfirmMethod,
    DeviceAuthority, GenesisRecoveryStep, ROLE_ADMIN, ROLE_AGENT, ROLE_OWNER, ResidenceAct,
    ResidenceDirective, authority_entry_hash, authority_transcript, genesis_vault_id,
};
use oneiron::test_doors::authority_fold_memory as door;

/// The bytes the process holds now, and the most it held since the last
/// reset.
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

impl CountingAllocator {
    fn grew(by: usize) {
        let live = LIVE.fetch_add(by, Ordering::Relaxed) + by;
        PEAK.fetch_max(live, Ordering::Relaxed);
    }

    fn shrank(by: usize) {
        LIVE.fetch_sub(by, Ordering::Relaxed);
    }
}

// SAFETY: every call goes to the system allocator with the caller's own
// arguments; the counters only add and subtract the sizes it was handed.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc` is the system's.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            Self::grew(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc_zeroed` is the system's.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            Self::grew(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from this allocator, so from the system's.
        unsafe { System.dealloc(ptr, layout) };
        Self::shrank(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: `ptr` came from this allocator, so from the system's.
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        if !moved.is_null() {
            if new_size >= layout.size() {
                Self::grew(new_size - layout.size());
            } else {
                Self::shrank(layout.size() - new_size);
            }
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// What one phase held when it returned, the most it held while it ran, both
/// over the bytes held before it, and its time.
struct Weight {
    held: usize,
    peak: usize,
    secs: f64,
}

fn weigh<T>(phase: impl FnOnce() -> T) -> (T, Weight) {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let started = Instant::now();
    let value = phase();
    let secs = started.elapsed().as_secs_f64();
    let weight = Weight {
        held: LIVE.load(Ordering::Relaxed).saturating_sub(before),
        peak: PEAK.load(Ordering::Relaxed).saturating_sub(before),
        secs,
    };
    (value, weight)
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

/// The `n`th key of the family `tag`.
fn numbered_key(tag: u8, n: usize) -> SigningKey {
    let mut seed = [tag; 32];
    seed[..8].copy_from_slice(&(n as u64).to_be_bytes());
    SigningKey::from_bytes(&seed)
}

/// `n` in the last eight bytes of `WIDTH` bytes of `tag`.
fn numbered<const WIDTH: usize>(tag: u8, n: usize) -> [u8; WIDTH] {
    let mut bytes = [tag; WIDTH];
    bytes[WIDTH - 8..].copy_from_slice(&(n as u64).to_be_bytes());
    bytes
}

fn numbered_id(tag: u8, n: usize) -> EntityId {
    EntityId::from_bytes(numbered(tag, n)).expect("entity id")
}

fn device(key: AuthorityKey, roles: u16) -> DeviceAuthority {
    DeviceAuthority {
        key,
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: AuthorityTier::Software,
        roles,
    }
}

/// `signer`'s row `op` at `seq` on `parents`, cosigned by `cosigner`.
fn signed(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &SigningKey,
    cosigner: Option<&SigningKey>,
) -> AuthorityLogEntry {
    let key = key_of(signer);
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes: parents,
        op,
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: seq + 1,
    };
    if let Some(cosigner) = cosigner {
        let key = key_of(cosigner);
        entry.cosigns.push(AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        });
    }
    let transcript = authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    if let Some(cosigner) = cosigner {
        entry.cosigns[0].signature = cosigner.sign(&transcript).to_bytes().to_vec();
    }
    entry
}

/// Row `n`'s op of `family`, and the key that cosigns it.
fn family_op(family: &str, n: usize) -> (AuthorityOp, Option<SigningKey>) {
    match family {
        "confirm" => (
            AuthorityOp::FederationConfirm(AuthorityConfirmAction {
                kind: AuthorityConfirmKind::Accept,
                confirm_id: numbered(0xC0, n),
                peer_vault_id: [77; 32],
                epoch: 1,
                nonce: numbered(0xC1, n),
            }),
            None,
        ),
        "critical" => (
            AuthorityOp::CriticalWriteConfirm(CriticalWriteConfirmAction {
                schema_version: CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION,
                confirm_id: numbered(0xC2, n),
                gate_decision_id: numbered(0xC3, n),
                claim_id: numbered_id(0x72, n),
                effect_digest: [0xE1; 32],
                read_frontier_hash: [0xF1; 32],
                nonce: numbered(0xC4, n),
                expires_at: 4_000_000_000,
                disposition: CriticalWriteConfirmDisposition::Clear,
                method: CriticalWriteConfirmMethod::TokenReauth,
            }),
            None,
        ),
        "enroll" => (
            AuthorityOp::EnrollDevice {
                device: device(key_of(&numbered_key(0xA7, n)), ROLE_AGENT),
            },
            None,
        ),
        "residence" => (
            AuthorityOp::ResidenceDirective(ResidenceDirective {
                id: numbered_id(0x73, n),
                machine: numbered_id(0x74, 1),
                owner: numbered_id(0x75, 1),
                issued_at: 1,
                act: ResidenceAct::SyncAll,
            }),
            None,
        ),
        "agents" if n % 2 == 0 => (
            AuthorityOp::EnrollDevice {
                device: device(key_of(&numbered_key(0xA6, n / 2)), ROLE_AGENT),
            },
            None,
        ),
        "agents" => {
            let agent = numbered_key(0xA6, n / 2);
            (
                AuthorityOp::BindActor {
                    authority_key: key_of(&agent),
                    actor_ref: numbered_id(0x71, n),
                    actor_class: "system".to_owned(),
                    epoch: 1,
                },
                Some(agent),
            )
        }
        other => panic!("unknown family {other}"),
    }
}

/// Genesis, then `rows` rows of `family` that the owner signs, in `shape`.
fn measured_log(family: &str, shape: &str, rows: usize) -> Vec<AuthorityLogEntry> {
    let owner = numbered_key(0x91, 0);
    let genesis = signed(
        None,
        0,
        Vec::new(),
        AuthorityOp::Genesis {
            device: device(key_of(&owner), ROLE_OWNER | ROLE_ADMIN),
            genesis_nonce: [0x91; 32],
            recovery: GenesisRecoveryStep::Saved([1; 32]),
        },
        &owner,
        None,
    );
    let vault_id = genesis_vault_id(&genesis).expect("vault id");
    let root = authority_entry_hash(&genesis).expect("genesis hash");
    let side = (1..).find(|side| side * side >= rows).unwrap_or(1);
    let mut hashes: Vec<AuthorityEntryHash> = Vec::with_capacity(rows);
    let mut entries = vec![genesis];
    for n in 0..rows {
        let parents = match shape {
            "chain" => vec![hashes.last().copied().unwrap_or(root)],
            "star" => vec![root],
            "grid" => {
                let mut parents = Vec::new();
                if n % side > 0 {
                    parents.push(hashes[n - 1]);
                }
                if n >= side {
                    parents.push(hashes[n - side]);
                }
                if parents.is_empty() {
                    parents.push(root);
                }
                parents
            }
            other => panic!("unknown shape {other}"),
        };
        let (op, cosigner) = family_op(family, n);
        let entry = signed(
            Some(vault_id),
            n as u64 + 1,
            parents,
            op,
            &owner,
            cosigner.as_ref(),
        );
        hashes.push(authority_entry_hash(&entry).expect("row hash"));
        entries.push(entry);
    }
    entries
}

/// This install's sequence floors when `entries` arrive in `order` (each row
/// keeps the highest sequence its signer had reached before it arrived), and
/// how many rows sit below their floor.
fn arrival_floors(
    entries: &[AuthorityLogEntry],
    order: &[usize],
) -> (BTreeMap<AuthorityEntryHash, u64>, usize) {
    let mut reached = BTreeMap::<AuthorityKey, u64>::new();
    let mut floors = BTreeMap::new();
    let mut floored = 0;
    for &at in order {
        let entry = &entries[at];
        let signer = entry.signer.public_key.clone();
        if let Some(high) = reached.get(&signer) {
            floors.insert(authority_entry_hash(entry).expect("row hash"), *high);
            floored += usize::from(entry.seq < *high);
        }
        let high = reached.entry(signer).or_insert(entry.seq);
        *high = (*high).max(entry.seq);
    }
    (floors, floored)
}

/// The arrival orders the floors pass runs under: the log's own order; the
/// last row first, then the rest in order; and each pair of rows swapped.
fn arrival_orders(rows: usize) -> Vec<(&'static str, Vec<usize>)> {
    let in_order: Vec<usize> = (0..rows).collect();
    let mut last_first = vec![0];
    if rows > 1 {
        last_first.push(rows - 1);
        last_first.extend(1..rows - 1);
    }
    let mut swapped = vec![0];
    let mut at = 1;
    while at < rows {
        if at + 1 < rows {
            swapped.extend([at + 1, at]);
        } else {
            swapped.push(at);
        }
        at += 2;
    }
    vec![
        ("in_order", in_order),
        ("last_first", last_first),
        ("swapped_pairs", swapped),
    ]
}

/// The floors pass runs on logs of at most this many rows, and on no larger
/// log of a (family, shape) once one of its orders took longer than
/// `FLOORS_BUDGET_SECS`.
const FLOORS_MAX_ROWS: usize = 1000;
const FLOORS_BUDGET_SECS: f64 = 120.0;
/// A (family, shape) whose run took longer than this runs no larger log.
const RUN_BUDGET_SECS: f64 = 900.0;

fn plan() -> Vec<(String, String, Vec<usize>)> {
    if let Ok(spec) = std::env::var("ONEIRON_FOLD_MEASURE") {
        return spec
            .split(';')
            .filter(|item| !item.trim().is_empty())
            .map(|item| {
                let mut parts = item.trim().split(':');
                let family = parts.next().expect("family").to_owned();
                let shape = parts.next().expect("shape").to_owned();
                let sizes = parts
                    .next()
                    .expect("rows")
                    .split(',')
                    .map(|rows| rows.parse().expect("row count"))
                    .collect();
                (family, shape, sizes)
            })
            .collect();
    }
    let sizes = vec![250, 500, 1000, 2000];
    let mut plan = Vec::new();
    for family in ["confirm", "critical", "enroll", "residence"] {
        for shape in ["chain", "star", "grid"] {
            plan.push((family.to_owned(), shape.to_owned(), sizes.clone()));
        }
    }
    plan.push(("agents".to_owned(), "chain".to_owned(), sizes));
    plan
}

fn ratio(bytes: usize, per: u64) -> u64 {
    (bytes as u64).checked_div(per).unwrap_or(0)
}

/// One run: every phase's weight on `family`'s log of `rows` rows in `shape`,
/// and with `with_floors` the floors pass under each arrival order. Answers
/// the run's time and the floors pass's longest.
fn measure(family: &str, shape: &str, rows: usize, with_floors: bool) -> (f64, f64) {
    let started = Instant::now();
    let entries = measured_log(family, shape, rows);
    let (by_hash, rows_weight) = weigh(|| door::rows(&entries));
    let (index, index_weight) = weigh(|| door::index(&by_hash));
    let (states, states_weight) = weigh(|| door::states(&by_hash, &index));
    let (deepest, deepest_weight) = weigh(|| states.deepest(&index));
    let deepest_entries = deepest.grown_entries();
    drop(deepest);
    let (merged, merge_weight) = weigh(|| states.merged());
    let merged_entries = merged.grown_entries();
    drop(merged);
    let folded_rows = states.len();
    let grown = states.grown_entries();
    drop(states);
    let (folded, fold_weight) = weigh(|| door::fold(&entries));
    let pairs = index.pairs();
    let projected = door::projected_bytes(entries.len(), pairs);
    println!(
        "FOLD-MEASURE family={family} shape={shape} rows={} pairs={pairs} counted_pairs={} \
         fold_counted_pairs={} folded_rows={folded_rows} valid={} grown_entries={grown} \
         deepest_grown={deepest_entries} merged_grown={merged_entries} \
         rows_held={} index_held={} index_peak={} index_secs={:.3} \
         states_held={} states_peak={} states_secs={:.3} deepest_state_bytes={} \
         merge_peak={} merge_secs={:.3} fold_peak={} fold_secs={:.3} projected={projected} \
         index_bytes_per_pair={} states_bytes_per_grown_entry={} states_bytes_per_row={} \
         fold_peak_bytes_per_pair={}",
        entries.len(),
        index.counted_pairs(),
        folded.counted_pairs,
        folded.valid,
        rows_weight.held,
        index_weight.held,
        index_weight.peak,
        index_weight.secs,
        states_weight.held,
        states_weight.peak,
        states_weight.secs,
        deepest_weight.held,
        merge_weight.peak,
        merge_weight.secs,
        fold_weight.peak,
        fold_weight.secs,
        ratio(index_weight.held, pairs),
        ratio(states_weight.held, grown as u64),
        ratio(states_weight.held, folded_rows as u64),
        ratio(fold_weight.peak, pairs),
    );
    let mut floors_secs: f64 = 0.0;
    if with_floors {
        for (order_name, order) in arrival_orders(entries.len()) {
            let (floors, floored) = arrival_floors(&entries, &order);
            let (left, weight) = weigh(|| door::causal_floors(&by_hash, &index, &floors));
            println!(
                "FOLD-FLOORS family={family} shape={shape} rows={} order={order_name} \
                 floored_before={floored} floored_after={left} peak={} secs={:.3}",
                entries.len(),
                weight.peak,
                weight.secs,
            );
            floors_secs = floors_secs.max(weight.secs);
        }
    }
    (started.elapsed().as_secs_f64(), floors_secs)
}

/// Every run of the plan, smallest log first. One test, so no other test's
/// allocations land in a weight.
#[test]
fn fold_memory_by_phase() {
    for (family, shape, sizes) in plan() {
        let mut with_floors = true;
        for rows in sizes {
            let (secs, floors_secs) = measure(
                &family,
                &shape,
                rows,
                with_floors && rows <= FLOORS_MAX_ROWS,
            );
            println!("FOLD-RUN family={family} shape={shape} rows={rows} secs={secs:.3}");
            if secs > RUN_BUDGET_SECS {
                println!("FOLD-RUN-STOP family={family} shape={shape} after rows={rows}");
                break;
            }
            if floors_secs > FLOORS_BUDGET_SECS {
                println!("FOLD-FLOORS-STOP family={family} shape={shape} after rows={rows}");
                with_floors = false;
            }
        }
    }
}
