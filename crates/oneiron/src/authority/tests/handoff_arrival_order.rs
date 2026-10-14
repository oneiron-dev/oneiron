//! Handoff settlement does not depend on the order rows arrive in (Astra
//! review 1 of #1410, Engine ruling 2026-10-14). The old root A hands the
//! vault to B at sequence 1; a forger holding A's key signs a sibling handoff
//! to D at a higher sequence. Whichever of the two this vault saw first, a
//! history that holds both installs neither successor. A door that settled
//! one first refuses the other and records the refusal.
use super::history_transfer::{re_root_entry, replica_with, store};
use super::support::*;
use super::world_floor::assert_no_vouch_widens;
use super::*;
use crate::authority::handoff_equivocation::RECORD_LIMIT;
use crate::{TimeRange, Vault, VaultConfig};
use std::sync::{Arc, Mutex, Weak, mpsc};

fn hash(entry: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(entry).unwrap()
}

fn body(entry: &AuthorityLogEntry) -> Vec<u8> {
    encode_authority_log_entry_body(entry).unwrap()
}

fn is_live(fold: &AuthorityFold, key: &SigningKey) -> bool {
    fold.roster
        .get(&authority_key_from_ed(key))
        .is_some_and(|device| !device.revoked)
}

fn withdrawal(
    id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    seq: u64,
    slip: u8,
) -> AuthorityLogEntry {
    sign_ed(
        unsigned_entry(
            Some(id),
            seq,
            vec![hash(parent)],
            AuthorityOp::SlipRevoke {
                slip_id: [slip; 32],
            },
            authority_key_from_ed(signer),
            2,
        ),
        signer,
    )
}

fn put(vault: &Vault, entries: &[&AuthorityLogEntry]) -> crate::error::Result<Vec<EntityId>> {
    let rows: Vec<_> = entries
        .iter()
        .map(|entry| ((*entry).clone(), TimeRange { start: 2, end: 2 }, 2))
        .collect();
    vault.put_authority_log_entries(&rows)
}

struct Fork {
    old: SigningKey,
    next: SigningKey,
    forger_heir: SigningKey,
    genesis: AuthorityLogEntry,
    handoff: AuthorityLogEntry,
    forged: AuthorityLogEntry,
}

/// G by A; H = ReRoot(A→B) at sequence 1 and F = ReRoot(A→D) at sequence 2,
/// both on G.
fn fork(seed: u8) -> Fork {
    let old = ed_key(seed);
    let next = ed_key(seed + 1);
    let forger_heir = ed_key(seed + 2);
    let genesis = genesis_entry(seed, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let handoff = re_root_entry(id, &genesis, &old, 1, &next);
    let forged = re_root_entry(id, &genesis, &old, 2, &forger_heir);
    Fork {
        old,
        next,
        forger_heir,
        genesis,
        handoff,
        forged,
    }
}

/// A history that holds both handoffs has no live root, and the forger's
/// heir signs nothing a door admits.
fn assert_no_live_root(vault: &Vault, fork: &Fork) {
    let fold = vault.authority_fold().unwrap();
    assert!(!fold.valid_entries.contains(&hash(&fork.handoff)));
    assert!(!fold.valid_entries.contains(&hash(&fork.forged)));
    assert!(fold.roster.values().all(|device| device.revoked));
    assert!(!is_live(&fold, &fork.next));
    assert!(!is_live(&fold, &fork.forger_heir));
    let id = genesis_vault_id(&fork.genesis).unwrap();
    let heir_row = withdrawal(id, &fork.forged, &fork.forger_heir, 1, 1);
    assert!(put(vault, &[&heir_row]).is_err());
    assert_no_vouch_widens(vault);
}

/// Check 1: one atomic import of the complete history, in either blob order.
/// Before the fix, [G, F, H] installed D: H failed on the sequence floor F's
/// earlier arrival set, so it never fenced.
#[test]
fn an_import_of_both_handoffs_installs_no_successor_in_either_order() {
    let fork = fork(230);
    for (first, second) in [(&fork.forged, &fork.handoff), (&fork.handoff, &fork.forged)] {
        let (_dir, replica) = replica_with(vec![body(&fork.genesis), body(first)], second);
        assert_no_live_root(&replica, &fork);
    }
}

/// Check 2: the same rows through one append batch, in either order.
#[test]
fn one_append_batch_of_both_handoffs_installs_no_successor_in_either_order() {
    let fork = fork(233);
    for (first, second) in [(&fork.forged, &fork.handoff), (&fork.handoff, &fork.forged)] {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
        put(&vault, &[&fork.genesis, first, second]).unwrap();
        assert_no_live_root(&vault, &fork);
    }
}

/// Check 3: sequential arrival. F arrives while its parent P (A, sequence 2)
/// is still in flight, so F cannot settle and no door refuses H. F's arrival
/// leaves A's sequence floor at 3 for every later row of A.
/// (a) H arrives alone: H settles, the door then refuses P, records it, and
///     B is the root.
/// (b) H and P arrive together: the history holds both handoffs, so neither
///     successor installs.
///
/// Before the fix, H failed on F's floor in both, and F installed D.
#[test]
fn a_handoff_that_arrives_after_its_siblings_floor_still_settles() {
    let base = fork(236);
    let id = genesis_vault_id(&base.genesis).unwrap();
    let in_flight = withdrawal(id, &base.genesis, &base.old, 2, 7);
    let forged = re_root_entry(id, &in_flight, &base.old, 3, &base.forger_heir);
    let fork = Fork { forged, ..base };

    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    store(&vault, &fork.genesis);
    put(&vault, &[&fork.forged]).unwrap();
    put(&vault, &[&fork.handoff]).unwrap();
    assert!(put(&vault, &[&in_flight]).is_err());
    let fold = vault.authority_fold().unwrap();
    assert!(fold.valid_entries.contains(&hash(&fork.handoff)));
    assert!(is_live(&fold, &fork.next));
    assert!(!is_live(&fold, &fork.old));
    assert_no_vouch_widens(&vault);
    assert!(
        !fold
            .roster
            .contains_key(&authority_key_from_ed(&fork.forger_heir))
    );
    assert_eq!(
        vault.authority_handoff_equivocations(),
        vec![AuthorityHandoffEquivocation {
            signer: authority_key_from_ed(&fork.old),
            handoffs: BTreeSet::from([hash(&fork.handoff)]),
            refused: hash(&in_flight),
        }]
    );

    for together in [[&fork.handoff, &in_flight], [&in_flight, &fork.handoff]] {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
        store(&vault, &fork.genesis);
        put(&vault, &[&fork.forged]).unwrap();
        put(&vault, &together).unwrap();
        assert_no_live_root(&vault, &fork);
    }
}

/// Control 5: local sequence floors still refuse every row outside a
/// handoff's line. After H settles, a row the successor B signs below B's
/// own observed floor is refused, though H's line stands unfloored.
#[test]
fn a_row_below_its_floor_outside_any_handoffs_line_stays_refused() {
    let fork = fork(239);
    let id = genesis_vault_id(&fork.genesis).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    store(&vault, &fork.genesis);
    vault.apply_signed_re_root(&fork.handoff).unwrap();
    let high = withdrawal(id, &fork.handoff, &fork.next, 5, 8);
    let rollback = withdrawal(id, &fork.handoff, &fork.next, 2, 9);
    put(&vault, &[&high]).unwrap();
    put(&vault, &[&rollback]).unwrap();
    let fold = vault.authority_fold().unwrap();
    assert!(fold.valid_entries.contains(&hash(&high)));
    assert!(!fold.valid_entries.contains(&hash(&rollback)));
    assert!(
        fold.issues
            .contains(&AuthorityFoldIssue::NonMonotonicSeq(hash(&rollback)))
    );
    assert!(is_live(&fold, &fork.next));
    assert_no_vouch_widens(&vault);
}

/// Sol review 6: a door records every retired key whose row it refuses, and
/// only a row whose signatures verify. A roster key the handoff fenced without
/// signing it is recorded with no handoff of its own. A row that names the
/// old root as its signer under a signature that does not verify records
/// nothing, so no one without the key can plant a record.
#[test]
fn a_door_records_each_retired_signer_and_only_rows_that_verify() {
    let old = ed_key(240);
    let (first, second, next) = (ed_key(241), ed_key(242), ed_key(243));
    let genesis = genesis_entry(240, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let id = genesis_vault_id(&genesis).unwrap();
    let enroll_first = enroll_entry(id, &genesis, &old, 241, 1, 2);
    let enroll_second = cosign_ed(
        enroll_entry(id, &enroll_first, &old, 242, 2, 2),
        &old,
        &first,
    );
    let handoff = cosign_ed(
        re_root_entry(id, &enroll_second, &old, 3, &next),
        &old,
        &first,
    );
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    put(&vault, &[&genesis, &enroll_first, &enroll_second, &handoff]).unwrap();
    assert!(is_live(&vault.authority_fold().unwrap(), &next));

    let fenced_peer_row = withdrawal(id, &enroll_second, &second, 1, 3);
    assert!(put(&vault, &[&fenced_peer_row]).is_err());
    let mut forged = withdrawal(id, &enroll_second, &old, 4, 4);
    forged.seq = 5;
    assert!(put(&vault, &[&forged]).is_err());
    assert_eq!(
        vault.authority_handoff_equivocations(),
        vec![AuthorityHandoffEquivocation {
            signer: authority_key_from_ed(&second),
            handoffs: BTreeSet::new(),
            refused: hash(&fenced_peer_row),
        }]
    );
}

/// Astra review 2: a peer that replays one refused row floods no log. The
/// same forged handoff twice through a door is refused both times and
/// recorded once, and its evidence logs no second warning. Control: new
/// evidence, a distinct refused handoff, still records and logs.
#[test]
fn a_replayed_refused_row_is_recorded_and_logged_once() {
    let fork = fork(244);
    let id = genesis_vault_id(&fork.genesis).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    store(&vault, &fork.genesis);
    vault.apply_signed_re_root(&fork.handoff).unwrap();
    assert!(put(&vault, &[&fork.forged]).is_err());
    assert!(put(&vault, &[&fork.forged]).is_err());
    let records = vault.authority_handoff_equivocations();
    assert_eq!(records.len(), 1);
    let log = &vault.store.authority_handoff_equivocations;
    assert!(!log.record(records[0].clone()));

    let second = re_root_entry(id, &fork.genesis, &fork.old, 3, &ed_key(247));
    assert!(put(&vault, &[&second]).is_err());
    assert_eq!(vault.authority_handoff_equivocations().len(), 2);
    assert!(log.record(AuthorityHandoffEquivocation {
        refused: [9; 32],
        ..records[0].clone()
    }));
}

/// Astra review 2: past its bound the record logs only at the first dropped
/// record and at each power of two, and reports how many it dropped.
#[test]
fn past_its_bound_the_record_logs_at_powers_of_two_and_counts_drops() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let extra = 100;
    let logged = (0..RECORD_LIMIT + extra)
        .filter(|n| {
            let mut refused = [0; 32];
            refused[..8].copy_from_slice(&n.to_be_bytes());
            vault
                .store
                .authority_handoff_equivocations
                .record(AuthorityHandoffEquivocation {
                    signer: authority_key_from_ed(&ed_key(250)),
                    handoffs: BTreeSet::new(),
                    refused,
                })
        })
        .count();
    // Drops 1, 2, 4, ..., 64 log: floor(log2 100) + 1 = 7 warnings.
    assert_eq!(logged, RECORD_LIMIT + 7);
    assert_eq!(vault.authority_handoff_equivocations().len(), RECORD_LIMIT);
    assert_eq!(vault.authority_handoff_equivocations_dropped(), 100);
}

/// A host's log consumer that reads the record when the record logs. It
/// reads on another thread under a timeout, so a read the door blocks shows
/// as `None` instead of hanging the test.
#[derive(Clone)]
struct RecordReader {
    vault: Weak<Vault>,
    /// What the read at each warning saw.
    seen: Arc<Mutex<Vec<Option<Counts>>>>,
}

/// Records held and dropped.
type Counts = (usize, u64);

impl RecordReader {
    /// What this reader read at the first warning `warn` raises, with `warn`
    /// run afresh, given its try number, until a warning reaches it.
    fn first_read(&self, mut warn: impl FnMut(u64)) -> Option<Counts> {
        for attempt in 0..3 {
            // Two registered dispatches make a callsite registration consult
            // both (embed/warn_capture.rs), and registering them rebuilds the
            // interest cache. A concurrent test that was registering the
            // record's callsite with no subscriber can still store `never`
            // after that rebuild, but registration happens once, so the next
            // try's rebuild settles it.
            let _other = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
            let dispatch = tracing::Dispatch::new(self.clone());
            tracing::dispatcher::with_default(&dispatch, || warn(attempt));
            if let Some(read) = self.seen.lock().unwrap().pop() {
                return read;
            }
        }
        None
    }
}

impl tracing::Subscriber for RecordReader {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata
            .target()
            .ends_with("authority::handoff_equivocation")
    }

    fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, _event: &tracing::Event<'_>) {
        let vault = self.vault.upgrade().unwrap();
        let (send, read) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = send.send((
                vault.authority_handoff_equivocations().len(),
                vault.authority_handoff_equivocations_dropped(),
            ));
        });
        let seen = read.recv_timeout(Duration::from_secs(10)).ok();
        self.seen.lock().unwrap().push(seen);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// Sol review 8: a host that reads the record from its log consumer when the
/// record warns neither stalls the door nor misses the evidence it was warned
/// of: the record is kept before the warning, and the read does not wait on
/// the door. Both warnings: a door's refusal, and a record dropped past the
/// bound. What the consumer read is what the record holds right after.
#[test]
fn a_log_consumer_reads_the_evidence_it_was_warned_of() {
    let fork = fork(252);
    let id = genesis_vault_id(&fork.genesis).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::default()).unwrap());
    store(&vault, &fork.genesis);
    vault.apply_signed_re_root(&fork.handoff).unwrap();
    let reader = RecordReader {
        vault: Arc::downgrade(&vault),
        seen: Arc::default(),
    };
    let now = || {
        (
            vault.authority_handoff_equivocations().len(),
            vault.authority_handoff_equivocations_dropped(),
        )
    };
    // The first try refuses the forged handoff itself; each later try a
    // sibling at the next sequence.
    let read = reader.first_read(|attempt| {
        let sibling = re_root_entry(id, &fork.genesis, &fork.old, 2 + attempt, &fork.forger_heir);
        assert!(put(&vault, &[&sibling]).is_err());
    });
    assert_eq!(read, Some(now()));

    let log = &vault.store.authority_handoff_equivocations;
    let template = vault.authority_handoff_equivocations()[0].clone();
    let mut next = 0_usize;
    let mut distinct = || {
        next += 1;
        let mut refused = [0xA5; 32];
        refused[..8].copy_from_slice(&next.to_be_bytes());
        AuthorityHandoffEquivocation {
            refused,
            ..template.clone()
        }
    };
    while vault.authority_handoff_equivocations().len() < RECORD_LIMIT {
        assert!(log.record(distinct()));
    }
    let read = reader.first_read(|_| while !log.record(distinct()) {});
    assert_eq!(read, Some(now()));
    assert_eq!(read.map(|(held, _)| held), Some(RECORD_LIMIT));
}
