//! Holder-proof nonces an admission spent in memory (FIX 12023 W0; Engine
//! ruling 10-31 with L02's five conditions).
//!
//! An admission that takes no writer ([`Vault::admit_capability_slip_request`])
//! spends its request's nonce here before it replies, in one step under this
//! set's lock that also reads the committed nonce rows, and queues the rows
//! the writer's path commits (the recording and proof clock floors,
//! `not_before` and the nonce row) on the detached door. Every writer that
//! spends a nonce reads this set as well, and stages its own spend here until
//! its transaction is decided, so one nonce is spent once at whichever door
//! it comes to. An entry an admission spent leaves once its rows land, after
//! their group's commit is visible (L02 10-31): a replay then finds the
//! committed row, which [`SpentNonces::admit`] reads under this set's lock,
//! and the writer's path refuses it. An entry whose rows have not landed,
//! failed or queued for another try, stays until its slip's replay window
//! ends: the slip's expiry on the authority clock, plus the window a proof's
//! signed time may stand off the proof clock.
//!
//! Only a slip issued and first seen after this handle opened is spent here,
//! so no earlier process spent its nonces in a set that ended with it. A
//! spend whose rows do not land is queued again from its after-commit
//! callback ([`DetachedWrite::after_commit`]); after
//! [`NONCE_SPEND_ATTEMPTS`] tries it files one healer item, and its nonce
//! stays spent here.
//!
//! Before the reply, each spend is also appended to the environment's
//! `slip-spend.journal` and fdatasynced (FIX 12023 W0, P1-a=B; L02 10-31),
//! under this set's lock and before the entry is spent here, so a crash
//! between the reply and the rows' group commit cannot lose the spend: the
//! next lease-holder open replays the journal's records into the
//! committed rows before it reads its opening second, then truncates the
//! journal. A journal failure spends nothing here and the writer's path
//! judges the request, as it did before. The journal is truncated while
//! running only once no entry here is unlanded, under the same lock; a
//! crash between a replay's commit and its truncate replays the same
//! records again, which the rows absorb. Only a lease holder appends to
//! it, replays it or truncates it (a lease-less spend's guard replays it
//! first, [`spend_guard`]).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard, OnceLock, PoisonError, Weak};
use std::time::Instant;

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use super::{
    NonceKey, PROOF_CLOCK_FLOOR, PROOF_NOT_BEFORE, REPLAY_NONCE, WINDOW_SECS, admission_now_in_txn,
    proof_floor_in_txn, put_nonce_row_in_txn,
};
use crate::authority::{AUTHORITY_FIRST_SEEN, FoldedSlip, authority_first_seen_sidecar_key};
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::self_heal::{
    DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass, DiagnosticReplayCoordinate,
    DiagnosticSourceKind, diagnostic_event_id, encode_diagnostic_event_body,
};
use crate::store::{
    AfterCommit, DetachedWrite, LeaderHolds, active_write_txn_guard, with_idempotency_intent,
};
use crate::{VAULT_WRITER_LEASE_HELD, Vault, VaultWriterLease};

/// The tries of one in-memory spend's rows before it files its healer item
/// and is tried no more (FIX 12023 W0).
const NONCE_SPEND_ATTEMPTS: u32 = 3;
/// The detector token of a nonce spend's healer item.
const NONCE_SPEND_DETECTOR: &str = "authority.nonce_spend.v1";
/// The detached door's name for a spend's rows, said in each warn about them.
const NONCE_SPEND_WRITE: &str = "nonce spend";
/// The detached door's name for a spend's healer item.
const NONCE_SPEND_HEALER_ITEM_WRITE: &str = "nonce spend healer item";
/// The detector token of a journal replay that could not prove every
/// journaled spend landed (FIX 12023 W0 review P1-2).
const NONCE_JOURNAL_DETECTOR: &str = "authority.nonce_journal_recovery.v1";

/// Why a journal replay could not prove every journaled spend landed.
#[derive(Clone, Copy, Debug)]
enum JournalRecoveryFailure {
    /// Complete records that do not read: each may be an answered spend.
    Unreadable(usize),
    /// The readable records' rows did not commit.
    Land,
}

impl JournalRecoveryFailure {
    /// The records the failure leaves unproven, as its healer item counts
    /// them: unknown (one) for a landing that failed.
    fn unproven(self) -> u64 {
        match self {
            Self::Unreadable(n) => n as u64,
            Self::Land => 1,
        }
    }
}
/// The journal a spend is appended to and fdatasynced on before its reply
/// (FIX 12023 W0, P1-a=B), beside the environment in its root.
const SPEND_JOURNAL_FILE: &str = "slip-spend.journal";
/// One journal record: the spent key (its signed time and digest), the
/// authority second its slip's replay window ends, the proof clock's `now`
/// its admission read, the highest proof clock any record appended to this
/// journal before it named (review #4484 P1, 11-04 16:05: a later readable
/// record bounds an earlier one that does not read, whatever the wall did),
/// and a short tag over them. All integers little-endian.
const JOURNAL_RECORD_LEN: usize = 68;
/// Past this many journal bytes a spend here takes the writer's path
/// instead (its rows are not landing fast enough to drain the journal):
/// durable, only slower. Never a reason to truncate.
const JOURNAL_CAP_BYTES: u64 = 1024 * 1024;

/// One spent holder proof, as its nonce row names it: its signed time, and
/// the digest of its binding key and nonce.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(in crate::authority) struct SpentKey {
    timestamp: u64,
    digest: [u8; 32],
}

impl SpentKey {
    /// The proof signed at `timestamp` with `nonce` under `binding_key`.
    pub(in crate::authority) fn of(binding_key: &[u8; 32], nonce: &[u8], timestamp: u64) -> Self {
        let mut material = binding_key.to_vec();
        material.extend_from_slice(nonce);
        Self {
            timestamp,
            digest: *blake3::hash(&material).as_bytes(),
        }
    }

    /// The key of its nonce row.
    pub(super) fn row(&self) -> NonceKey {
        NonceKey {
            timestamp: self.timestamp,
            digest_hex: blake3::Hash::from(self.digest).to_hex().to_string(),
        }
    }
}

/// One environment's in-memory nonce spends (FIX 12023 W0), shared by every
/// handle this process holds on it ([`Self::shared_for`]): a replaced handle
/// spends into the same set as its replacement, so one nonce is spent once.
/// In memory only: a close or a crash drops them, and a slip minted before
/// the next open takes the writer there.
#[derive(Default)]
pub(crate) struct SpentNonces {
    /// The process that minted this set: a forked child holding an inherited
    /// set (its locks, its journal descriptor) never spends through it (P2),
    /// as a child minting its own does not ([`Self::shared_for`]).
    pid: u32,
    /// The authority second this process first opened the environment at;
    /// unset, no admission spends here. A later handle of the same
    /// environment is not a new open and never moves it.
    opened_at: OnceLock<u64>,
    /// The handle this process serves at this vault's root, last found: an
    /// in-memory spend's rows are written on it. Re-found when it dies, so
    /// a replacement handle is spent through (FIX 12023 W0, P2).
    served: Mutex<Option<Weak<Vault>>>,
    nonces: Mutex<Nonces>,
    /// Wakes a swap that waits for the spends admitted here to be queued
    /// ([`Self::close_for_swap`]); waited on with the set's lock.
    queued: Condvar,
}

/// Canonical root -> the environment's spent set, weakly: the entry leaves
/// when the last handle drops, and a later open mints a fresh set.
struct Registry {
    // Published before the LazyLock or the Mutex is touched: either can be
    // inherited locked by a forked child whose other threads no longer exist
    // (oneiron-remote's embedded registry, FIX 12023 W0, P2).
    pid: AtomicU32,
    entries: LazyLock<Mutex<HashMap<PathBuf, Weak<SpentNonces>>>>,
}

static REGISTRY: Registry = Registry {
    pid: AtomicU32::new(0),
    entries: LazyLock::new(|| Mutex::new(HashMap::new())),
};

#[derive(Default)]
struct Nonces {
    /// A restore's swap closed this set, before it waits for the spends
    /// queued here ([`SpentNonces::close_for_swap`]), and its fence keeps it
    /// closed: from then on every admission takes the writer, which the swap
    /// seals.
    fenced: bool,
    /// An owner's clock recovery is under way ([`SpentNonces::begin_clock_recovery`]):
    /// every admission takes the writer, which the recovery's writer
    /// serializes with, so no spend judged on the clock that ran ahead lands
    /// after the recovery set it back (L02 11-04 16:34 condition).
    recovering: bool,
    /// Spent by an admission here and not yet landed, each with the authority
    /// second its slip's replay window ends: it leaves once its rows land, or
    /// past that second when they have not.
    admitted: HashMap<SpentKey, u64>,
    /// `admitted` in the order its entries leave.
    leaving: BTreeSet<(u64, SpentKey)>,
    /// Admitted entries whose replay window ended before their rows landed:
    /// their journal records are still owed a replay, so the journal keeps
    /// them and a restore's fence still counts them, until the rows land.
    /// One that never lands (its tries spent) keeps the journal for the
    /// process's life: past the journal's cap every spend takes the writer's
    /// path until a restart replays and truncates it (L02 11-04 10:39, an
    /// accepted availability cost, never a double admission).
    expired_unlanded: HashSet<SpentKey>,
    /// Spent in a writer whose transaction is not known to be decided, each
    /// with the id that transaction commits as.
    staged: HashMap<SpentKey, usize>,
    /// Spent here by an admission whose rows are not queued on the detached
    /// door yet, which they are just after the lock is let go.
    queuing: usize,
    /// The spend journal, opened on the first spend that appends to it;
    /// dropped after an append failure, and opened again by the next one.
    journal: Option<File>,
    /// The journal's length as this set last measured or wrote it.
    journal_len: u64,
    /// A past-cap spend has warned since the journal last drained under the
    /// cap, so a stalled drain warns once, not per spend.
    cap_warned: bool,
    /// The highest proof clock a record of this journal named, read from its
    /// records when it opens and carried into each record appended after.
    journal_high: u64,
    /// The highest proof clock a spend this process journaled judged on: the
    /// live proof clock reads at or above it until an owner's clock recovery
    /// lets it go (review #4484 Astra round 2-3). Never seeded from the
    /// journal's records, and kept apart from `journal_high`, which bounds
    /// damaged records and never falls while a record remains.
    live_high: u64,
}

impl Nonces {
    /// Lets go of every admitted entry whose slip's replay window ended
    /// before authority second `now`, never one sooner: those whose rows did
    /// not land, as one whose rows landed left then ([`Self::leave`]).
    fn leave_before(&mut self, now: u64) {
        while self.leaving.first().is_some_and(|(until, _)| *until < now) {
            if let Some((_, key)) = self.leaving.pop_first() {
                self.admitted.remove(&key);
                // Its rows have not landed: its journal record stays owed.
                self.expired_unlanded.insert(key);
            }
        }
    }

    /// Lets go of `key`'s admitted entry, whose rows landed.
    fn leave(&mut self, key: &SpentKey) {
        if let Some(until) = self.admitted.remove(key) {
            self.leaving.remove(&(until, *key));
        }
        self.expired_unlanded.remove(key);
    }

    /// Whether every spend journaled here has landed its rows: no admitted
    /// entry, no expired one still unlanded, none queuing.
    fn drained(&self) -> bool {
        self.admitted.is_empty() && self.expired_unlanded.is_empty() && self.queuing == 0
    }

    /// Opens the journal in the environment at `root` on first use: a torn
    /// tail a failed append left is trimmed, since that spend took the
    /// writer's path and is durable there, and a record after it would
    /// misalign every record that follows. The root directory is synced
    /// with it, so the file a first spend created survives the power loss
    /// its fdatasync guards against. `false`: it did not open, said in a
    /// warn.
    fn open_journal_if_needed(&mut self, root: &Path) -> bool {
        if self.journal.is_some() {
            return true;
        }
        match open_journal(&root.join(SPEND_JOURNAL_FILE)) {
            Ok(file) => {
                if let Err(error) = File::open(root).and_then(|dir| dir.sync_all()) {
                    tracing::warn!(
                        error = %error,
                        "the slip-spend journal's directory did not sync; the spend takes the writer's path"
                    );
                    return false;
                }
                self.journal_len = match file.metadata() {
                    Ok(meta) => meta.len(),
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            "the slip-spend journal's length did not read; the spend takes the writer's path"
                        );
                        return false;
                    }
                };
                let torn = self.journal_len % (JOURNAL_RECORD_LEN as u64);
                if torn > 0 {
                    if let Err(error) = file.set_len(self.journal_len - torn) {
                        tracing::warn!(
                            error = %error,
                            "the slip-spend journal's torn tail did not trim; the spend takes the writer's path"
                        );
                        return false;
                    }
                    self.journal_len -= torn;
                }
                if self.journal_len > 0
                    && let Ok(bytes) = std::fs::read(root.join(SPEND_JOURNAL_FILE))
                {
                    for record in bytes
                        .chunks_exact(JOURNAL_RECORD_LEN)
                        .filter_map(parse_journal_record)
                    {
                        self.journal_high =
                            self.journal_high.max(record.proof_now).max(record.high);
                    }
                }
                self.journal = Some(file);
                true
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "the slip-spend journal did not open; the spend takes the writer's path"
                );
                false
            }
        }
    }

    /// Appends one spend's record to the journal at `root` and fdatasyncs it,
    /// the spend's durability before its reply (P1-a=B). `false`, spending
    /// nothing, past [`JOURNAL_CAP_BYTES`] or on any failure of the append:
    /// the writer's path judges the request.
    fn append_journal(
        &mut self,
        root: &Path,
        key: &SpentKey,
        window_end: u64,
        proof_now: u64,
    ) -> bool {
        if !self.open_journal_if_needed(root) {
            return false;
        }
        if self.journal_len.saturating_add(JOURNAL_RECORD_LEN as u64) > JOURNAL_CAP_BYTES {
            if !self.cap_warned {
                self.cap_warned = true;
                tracing::warn!(
                    journal_len = self.journal_len,
                    "the slip-spend journal is past its cap; the spend takes the writer's path"
                );
            }
            return false;
        }
        let high = self.journal_high.max(proof_now);
        let record = journal_record(key, window_end, proof_now, high);
        let started = Instant::now();
        let Some(file) = self.journal.as_mut() else {
            return false;
        };
        let appended = file.write_all(&record).and_then(|()| file.sync_data());
        tracing::Span::current().record(
            "journal_us",
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        match appended {
            Ok(()) => {
                self.journal_len += JOURNAL_RECORD_LEN as u64;
                self.journal_high = high;
                self.live_high = self.live_high.max(proof_now);
                true
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "the slip-spend journal append failed; the spend takes the writer's path"
                );
                // The append may have torn: measure the journal again when
                // it next opens, and trim there.
                self.journal = None;
                self.journal_len = 0;
                false
            }
        }
    }

    /// Truncates the journal once no entry here is unlanded (P1-a=B): every
    /// journaled spend's rows are committed, so no record is owed a replay.
    /// A failed truncate leaves the records for a replay the rows absorb.
    fn truncate_journal_if_drained(&mut self) {
        if !self.drained() || self.journal_len == 0 {
            return;
        }
        if let Some(file) = self.journal.as_mut() {
            match file.set_len(0) {
                Ok(()) => {
                    self.journal_len = 0;
                    self.cap_warned = false;
                }
                Err(error) => tracing::warn!(
                    error = %error,
                    "the drained slip-spend journal did not truncate; its records replay harmlessly"
                ),
            }
        }
    }
}

/// Opens the spend journal for appends, creating it owner-only, without
/// following a link and leaking no descriptor to a child.
fn open_journal(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options.open(path)
}

/// One journal record as it is written ([`JOURNAL_RECORD_LEN`]).
fn journal_record(
    key: &SpentKey,
    window_end: u64,
    proof_now: u64,
    high: u64,
) -> [u8; JOURNAL_RECORD_LEN] {
    let mut record = [0_u8; JOURNAL_RECORD_LEN];
    record[0..8].copy_from_slice(&key.timestamp.to_le_bytes());
    record[8..40].copy_from_slice(&key.digest);
    record[40..48].copy_from_slice(&window_end.to_le_bytes());
    record[48..56].copy_from_slice(&proof_now.to_le_bytes());
    record[56..64].copy_from_slice(&high.to_le_bytes());
    let tag = xxhash_rust::xxh32::xxh32(&record[..64], 0);
    record[64..68].copy_from_slice(&tag.to_le_bytes());
    record
}

/// A journal record read back, its tag checked.
struct JournalRecord {
    key: SpentKey,
    window_end: u64,
    proof_now: u64,
    /// The highest proof clock a record before it named.
    high: u64,
}

fn parse_journal_record(bytes: &[u8]) -> Option<JournalRecord> {
    if bytes.len() != JOURNAL_RECORD_LEN
        || xxhash_rust::xxh32::xxh32(&bytes[..64], 0).to_le_bytes() != bytes[64..68]
    {
        return None;
    }
    let le_u64 = |at: usize| -> Option<u64> {
        bytes
            .get(at..at + 8)?
            .try_into()
            .ok()
            .map(u64::from_le_bytes)
    };
    Some(JournalRecord {
        key: SpentKey {
            timestamp: le_u64(0)?,
            digest: bytes[8..40].try_into().ok()?,
        },
        window_end: le_u64(40)?,
        proof_now: le_u64(48)?,
        high: le_u64(56)?,
    })
}

/// Whether this process holds `vault`'s exclusive writer lease, taken by its
/// owned open ([`Vault::open_owned`]): no other process writes there.
fn holds_writer_lease(vault: &Vault) -> bool {
    vault
        .writer_lease()
        .is_some_and(VaultWriterLease::held_by_current_process)
}

/// The writer lease a writer's nonce spend on `vault` holds while it spends,
/// in a process that holds none (FIX 12023 W0, P1-b): taken without waiting
/// ([`Vault::try_acquire_writer_lease`]), so no process spends a nonce in
/// memory beside it, since only a lease holder does. `None` when this
/// process holds the lease already, and on a target without one, where no
/// process can hold it and no admission spends in memory either: every
/// spend there takes the durable writer. The lease another process holds
/// refuses with [`Error::VaultServedElsewhere`]: that process serves the
/// vault and may have spent this nonce in memory, its row not landed yet.
///
/// Threads of one process take [`spend_guard`]'s per-environment lock first,
/// so the try-lock here never meets this process's own spend: each spend
/// guard is a fresh open file description, which `flock` would otherwise
/// refuse against itself.
pub(super) fn writer_spend_lease(vault: &Vault) -> Result<Option<VaultWriterLease>> {
    if holds_writer_lease(vault) || cfg!(not(unix)) {
        return Ok(None);
    }
    match vault.try_acquire_writer_lease() {
        Ok(lease) => Ok(Some(lease)),
        Err(Error::ConcurrentWrite(VAULT_WRITER_LEASE_HELD)) => Err(Error::VaultServedElsewhere),
        Err(error) => Err(error),
    }
}

/// Per-environment locks of this process's own writer spends, by canonical
/// root: one small lock per environment ever spent on, kept for the
/// process's life.
static SPEND_LOCKS: LazyLock<Mutex<HashMap<PathBuf, &'static Mutex<()>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The lock this process's spends on the environment at `root` queue on, so
/// a second thread waits its turn instead of refusing itself on the spend
/// lease's `flock` (each guard locks through its own open file description,
/// which `flock` treats as a stranger).
fn spend_lock(root: &Path) -> &'static Mutex<()> {
    let mut locks = SPEND_LOCKS.lock().unwrap_or_else(PoisonError::into_inner);
    *locks
        .entry(root.to_path_buf())
        .or_insert_with(|| Box::leak(Box::new(Mutex::new(()))))
}

/// What [`spend_guard`] holds for a door's writer spend: this process's turn
/// at the environment, and, in a lease-less process, the spend lease itself.
pub(in crate::authority) struct SpendGuard {
    _turn: MutexGuard<'static, ()>,
    _lease: Option<VaultWriterLease>,
}

/// What a door that spends a request's nonce in its own writer holds from
/// before that writer opens until it commits (FIX 12023 W0, P1-b): this
/// process's turn at the environment, and, in a lease-less process, the
/// writer lease taken for the spend ([`writer_spend_lease`]) under that
/// turn: no lease holder spends the nonce in memory between this writer's
/// read of its row and its commit, and a process opening under the lease
/// after this door lets go reads the committed row. Under that lease the
/// door first replays a journal a crashed lease holder left (P1-a=B), so a
/// spend it answered is a row this writer reads; an absent or empty
/// journal, the common path, costs one stat.
pub(in crate::authority) fn spend_guard(vault: &Vault) -> Result<SpendGuard> {
    // Inherited turn locks may be held by a thread that does not exist here.
    if !vault.spent_nonces.in_own_process() {
        return Err(Error::VaultServedElsewhere);
    }
    let turn = spend_lock(vault.store.canonical_root())
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let lease = writer_spend_lease(vault)?;
    if lease.is_some() {
        let journal = vault.store.canonical_root().join(SPEND_JOURNAL_FILE);
        let owed = match std::fs::metadata(&journal) {
            Ok(meta) => meta.len() > 0,
            Err(error) => error.kind() != std::io::ErrorKind::NotFound,
        };
        if owed {
            vault.spent_nonces.replay_journal(vault)?;
        }
    }
    Ok(SpendGuard {
        _turn: turn,
        _lease: lease,
    })
}

impl SpentNonces {
    fn new() -> Self {
        Self {
            pid: std::process::id(),
            ..Self::default()
        }
    }

    /// Whether this set is this process's own, not one inherited across a
    /// fork: checked before any of its locks or its journal are touched, so
    /// a child takes the writer's path instead of an inherited lock a
    /// vanished thread may hold.
    fn in_own_process(&self) -> bool {
        self.pid == std::process::id()
    }

    fn lock(&self) -> MutexGuard<'_, Nonces> {
        self.nonces.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The set of the environment at canonical `root`, shared by every
    /// handle this process opens on it (FIX 12023 W0, P2). A forked child
    /// mints a fresh set instead of spending through the inherited one: its
    /// entries and journal descriptor belong to threads that do not exist
    /// here, and the inherited lock is never touched.
    pub(crate) fn shared_for(root: &Path) -> Arc<SpentNonces> {
        let pid = std::process::id();
        match REGISTRY
            .pid
            .compare_exchange(0, pid, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(owner) if owner == pid => {}
            Err(_) => return Arc::new(SpentNonces::new()),
        }
        let mut entries = REGISTRY
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        entries.retain(|_, set| set.strong_count() > 0);
        if let Some(set) = entries.get(root).and_then(Weak::upgrade) {
            return set;
        }
        let set = Arc::new(SpentNonces::new());
        entries.insert(root.to_path_buf(), Arc::downgrade(&set));
        set
    }

    /// Notes the authority second this process opened `vault`'s environment
    /// at, on the clock a slip's mint takes its time from
    /// ([`Vault::capability_slip_now`]). The first handle whose reading
    /// succeeds sets it (the set is the environment's, not a handle's); while
    /// it is unset every admission on the environment takes the writer, as
    /// today.
    pub(crate) fn note_open(&self, vault: &Vault) {
        match vault.capability_slip_now() {
            Ok(now) => {
                let _ = self.opened_at.set(now);
            }
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "the open's authority second did not read; every admission on this environment takes the writer"
            ),
        }
    }

    /// The door an admission on `vault` spends through in memory, while it
    /// may: this environment opened at a second it read, and a handle this
    /// process serves at its root holds the writer lease and is not sealed,
    /// which a spend's rows are written on. Any served handle of the
    /// environment serves, this `vault` or a replacement (FIX 12023 W0, P2),
    /// since the set is the environment's, not a handle's. `None`: the
    /// writer's path.
    pub(in crate::authority) fn door(&self, vault: &Vault) -> Option<SpendDoor> {
        if !self.in_own_process() {
            return None;
        }
        let opened_at = *self.opened_at.get()?;
        let served = self.served_of(vault)?;
        if !holds_writer_lease(&served) || served.store.writes_sealed() {
            return None;
        }
        Some(SpendDoor { served, opened_at })
    }

    /// A live handle this process serves at `vault`'s root, the last found
    /// while it lives, else found now. `None`: none is served, and the
    /// writer's path judges every admission (FIX 12023 W0, P2).
    fn served_of(&self, vault: &Vault) -> Option<Arc<Vault>> {
        if !self.in_own_process() {
            return None;
        }
        let mut cached = self.served.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(served) = cached.as_ref().and_then(Weak::upgrade) {
            return Some(served);
        }
        let served = crate::store::served_vault_at(vault.store.canonical_root())?;
        *cached = Some(Arc::downgrade(&served));
        Some(served)
    }

    /// Spends `key` here for an admission at authority second `now` whose
    /// slip expires at `expires_at`, judged on proof clock `clock`, in one
    /// step under this set's lock: the entries past their slip's replay
    /// window leave, then `key` is spent unless this set holds it, a writer's
    /// spend of it may still commit, or a committed row holds it, read in a
    /// snapshot taken under the lock. An entry leaves this set under the lock
    /// only once its row is visible to that snapshot ([`Self::landed`]), so
    /// between the two one of them holds it. The spend is journaled and
    /// fdatasynced before it is spent here, in the same step, so no crash
    /// sees it spent in memory without its journal record (P1-a=B).
    /// `false` when it is not spent here: the writer's path judges it.
    fn admit(
        &self,
        vault: &Vault,
        key: SpentKey,
        now: u64,
        expires_at: u64,
        clock: super::ProofClock,
    ) -> bool {
        let mut nonces = self.lock();
        if nonces.fenced || nonces.recovering {
            return false;
        }
        // A spend journaled since this proof was judged on `clock` took a
        // later proof clock: the writer's path judges this one afresh
        // (review #4484 Astra round 3 P1).
        if nonces.live_high > clock.now {
            return false;
        }
        nonces.leave_before(now);
        // A writer's spend whose transaction is decided left its row, when it
        // committed, for the snapshot below, which is taken after.
        let decided = vault.store.env.info().last_txn_id;
        nonces.staged.retain(|_, commits_as| *commits_as > decided);
        if nonces.admitted.contains_key(&key)
            || nonces.expired_unlanded.contains(&key)
            || nonces.staged.contains_key(&key)
        {
            return false;
        }
        // The proof was judged on `clock`, read in an earlier snapshot: a
        // writer since may have moved the proof floor or `not_before` and let
        // this nonce's row go (review #4484 Astra P1, 11-04 16:2x), or an
        // owner's clock recovery may have set the clock back below it (Astra
        // round 6): the clock read now, as `request_now_in_txn` reads it,
        // must not stand below the one the proof was judged on. Any move
        // sends the request to the writer's path, which judges it afresh.
        let live_high = nonces.live_high;
        let committed = match vault.store.env.read_txn() {
            Ok(txn) => (|| -> Result<bool> {
                let floor = proof_floor_in_txn(vault, &txn)?;
                let now = floor.max(vault.store.clock.wall_now()).max(live_high);
                if floor > clock.now
                    || now < clock.now
                    || PROOF_NOT_BEFORE.get(&vault.store, &txn, &())?.unwrap_or(0)
                        > clock.not_before
                {
                    return Ok(true);
                }
                REPLAY_NONCE.contains(&vault.store, &txn, &key.row())
            })(),
            Err(error) => Err(error.into()),
        };
        if !matches!(committed, Ok(false)) {
            return false;
        }
        let until = expires_at.saturating_add(WINDOW_SECS);
        if !nonces.append_journal(vault.store.canonical_root(), &key, until, clock.now) {
            return false;
        }
        nonces.admitted.insert(key, until);
        nonces.leaving.insert((until, key));
        nonces.queuing += 1;
        true
    }

    /// The highest proof clock a spend journaled here judged on (review #4484
    /// Astra round 2 P1): the proof clock reads at or above it
    /// ([`super::request_now_in_txn`]). 0 off this set's own process.
    pub(super) fn proof_high(&self) -> u64 {
        if self.in_own_process() {
            self.lock().live_high
        } else {
            0
        }
    }

    /// Starts an owner's clock recovery ([`Vault::recover_proof_clock`]),
    /// enforcing the stopped vault it needs (L02 11-04 16:34): `None` while
    /// any spend made here has not landed, whose landing would raise the
    /// floor again after the recovery, or while another recovery is under
    /// way (review #4484 Astra round 5). Until the returned guard drops,
    /// every admission takes the writer. The live high-water goes now,
    /// before the recovery's writer: every spend judged on it has landed,
    /// and each landing raised the committed floor to its clock, so the
    /// floor holds it, and a writer admission after the recovery commits
    /// reads only the lowered floor (Astra round 5).
    pub(super) fn begin_clock_recovery(&self) -> Option<ClockRecovery<'_>> {
        let mut nonces = self.lock();
        if nonces.recovering || (self.in_own_process() && !nonces.drained()) {
            return None;
        }
        nonces.recovering = true;
        nonces.live_high = 0;
        Some(ClockRecovery { nonces: self })
    }

    /// Notes that the rows of a spend [`Self::admit`] took are queued on the
    /// detached door, where a swap's wait for them counts them.
    fn note_queued(&self) {
        let mut nonces = self.lock();
        nonces.queuing = nonces.queuing.saturating_sub(1);
        // Its rows may have landed before it was noted, while it still
        // counted as queuing (review #4484 P2, 11-04 16:05).
        nonces.truncate_journal_if_drained();
        drop(nonces);
        self.queued.notify_all();
    }

    /// Stages `key`'s spend in a writer of `vault` (FIX 12023 W0): `false`
    /// when an admission spent it here, so the nonce is spent though its row
    /// may not have landed. Else it stays staged here, with the id that
    /// writer commits as, so no admission spends it while that writer may
    /// still commit; the spends of every earlier writer, all decided by now,
    /// leave. Where no admission can spend in memory in this process (no
    /// served handle of the environment holds its writer lease) nothing is
    /// staged: the writer's door holds the lease for the spend instead
    /// ([`spend_guard`]), so no process spends in memory beside it.
    pub(super) fn stage(&self, vault: &Vault, key: SpentKey) -> bool {
        if !self.in_own_process() {
            return true;
        }
        if !holds_writer_lease(vault)
            && !self
                .served_of(vault)
                .is_some_and(|served| holds_writer_lease(&served))
        {
            return true;
        }
        let commits_as = vault.store.env.info().last_txn_id + 1;
        let mut nonces = self.lock();
        nonces.staged.retain(|_, staged| *staged >= commits_as);
        if nonces.admitted.contains_key(&key) || nonces.expired_unlanded.contains(&key) {
            return false;
        }
        nonces.staged.insert(key, commits_as);
        true
    }

    /// Whether an admission spent `key` here and its rows have not landed.
    /// Its entry leaves once they land, so a reader that reads the committed
    /// row as well reads it in a writer, or in a snapshot opened after this
    /// call, never in one opened before.
    pub(super) fn admitted(&self, key: &SpentKey) -> bool {
        self.in_own_process() && self.lock().admitted.contains_key(key)
    }

    /// Lets go of `key`'s entry, from its spend's after-commit callback once
    /// its rows landed, after their group's commit is visible (FIX 12023 W0,
    /// L02 10-31): a replay of it then finds the committed row, read under
    /// this lock ([`Self::admit`]), and takes the writer's path. Once the
    /// last unlanded entry leaves, the journal truncates under the same lock
    /// (P1-a=B).
    fn landed(&self, key: &SpentKey) {
        let mut nonces = self.lock();
        nonces.leave(key);
        nonces.truncate_journal_if_drained();
    }

    /// Replays the spend journal into the committed rows at a lease-holder
    /// open (P1-a=B), before the open reads its second ([`Self::note_open`]),
    /// so a spent slip replayed after a crash meets its row on the writer's
    /// path. Only an open that took the writer lease replays it; a
    /// lease-less open leaves it for the next lease holder (or for a spend's
    /// guard, [`spend_guard`]). A replay that cannot prove every journaled
    /// spend landed raises the proof floor past them first
    /// ([`Self::refuse_journaled_proofs`]); only a floor that does not
    /// commit fails the open.
    pub(crate) fn replay_journal_at_open(&self, vault: &Vault) -> Result<()> {
        if vault.store.opened_with_writer_lease() {
            self.replay_journal(vault)?;
        }
        Ok(())
    }

    /// Lands every spend the journal holds, in one writer, then
    /// truncates it. The caller holds the environment's writer lease, by its
    /// open or by a spend's guard, so no other process appends beside the
    /// replay. This set's lock is never held across the writer (a writer
    /// spend stages under it, the opposite order), and the truncate after
    /// the commit takes it only to check that nothing appended since the
    /// read and no entry here is unlanded. `proof_now` is never restored as
    /// a floor (L02 11-03): replay reads the proof clock fresh in its own
    /// writer, as a landing does, so a floor an owner's clock recovery
    /// lowered is never raised again; a record whose `proof_now` stands far
    /// ahead of the authority second now only warns, the wall having stepped
    /// back across the crash.
    fn replay_journal(&self, vault: &Vault) -> Result<()> {
        let path = vault.store.canonical_root().join(SPEND_JOURNAL_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            // No record bounds its proofs, and the file's last write time
            // is no bound after a wall step back: fail closed and keep the
            // journal (review #4484 Astra P1, 11-04 16:2x), as a last record
            // that does not read does below.
            Err(error) => {
                tracing::error!(
                    error = %error,
                    journal = %path.display(),
                    "the slip-spend journal did not read; the open fails. To recover: move the journal aside, open, and revoke every capability slip issued before its last write"
                );
                return Err(Error::Io(error));
            }
        };
        if bytes.is_empty() {
            return Ok(());
        }
        let mut records = Vec::new();
        let mut unreadable = 0_usize;
        // A complete record that does not read, with no readable record
        // after it: no record bounds its proof clock.
        let mut unbounded = false;
        for chunk in bytes.chunks_exact(JOURNAL_RECORD_LEN) {
            match parse_journal_record(chunk) {
                Some(record) => {
                    records.push(record);
                    unbounded = false;
                }
                // Zeros too: they do not prove the append's fdatasync never
                // returned (review #4484 Astra P1, 11-04 16:2x).
                None => {
                    unreadable += 1;
                    unbounded = true;
                }
            }
        }
        let torn = bytes.len() % JOURNAL_RECORD_LEN;
        // Every proof a record holds was admitted at or below the largest
        // proof clock a readable record names, its own or the highest of
        // the records before it, and the file's last write time: a failed
        // replay's floor rises past all of them, whatever the clock reads
        // after a step back across the crash (review #4484 P1 x2). A record
        // that does not read is bounded by a readable one after it; one with
        // none after it bounds nothing, so the replay fails closed and the
        // journal stays for the owner (11-04 16:05; L02 16:14: unavailability
        // over rollback). The owner's way back: move the journal aside, open,
        // then revoke every capability slip issued before the journal's last
        // write. A proof of the unbounded spend then meets a revoked slip,
        // whatever its nonce.
        if unbounded {
            tracing::error!(
                journal = %path.display(),
                "the slip-spend journal's last complete record does not read and no record bounds its proof; the open fails. To recover: move the journal aside, open, and revoke every capability slip issued before its last write"
            );
            return Err(Error::CorruptedIndex("slip-spend journal"));
        }
        let proof_bound = records
            .iter()
            .flat_map(|record| [record.proof_now, record.high])
            .chain(journal_written_secs(&path))
            .max()
            .unwrap_or(0);
        if unreadable > 0 || torn > 0 {
            tracing::warn!(
                unreadable,
                torn,
                "the slip-spend journal holds records that do not read; they are skipped"
            );
        }
        // Every record lands, its window ended or not: the authority second
        // that would judge it ended may not be durable, and a crash that takes
        // it back makes the slip live again (review #4484 Astra P1, 11-04
        // 16:2x). The retention rule lets the extra rows go later.
        if let Ok(now) = vault.capability_slip_now() {
            let ended = records
                .iter()
                .filter(|record| record.window_end < now)
                .count();
            tracing::debug!(
                ended,
                "slip-spend journal records whose replay window ended land too"
            );
            if records
                .iter()
                .any(|record| record.proof_now > now.saturating_add(WINDOW_SECS))
            {
                tracing::warn!(
                    now,
                    "a slip-spend journal record stands ahead of the authority clock; the wall stepped back across the crash"
                );
            }
        }
        let read_len = (bytes.len() - torn) as u64;
        if !records.is_empty() {
            let landed = (|| -> Result<()> {
                let mut txn = vault.store.env.write_txn()?;
                let clock = admission_now_in_txn(vault, &mut txn)?;
                for record in &records {
                    put_nonce_row_in_txn(vault, &mut txn, &record.key.row(), clock)?;
                }
                txn.commit()?;
                Ok(())
            })();
            if let Err(error) = landed {
                tracing::error!(
                    kind = ?error.kind(),
                    "the slip-spend journal replay did not land; every proof it may hold is refused"
                );
                return self.refuse_journaled_proofs(
                    vault,
                    JournalRecoveryFailure::Land,
                    proof_bound,
                );
            }
        }
        // A complete record that does not read may be a spend already
        // answered: no row says it landed, so its proof is refused too.
        if unreadable > 0 {
            return self.refuse_journaled_proofs(
                vault,
                JournalRecoveryFailure::Unreadable(unreadable),
                proof_bound,
            );
        }
        // After the commit, never before: a crash between the two replays
        // the same records at the next open, which the rows absorb. Only a
        // journal nothing appended to since the read truncates, and only
        // once no entry here is unlanded; else `landed` truncates it when
        // it drains.
        let mut nonces = self.lock();
        if nonces.open_journal_if_needed(vault.store.canonical_root())
            && nonces.journal_len == read_len
            && nonces.drained()
        {
            let truncated = match nonces.journal.as_mut() {
                Some(file) => file.set_len(0),
                None => Ok(()),
            };
            match truncated {
                Ok(()) => {
                    nonces.journal_len = 0;
                    nonces.cap_warned = false;
                }
                Err(error) => tracing::warn!(
                    error = %error,
                    "the replayed slip-spend journal did not truncate; its records replay harmlessly"
                ),
            }
        }
        Ok(())
    }

    /// A journal whose spends a replay cannot prove landed (FIX 12023 W0
    /// review P1-2; Engine 11-04 10:3x, P1-2 = A): raises the proof floor
    /// (`not_before`) past every proof it can hold, in one writer that also
    /// files the failure as a Critical healer item the owner sees, then
    /// truncates the journal that floor covers. Each journaled proof was
    /// admitted within [`WINDOW_SECS`] of a proof clock that never runs back,
    /// so a floor [`WINDOW_SECS`] + 1 past the clock now refuses every one;
    /// a fresh proof is refused only until the clock passes the floor, and no
    /// slip is touched. A floor that does not commit fails the caller.
    /// Residual corner (L02 11-04 10:39): a proof signed up to WINDOW_SECS
    /// ahead of the clock, met again after the wall stepped back across the
    /// crash, can sit past this floor; the floor is never lowered, and the
    /// proof clock's own floor holds the clock at or above its last reading.
    fn refuse_journaled_proofs(
        &self,
        vault: &Vault,
        failure: JournalRecoveryFailure,
        proof_bound: u64,
    ) -> Result<()> {
        let _active_write_txn = active_write_txn_guard();
        let mut txn = vault.store.env.write_txn()?;
        let clock = admission_now_in_txn(vault, &mut txn)?;
        let floor = clock.now.max(proof_bound).saturating_add(WINDOW_SECS + 1);
        if PROOF_NOT_BEFORE
            .get(&vault.store, &txn, &())?
            .is_none_or(|kept| kept < floor)
        {
            PROOF_NOT_BEFORE.put(&vault.store, &mut txn, &(), &floor)?;
        }
        file_journal_recovery_item_in_txn(vault, &mut txn, failure, clock.now, floor)?;
        txn.commit()?;
        tracing::error!(
            ?failure,
            not_before = floor,
            "the slip-spend journal did not replay; proofs signed before not_before are refused, and a healer item is filed"
        );
        // Every record it holds is now refused by the floor; one appended
        // here since is an unlanded entry, which `drained` waits for.
        let mut nonces = self.lock();
        if nonces.open_journal_if_needed(vault.store.canonical_root()) && nonces.drained() {
            if let Some(file) = nonces.journal.as_mut() {
                match file.set_len(0) {
                    Ok(()) => {
                        nonces.journal_len = 0;
                        nonces.cap_warned = false;
                    }
                    Err(error) => tracing::warn!(
                        error = %error,
                        "the refused slip-spend journal did not truncate; its records stay refused by the floor"
                    ),
                }
            }
        }
        Ok(())
    }

    /// Closes this set for a restore's swap, first in it (FIX 12023 W0, L02
    /// 10-31): every later admission takes the writer, so the spends made
    /// here so far are the last the swap waits for before its writer opens.
    /// Then waits until `deadline` at most for each of them to be queued on
    /// the detached door, where the swap's wait for the queue finds it:
    /// `false` when one is not by then. It stays closed on this handle
    /// whether the swap goes on or fails; that handle's admissions keep the
    /// writer's path, which refuses none of them.
    pub(crate) fn close_for_swap(&self, deadline: Instant) -> bool {
        let mut nonces = self.lock();
        nonces.fenced = true;
        let timeout = deadline.saturating_duration_since(Instant::now());
        let (nonces, _) = self
            .queued
            .wait_timeout_while(nonces, timeout, |now| now.queuing > 0)
            .unwrap_or_else(PoisonError::into_inner);
        nonces.queuing == 0
    }

    /// A restore swap's fence over `vault`'s proof freshness, run in the
    /// swap's writer `txn` with `rows_match`, its comparison of the committed
    /// rows, under this set's lock: `false` when an admission spent a nonce
    /// here whose row has not landed, which the replacement cannot know, or
    /// when the rows differ. The swap closed this set before it waited for
    /// the spends queued here ([`Self::close_for_swap`]); once this passes,
    /// it stays closed: every later admission takes the writer, which the
    /// swap seals.
    pub(super) fn fence(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        rows_match: impl FnOnce() -> Result<bool>,
    ) -> Result<bool> {
        let mut nonces = self.lock();
        for key in nonces.admitted.keys().chain(nonces.expired_unlanded.iter()) {
            if !REPLAY_NONCE.contains(&vault.store, txn, &key.row())? {
                return Ok(false);
            }
        }
        if !rows_match()? {
            return Ok(false);
        }
        nonces.fenced = true;
        Ok(true)
    }
}

/// What an in-memory admission spends through (FIX 12023 W0): the handle this
/// process serves, which the spend's rows are written on, and the authority
/// second it opened at.
pub(in crate::authority) struct SpendDoor {
    served: Arc<Vault>,
    opened_at: u64,
}

/// An owner's clock recovery in progress ([`SpentNonces::begin_clock_recovery`]).
pub(super) struct ClockRecovery<'a> {
    nonces: &'a SpentNonces,
}

impl Drop for ClockRecovery<'_> {
    fn drop(&mut self) {
        self.nonces.lock().recovering = false;
    }
}

impl SpendDoor {
    /// Whether `mint`'s slip was minted since this handle opened: issued
    /// after that second, and first seen here after it, read in `txn`. The
    /// first-seen stamp is this vault's own clock, whoever signed the mint;
    /// one stamped before the open is never later than it, since every
    /// stamp commits its clock floor and a reopen resumes from that floor.
    pub(in crate::authority) fn minted_since_open(
        &self,
        txn: &RoTxn<'_>,
        mint: &FoldedSlip,
    ) -> Result<bool> {
        if mint.action.claims.issued_at <= self.opened_at {
            return Ok(false);
        }
        let seen = AUTHORITY_FIRST_SEEN.get(
            &self.served.store,
            txn,
            &authority_first_seen_sidecar_key(&mint.entry_hash),
        )?;
        Ok(seen.is_some_and(|seen| seen > self.opened_at))
    }

    /// Spends `key`, the nonce of a request judged at authority second `now`
    /// whose slip expires at `expires_at`, before the reply
    /// ([`SpentNonces::admit`]), and queues the rows its writer would have
    /// committed on the detached door. The `nonce_spend` span carries the
    /// journal's append-and-fdatasync microseconds (`journal_us`), the
    /// spend's cost against the speed of light. `false` when it is not
    /// spent here: the writer's path judges the request.
    pub(in crate::authority) fn spend(
        self,
        key: SpentKey,
        now: u64,
        expires_at: u64,
        clock: super::ProofClock,
    ) -> bool {
        let span = tracing::info_span!(
            target: "oneiron::authority",
            "nonce_spend",
            journal_us = tracing::field::Empty,
            admitted = tracing::field::Empty,
        );
        let _entered = span.enter();
        let served = &self.served;
        let proof_now = clock.now;
        let admitted = served
            .spent_nonces
            .admit(served, key, now, expires_at, clock);
        span.record("admitted", admitted);
        if !admitted {
            return false;
        }
        NonceSpend {
            vault: Arc::downgrade(served),
            holds: served.store.leader_holds(),
            key,
            admitted_at: now,
            proof_now,
            failures: 0,
        }
        .queue(served);
        served.spent_nonces.note_queued();
        // The reply goes out here. The spend is durable already: journaled
        // and fdatasynced inside `admit` (P1-a=B), its rows on their way
        // through the detached door. A crash before they land replays the
        // journal at the next lease-holder open, where its slip is minted
        // before that open and meets its row on the writer's path.
        true
    }
}

/// The rows a writer's spend of `key` commits, in `txn`: the recording
/// clock's floor, the proof clock's floor, `not_before` and the nonce row,
/// on the proof clock read here. That reading is the one its evictions are
/// judged on, and it never raises again a floor an owner's clock recovery
/// lowered since the admission. A failure rolls them back, said by the
/// door in a warn with the write's name.
fn put_spend_rows_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    key: SpentKey,
    proof_now: u64,
) -> Result<()> {
    // The proof clock its admission judged on rises into the floor first, as
    // the admission's own writer committed it before FIX 12023: a wall
    // stepped back between the reply and this landing never lets a later
    // proof judge below it (review #4484 Astra P1, 11-04 16:2x). A running
    // landing never meets an owner clock recovery, which needs a stopped
    // vault; replay still reads the clock fresh (L02 11-03).
    if PROOF_CLOCK_FLOOR
        .get(&vault.store, txn, &())?
        .is_none_or(|floor| floor < proof_now)
    {
        PROOF_CLOCK_FLOOR.put(&vault.store, txn, &(), &proof_now)?;
    }
    let clock = admission_now_in_txn(vault, txn)?;
    put_nonce_row_in_txn(vault, txn, &key.row(), clock)?;
    Ok(())
}

/// One in-memory spend's rows, on their way through the detached door.
struct NonceSpend {
    vault: Weak<Vault>,
    /// The handles its vault's store leader holds, which its callbacks take
    /// theirs through (FIX 12316).
    holds: LeaderHolds,
    key: SpentKey,
    /// The authority second its admission took.
    admitted_at: u64,
    /// The proof clock its admission judged on.
    proof_now: u64,
    /// Its tries whose rows did not land.
    failures: u32,
}

impl NonceSpend {
    /// Queues its rows on `served`'s detached door: clock floors and replay
    /// rows only (FIX 11568), counted on no intent, as its writer was, with
    /// its after-commit callback, which tries them again when they did not
    /// land.
    fn queue(self, served: &Arc<Vault>) {
        let (key, proof_now) = (self.key, self.proof_now);
        let write = DetachedWrite::of_vault(NONCE_SPEND_WRITE, served, move |vault, txn| {
            put_spend_rows_in_txn(vault, txn, key, proof_now)
        })
        .replay_only()
        .after_commit(self.after_commit());
        served.store.group_write_detached(write);
    }

    /// Its after-commit callback: when its rows landed its entry leaves the
    /// set, else another try. The door runs it once its group's commit
    /// returned, and tells it `false` when its closure failed, its group's
    /// commit failed, or it was lost before any group ran it.
    fn after_commit(self) -> AfterCommit {
        Box::new(move |landed| {
            if landed {
                self.leave();
            } else {
                self.retry();
            }
        })
    }

    /// Lets go of its entry in its vault's set ([`SpentNonces::landed`]),
    /// its rows committed and visible. A vault already closing takes its set
    /// with it. This runs on the store's leader, so it takes its handle as
    /// the door takes its own, since it may be the last.
    fn leave(&self) {
        let Some(vault) = self.holds.take(&self.vault) else {
            return;
        };
        vault.spent_nonces.landed(&self.key);
        drop(vault);
    }

    /// Queues its rows again after a try whose rows did not land, or, once
    /// [`NONCE_SPEND_ATTEMPTS`] tries have not, its healer item. Its nonce
    /// stays spent in memory either way, until its slip's replay window
    /// ends. This runs in the after-commit callback, on the store's leader,
    /// which drains the queue: it queues without waiting for the drain, and
    /// takes its handle as the door takes its own, since it may be the last.
    fn retry(mut self) {
        self.failures += 1;
        let Some(vault) = self.holds.take(&self.vault) else {
            tracing::warn!(
                failures = self.failures,
                "a nonce spend's rows did not land as its vault closed; its nonce stayed spent while the vault was open"
            );
            return;
        };
        let leader = active_write_txn_guard();
        if self.failures < NONCE_SPEND_ATTEMPTS {
            tracing::warn!(
                failures = self.failures,
                "a nonce spend's rows did not land; they are queued again"
            );
            self.queue(vault.handle());
        } else {
            tracing::warn!(
                failures = self.failures,
                "a nonce spend's rows did not land in any try; its healer item is queued, and its nonce stays spent in memory"
            );
            self.queue_healer_item(vault.handle());
        }
        drop(leader);
        drop(vault);
    }

    /// Queues its healer item on `served`'s detached door, counted on no
    /// intent: the callback that queues it may run on a request's own
    /// thread.
    fn queue_healer_item(self, served: &Arc<Vault>) {
        let write = with_idempotency_intent(None, || {
            DetachedWrite::of_vault(NONCE_SPEND_HEALER_ITEM_WRITE, served, move |vault, txn| {
                self.file_healer_item_in_txn(vault, txn)
            })
        });
        served.store.group_write_detached(write);
    }

    /// Stores its healer item: a system self-report, Critical, addressed by
    /// the digest its nonce row is keyed by and valid from its admission.
    /// Its body depends on the spend alone, so its id does too: a spend
    /// already filed stores nothing.
    fn file_healer_item_in_txn(&self, vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
        let failures = u64::from(self.failures);
        let event = DiagnosticEvent {
            detector_id: NONCE_SPEND_DETECTOR.to_owned(),
            event_class: DiagnosticEventClass::DurableWriteFailure,
            signal: None,
            actor_class: "system".to_owned(),
            actor_ref: None,
            source: DiagnosticSourceKind::SelfReport,
            criticality: DiagnosticCriticality::Critical,
            // The spend's rows should land in their first try; this many
            // tries missed.
            expected: Value::from(0_u64),
            actual: Value::from(failures),
            delta: Value::from(failures),
            replay: DiagnosticReplayCoordinate {
                content_hash: self.key.digest,
                run_ref: None,
                checkpoint_ref: None,
            },
            evidence_refs: Vec::new(),
            valid_from: self.admitted_at,
            valid_to: None,
        };
        let body = encode_diagnostic_event_body(&event)?;
        let id = diagnostic_event_id(NONCE_SPEND_DETECTOR, &body);
        if vault.store.port_entity_raw(&*txn, &id)?.is_some() {
            return Ok(());
        }
        vault.emit_diagnostic_event_in_txn(txn, &id, &event)
    }
}

/// Stores the healer item of a journal replay that could not prove every
/// journaled spend landed: a system self-report, Critical, addressed by the
/// floor it raised and valid from the proof clock's second. A replay that
/// failed the same way at the same floor stores nothing new.
fn file_journal_recovery_item_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    failure: JournalRecoveryFailure,
    now: u64,
    floor: u64,
) -> Result<()> {
    let unproven = failure.unproven();
    let event = DiagnosticEvent {
        detector_id: NONCE_JOURNAL_DETECTOR.to_owned(),
        event_class: DiagnosticEventClass::ChainVerifyFailure,
        signal: None,
        actor_class: "system".to_owned(),
        actor_ref: None,
        source: DiagnosticSourceKind::SelfReport,
        criticality: DiagnosticCriticality::Critical,
        // Every journaled spend should replay; this many could not be proven.
        expected: Value::from(0_u64),
        actual: Value::from(unproven),
        delta: Value::from(unproven),
        replay: DiagnosticReplayCoordinate {
            content_hash: *blake3::hash(&floor.to_le_bytes()).as_bytes(),
            run_ref: None,
            checkpoint_ref: None,
        },
        evidence_refs: Vec::new(),
        valid_from: now,
        valid_to: None,
    };
    let body = encode_diagnostic_event_body(&event)?;
    let id = diagnostic_event_id(NONCE_JOURNAL_DETECTOR, &body);
    if vault.store.port_entity_raw(&*txn, &id)?.is_some() {
        return Ok(());
    }
    vault.emit_diagnostic_event_in_txn(txn, &id, &event)
}

/// The journal file's last write time in Unix seconds, from its metadata,
/// which reads even when its records do not: no record's proof clock is
/// later than it, as the host's wall wrote them.
fn journal_written_secs(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}
