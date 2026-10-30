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

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use super::{NonceKey, REPLAY_NONCE, WINDOW_SECS, admission_now_in_txn, put_nonce_row_in_txn};
use crate::authority::{AUTHORITY_FIRST_SEEN, FoldedSlip, authority_first_seen_sidecar_key};
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::self_heal::{
    DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass, DiagnosticReplayCoordinate,
    DiagnosticSourceKind, diagnostic_event_id, encode_diagnostic_event_body,
};
use crate::store::{
    AfterCommit, DetachedWrite, active_write_txn_guard, release_vault_handle,
    with_idempotency_intent,
};
use crate::{Vault, VaultWriterLease};

/// The tries of one in-memory spend's rows before it files its healer item
/// and is tried no more (FIX 12023 W0).
const NONCE_SPEND_ATTEMPTS: u32 = 3;
/// The detector token of a nonce spend's healer item.
const NONCE_SPEND_DETECTOR: &str = "authority.nonce_spend.v1";
/// The detached door's name for a spend's rows, said in each warn about them.
const NONCE_SPEND_WRITE: &str = "nonce spend";
/// The detached door's name for a spend's healer item.
const NONCE_SPEND_HEALER_ITEM_WRITE: &str = "nonce spend healer item";

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

/// This handle's in-memory nonce spends (FIX 12023 W0). In memory only: a
/// close or a crash drops them, and a slip minted before the next open takes
/// the writer there.
#[derive(Default)]
pub(crate) struct SpentNonces {
    /// The authority second this handle opened at; unset, no admission
    /// spends here.
    opened_at: OnceLock<u64>,
    /// The handle this process serves at this vault's root, once found: an
    /// in-memory spend's rows are written on it.
    served: OnceLock<Weak<Vault>>,
    nonces: Mutex<Nonces>,
}

#[derive(Default)]
struct Nonces {
    /// A restore's swap passed its fence: from then on every admission takes
    /// the writer, which the swap seals.
    fenced: bool,
    /// Spent by an admission here and not yet landed, each with the authority
    /// second its slip's replay window ends: it leaves once its rows land, or
    /// past that second when they have not.
    admitted: HashMap<SpentKey, u64>,
    /// `admitted` in the order its entries leave.
    leaving: BTreeSet<(u64, SpentKey)>,
    /// Spent in a writer whose transaction is not known to be decided, each
    /// with the id that transaction commits as.
    staged: HashMap<SpentKey, usize>,
}

impl Nonces {
    /// Lets go of every admitted entry whose slip's replay window ended
    /// before authority second `now`, never one sooner: those whose rows did
    /// not land, as one whose rows landed left then ([`Self::leave`]).
    fn leave_before(&mut self, now: u64) {
        while self.leaving.first().is_some_and(|(until, _)| *until < now) {
            if let Some((_, key)) = self.leaving.pop_first() {
                self.admitted.remove(&key);
            }
        }
    }

    /// Lets go of `key`'s admitted entry, whose rows landed.
    fn leave(&mut self, key: &SpentKey) {
        if let Some(until) = self.admitted.remove(key) {
            self.leaving.remove(&(until, *key));
        }
    }
}

/// Whether this process holds `vault`'s exclusive writer lease, taken by its
/// owned open ([`Vault::open_owned`]): no other process writes there.
fn holds_writer_lease(vault: &Vault) -> bool {
    vault
        .writer_lease()
        .is_some_and(VaultWriterLease::held_by_current_process)
}

impl SpentNonces {
    fn lock(&self) -> MutexGuard<'_, Nonces> {
        self.nonces.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Notes the authority second `vault` opened at, on the clock a slip's
    /// mint takes its time from ([`Vault::capability_slip_now`]). A reading
    /// that fails leaves it unset, and every admission on this handle takes
    /// the writer, as today.
    pub(crate) fn note_open(&self, vault: &Vault) {
        match vault.capability_slip_now() {
            Ok(now) => {
                let _ = self.opened_at.set(now);
            }
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "the open's authority second did not read; every admission on this handle takes the writer"
            ),
        }
    }

    /// The door an admission on `vault` spends through in memory, while it
    /// may: this process holds the vault's writer lease, the handle opened at
    /// a second it read, no write on it is sealed, and it is the handle this
    /// process serves, which a spend's rows are written on. `None`: the
    /// writer's path.
    pub(in crate::authority) fn door(&self, vault: &Vault) -> Option<SpendDoor> {
        let opened_at = *self.opened_at.get()?;
        if !holds_writer_lease(vault) || vault.store.writes_sealed() {
            return None;
        }
        let served = match self.served.get() {
            Some(served) => served.upgrade()?,
            None => {
                let served = vault.served_handle()?;
                let _ = self.served.set(Arc::downgrade(&served));
                served
            }
        };
        Some(SpendDoor { served, opened_at })
    }

    /// Spends `key` here for an admission at authority second `now` whose
    /// slip expires at `expires_at`, in one step under this set's lock: the
    /// entries past their slip's replay window leave, then `key` is spent
    /// unless this set holds it, a writer's spend of it may still commit, or
    /// a committed row holds it, read in a snapshot taken under the lock. An
    /// entry leaves this set under the lock only once its row is visible to
    /// that snapshot ([`Self::landed`]), so between the two one of them holds
    /// it. `false` when it is not spent here: the writer's path judges it.
    fn admit(&self, vault: &Vault, key: SpentKey, now: u64, expires_at: u64) -> bool {
        let mut nonces = self.lock();
        if nonces.fenced {
            return false;
        }
        nonces.leave_before(now);
        // A writer's spend whose transaction is decided left its row, when it
        // committed, for the snapshot below, which is taken after.
        let decided = vault.store.env.info().last_txn_id;
        nonces.staged.retain(|_, commits_as| *commits_as > decided);
        if nonces.admitted.contains_key(&key) || nonces.staged.contains_key(&key) {
            return false;
        }
        let committed = match vault.store.env.read_txn() {
            Ok(txn) => REPLAY_NONCE.contains(&vault.store, &txn, &key.row()),
            Err(error) => Err(error.into()),
        };
        if !matches!(committed, Ok(false)) {
            return false;
        }
        let until = expires_at.saturating_add(WINDOW_SECS);
        nonces.admitted.insert(key, until);
        nonces.leaving.insert((until, key));
        true
    }

    /// Stages `key`'s spend in a writer of `vault` (FIX 12023 W0): `false`
    /// when an admission spent it here, so the nonce is spent though its row
    /// may not have landed. Else it stays staged here, with the id that
    /// writer commits as, so no admission spends it while that writer may
    /// still commit; the spends of every earlier writer, all decided by now,
    /// leave. A handle that does not hold its writer lease spends nothing
    /// here and stages nothing.
    pub(super) fn stage(&self, vault: &Vault, key: SpentKey) -> bool {
        if !holds_writer_lease(vault) {
            return true;
        }
        let commits_as = vault.store.env.info().last_txn_id + 1;
        let mut nonces = self.lock();
        nonces.staged.retain(|_, staged| *staged >= commits_as);
        if nonces.admitted.contains_key(&key) {
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
        self.lock().admitted.contains_key(key)
    }

    /// Lets go of `key`'s entry, from its spend's after-commit callback once
    /// its rows landed, after their group's commit is visible (FIX 12023 W0,
    /// L02 10-31): a replay of it then finds the committed row, read under
    /// this lock ([`Self::admit`]), and takes the writer's path.
    fn landed(&self, key: &SpentKey) {
        self.lock().leave(key);
    }

    /// A restore swap's fence over `vault`'s proof freshness, run in the
    /// swap's writer `txn` with `rows_match`, its comparison of the committed
    /// rows, under this set's lock: `false` when an admission spent a nonce
    /// here whose row has not landed, which the replacement cannot know, or
    /// when the rows differ. Once it passes, nothing more is spent here:
    /// every later admission takes the writer, which the swap seals.
    pub(super) fn fence(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        rows_match: impl FnOnce() -> Result<bool>,
    ) -> Result<bool> {
        let mut nonces = self.lock();
        for key in nonces.admitted.keys() {
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
    /// committed on the detached door. `false` when it is not spent here:
    /// the writer's path judges the request.
    pub(in crate::authority) fn spend(self, key: SpentKey, now: u64, expires_at: u64) -> bool {
        let served = &self.served;
        if !served.spent_nonces.admit(served, key, now, expires_at) {
            return false;
        }
        NonceSpend {
            vault: Arc::downgrade(served),
            key,
            admitted_at: now,
            failures: 0,
        }
        .queue(served);
        true
    }
}

/// The rows a writer's spend of `key` commits, in `txn`: the recording
/// clock's floor, the proof clock's floor, `not_before` and the nonce row,
/// on the proof clock read here. That reading is the one its evictions are
/// judged on, and it never raises again a floor an owner's clock recovery
/// lowered since the admission. A failure rolls them back, said by the
/// door in a warn with the write's name.
fn put_spend_rows_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, key: SpentKey) -> Result<()> {
    let clock = admission_now_in_txn(vault, txn)?;
    put_nonce_row_in_txn(vault, txn, &key.row(), clock)?;
    Ok(())
}

/// One in-memory spend's rows, on their way through the detached door.
struct NonceSpend {
    vault: Weak<Vault>,
    key: SpentKey,
    /// The authority second its admission took.
    admitted_at: u64,
    /// Its tries whose rows did not land.
    failures: u32,
}

impl NonceSpend {
    /// Queues its rows on `served`'s detached door: clock floors and replay
    /// rows only (FIX 11568), counted on no intent, as its writer was, with
    /// its after-commit callback, which tries them again when they did not
    /// land.
    fn queue(self, served: &Arc<Vault>) {
        let key = self.key;
        let write = DetachedWrite::of_vault(NONCE_SPEND_WRITE, served, move |vault, txn| {
            put_spend_rows_in_txn(vault, txn, key)
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
    /// with it. This runs on the store's leader, so it lets go of the handle
    /// it took as the door lets go of its own, since it may be the last.
    fn leave(&self) {
        let Some(vault) = self.vault.upgrade() else {
            return;
        };
        vault.spent_nonces.landed(&self.key);
        release_vault_handle(vault);
    }

    /// Queues its rows again after a try whose rows did not land, or, once
    /// [`NONCE_SPEND_ATTEMPTS`] tries have not, its healer item. Its nonce
    /// stays spent in memory either way, until its slip's replay window
    /// ends. This runs in the after-commit callback, on the store's leader,
    /// which drains the queue: it queues without waiting for the drain, and
    /// lets go of the handle it took as the door lets go of its own, since it
    /// may be the last.
    fn retry(mut self) {
        self.failures += 1;
        let Some(vault) = self.vault.upgrade() else {
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
            self.queue(&vault);
        } else {
            tracing::warn!(
                failures = self.failures,
                "a nonce spend's rows did not land in any try; its healer item is queued, and its nonce stays spent in memory"
            );
            self.queue_healer_item(&vault);
        }
        drop(leader);
        release_vault_handle(vault);
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
            event_class: DiagnosticEventClass::ChainVerifyFailure,
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
