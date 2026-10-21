//! Durable retirement intents and the one finisher that carries them out.
//!
//! A client stages an intent in the same transaction as the redaction or
//! removal of everything the retiring generations decrypt, so a crash before
//! the commit leaves readable rows and a crash after it leaves a resumable
//! intent and nothing that needs the entries. One intent stands per subject:
//! its generation only rises, and an erase's dominates a retention's.

use heed::{RoTxn, RwTxn};

use crate::error::{Error, Result, StoreError};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable, SideTableDbs};
use crate::store::Store;

use super::files::LocalCustody;
use super::identity::{CustodyKind, CustodySubject};
use super::log::LogEntry;

/// Why a subject's entries retire. An erase is complete, so nothing defers
/// it (ARCH-0038 #erasure-completeness); a retention's may wait on its
/// client's holds. Ordered so the larger dominates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RetireCause {
    Retention,
    Erase,
}

/// A committed intent to destroy every generation of `subject` through
/// `through`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RetirementIntent {
    pub(crate) subject: CustodySubject,
    pub(crate) through: u64,
    pub(crate) cause: RetireCause,
}

/// `through (u64be) | cause (0 retention, 1 erase)`.
struct IntentValue {
    through: u64,
    cause: RetireCause,
}

impl RawValue for IntentValue {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut out = self.through.to_be_bytes().to_vec();
        out.push(match self.cause {
            RetireCause::Retention => 0,
            RetireCause::Erase => 1,
        });
        Ok(out)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let (through, cause) = bytes
            .split_first_chunk::<8>()
            .ok_or_else(|| CodecError::from(intent_corrupt()))?;
        let cause = match cause {
            [0] => RetireCause::Retention,
            [1] => RetireCause::Erase,
            _ => return Err(intent_corrupt().into()),
        };
        Ok(Self {
            through: u64::from_be_bytes(*through),
            cause,
        })
    }
}

fn intent_corrupt() -> Error {
    Error::CorruptedIndex("key custody retirement intent")
}

const RETIRE_PENDING: SideTable<CustodySubject, IntentValue, Raw> =
    SideTable::new(&side_table::KEY_CUSTODY_RETIRE_PENDING);

/// The `vault_meta` prefix of the intents, for readers of raw rows.
pub(crate) fn retirement_prefix() -> &'static [u8] {
    RETIRE_PENDING.decl().prefix
}

/// Stages `intent` in the caller's transaction, merged with the one already
/// standing for its subject: the newer generation, and erase over retention.
pub(crate) fn stage_retirement_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    intent: &RetirementIntent,
) -> Result<()> {
    let standing = RETIRE_PENDING.get(dbs, &*wtxn, &intent.subject)?;
    let value = IntentValue {
        through: standing.as_ref().map_or(intent.through, |standing| {
            standing.through.max(intent.through)
        }),
        cause: standing
            .as_ref()
            .map_or(intent.cause, |standing| standing.cause.max(intent.cause)),
    };
    RETIRE_PENDING.put(dbs, wtxn, &intent.subject, &value)
}

/// Withdraws the Retention intent standing for `subject`, in `wtxn`, when
/// its client's policy keeps the entries now (FIX 6022): an erase's is never
/// withdrawn. `true` when one went.
pub(crate) fn withdraw_retention_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    subject: &CustodySubject,
) -> Result<bool> {
    match RETIRE_PENDING.get(dbs, &*wtxn, subject)? {
        Some(standing) if standing.cause == RetireCause::Retention => {
            RETIRE_PENDING.delete(dbs, wtxn, subject)
        }
        _ => Ok(false),
    }
}

/// The intent standing for `subject`, if any.
pub(crate) fn retirement_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    subject: &CustodySubject,
) -> Result<Option<RetirementIntent>> {
    Ok(RETIRE_PENDING
        .get(dbs, txn, subject)?
        .map(|value| RetirementIntent {
            subject: subject.clone(),
            through: value.through,
            cause: value.cause,
        }))
}

/// Every standing intent of `kind`, in key order.
pub(crate) fn retirements_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    kind: CustodyKind,
) -> Result<Vec<RetirementIntent>> {
    Ok(RETIRE_PENDING
        .scan(dbs, txn)?
        .into_iter()
        .filter(|(subject, _)| subject.kind() == kind)
        .map(|(subject, value)| RetirementIntent {
            subject,
            through: value.through,
            cause: value.cause,
        })
        .collect())
}

/// Clears every standing intent in `wtxn`, whatever its kind.
pub(super) fn clear_all_in_txn(dbs: &impl SideTableDbs, wtxn: &mut RwTxn<'_>) -> Result<()> {
    for (subject, _) in RETIRE_PENDING.scan(dbs, &*wtxn)? {
        RETIRE_PENDING.delete(dbs, wtxn, &subject)?;
    }
    Ok(())
}

/// Every intent among raw `vault_meta` rows (a checkpoint's, or a live
/// vault's custody rows). A key the engine would not write is no intent.
pub(crate) fn retirements_in_rows(rows: &[(Vec<u8>, Vec<u8>)]) -> Result<Vec<RetirementIntent>> {
    let mut intents = Vec::new();
    for (key, value) in rows {
        let Some(subject) = key
            .strip_prefix(retirement_prefix())
            .and_then(<CustodySubject as crate::side_table::SideKey>::decode_key)
        else {
            continue;
        };
        let value = RETIRE_PENDING.decode_value(value)?;
        intents.push(RetirementIntent {
            subject,
            through: value.through,
            cause: value.cause,
        });
    }
    Ok(intents)
}

/// Clears an intent whose generations are all retired here, in the
/// finisher's own write transaction: the retirement handoff (KS-4, FIX
/// 5685).
///
/// The retirement is handed to the exterior journal first: one keyless
/// Retire frame, synced, then its obligation (KS-4A2), synced, naming that
/// frame's position. Only then does the intent clear. A frame an
/// interrupted handoff journaled is found by the journal's reconcile walk,
/// never journaled again. The obligation, not the intent, waits on every
/// required target's durable acknowledgement and the anchor: the local
/// retirement is effective at once, nothing refuses for a lagging target,
/// and the completion status names each one still pending (Engine 10-20).
/// The claim finisher stays warning-only.
fn clear_finished_intent_in_txn(
    store: &Store,
    custody: LocalCustody<'_>,
    wtxn: &mut RwTxn<'_>,
    intent: &RetirementIntent,
) -> Result<()> {
    let journal = custody.journal()?;
    journal.reconcile()?;
    if journal.obligation(intent)?.is_none() {
        let at = custody.journal_entry(&LogEntry::Retire {
            subject: intent.subject.clone(),
            through: intent.through,
            cause: intent.cause,
        })?;
        journal.record_obligation(intent, &at)?;
    }
    RETIRE_PENDING.delete(store, wtxn, &intent.subject)?;
    Ok(())
}

/// How many intents stand in `txn`, whatever their kind: retirements whose
/// local destruction has not been handed off yet.
pub(crate) fn standing_retirements_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<usize> {
    Ok(RETIRE_PENDING.scan(dbs, txn)?.len())
}

#[cfg(test)]
thread_local! {
    static BEFORE_RETIRE_LOCK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

/// Runs `callback` once, on this thread, before the finisher takes the
/// custody write lock for an intent.
#[cfg(test)]
pub(crate) fn arm_before_retire_lock(callback: impl FnOnce() + 'static) {
    BEFORE_RETIRE_LOCK.with(|slot| *slot.borrow_mut() = Some(Box::new(callback)));
}

impl Store {
    /// Completes every durable retirement of `kind`, including ones an
    /// interrupted process left behind. An intent names the newest
    /// generation to destroy; every older one goes with it.
    ///
    /// For each intent: the custody write lock FIRST, so every live reader
    /// snapshot has finished, then the LMDB writer (never wait on readers
    /// while holding the writer slot they may need); the intent, binding and
    /// archive are read again under both; `ready`, the client's predicate,
    /// says whether it may run now (`false` defers it, an error refuses it:
    /// a claim intent with live ciphertext under a retiring generation);
    /// then each generation's marker is synced, its entry unlinked and the
    /// directory synced, including a generation whose unlink an interrupted
    /// pass left behind its marker; then the intent clears.
    pub(crate) fn finish_custody_retirements(
        &self,
        kind: CustodyKind,
        ready: impl Fn(&RoTxn<'_>, &RetirementIntent) -> Result<bool>,
    ) -> Result<()> {
        let txn = self.env.read_txn()?;
        let pending = retirements_in_txn(self, &txn, kind)?;
        if pending.is_empty() {
            return Ok(());
        }
        // An archived vault shares its custody with the vault that replaced
        // it, and destroys none of it until an owner activates it.
        if self.archived_in_txn(&txn)? {
            return Err(Error::Store(StoreError::ArchivedVault));
        }
        drop(txn);
        for intent in pending {
            #[cfg(test)]
            BEFORE_RETIRE_LOCK.with(|slot| {
                if let Some(callback) = slot.borrow_mut().take() {
                    callback();
                }
            });
            let _custody = self.core.key_custody.write_guard()?;
            let mut wtxn = self.env.write_txn()?;
            // Another finisher may have consumed the intent, or a later
            // erase raised it.
            let Some(intent) = retirement_in_txn(self, &wtxn, &intent.subject)? else {
                continue;
            };
            // A swap may have archived it since the check above.
            if self.archived_in_txn(&wtxn)? {
                return Err(Error::Store(StoreError::ArchivedVault));
            }
            // Only the custody this vault is bound to is ever destroyed.
            let custody = self.core.key_custody.committed_in_txn(self, &wtxn)?;
            if !ready(&*wtxn, &intent)? {
                continue;
            }
            for generation in 0..=intent.through {
                let id = intent.subject.at(generation);
                if custody.retired(&id)? && !custody.published(&id)? {
                    continue;
                }
                custody.retire_local(&id)?;
            }
            clear_finished_intent_in_txn(self, custody, &mut wtxn, &intent)?;
            wtxn.commit()?;
        }
        Ok(())
    }
}
