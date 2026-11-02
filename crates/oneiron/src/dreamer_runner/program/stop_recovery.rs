//! The abandon an owner's Stop still owes its try's sends (FIX 7188, FIX
//! 7352), retried on every wake host whether or not it binds a program
//! runtime.
//!
//! A Stop whose abandon the ledger refused keeps its mark (`STOP_OWED`) in
//! the Stop's own write. Each wake pass's start retries every mark that is
//! due, in a writer of its own per mark, and the deadline lane arms a pass
//! for the next due one. A retry that lands clears the mark; one the ledger
//! refuses again (a corrupt intent row, a replaced dedupe reservation) keeps
//! it, due again the vault's resolved Retry pause later (FIX 8716), and
//! never gives up: the owed send is never dropped or called delivered. The
//! first failure raises one owner notice naming the stuck Stop, a truthful
//! record that blocks nothing; it is raised once per Stop.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{DREAMER_TURN_PROGRAM_ATTEMPT_KIND, DreamerRunnerStore};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::side_table::{self, Named, SideTable};

use super::stop_sends::abandon_sends_in_txn;

/// The producer of the owner notice a stuck Stop raises.
const STOP_OWED_PRODUCER: &str = "dreamer.turn_program.stop_owed";
/// The notice's static code: an owner's Stop whose sends' abandon did not
/// land, retried until it does.
const STOP_OWED_DETAIL: &str = "turn_program.stop_abandon_owed";

/// The abandon an owner Stop still owes its try's sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StopOwed {
    /// When the owner stopped the try.
    stopped_at: u64,
    /// When its next retry is due, in store-clock seconds.
    next_retry_at: u64,
    /// Whether the owner's notice naming this Stop was raised.
    escalated: bool,
}

/// One stopped try whose sends' abandon is still owed, keyed by attempt.
const STOP_OWED: SideTable<AttemptId, StopOwed, Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_STOP_OWED);

/// Marks `attempt`'s abandon owed in the Stop's writer, due again the
/// vault's Retry pause later, and raises the owner's notice for it. A mark
/// that is not written is logged; the Stop still commits.
pub(super) fn owe_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, attempt: AttemptId, now: u64) {
    let owed = (|| -> Result<()> {
        let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
        let owed = StopOwed {
            stopped_at: now,
            next_retry_at: paced(vault, &savepoint, now),
            escalated: false,
        };
        STOP_OWED.put(vault, &mut savepoint, &attempt, &owed)?;
        savepoint.commit()?;
        Ok(())
    })();
    match owed {
        Ok(()) => escalate_once_in_txn(vault, wtxn, attempt, now),
        Err(error) => tracing::warn!(
            kind = ?error.kind(),
            attempt = %bytes_to_hex_lower(attempt.as_bytes()),
            "a stopped turn program try's owed abandon was not marked; its pending sends stay \
             as they are"
        ),
    }
}

impl DreamerRunnerStore<'_> {
    /// Retries every owed Stop abandon that is due at `now`, each in a
    /// writer of its own: from each wake pass's start, on every wake host.
    /// Read-only first, so nothing due opens no write. Never fails its
    /// caller: each miss is logged and stays owed.
    pub(crate) fn recover_owed_stop_abandons(&self, now: u64) {
        let vault = self.vault;
        let due = (|| -> Result<Vec<AttemptId>> {
            let rtxn = vault.store.env.read_txn()?;
            Ok(STOP_OWED
                .scan(vault, &rtxn)?
                .into_iter()
                .filter(|(_, owed)| owed.next_retry_at <= now)
                .map(|(attempt, _)| attempt)
                .collect())
        })();
        let due = match due {
            Ok(due) => due,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "the owed abandons of stopped turn program tries were not read; the next \
                     pass retries"
                );
                return;
            }
        };
        if due.is_empty() {
            return;
        }
        for attempt in due {
            let retried =
                vault.with_write_txn_grouped(|wtxn| retry_in_txn(vault, wtxn, attempt, now));
            if let Err(error) = retried {
                tracing::warn!(
                    kind = ?error.kind(),
                    attempt = %bytes_to_hex_lower(attempt.as_bytes()),
                    "a stopped turn program try's owed abandon was not retried; it stays owed"
                );
            }
        }
        // The deadline lane arms the next owed retry anew.
        vault.store.notify_proactivity_changes();
    }

    /// When the next owed Stop abandon is due, in store-clock seconds:
    /// the deadline lane arms a wake pass for it. `None` with none owed.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn next_owed_stop_retry(&self) -> Result<Option<u64>> {
        let rtxn = self.vault.store.env.read_txn()?;
        Ok(STOP_OWED
            .scan(self.vault, &rtxn)?
            .into_iter()
            .map(|(_, owed)| owed.next_retry_at)
            .min())
    }
}

/// One owed abandon retried in `wtxn`, if it is still owed and due: the
/// abandon and the mark's removal commit together in a savepoint, or the
/// mark stays, due again the vault's pause later, and the owner's notice is
/// raised if it was not yet.
fn retry_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    now: u64,
) -> Result<()> {
    let Some(owed) = STOP_OWED.get(vault, &*wtxn, &attempt)? else {
        return Ok(());
    };
    if owed.next_retry_at > now {
        return Ok(());
    }
    let landed = (|| -> Result<usize> {
        let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
        let abandoned = abandon_sends_in_txn(vault, &mut savepoint, attempt, now)?;
        STOP_OWED.delete(vault, &mut savepoint, &attempt)?;
        savepoint.commit()?;
        Ok(abandoned)
    })();
    match landed {
        Ok(abandoned) => {
            tracing::info!(
                attempt = %bytes_to_hex_lower(attempt.as_bytes()),
                abandoned,
                "a stopped turn program try's owed abandon landed"
            );
            Ok(())
        }
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                attempt = %bytes_to_hex_lower(attempt.as_bytes()),
                "a stopped turn program try's owed abandon did not land; it stays owed"
            );
            let next_retry_at = paced(vault, wtxn, now);
            STOP_OWED.put(
                vault,
                wtxn,
                &attempt,
                &StopOwed {
                    next_retry_at,
                    ..owed
                },
            )?;
            if !owed.escalated {
                escalate_once_in_txn(vault, wtxn, attempt, now);
            }
            Ok(())
        }
    }
}

/// `now` plus the vault's resolved Retry pause in `txn`. A pause that
/// cannot be read makes the mark due at once: a retry is never delayed by a
/// read that failed, nor its mark lost.
fn paced(vault: &Vault, txn: &heed::RoTxn<'_>, now: u64) -> u64 {
    match vault.dreamer_retry_park_secs_in_txn(txn) {
        Ok(pause) => now.saturating_add(pause),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "the vault's retry pause was not read; an owed stop abandon is due at once"
            );
            now
        }
    }
}

/// Raises the owner's notice for `attempt`'s stuck Stop, once: one
/// NOTIFICATION per Stop, its id derived from the attempt, so a replay
/// finds the row it wrote. A notice that is not written is logged, and the
/// next failed retry raises it.
fn escalate_once_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, attempt: AttemptId, now: u64) {
    let raised = (|| -> Result<bool> {
        let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
        let Some(owed) = STOP_OWED.get(vault, &savepoint, &attempt)? else {
            return Ok(false);
        };
        if owed.escalated {
            return Ok(false);
        }
        let attempt_hex = bytes_to_hex_lower(attempt.as_bytes());
        vault.record_notification_in_txn(
            &mut savepoint,
            &NotificationEvent {
                kind: NotificationKind::Finding,
                source: NotificationSource {
                    producer: STOP_OWED_PRODUCER.to_owned(),
                    event: attempt_hex.clone(),
                    job_kind: Some(DREAMER_TURN_PROGRAM_ATTEMPT_KIND.to_owned()),
                    attempt: Some(attempt_hex),
                    detail: Some(STOP_OWED_DETAIL.to_owned()),
                    ..NotificationSource::default()
                },
                subject_refs: Vec::new(),
                recipient: None,
                created_at: now,
                origin_conversation: None,
            },
        )?;
        STOP_OWED.put(
            vault,
            &mut savepoint,
            &attempt,
            &StopOwed {
                escalated: true,
                ..owed
            },
        )?;
        savepoint.commit()?;
        Ok(true)
    })();
    match raised {
        Ok(true) => tracing::info!(
            attempt = %bytes_to_hex_lower(attempt.as_bytes()),
            "the owner was told a stopped turn program try's abandon is still owed"
        ),
        Ok(false) => {}
        Err(error) => tracing::warn!(
            kind = ?error.kind(),
            attempt = %bytes_to_hex_lower(attempt.as_bytes()),
            "the owner's notice of a stuck stop was not written; the next failed retry raises it"
        ),
    }
}
