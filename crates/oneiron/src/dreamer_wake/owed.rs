//! The wake's owed paid calls (FIX 11450): a paid model call a crash left unsettled.
//!
//! A Dreamer wake attempt's paid call is charged when the attempt settles. If
//! the process dies after the call and before that settle, the spend is never
//! charged. What survives is the step layer's terminal `dreamer.step` claim,
//! whose stored response carries `usage`.
//!
//! Each paid send writes one row before it goes, keyed by attempt and step
//! hash, naming the attempt's budget line, the lease, what the lease reserved
//! and the boot that wrote it. Every settle deletes its attempt's rows in the
//! same write as the charge. The next wake's start reconciles what a dead boot
//! left: a row whose step already reads charged charges nothing, a row with
//! terminal usage charges its attempt's line, and a row with no terminal usage
//! is dropped as unspent, warned. The charge and the deletes commit in one
//! write, so a second wake finds nothing left to charge.

use std::collections::BTreeMap;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{
    DreamerBudgetSettlementOutcome, DreamerRunnerStore, SettleDreamerBudget,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result, SideTableRowProblem};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

/// One paid wake call not yet settled: the line it charges, the lease that
/// admitted it, what that lease reserved, the boot that wrote the row and
/// when, in Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WakeOwedCall {
    pub(crate) boot: [u8; 16],
    pub(crate) line: String,
    pub(crate) lease: String,
    pub(crate) reserved_units: u64,
    pub(crate) at: u64,
}

/// Owed paid calls. Key: id16(attempt) + hash32(step).
const OWED: SideTable<(AttemptId, [u8; 32]), WakeOwedCall, Raw> =
    SideTable::new(&side_table::DREAMER_WAKE_OWED_CALL);

/// The row's bytes: the boot, each string after its u16be length, then the
/// reserved units and the stamp, each u64be.
impl RawValue for WakeOwedCall {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut out = Vec::with_capacity(16 + 2 + self.line.len() + 2 + self.lease.len() + 8 + 8);
        out.extend_from_slice(&self.boot);
        push_str(&mut out, &self.line)?;
        push_str(&mut out, &self.lease)?;
        out.extend_from_slice(&self.reserved_units.to_be_bytes());
        out.extend_from_slice(&self.at.to_be_bytes());
        Ok(out)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let mut rest = bytes;
        let boot: [u8; 16] = take(&mut rest, 16)?.try_into().map_err(|_| undecodable())?;
        let line = take_str(&mut rest)?;
        let lease = take_str(&mut rest)?;
        let reserved_units =
            u64::from_be_bytes(take(&mut rest, 8)?.try_into().map_err(|_| undecodable())?);
        let at = u64::from_be_bytes(take(&mut rest, 8)?.try_into().map_err(|_| undecodable())?);
        if !rest.is_empty() {
            return Err(CodecError::Row(SideTableRowProblem::TrailingBytes));
        }
        Ok(Self {
            boot,
            line,
            lease,
            reserved_units,
            at,
        })
    }
}

fn push_str(out: &mut Vec<u8>, text: &str) -> std::result::Result<(), CodecError> {
    let len =
        u16::try_from(text.len()).map_err(|_| CodecError::Row(SideTableRowProblem::Unencodable))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

fn take<'a>(rest: &mut &'a [u8], len: usize) -> std::result::Result<&'a [u8], CodecError> {
    let (head, tail) = rest.split_at_checked(len).ok_or_else(undecodable)?;
    *rest = tail;
    Ok(head)
}

fn take_str(rest: &mut &[u8]) -> std::result::Result<String, CodecError> {
    let len = u16::from_be_bytes(take(rest, 2)?.try_into().map_err(|_| undecodable())?) as usize;
    let bytes = take(rest, len)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| undecodable())
}

fn undecodable() -> CodecError {
    CodecError::Row(SideTableRowProblem::Undecodable)
}

/// Writes the owed row for one paid send, overwriting the same step's: a
/// schema correction's second send for one step replaces the first, which is
/// right, since only the last send's lease can still settle.
pub(crate) fn put_owed_call_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    step_hash: &[u8; 32],
    row: &WakeOwedCall,
) -> Result<()> {
    OWED.put(&vault.store, wtxn, &(attempt, *step_hash), row)
}

/// Removes every owed row of one attempt.
pub(crate) fn delete_attempt_owed_calls_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
) -> Result<()> {
    OWED.delete_from(&vault.store, wtxn, attempt.as_bytes())?;
    Ok(())
}

/// Reconciles what dead boots left owed: each row from another boot whose
/// step already reads charged charges nothing, each row with terminal usage
/// charges its attempt's line, and a row with no terminal usage is dropped
/// as unspent, warned. A row from this boot is a live call of this process
/// and is left. The charge and the deletes commit in one write. Returns the
/// rows charged and the rows dropped.
pub(crate) fn reconcile_owed_calls(vault: &Vault, now: u64) -> Result<(u64, u64)> {
    vault.with_write_txn_grouped(|wtxn| {
        let boot = vault.active_wakes.boot();
        let store = DreamerRunnerStore::new(vault);
        let mut sums: BTreeMap<(AttemptId, String), u64> = BTreeMap::new();
        let mut charged = 0u64;
        let mut dropped = 0u64;
        for ((attempt, step_hash), row) in OWED.scan(&vault.store, &*wtxn)? {
            if row.boot == boot {
                continue;
            }
            if store.step_charge_marked_in_txn(&*wtxn, attempt, &step_hash)? {
                sums.entry((attempt, row.line)).or_insert(0);
                continue;
            }
            let usage = crate::llm::settled_step_usage_in_txn(vault, &*wtxn, attempt, &step_hash)
                .map_err(|_| {
                Error::InvalidClaimBody("owed wake call step usage did not decode")
            })?;
            match usage {
                Some(usage) => {
                    let units = crate::dreamer_consolidation::step_charge::usage_units(&usage);
                    let sum = sums.entry((attempt, row.line)).or_insert(0);
                    *sum = sum.saturating_add(units);
                    charged += 1;
                }
                None => {
                    tracing::warn!(
                        lease = %row.lease,
                        attempt = %bytes_to_hex_lower(attempt.as_bytes()),
                        step = %bytes_to_hex_lower(&step_hash),
                        reserved_units = row.reserved_units,
                        "owed wake call never completed; dropping as unspent"
                    );
                    sums.entry((attempt, row.line)).or_insert(0);
                    dropped += 1;
                }
            }
        }
        for ((attempt, line), sum) in sums {
            let outcome = store.settle_budget_in_txn(
                wtxn,
                SettleDreamerBudget {
                    budget_id: line.clone(),
                    child_attempt: attempt,
                    actual_units: sum,
                    now,
                },
            )?;
            match outcome {
                DreamerBudgetSettlementOutcome::Settled(_) => {}
                DreamerBudgetSettlementOutcome::NoReservation => {
                    if sum > 0 {
                        let mut budget = store.owing_budget_in_txn(wtxn, &line)?;
                        store.owe_usage_in_txn(wtxn, &mut budget, attempt, sum, now)?;
                    }
                    delete_attempt_owed_calls_in_txn(vault, wtxn, attempt)?;
                }
            }
        }
        Ok((charged, dropped))
    })
}
