//! Original native NET invoices. These rows never reserve funds or authorize work.

use serde::{Deserialize, Serialize};

use super::budget_line::AdmittedCallId;
use super::{DreamerRunnerStore, invalid_dreamer_runner, validate_budget_id};
use crate::Vault;
use crate::dreamer_wake::owed::WakeOwedCall;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideKey, SideTable};
use oneiron_model::llm::BudgetMeterRange;

const CALLS: SideTable<AdmittedCallId, NativeCallObligation, Named> =
    SideTable::new(&side_table::DREAMER_BUDGET_NATIVE_CALL);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeCallObligation {
    line: String,
    step_hash: [u8; 32],
    boot: [u8; 16],
    lease: String,
    reserved_units: u64,
    admitted_at: u64,
    invoice: NativeCallInvoice,
    terminal_claims: Vec<EntityId>,
    meter: NativeCallMeter,
    gross_coverage: NativeGrossCoverage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum NativeCallInvoice {
    /// No native response quantity is known. This is not a zero invoice.
    Admitted,
    /// Native input.total + output.total, before corrective aggregation.
    Invoiced { units: u64 },
    /// The original line's money and this fact committed in the same writer.
    Paid { units: u64, at: u64 },
}

/// A producer-observed interval, not a vault payment or cross-guard credit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum NativeCallMeter {
    Unknown,
    Settled {
        start_used_units: u64,
        end_used_units: u64,
    },
}

/// A real aggregate settlement included this lease's native meter interval.
/// GROSS inclusion alone does not settle its potentially different NET invoice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum NativeGrossCoverage {
    Unknown,
    Included {
        meter_start_used_units: u64,
        meter_end_used_units: u64,
        aggregate_units: u64,
        settled_units: u64,
        at: u64,
    },
}

/// Result of explicitly paying one retained native NET invoice. It says
/// nothing about whether an executor's aggregate includes that invoice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeCallPayment {
    Uninvoiced,
    Paid { units: u64 },
    AlreadyPaid { units: u64 },
}

impl SideKey for AdmittedCallId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.attempt_id.as_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.invocation.to_be_bytes());
        out.extend_from_slice(&self.ordinal.to_be_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        Some(Self {
            attempt_id: crate::attempt_queue::AttemptId::from_bytes(&bytes[..16]).ok()?,
            generation: u32::from_be_bytes(bytes[16..20].try_into().ok()?),
            invocation: u64::from_be_bytes(bytes[20..28].try_into().ok()?),
            ordinal: u32::from_be_bytes(bytes[28..32].try_into().ok()?),
        })
    }
}

/// Retain the original admission before bytes leave. Repeating registration
/// cannot replace its line, step, lease, invoice or paid fact.
pub(crate) fn retain_native_call_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    step_hash: [u8; 32],
    admitted: &WakeOwedCall,
) -> Result<()> {
    validate_budget_id(&admitted.line)?;
    let row = NativeCallObligation {
        line: admitted.line.clone(),
        step_hash,
        boot: admitted.boot,
        lease: admitted.lease.clone(),
        reserved_units: admitted.reserved_units,
        admitted_at: admitted.at,
        invoice: NativeCallInvoice::Admitted,
        terminal_claims: Vec::new(),
        meter: NativeCallMeter::Unknown,
        gross_coverage: NativeGrossCoverage::Unknown,
    };
    if let Some(existing) = CALLS.get(&vault.store, &*wtxn, &admitted.origin)? {
        let mut original = existing;
        original.invoice = NativeCallInvoice::Admitted;
        original.terminal_claims.clear();
        original.meter = NativeCallMeter::Unknown;
        original.gross_coverage = NativeGrossCoverage::Unknown;
        if original != row {
            return Err(invalid_dreamer_runner(
                "native call original admission differs",
            ));
        }
        return Ok(());
    }
    CALLS.put(&vault.store, wtxn, &admitted.origin, &row)
}

/// Keep the actual response quantity at its native producer, before schema
/// correction combines responses. Unknown or absent admissions stay unknown;
/// a repeated result may confirm but never replace the first invoice.
pub(crate) fn invoice_native_call_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    origin: AdmittedCallId,
    units: u64,
) -> Result<()> {
    let Some(mut row) = CALLS.get(&vault.store, &*wtxn, &origin)? else {
        return Err(invalid_dreamer_runner(
            "native call has no original admission",
        ));
    };
    match row.invoice {
        NativeCallInvoice::Admitted => {
            row.invoice = NativeCallInvoice::Invoiced { units };
            CALLS.put(&vault.store, wtxn, &origin, &row)
        }
        NativeCallInvoice::Invoiced { units: original }
        | NativeCallInvoice::Paid {
            units: original, ..
        } if units == original => Ok(()),
        _ => Err(invalid_dreamer_runner("native call invoice differs")),
    }
}

impl DreamerRunnerStore<'_> {
    /// Pay one native NET invoice from its original retained line, regardless
    /// of a later generation's reservation. This primitive is not called by
    /// the aggregate driver: that caller must first retain exact coverage of
    /// each invoice in its NET or GROSS charge. A scalar subtraction is not
    /// sufficient, and neither a logical memo nor a CONTENT mark is payment.
    pub(crate) fn pay_native_call_invoice_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        origin: AdmittedCallId,
        now: u64,
    ) -> Result<NativeCallPayment> {
        let Some(mut row) = CALLS.get(&self.vault.store, &*wtxn, &origin)? else {
            return Ok(NativeCallPayment::Uninvoiced);
        };
        let units = match row.invoice {
            NativeCallInvoice::Admitted => return Ok(NativeCallPayment::Uninvoiced),
            NativeCallInvoice::Paid { units, .. } => {
                return Ok(NativeCallPayment::AlreadyPaid { units });
            }
            NativeCallInvoice::Invoiced { units } => units,
        };
        self.charge_native_invoice_in_txn(wtxn, &row.line, origin.attempt_id, units, now)?;
        row.invoice = NativeCallInvoice::Paid { units, at: now };
        CALLS.put(&self.vault.store, wtxn, &origin, &row)?;
        Ok(NativeCallPayment::Paid { units })
    }
}

/// Bind every original physical call of an invocation to this actual terminal
/// claim. Recovery may emit another claim; it never replaces earlier aliases.
/// This optional record uses a child transaction, not the mutable memo index.
pub(crate) fn bind_native_call_terminal_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    origin: AdmittedCallId,
    attempt_id: crate::attempt_queue::AttemptId,
    step_hash: [u8; 32],
    claim: EntityId,
) {
    let written = (|| -> Result<()> {
        if origin.attempt_id != attempt_id || origin.ordinal != 0 {
            return Err(invalid_dreamer_runner(
                "native call terminal origin differs",
            ));
        }
        let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
        let mut prefix = Vec::new();
        origin.encode_into(&mut prefix);
        // The last four bytes are the corrective ordinal, not a new invocation.
        prefix.truncate(28);
        let calls = CALLS.scan_from(&vault.store, &savepoint, &prefix)?;
        for (call, mut row) in calls {
            if row.step_hash != step_hash {
                return Err(invalid_dreamer_runner("native call terminal step differs"));
            }
            if !row.terminal_claims.contains(&claim) {
                row.terminal_claims.push(claim);
                CALLS.put(&vault.store, &mut savepoint, &call, &row)?;
            }
        }
        savepoint.commit().map_err(Error::from)
    })();
    if let Err(error) = written {
        tracing::warn!(kind = ?error.kind(), %error, "native call terminal binding skipped");
    }
}

/// Retain the interval read from the original native guard and lease token.
/// Empty is a known settled interval; absence is not converted to zero.
pub(crate) fn record_native_call_meter_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    origin: AdmittedCallId,
    lease_id: &str,
    range: BudgetMeterRange,
) -> Result<()> {
    let Some(mut row) = CALLS.get(&vault.store, &*wtxn, &origin)? else {
        return Err(invalid_dreamer_runner(
            "native call has no original admission",
        ));
    };
    if row.lease != lease_id || range.end_used_units < range.start_used_units {
        return Err(invalid_dreamer_runner("native call meter binding differs"));
    }
    let settled = NativeCallMeter::Settled {
        start_used_units: range.start_used_units,
        end_used_units: range.end_used_units,
    };
    match row.meter {
        NativeCallMeter::Unknown => {
            row.meter = settled;
            CALLS.put(&vault.store, wtxn, &origin, &row)
        }
        _ if row.meter == settled => Ok(()),
        _ => Err(invalid_dreamer_runner("native call settled meter differs")),
    }
}

/// Optional source evidence in the aggregate's writer. Failed evidence rolls
/// back only its child transaction; the original charge and receipts stand.
pub(super) fn record_native_gross_settlement_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    settlement: &super::SettleDreamerBudget,
    settled_units: u64,
    native: &super::NativeMeterSnapshot,
) {
    let recorded = (|| -> Result<()> {
        let interval = native.interval();
        if !native.matches_settlement(&settlement.budget_id, settlement.child_attempt)
            || interval.end_used_units < interval.start_used_units
            || settlement.actual_units < interval.end_used_units - interval.start_used_units
        {
            return Err(invalid_dreamer_runner("native aggregate meter differs"));
        }
        let coverage = NativeGrossCoverage::Included {
            meter_start_used_units: interval.start_used_units,
            meter_end_used_units: interval.end_used_units,
            aggregate_units: settlement.actual_units,
            settled_units,
            at: settlement.now,
        };
        let mut child = vault.store.env.nested_write_txn(wtxn)?;
        for (origin, lease_id, range) in native.included_calls() {
            let Some(mut row) = CALLS.get(&vault.store, &child, &origin)? else {
                return Err(invalid_dreamer_runner("native aggregate admission missing"));
            };
            if row.line != settlement.budget_id || row.lease != lease_id {
                return Err(invalid_dreamer_runner("native aggregate original differs"));
            }
            let meter = NativeCallMeter::Settled {
                start_used_units: range.start_used_units,
                end_used_units: range.end_used_units,
            };
            if row.meter != NativeCallMeter::Unknown && row.meter != meter {
                return Err(invalid_dreamer_runner("native aggregate interval differs"));
            }
            if row.gross_coverage != NativeGrossCoverage::Unknown && row.gross_coverage != coverage
            {
                return Err(invalid_dreamer_runner("native aggregate coverage differs"));
            }
            row.meter = meter;
            row.gross_coverage = coverage.clone();
            CALLS.put(&vault.store, &mut child, &origin, &row)?;
        }
        child.commit().map_err(Error::from)
    })();
    if let Err(error) = recorded {
        tracing::warn!(kind = ?error.kind(), %error, "native aggregate inclusion skipped");
    }
}
