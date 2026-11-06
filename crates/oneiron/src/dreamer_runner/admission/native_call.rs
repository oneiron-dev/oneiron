//! Original native NET invoices. These rows never reserve funds or authorize work.

use serde::{Deserialize, Serialize};

use super::budget_line::AdmittedCallId;
use super::{DreamerRunnerStore, invalid_dreamer_runner, validate_budget_id};
use crate::Vault;
use crate::dreamer_wake::owed::WakeOwedCall;
use crate::error::Result;
use crate::side_table::{self, Named, SideKey, SideTable};

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
    };
    if let Some(existing) = CALLS.get(&vault.store, &*wtxn, &admitted.origin)? {
        let mut original = existing;
        original.invoice = NativeCallInvoice::Admitted;
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
