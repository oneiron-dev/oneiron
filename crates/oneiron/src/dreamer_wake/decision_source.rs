//! Original caller provenance for a native decision read, never an execution grant.

use super::WakePassDeadline;
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::AdmittedCallId;
use oneiron_model::llm::{BudgetAccountingSnapshot, BudgetGuard, BudgetLease};

/// The original admitted line of a scoped caller. Merely carrying this value
/// allocates nothing; the native read draws its own invocation after admission.
#[derive(Clone, Copy)]
pub struct DecisionCallSource<'a> {
    deadline: &'a WakePassDeadline,
    attempt_id: AttemptId,
    boot: [u8; 16],
}

impl<'a> DecisionCallSource<'a> {
    pub(crate) fn new(
        vault: &Vault,
        deadline: &'a WakePassDeadline,
        attempt_id: AttemptId,
    ) -> Self {
        Self {
            deadline,
            attempt_id,
            boot: vault.active_wakes.boot(),
        }
    }

    pub(crate) fn admitted(
        &self,
        guard: &BudgetGuard,
        lease: &BudgetLease,
    ) -> crate::Result<Option<DecisionCallAdmission>> {
        Ok(self
            .deadline
            .admitted_call_id(self.attempt_id)?
            .map(|origin| {
                if let Some(line) = self.deadline.original_budget_line() {
                    line.retain_native_lease(origin, lease);
                }
                DecisionCallAdmission {
                    origin,
                    guard: guard.clone(),
                    lease: lease.clone(),
                    boot: self.boot,
                    line: self
                        .deadline
                        .admitted_budget_line(self.attempt_id)
                        .map(str::to_owned),
                    reserved_units: guard.reserved_for(lease),
                    admitted_at: crate::unix_seconds_now(),
                }
            }))
    }
}

/// One native admission's original coordinate and the actual issuing guard and
/// lease. A snapshot is GROSS meter data, not a NET invoice or a paid receipt.
#[derive(Clone)]
pub struct DecisionCallAdmission {
    pub(crate) origin: AdmittedCallId,
    pub(crate) guard: BudgetGuard,
    pub(crate) lease: BudgetLease,
    boot: [u8; 16],
    line: Option<String>,
    reserved_units: Option<u64>,
    admitted_at: u64,
}

/// A native producer whose original admission was retained before its read.
/// Recording its response quantity never pays or authorizes the call.
pub struct DecisionCallInvoice<'a> {
    vault: &'a Vault,
    origin: AdmittedCallId,
}

impl DecisionCallInvoice<'_> {
    /// Records the native terminal quantity, not a quote or a GROSS meter delta.
    pub fn record_usage(&self, usage: &oneiron_model::llm::LlmUsage) -> crate::Result<()> {
        let units = usage
            .input
            .total
            .checked_add(usage.output.total)
            .ok_or(crate::Error::ArithmeticOverflow("native decision usage"))?;
        self.vault.with_write_txn_grouped(|wtxn| {
            crate::dreamer_runner::invoice_native_call_in_txn(self.vault, wtxn, self.origin, units)
        })
    }
}

impl DecisionCallAdmission {
    /// Retains the actual native input plan on this admission before bytes leave.
    /// The returned producer can record usage only in this original vault boot.
    /// Failure is evidence loss; callers keep the ordinary read and settlement.
    pub fn retain_native_input<'a>(
        &self,
        vault: &'a Vault,
        input_hash: [u8; 32],
    ) -> crate::Result<DecisionCallInvoice<'a>> {
        let invalid = || crate::Error::InvalidConfig("native decision admission differs".into());
        if vault.active_wakes.boot() != self.boot {
            return Err(invalid());
        }
        let admitted = crate::dreamer_wake::owed::WakeOwedCall {
            origin: self.origin,
            boot: self.boot,
            line: self.line.clone().ok_or_else(invalid)?,
            lease: self.lease.id().to_owned(),
            reserved_units: self.reserved_units.ok_or_else(invalid)?,
            at: self.admitted_at,
        };
        vault.with_write_txn_grouped(|wtxn| {
            crate::dreamer_runner::retain_native_call_in_txn(vault, wtxn, input_hash, &admitted)
        })?;
        Ok(DecisionCallInvoice {
            vault,
            origin: self.origin,
        })
    }

    /// Samples this exact lease through its issuing guard, including unknown
    /// and unstarted states. Its public lease id is never used to reconstruct it.
    #[must_use]
    pub fn accounting_snapshot(&self) -> BudgetAccountingSnapshot {
        self.guard.accounting_snapshot(&[&self.lease])
    }
}

impl std::fmt::Debug for DecisionCallAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecisionCallAdmission")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl PartialEq for DecisionCallAdmission {
    fn eq(&self, other: &Self) -> bool {
        self.origin == other.origin && self.lease == other.lease
    }
}

impl Eq for DecisionCallAdmission {}
