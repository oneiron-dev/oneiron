//! The native System One response's single aggregate measurement, not per-answer shares.

use super::{
    AdmittedCallId, CALLS, DreamerRunnerStore, Result, invalid_dreamer_runner,
    invoice_native_call_in_txn,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SystemOneTerminalUsage {
    input_tokens: u64,
    output_tokens: u64,
}

impl SystemOneTerminalUsage {
    pub(super) fn terminal_usage(&self) -> oneiron_model::llm::LlmUsage {
        let mut usage = oneiron_model::llm::LlmUsage::zero();
        usage.input.total = self.input_tokens;
        usage.output.total = self.output_tokens;
        usage.raw_provider = serde_json::json!({
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
        });
        usage
    }
}

impl DreamerRunnerStore<'_> {
    /// Source counters and the original invoice commit together. This does not
    /// settle the call or identify any logical answer's share of the measurement.
    pub(crate) fn record_native_systemone_usage_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        origin: AdmittedCallId,
        usage: &oneiron_model::llm::LlmUsage,
    ) -> Result<()> {
        let units = usage
            .input
            .total
            .checked_add(usage.output.total)
            .ok_or(crate::Error::ArithmeticOverflow("native System One usage"))?;
        let observed = SystemOneTerminalUsage {
            input_tokens: usage.input.total,
            output_tokens: usage.output.total,
        };
        let Some(mut row) = CALLS.get(&self.vault.store, &*wtxn, &origin)? else {
            return Err(invalid_dreamer_runner(
                "native call has no original admission",
            ));
        };
        match &row.systemone_usage {
            None => {
                row.systemone_usage = Some(observed);
                CALLS.put(&self.vault.store, wtxn, &origin, &row)?;
            }
            Some(original) if original == &observed => {}
            _ => {
                return Err(invalid_dreamer_runner(
                    "native System One observations differ",
                ));
            }
        }
        invoice_native_call_in_txn(self.vault, wtxn, origin, units)
    }
}

impl DreamerRunnerStore<'_> {
    /// Source-only write: no invoice, settlement, payment or coverage changes.
    pub(crate) fn record_native_systemone_response_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        origin: AdmittedCallId,
        response: &crate::dreamer_wake::DecisionSystemOneResponse,
    ) -> Result<()> {
        let Some(mut row) = CALLS.get(&self.vault.store, &*wtxn, &origin)? else {
            return Err(invalid_dreamer_runner(
                "native call has no original admission",
            ));
        };
        match &row.systemone_response {
            None => {
                row.systemone_response = Some(response.clone());
                CALLS.put(&self.vault.store, wtxn, &origin, &row)
            }
            Some(original) if original == response => Ok(()),
            _ => Err(invalid_dreamer_runner(
                "native System One raw responses differ",
            )),
        }
    }

    pub(crate) fn native_systemone_response(
        &self,
        origin: AdmittedCallId,
        boot: [u8; 16],
        line: &str,
        lease: &str,
    ) -> Result<Option<crate::dreamer_wake::DecisionSystemOneResponse>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let Some(row) = CALLS.get(&self.vault.store, &rtxn, &origin)? else {
            return Ok(None);
        };
        if row.boot != boot || row.line != line || row.lease != lease {
            return Err(invalid_dreamer_runner("native original admission differs"));
        }
        Ok(row.systemone_response)
    }
}
