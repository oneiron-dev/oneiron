//! Source quantities for the actual paid SystemOne permit, never per-answer shares.

use oneiron::llm::decision::{DecisionCallAdmission, SeatRead};
use oneiron_llm_systemone::{PreparedSystemOneRead, SystemOneHttpRequest, SystemOnePackRead};

use super::{SeatRequest, SystemOnePackReadRequest, SystemOneRung};

impl SystemOneRung {
    fn native_systemone_invoice<'a>(
        &'a self,
        sent: &SystemOneHttpRequest,
        admission: Option<&DecisionCallAdmission>,
    ) -> Option<oneiron::dreamer_wake::DecisionCallInvoice<'a>> {
        let admission = admission?;
        let input_hash = *blake3::hash(&sent.body).as_bytes();
        match admission.retain_native_input(&self.vault, input_hash) {
            Ok(invoice) => Some(invoice),
            Err(error) => {
                tracing::warn!(%error, "native SystemOne input was not retained");
                None
            }
        }
    }

    pub(super) async fn ask_single_request<'a>(
        &'a self,
        request: SeatRequest,
        prepared: Option<PreparedSystemOneRead<'a>>,
        lease: &'a oneiron::BudgetLease,
        time_left: std::time::Duration,
        release: Option<oneiron::llm::DispatchRelease<'a>>,
        admission: Option<&DecisionCallAdmission>,
    ) -> SeatRead {
        let prepared = match prepared {
            Some(prepared) => prepared,
            None => match self.seat.prepare_read(request, time_left).await {
                Ok(prepared) => prepared,
                Err(error) => {
                    return SeatRead {
                        request: None,
                        result: Err(error),
                    };
                }
            },
        };
        let invoice = self.native_systemone_invoice(prepared.request(), admission);
        let (read, response) = prepared.ask_observed(lease, time_left, release).await;
        if let Some(invoice) = invoice {
            if let Some(response) = response
                && let Err(error) = invoice.record_systemone_response(&response)
            {
                tracing::warn!(%error, "native SystemOne raw response was not retained");
            }
            if let Ok(answer) = &read.result
                && let Err(error) = invoice.record_systemone_usage(&answer.usage)
            {
                tracing::warn!(%error, "native SystemOne quantity was not retained");
            }
        }
        read
    }

    pub(super) async fn ask_pack_request<'a>(
        &'a self,
        request: SystemOnePackReadRequest<'a>,
        lease: &'a oneiron::BudgetLease,
        time_left: std::time::Duration,
        release: Option<oneiron::llm::DispatchRelease<'a>>,
        admission: Option<&DecisionCallAdmission>,
    ) -> SystemOnePackRead {
        let prepared = match request {
            SystemOnePackReadRequest::Prepared(prepared) => prepared,
            SystemOnePackReadRequest::Logical(request) => {
                match self.seat.prepare_pack_read(request, time_left).await {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        return SystemOnePackRead {
                            request: None,
                            result: Err(error),
                        };
                    }
                }
            }
        };
        let invoice = self.native_systemone_invoice(prepared.request(), admission);
        let (read, response) = prepared.ask_observed(lease, time_left, release).await;
        if let Some(invoice) = invoice {
            if let Some(response) = response
                && let Err(error) = invoice.record_systemone_response(&response)
            {
                tracing::warn!(%error, "native SystemOne raw response was not retained");
            }
            if let Ok(answer) = &read.result
                && let Err(error) = invoice.record_systemone_usage(&answer.usage)
            {
                tracing::warn!(%error, "native SystemOne quantity was not retained");
            }
        }
        read
    }
}

/// A failed read keeps unknown usage unless its same original call already has
/// complete source counters. The evidence lookup never replaces its error.
pub(super) fn retained_native_usage(
    admission: Option<&DecisionCallAdmission>,
) -> Option<oneiron::LlmUsage> {
    let admission = admission?;
    match admission.terminal_usage() {
        Ok(Some(usage)) => Some(usage),
        Ok(None) => match admission.systemone_response() {
            Ok(response) => response.and_then(|response| response.observed_usage()),
            Err(error) => {
                tracing::warn!(%error, "native SystemOne raw response was not available");
                None
            }
        },
        Err(error) => {
            tracing::warn!(%error, "native SystemOne quantity was not available");
            None
        }
    }
}
