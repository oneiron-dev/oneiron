//! Where the server's run receipts go by default: one structured log line per
//! row. A row holds no credential and no prompt, only the request's digest.
use std::sync::{Arc, RwLock};

use oneiron::llm::ModelId;
use oneiron::llm::run_admission::{RunEvent, RunReceipt, RunReceiptSink};
use serde_json::{Value, json};

/// The log target every receipt row is written under.
pub const RUN_RECEIPT_TARGET: &str = "oneiron::run_receipt";

/// Logged in place of a model string that is not a model id.
const UNRECOGNISED: &str = "unrecognised";

/// Writes each run receipt row to the log as JSON.
#[derive(Debug, Default)]
pub struct LoggedReceipts;

impl RunReceiptSink for LoggedReceipts {
    fn record(&self, receipt: RunReceipt) {
        tracing::info!(target: RUN_RECEIPT_TARGET, row = %logged_row(&receipt));
    }
}

/// What a receipt's log line carries: ids, counts, codes and the request
/// digest (owner ruling 2026-10-14, fix 6). The run's name, a teacher's
/// purpose and a caller's selector are text someone wrote, and a provider may
/// report any string as the model it served, so none of them is logged as
/// given. The host's own sink still gets the whole receipt.
fn logged_row(receipt: &RunReceipt) -> Value {
    let revision = receipt.revision;
    match &receipt.event {
        RunEvent::Admitted(facts) => json!({
            "event": "admitted",
            "revision": revision,
            "lease": facts.lease,
            "subject": model(&facts.subject),
            "route": facts.route,
            "locality": facts.locality,
            "payer": facts.payer,
            "reserved_units": facts.reserved_units,
            "unit": facts.unit,
            "allocation_reserved_units": facts.allocation_reserved_units,
            "rules_enforced": facts.rules_enforced,
        }),
        RunEvent::Denied {
            subject,
            lease,
            reason,
            ..
        } => json!({
            "event": "denied",
            "revision": revision,
            "lease": lease,
            "subject": subject.as_deref().map(model),
            "reason": reason,
        }),
        RunEvent::Dispatched {
            lease,
            subject,
            route,
            request_digest,
            served_model,
            broker_isolation,
            answered,
        } => json!({
            "event": "dispatched",
            "revision": revision,
            "lease": lease,
            "subject": model(subject),
            "route": route,
            "request_digest": request_digest,
            "served_model": served_model.as_deref().map(model),
            "broker_isolation": broker_isolation,
            "answered": answered,
        }),
        RunEvent::Settled {
            lease,
            units,
            unit,
            allocation_units,
            error,
            allocation_error,
        } => json!({
            "event": "settled",
            "revision": revision,
            "lease": lease,
            "units": units,
            "unit": unit,
            "allocation_units": allocation_units,
            "refused": error.is_some(),
            "allocation_refused": allocation_error.is_some(),
        }),
        RunEvent::Revised { from, .. } => json!({
            "event": "revised",
            "revision": revision,
            "from": from,
        }),
    }
}

/// A model string as logged: itself when it is a model id, else a marker.
fn model(value: &str) -> &str {
    if ModelId::new(value).is_ok() {
        value
    } else {
        UNRECOGNISED
    }
}

/// The server's one receipt sink: it forwards each row to the sink the host
/// chose, the log until it chooses one. Whatever took this sink before the
/// host chose writes to the chosen sink too.
#[derive(Default)]
pub(crate) struct ServerReceipts {
    chosen: RwLock<Option<Arc<dyn RunReceiptSink>>>,
}

impl ServerReceipts {
    pub(crate) fn choose(&self, sink: Arc<dyn RunReceiptSink>) {
        *self.chosen.write().expect("receipt sink lock poisoned") = Some(sink);
    }
}

impl RunReceiptSink for ServerReceipts {
    fn record(&self, receipt: RunReceipt) {
        let chosen = self
            .chosen
            .read()
            .expect("receipt sink lock poisoned")
            .clone();
        match chosen {
            Some(sink) => sink.record(receipt),
            None => LoggedReceipts.record(receipt),
        }
    }
}
