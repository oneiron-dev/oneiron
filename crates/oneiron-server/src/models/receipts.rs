//! Where the server's run receipts go by default: one structured log line per
//! row. A row holds no credential and no prompt, only the request's digest.
use std::sync::{Arc, RwLock};

use oneiron::llm::run_admission::{RunReceipt, RunReceiptSink};

/// The log target every receipt row is written under.
pub const RUN_RECEIPT_TARGET: &str = "oneiron::run_receipt";

/// Writes each run receipt row to the log as JSON.
#[derive(Debug, Default)]
pub struct LoggedReceipts;

impl RunReceiptSink for LoggedReceipts {
    fn record(&self, receipt: RunReceipt) {
        match serde_json::to_string(&receipt) {
            Ok(row) => tracing::info!(target: RUN_RECEIPT_TARGET, run = %receipt.run, %row),
            Err(error) => {
                tracing::error!(target: RUN_RECEIPT_TARGET, run = %receipt.run, %error, "a run receipt did not serialize");
            }
        }
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
