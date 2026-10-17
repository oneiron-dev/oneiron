//! Where the server's run receipts go by default: one structured log line per
//! row. A row holds no credential and no prompt, only the request's digest.
use std::sync::{Arc, RwLock};

use oneiron::llm::ModelId;
use oneiron::llm::run_admission::{LeaseUnit, RunDenied, RunEvent, RunReceipt, RunReceiptSink};
use serde_json::{Value, json};

/// The log target every receipt row is written under.
pub const RUN_RECEIPT_TARGET: &str = "oneiron::run_receipt";

/// Logged in place of a string that is not the id its field names.
const UNRECOGNISED: &str = "unrecognised";

/// The names this server gives the runs it starts itself: `ai_host`'s
/// `CODE_MODE_RUN`, `COMPACTION_RUN` and `DREAMER_PASS_RUN`, the embedder's
/// `EMBEDDING_RUN` and `raw`'s `RAW_RUN`. A run renamed at its source logs as
/// unrecognised.
const SERVER_RUNS: [&str; 5] = [
    "code-mode",
    "code-mode-compaction",
    "dreamer-pass",
    "remote-embedding",
    "raw-inference",
];

/// A recall rerank's run: this name, `:` and a random hex suffix
/// (`server::recall_rerank`).
const RECALL_RERANK_RUN: &str = "recall-rerank";

/// Writes each run receipt row to the log as JSON.
#[derive(Debug, Default)]
pub struct LoggedReceipts;

impl RunReceiptSink for LoggedReceipts {
    fn record(&self, receipt: RunReceipt) {
        tracing::info!(target: RUN_RECEIPT_TARGET, row = %logged_row(&receipt));
    }
}

/// What a receipt's log line carries: ids, counts, codes and the request
/// digest (owner ruling 2026-10-14, fix 6). A run's name is text someone
/// wrote unless this server named it, so only the server's own run names are
/// logged. A teacher's purpose and a caller's selector are text someone
/// wrote, a lease id begins with the run's name, a refusal can name a
/// caller's connector, and a provider may report any string as the model it
/// served, so none of them is logged as given. A route, a unit and a digest
/// come from a host's config or backend as free strings, so each is logged
/// only when it is an id. The host's own sink still gets the whole receipt.
fn logged_row(receipt: &RunReceipt) -> Value {
    let revision = receipt.revision;
    let mut row = match &receipt.event {
        RunEvent::Admitted(facts) => json!({
            "event": "admitted",
            "revision": revision,
            "lease_seq": lease_seq(&facts.lease),
            "subject": model(&facts.subject),
            "route": id(&facts.route),
            "locality": facts.locality,
            "payer": facts.payer,
            "reserved_units": facts.reserved_units,
            "unit": unit_name(&facts.unit),
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
            "lease_seq": lease.as_deref().and_then(lease_seq),
            "subject": subject.as_deref().map(model),
            "reason": denial_kind(reason),
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
            "lease_seq": lease_seq(lease),
            "subject": model(subject),
            "route": id(route),
            "request_digest": id(request_digest),
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
            dispatched,
            usage,
            service_quantity,
        } => json!({
            "event": "settled",
            "revision": revision,
            "lease_seq": lease_seq(lease),
            "units": units,
            "unit": unit_name(unit),
            "allocation_units": allocation_units,
            "dispatched": dispatched,
            "usage": usage,
            "service_quantity": service_quantity,
            "refused": error.is_some(),
            "allocation_refused": allocation_error.is_some(),
        }),
        RunEvent::Revised { from, .. } => json!({
            "event": "revised",
            "revision": revision,
            "from": from,
        }),
    };
    row["run"] = Value::from(run_name(&receipt.run));
    row
}

/// A run as logged: a run this server started, by its name, else a marker.
fn run_name(run: &str) -> &'static str {
    if let Some(name) = SERVER_RUNS.into_iter().find(|name| *name == run) {
        return name;
    }
    match run.split_once(':') {
        Some((RECALL_RERANK_RUN, suffix))
            if !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            RECALL_RERANK_RUN
        }
        _ => UNRECOGNISED,
    }
}

/// A lease as logged: its sequence number in the run, the last `:` field of
/// the id. The id begins with the run's name, so no other part of it is.
fn lease_seq(lease: &str) -> Option<u64> {
    lease.rsplit(':').next()?.parse().ok()
}

/// A refusal as logged: its closed kind, never a field a variant carries.
fn denial_kind(reason: &RunDenied) -> Value {
    serde_json::to_value(reason)
        .ok()
        .and_then(|value| value.get("kind").cloned())
        .unwrap_or_else(|| Value::from(UNRECOGNISED))
}

/// A model string as logged: itself when it is a model id, else a marker.
fn model(value: &str) -> &str {
    if ModelId::new(value).is_ok() {
        value
    } else {
        UNRECOGNISED
    }
}

/// A unit as logged: itself when it is a unit name, else a marker. A unit
/// read from serialized config skips [`LeaseUnit::new`]'s grammar.
fn unit_name(value: &LeaseUnit) -> &str {
    if LeaseUnit::new(value.as_str()).is_ok() {
        value.as_str()
    } else {
        UNRECOGNISED
    }
}

/// A route or digest as logged: itself when it is an id (ASCII letters,
/// digits and `.` `_` `-` `:` `/` `@`, at most 256 bytes), else a marker.
fn id(value: &str) -> &str {
    let id_byte =
        |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'/' | b'@');
    if !value.is_empty() && value.len() <= 256 && value.bytes().all(id_byte) {
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
    usage: RwLock<Option<Arc<crate::runtime::VaultUsage>>>,
    /// The vault whose `host.budget.hit` hooks a spent line runs.
    hooks: Option<Arc<oneiron::Vault>>,
}

impl ServerReceipts {
    /// The server's sink, running its vault's budget-hit hooks.
    pub(crate) fn hooked(vault: Arc<oneiron::Vault>) -> Self {
        Self {
            hooks: Some(vault),
            ..Self::default()
        }
    }

    pub(crate) fn meter(&self, usage: Arc<crate::runtime::VaultUsage>) {
        *self.usage.write().expect("usage sink lock poisoned") = Some(usage);
    }

    pub(crate) fn usage(&self) -> Option<Arc<crate::runtime::VaultUsage>> {
        self.usage.read().expect("usage sink lock poisoned").clone()
    }

    pub(crate) fn choose(&self, sink: Arc<dyn RunReceiptSink>) {
        *self.chosen.write().expect("receipt sink lock poisoned") = Some(sink);
    }
}

impl RunReceiptSink for ServerReceipts {
    fn record(&self, receipt: RunReceipt) {
        if let Some(usage) = self.usage() {
            usage.record(&receipt);
        }
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

    fn budget_hit(
        &self,
        seat: &str,
        guard: &oneiron::BudgetGuard,
        denied: &oneiron::llm::BudgetDenied,
    ) {
        if let Some(vault) = &self.hooks {
            vault.budget_denied_hooks(denied, guard, seat, None);
        }
    }
}
