//! The run admission's receipts: every admission, refusal, dispatch,
//! settlement and revision, keyed by lease. A row never holds a credential, an
//! auth header or a prompt; a request appears only as its digest.
use std::sync::Mutex;

use serde::Serialize;

use super::super::{
    BrokerIsolation, BudgetDenied, LlmInputUsage, LlmOutputUsage, ModelId, ModelLocality,
};
use super::admission::RunDenied;
use super::declaration::{DeclarationEditor, LeaseUnit};
use super::host::{AllocationRef, Payer, PayerPerson};
use crate::EntityId;

/// One receipt row, with the run and the declaration revision it ran under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunReceipt {
    /// Unique even when a host reuses a run name and a meter starts over.
    pub instance: EntityId,
    pub occurred_at: u64,
    pub run: String,
    pub revision: u32,
    #[serde(flatten)]
    pub event: RunEvent,
}

/// What happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum RunEvent {
    Admitted(Box<PermitFacts>),
    Denied {
        #[serde(skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        subject: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        lease: Option<String>,
        reason: RunDenied,
    },
    /// The call passed the dispatch check and went out.
    Dispatched {
        lease: String,
        subject: String,
        route: String,
        request_digest: String,
        /// The model the provider reported serving, when it reported one.
        #[serde(skip_serializing_if = "Option::is_none")]
        served_model: Option<String>,
        /// How the credential broker that sent the call is kept apart from
        /// the daemon, when one sent it.
        #[serde(skip_serializing_if = "Option::is_none")]
        broker_isolation: Option<BrokerIsolation>,
        answered: bool,
    },
    Settled {
        lease: String,
        dispatched: bool,
        /// Provider token counts only; raw provider payloads never enter a receipt.
        #[serde(skip_serializing_if = "Option::is_none")]
        usage: Option<RunTokenUsage>,
        #[serde(skip_serializing_if = "Option::is_none")]
        service_quantity: Option<u64>,
        /// A metered stream's audio, alongside its charge in `units`.
        #[serde(skip_serializing_if = "Option::is_none")]
        stream: Option<RunStreamUsage>,
        units: u64,
        unit: LeaseUnit,
        #[serde(skip_serializing_if = "Option::is_none")]
        allocation_units: Option<u64>,
        /// A settlement the run's meter refused. It is kept here, never
        /// dropped.
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<BudgetDenied>,
        /// A settlement the allocation's meter refused.
        #[serde(skip_serializing_if = "Option::is_none")]
        allocation_error: Option<BudgetDenied>,
    },
    Revised {
        editor: DeclarationEditor,
        from: u32,
    },
}

/// One metered stream's audio: the milliseconds it admitted and the bound
/// its permit reserved for. Admitted audio is what the stream sent, not what
/// the provider billed or the person heard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RunStreamUsage {
    pub admitted_ms: u64,
    pub bound_ms: u64,
}

/// Token facts reported by one physical model call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunTokenUsage {
    pub input: LlmInputUsage,
    pub output: LlmOutputUsage,
}

/// Everything one permit binds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PermitFacts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    /// The model id, or the paid connector.
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelId>,
    pub offer: String,
    pub route: String,
    pub locality: ModelLocality,
    pub payer: Payer,
    /// The PERSON, root spend scope and billing account a room-paid call
    /// bills, bound at admission (OF-531); `None` when no room pays.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer_person: Option<PayerPerson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_revision: Option<String>,
    pub lease: String,
    pub reserved_units: u64,
    pub unit: LeaseUnit,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allocation: Option<AllocationRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allocation_unit: Option<LeaseUnit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allocation_reserved_units: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub teacher_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// The seat the call was admitted on (its metered seat), so the meter
    /// can attribute the call to one seat. `None` for a paid connector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seat: Option<String>,
    /// False when the run's teacher and budget rules do not hold for this
    /// call: a BYO seat, or a T1 key the owner allowed.
    pub rules_enforced: bool,
}

/// Where a run admission writes its receipts. The host persists or ships
/// them; the engine never reads them back to decide.
pub trait RunReceiptSink: Send + Sync {
    fn record(&self, receipt: RunReceipt);

    /// A line the run draws on refused a reservation (`host.budget.hit`):
    /// `seat` is the model, connector or allocation it refused, and `guard`
    /// the line's meter. A sink with no vault runs no hooks.
    fn budget_hit(&self, seat: &str, guard: &super::super::BudgetGuard, denied: &BudgetDenied) {
        let _ = (seat, guard, denied);
    }
}

/// Receipts kept in memory, in order.
#[derive(Debug, Default)]
pub struct MemoryReceipts {
    rows: Mutex<Vec<RunReceipt>>,
}

impl MemoryReceipts {
    #[must_use]
    pub fn rows(&self) -> Vec<RunReceipt> {
        self.rows.lock().expect("receipt mutex poisoned").clone()
    }
}

impl RunReceiptSink for MemoryReceipts {
    fn record(&self, receipt: RunReceipt) {
        self.rows
            .lock()
            .expect("receipt mutex poisoned")
            .push(receipt);
    }
}

/// The declared teachers next to the teachers called.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TeacherReport {
    pub declared: Vec<ModelId>,
    pub called: Vec<CalledTeacher>,
}

/// One dispatched model call of the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CalledTeacher {
    pub model: ModelId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub served_model: Option<String>,
    pub request_digest: String,
    pub lease: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settled_units: Option<u64>,
}
