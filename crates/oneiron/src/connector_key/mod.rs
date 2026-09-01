//! Connector-key registry records with effector budgets for OF-277 GOV-01.
//!
//! A CONNECTOR_KEY is an engine-authored, vault-resident
//! maintenance record that governs external-effect dispatch for one outbound
//! connector, optionally narrowed to one acting entity. Budgets (sends / spend
//! / rate) live on the record; live usage counters live in `vault_meta` rows
//! debited inside the outbound chokepoint's write transaction, so debit +
//! intent evidence + decision + (on exhaust-suspend) the key-status flip
//! commit atomically. The `charter` /
//! `pending_charter` slots are pinned in the v1 body so GOV-10 (ONE-1417) can
//! fill them without re-versioning the schema.

mod accounting;
mod charter;
mod codec;
mod lifecycle;
mod meter;
mod record;
mod txn;

#[cfg(test)]
mod tests;

pub use self::accounting::CONNECTOR_KEY_MAX_DISPATCH_BATCH;
pub use self::charter::{CompiledCharter, ConnectorCharterCompileIssue, compile_connector_charter};
pub use self::codec::{
    CONNECTOR_KEY_BODY_KEYS, CONNECTOR_KEY_SCHEMA_VERSION, decode_connector_key_body,
    encode_connector_key_body,
};
pub use self::meter::{
    CONNECTOR_KEY_CHARTER_ROW_BASE, ConnectorDispatchTelemetry, ConnectorKeyDispatchTally,
    EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE, EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE_ID,
    EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE, EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE_ID,
    EffectorBudgetCharge, EffectorBudgetRead, EffectorBudgetRowRead,
};
pub use self::record::{
    CONNECTOR_KEY_MAX_BUDGET_ROWS, CalendarPeriod, CompiledConnectorPolicy, ConnectorCharterBlock,
    ConnectorKeyRecord, ConnectorKeyStatus, EffectorBudget, EffectorBudgetDimension,
    EffectorBudgetOnExhaust, EffectorBudgetReservePolicy, EffectorBudgetWindow,
    PendingConnectorCharter,
};

pub(crate) use self::charter::{charter_block_drifted, charter_never_list_matches_capability};
pub(crate) use self::meter::{
    EffectorBudgetChargeOutcome, budget_exhausted_reason, charge_effector_budgets,
};
pub(crate) use self::record::normalize_connector_key;
pub(crate) use self::txn::{governing_connector_key, suspend_connector_key_in_txn};

// Crate-visible paths whose only live consumers are the test modules of sibling
// modules; gated so the non-test build carries no unused re-export.
#[cfg(test)]
pub(crate) use self::meter::connector_key_usage_row_key;
#[cfg(test)]
pub(crate) use self::txn::rewrite_connector_key_in_txn;

// The flat connector_key.rs module used to provide these names to the test
// module through `use super::*`; after the directory split the seam re-imports
// them so the sibling `tests.rs` resolves exactly as it did inline.
#[cfg(test)]
use self::accounting::connector_key_settle_event_key;
// `charter_never_list_matches` stays production-reachable through the capability
// matcher's delegation path; only this module's own tests name it directly.
#[cfg(test)]
use self::charter::{charter_never_list_matches, charter_stamped_aggregate};
#[cfg(test)]
use self::meter::{
    ConnectorKeyUsage, SECONDS_PER_DAY, calendar_window_start, effector_steering_signal,
};
#[cfg(test)]
use self::record::validate_compiled_policy;

#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::llm::{BudgetSignalDeliveryChannel, BudgetThreshold};
#[cfg(test)]
use crate::registry::ENTITY_TYPE_CONNECTOR_KEY;
