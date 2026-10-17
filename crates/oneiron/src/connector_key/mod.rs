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
mod channel_subscription;
mod charter;
mod codec;
pub mod events;
mod lifecycle;
mod manifest_drift;
mod meter;
pub mod qualification;
mod record;
mod setup;
mod slate;
mod slate_draft;
mod slate_setting;
mod txn;

#[cfg(test)]
mod tests;

pub use self::accounting::{CONNECTOR_KEY_MAX_DISPATCH_BATCH, ConnectorKeySendAdmission};
pub use self::channel_subscription::ChannelMessageSubscription;
pub use self::charter::{CompiledCharter, ConnectorCharterCompileIssue, compile_connector_charter};
pub use self::codec::{
    CONNECTOR_KEY_BODY_KEYS, CONNECTOR_KEY_SCHEMA_VERSION, decode_connector_key_body,
    encode_connector_key_body,
};
pub use self::lifecycle::{
    ActorConnectorRegistration, CONNECTOR_CONSENT_ORIGIN_ACTION_ID,
    CONNECTOR_CONSENT_ORIGIN_COMPONENT_ID, ConnectorCallRoute, ConnectorConsentRowView,
    ConnectorConsentTarget, ConnectorConsentView, ConnectorDescription, ConnectorManifestQualifier,
    ConnectorQualificationError, ConnectorToolConsent, ConnectorToolConsentRow, ConnectorToolGrant,
    ProbeManifestQualifier,
};
pub use self::meter::{
    CONNECTOR_KEY_CHARTER_ROW_BASE, ConnectorDispatchTelemetry, ConnectorKeyDispatchTally,
    EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE, EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE_ID,
    EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE, EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE_ID,
    EffectorBudgetCharge, EffectorBudgetRead, EffectorBudgetRowRead,
};
pub use self::record::{
    CONNECTOR_KEY_MAX_BUDGET_ROWS, CalendarPeriod, CompiledConnectorPolicy, ConnectorCallClass,
    ConnectorCatalogEntry, ConnectorCharterBlock, ConnectorKeyRecord, ConnectorKeySpec,
    ConnectorKeyStatus, EffectorBudget, EffectorBudgetDimension, EffectorBudgetOnExhaust,
    EffectorBudgetReservePolicy, EffectorBudgetWindow, PendingConnectorCharter,
    PendingConnectorManifest,
};
pub use self::setup::{
    BROWSER_SESSION_CHECK, GMAIL_PROFILE_CHECK, LINE_BOT_INFO_CHECK, LINKEDIN_SESSION_CHECK,
    NATIVE_MAIL_JMAP_CHECK, PACK_CONNECTION_ACTOR_CLASS, PackConnectionCheck,
    PackConnectionEvidence, PackConnectionVerifier, ProviderConnectionChecks,
    SLACK_AUTH_TEST_CHECK,
};
pub use self::txn::ConnectorKeyGeneration;

pub(crate) use self::charter::{
    charter_block_drifted, charter_never_list_matches, charter_never_list_matches_capability,
    charter_never_list_matches_scoped_channel,
};
pub(crate) use self::lifecycle::{catalog_charter_in_txn, scoped_server_debits_sends_in_txn};
pub(crate) use self::meter::{
    EffectorBudgetChargeOutcome, budget_exhausted_reason, charge_effector_budgets,
    charge_effector_budgets_pooled, preflight_effector_budgets_pooled, shares_budget_pool,
};
pub(crate) use self::record::{
    ScopedCapabilityProvenance, canonical_scoped_server_segment, normalize_connector_key,
};
pub(crate) use self::slate::read_connector_slate_in_txn;
pub(crate) use self::txn::{governing_connector_key, suspend_connector_key_in_txn};

// Crate-visible paths whose only live consumers are the test modules of sibling
// modules; gated so the non-test build carries no unused re-export.
#[cfg(test)]
pub(crate) use self::txn::rewrite_connector_key_in_txn;

// The flat connector_key.rs module used to provide these names to the test
// module through `use super::*`; after the directory split the seam re-imports
// them so the sibling `tests.rs` resolves exactly as it did inline.
#[cfg(test)]
use self::accounting::SETTLE_EVENT;
#[cfg(test)]
use self::charter::charter_stamped_aggregate;
#[cfg(test)]
use self::meter::{SECONDS_PER_DAY, calendar_window_start};
#[cfg(test)]
use self::record::validate_compiled_policy;
#[cfg(test)]
use self::txn::{CATALOG_NAME_INDEX, GENERATION_LOG};

#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::registry::ENTITY_TYPE_CONNECTOR_KEY;

pub(crate) use self::txn::rebuild_checkpoint_connector_index;
pub use slate::{
    ConnectorGrantSlate, SlateDataClass, SlateDisposition, SlateDraftRow, SlateFacetNarrow,
    SlateHolderNarrow, SlateOwnerOverride, SlateRow, SlateToolManifest,
};
pub use slate_draft::{
    ConnectorSlateDelta, ConnectorSlateDrafter, ConnectorSlateRedraft, SlatePastRulings,
    SlateTrait, draft_connector_slate, rule_draft_row,
};
pub(crate) use slate_setting::{connector_tool_setting_in_txn, effect_slate_always_allows};

pub use manifest_drift::{
    ConnectorDriftKind, ConnectorManifestDrift, ConnectorToolSchema, ResolvedConnectorManifest,
};

/// Scoped connector-pack admission reads the key under its own writer txn.
pub(crate) fn read_key_for_pack_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: &crate::EntityId,
) -> crate::Result<Option<ConnectorKeyRecord>> {
    txn::read_connector_key_in_txn(&vault.store, txn, id)
}
