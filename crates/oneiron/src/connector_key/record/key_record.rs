//! Key and catalog registry shapes: status, call class, catalog entry, key spec/record with validate, charter data shapes.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::{
    CONNECTOR_KEY_MAX_BUDGET_ROWS, EffectorBudget, normalize_connector_key, validate_budget_row,
    validate_never_list_entry, validate_suggested_budget_row,
};
use crate::error::RecordError;

/// ConnectorKeyRecord lifecycle status.
///
/// v1 reachable states: `Active ⇄ Suspended`, `→ Revoked` (terminal).
/// `Pending` is accepted by decode for forward-compat with the ARCH-0028
/// qualification suite but is never minted by v1 registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectorKeyStatus {
    Pending,
    Active,
    Suspended,
    Revoked,
}

impl ConnectorKeyStatus {
    /// Returns the pinned on-disk status string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
        }
    }

    /// Parses a pinned on-disk status string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// How one catalogued connector's calls are classified for effector
/// budgeting (ARCH-0054: *"the Send class applies to counterparty
/// communications only, and scoped-MCP tool calls are unbudgeted by
/// default"*).
///
/// The classification is ENTRY-WIDE by construction: there is deliberately no
/// per-verb parameter, so a mixed-verb connector registered as
/// `CounterpartyComm` budgets its read-only calls as sends too. Over-budgeting
/// is the safe direction — under-budgeting a counterparty send is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectorCallClass {
    /// Communication with a counterparty: the only class that debits `Sends`.
    CounterpartyComm,
    /// Retrieval with no counterparty-visible effect; unbudgeted for `Sends`.
    ReadOnly,
    /// Scoped-MCP tool calls; unbudgeted for `Sends` per ARCH-0054 canon.
    ScopedMcp,
}

impl ConnectorCallClass {
    /// Returns the pinned on-disk class string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CounterpartyComm => "counterparty_comm",
            Self::ReadOnly => "read_only",
            Self::ScopedMcp => "scoped_mcp",
        }
    }

    /// Parses a pinned on-disk class string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "counterparty_comm" => Some(Self::CounterpartyComm),
            "read_only" => Some(Self::ReadOnly),
            "scoped_mcp" => Some(Self::ScopedMcp),
            _ => None,
        }
    }

    /// Whether a call through this connector debits the `Sends` dimension.
    /// True for `CounterpartyComm` and nothing else.
    #[must_use]
    pub const fn debits_sends(self) -> bool {
        matches!(self, Self::CounterpartyComm)
    }
}

/// The engine-catalog entry embedded on a connector key: what the connector
/// IS, so the engine can find it, describe it, and classify its calls.
///
/// Embedded on the key record rather than filed under its own entity type —
/// a catalogued connector and its governing key are one registration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectorCatalogEntry {
    /// Engine-catalog name, stored normalized and unique per vault ACROSS
    /// HISTORY (removal never frees it).
    pub name: String,
    /// The connector this entry describes; MUST equal the key's `connector`.
    pub connector: String,
    /// One-line human summary; searched case-insensitively.
    pub summary: String,
    /// Verbs the connector advertises. Descriptive only: budget
    /// classification is entry-wide, never per-verb.
    pub verbs: Vec<String>,
    pub call_class: ConnectorCallClass,
    /// Stamped by the registration door from its `registered_at` parameter,
    /// never from caller-supplied entry state.
    pub registered_at: u64,
}

impl ConnectorCatalogEntry {
    /// Structural validation shared by encode, decode, and registration.
    pub fn validate(&self) -> Result<()> {
        validate_catalog_name(&self.name)?;
        validate_connector_token(&self.connector)?;
        if self.summary.trim().is_empty() {
            return Err(invalid_body("catalog summary must not be blank"));
        }
        if self.summary.as_bytes().contains(&0) {
            return Err(invalid_body("catalog summary must not contain NUL"));
        }
        if self.verbs.len() > CONNECTOR_CATALOG_MAX_VERBS {
            return Err(invalid_body("too many catalog verbs"));
        }
        for verb in &self.verbs {
            if verb.trim().is_empty() {
                return Err(invalid_body("catalog verb must not be blank"));
            }
            if verb.as_bytes().contains(&0) {
                return Err(invalid_body("catalog verb must not contain NUL"));
            }
        }
        Ok(())
    }
}

/// The key half of a composed [`crate::Vault::register_connector`] call: what
/// the catalogued connector's governing key should be minted as. The status is
/// not a parameter — a composed registration always mints an Active,
/// charter-free, generation-0 key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorKeySpec {
    /// Same string space as the catalog entry's `connector`; normalized by
    /// the door before the uniqueness check.
    pub connector: String,
    /// `None` = any actor on this connector.
    pub actor_entity_ref: Option<EntityId>,
    pub budgets: Vec<EffectorBudget>,
    /// Custody record NAME minted by SECRET-01 (ONE-1919), resolved
    /// pre-write. Value-less by construction: this names a record, it never
    /// carries the secret.
    pub secret_ref: Option<String>,
}

impl ConnectorKeySpec {
    /// An unbudgeted, custody-free key spec for `connector`.
    #[must_use]
    pub fn new(connector: impl Into<String>) -> Self {
        Self {
            connector: connector.into(),
            actor_entity_ref: None,
            budgets: Vec::new(),
            secret_ref: None,
        }
    }
}

/// Vault-resident connector-key registry record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorKeyRecord {
    /// Stable outbound connector key (same string space as
    /// `OutboundCapabilityManifest.connector`), stored normalized.
    pub connector: String,
    /// `None` = any actor on this connector.
    pub actor_entity_ref: Option<EntityId>,
    pub status: ConnectorKeyStatus,
    pub budgets: Vec<EffectorBudget>,
    /// Advisory rows staged by a connector handshake. These rows are never
    /// charged until an owner explicitly accepts one into `budgets`.
    pub suggested_budgets: Vec<EffectorBudget>,
    pub registered_at: u64,
    pub status_changed_at: Option<u64>,
    /// `"budget_exhausted:row:{i}"` | `"budget_exhausted:charter_row:{i}"`
    /// (GOV-10) | an owner-supplied reason.
    pub suspended_reason: Option<String>,
    /// GOV-10 fills; GOV-01 encodes Nil.
    pub charter: Option<ConnectorCharterBlock>,
    /// GOV-10 fills; GOV-01 encodes Nil.
    pub pending_charter: Option<PendingConnectorCharter>,
    /// The custody record NAME this key currently authenticates with (SECRET-01,
    /// ONE-1919). VALUE-LESS by construction: the key names a custody record,
    /// it never carries, reads, or copies the secret value. `None` = a key
    /// registered before/without a custody reference.
    pub secret_ref: Option<String>,
    /// Rotation counter: `0` is the as-registered generation. Every
    /// [`crate::Vault::rotate_connector_key`] bumps it and appends the matching
    /// generation-log row. Legacy bodies decode as `0`.
    pub key_generation: u32,
    /// Engine-catalog entry. `None` = an UNCLASSIFIED key: it has no route,
    /// so the executor keeps the ARCH-0054 default (scoped-MCP tool calls
    /// unbudgeted). Only the composed registration door mints one.
    pub catalog: Option<ConnectorCatalogEntry>,
}

impl ConnectorKeyRecord {
    /// Constructs an active record with no charter, ready for registration.
    #[must_use]
    pub fn active(
        connector: impl Into<String>,
        actor_entity_ref: Option<EntityId>,
        budgets: Vec<EffectorBudget>,
        registered_at: u64,
    ) -> Self {
        Self {
            connector: connector.into(),
            actor_entity_ref,
            status: ConnectorKeyStatus::Active,
            budgets,
            suggested_budgets: Vec::new(),
            registered_at,
            status_changed_at: None,
            suspended_reason: None,
            charter: None,
            pending_charter: None,
            secret_ref: None,
            key_generation: 0,
            catalog: None,
        }
    }

    /// Validates structural invariants shared by encode, decode, and register.
    ///
    /// Registration-only checks (status must be Active, no pre-stamped
    /// charter) deliberately do NOT live here: decode must accept every
    /// status and any stored charter block.
    pub fn validate(&self) -> Result<()> {
        validate_connector_token(&self.connector)?;
        if self.budgets.len() > CONNECTOR_KEY_MAX_BUDGET_ROWS {
            return Err(invalid_body("too many budget rows"));
        }
        for budget in &self.budgets {
            validate_budget_row(budget)?;
        }
        if self.suggested_budgets.len() > CONNECTOR_KEY_MAX_BUDGET_ROWS {
            return Err(invalid_body("too many suggested budget rows"));
        }
        for budget in &self.suggested_budgets {
            validate_suggested_budget_row(budget)?;
        }
        if let Some(reason) = self.suspended_reason.as_deref() {
            if reason.trim().is_empty() {
                return Err(invalid_body("suspended_reason must not be blank"));
            }
            if self.status != ConnectorKeyStatus::Suspended {
                return Err(invalid_body("suspended_reason requires suspended status"));
            }
        }
        if let Some(status_changed_at) = self.status_changed_at
            && status_changed_at < self.registered_at
        {
            return Err(invalid_body("status_changed_at before registered_at"));
        }
        if let Some(charter) = self.charter.as_ref() {
            if charter.text.trim().is_empty() {
                return Err(invalid_body("charter text must not be blank"));
            }
            if charter.stamped_by.trim().is_empty() {
                return Err(invalid_body("charter stamped_by must not be blank"));
            }
            validate_compiled_policy(&charter.compiled)?;
        }
        if let Some(pending) = self.pending_charter.as_ref() {
            if pending.text.trim().is_empty() {
                return Err(invalid_body("pending charter text must not be blank"));
            }
            validate_compiled_policy(&pending.compiled)?;
        }
        if let Some(secret_ref) = self.secret_ref.as_deref() {
            validate_secret_ref(secret_ref)?;
        }
        if let Some(catalog) = self.catalog.as_ref() {
            catalog.validate()?;
            // The entry describes the connector this key governs. A divergent
            // pair would route callers through a key that does not govern the
            // connector they asked for, so it fails closed at every
            // encode/decode — including a replicated or imported body.
            if catalog.connector != self.connector {
                return Err(invalid_body("catalog connector must match the key"));
            }
        }
        Ok(())
    }
}

/// Compiled connector policy (GOV-10 fills; pinned now so the v1 body encoding
/// is stable). v1 carries only what the gate can enforce today.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CompiledConnectorPolicy {
    /// Sorted, deduped `"channel:verb"` entries; `"*"` wildcard on either side.
    pub never_list: Vec<String>,
    /// Extra budget rows, enforced identically to key budgets.
    pub channel_caps: Vec<EffectorBudget>,
}

/// Human-stamped charter block (GOV-10). Enforcement reads only `compiled`,
/// never `text`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectorCharterBlock {
    pub text: String,
    pub text_hash: [u8; 32],
    pub compiled: CompiledConnectorPolicy,
    pub compiled_hash: [u8; 32],
    /// `sha256(STAMP_DOMAIN ‖ text_hash ‖ compiled_hash)`.
    pub stamped_aggregate: [u8; 32],
    pub stamped_by: String,
    pub stamped_at: u64,
}

/// Staged (compiled but not yet human-approved) charter (GOV-10).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PendingConnectorCharter {
    pub text: String,
    pub text_hash: [u8; 32],
    pub compiled: CompiledConnectorPolicy,
    pub compiled_hash: [u8; 32],
    pub proposed_at: u64,
}

/// Upper bound on a stored custody `secret_ref` and on a catalog name. Both
/// ride inside `vault_meta` keys (the catalog name index) or are resolved
/// against one, so they must stay bounded; the value matches the settlement
/// event-ref cap so every caller-supplied identifier in this module has one
/// length rule.
pub(super) const CONNECTOR_KEY_NAME_MAX_LEN: usize = 128;

/// Upper bound on the verbs one catalog entry may advertise. The list is
/// DESCRIPTIVE only — classification is entry-wide — so this exists purely to
/// keep the encoded body bounded.
pub(super) const CONNECTOR_CATALOG_MAX_VERBS: usize = 64;

pub(in crate::connector_key) fn validate_connector_token(connector: &str) -> Result<()> {
    if normalize_connector_key(connector).is_empty() {
        return Err(invalid_body("connector must not be blank"));
    }
    if connector.as_bytes().contains(&0) {
        return Err(invalid_body("connector must not contain NUL"));
    }
    // The stored form MUST be the canonical (normalized) form: the connector
    // index key and the gate's governing-key lookup are both derived from
    // the normalized channel, so a record stored non-canonical would exist
    // but never match — a budget key that silently fails to govern. Vault
    // write doors normalize before validate; this makes the invariant hold
    // for every encode/decode, including replicated or imported bodies.
    if connector != normalize_connector_key(connector) {
        return Err(invalid_body("connector must be stored normalized"));
    }
    Ok(())
}

/// A custody reference is a NAME in SECRET-01's name space (ONE-1919), which
/// keeps names verbatim — so this deliberately does NOT normalize. It only
/// bounds the string and keeps it index-safe; whether the name RESOLVES is a
/// live-vault question the write doors answer inside their transaction.
pub(in crate::connector_key) fn validate_secret_ref(secret_ref: &str) -> Result<()> {
    if secret_ref.trim().is_empty() {
        return Err(invalid_body("secret_ref must not be blank"));
    }
    if secret_ref.len() > CONNECTOR_KEY_NAME_MAX_LEN {
        return Err(invalid_body("secret_ref too long"));
    }
    if secret_ref.as_bytes().contains(&0) {
        return Err(invalid_body("secret_ref must not contain NUL"));
    }
    Ok(())
}

/// The catalog name obeys the same stored-form == index-form invariant as the
/// connector token: the permanent name index and every lookup derive from
/// `normalize_connector_key`, so a non-canonical stored name would exist but
/// never resolve.
pub(super) fn validate_catalog_name(name: &str) -> Result<()> {
    if normalize_connector_key(name).is_empty() {
        return Err(invalid_body("catalog name must not be blank"));
    }
    if name.as_bytes().contains(&0) {
        return Err(invalid_body("catalog name must not contain NUL"));
    }
    if name.len() > CONNECTOR_KEY_NAME_MAX_LEN {
        return Err(invalid_body("catalog name too long"));
    }
    if name != normalize_connector_key(name) {
        return Err(invalid_body("catalog name must be stored normalized"));
    }
    Ok(())
}

pub(in crate::connector_key) fn validate_compiled_policy(
    compiled: &CompiledConnectorPolicy,
) -> Result<()> {
    if compiled.channel_caps.len() > CONNECTOR_KEY_MAX_BUDGET_ROWS {
        return Err(invalid_body("too many charter channel caps"));
    }
    for cap in &compiled.channel_caps {
        validate_budget_row(cap)?;
    }
    for entry in &compiled.never_list {
        if entry.trim().is_empty() {
            return Err(invalid_body("never_list entry must not be blank"));
        }
        validate_never_list_entry(entry)?;
    }
    Ok(())
}

pub(crate) fn invalid_body(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidConnectorKeyBody(reason))
}
