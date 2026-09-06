use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::charter::parse_charter_verb;

const CALENDAR_TZ_UTC: &str = "UTC";

/// Maximum number of budget rows on one key (and compiled caps on one charter).
pub const CONNECTOR_KEY_MAX_BUDGET_ROWS: usize = 16;

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

/// Budget dimension per OF-277 §3.3 (ticket prose "rate_limit" = `Rate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EffectorBudgetDimension {
    Sends,
    Spend,
    Rate,
}

impl EffectorBudgetDimension {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sends => "sends",
            Self::Spend => "spend",
            Self::Rate => "rate",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "sends" => Some(Self::Sends),
            "spend" => Some(Self::Spend),
            "rate" => Some(Self::Rate),
            _ => None,
        }
    }
}

/// Calendar bucket period for calendar budget windows (UTC-only in v1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CalendarPeriod {
    Day,
    Week,
    Month,
}

impl CalendarPeriod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "day" => Some(Self::Day),
            "week" => Some(Self::Week),
            "month" => Some(Self::Month),
            _ => None,
        }
    }
}

/// Accounting window for one budget row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EffectorBudgetWindow {
    /// Sliding window: a debit is live while `ts + duration_s > now`.
    Rolling { duration_s: u64 },
    /// Calendar bucket (UTC-only in v1: `tz` must be absent or `"UTC"`).
    Calendar {
        period: CalendarPeriod,
        tz: Option<String>,
    },
}

/// What happens when a budget row would be exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EffectorBudgetOnExhaust {
    /// Deny the effect; the key stays active.
    Refuse,
    /// Deny the effect AND flip the whole key to Suspended (hard cap).
    Suspend,
}

impl EffectorBudgetOnExhaust {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Refuse => "refuse",
            Self::Suspend => "suspend",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "refuse" => Some(Self::Refuse),
            "suspend" => Some(Self::Suspend),
            _ => None,
        }
    }
}

/// Spend reserve policy. `PreauthorizeEstimateThenSettle` round-trips through
/// the schema but enforces as `SettleOnly` in v1 (documented limitation,
/// ratified OF-277 §7 item 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EffectorBudgetReservePolicy {
    SettleOnly,
    PreauthorizeEstimateThenSettle,
}

impl EffectorBudgetReservePolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SettleOnly => "settle_only",
            Self::PreauthorizeEstimateThenSettle => "preauthorize_estimate_then_settle",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "settle_only" => Some(Self::SettleOnly),
            "preauthorize_estimate_then_settle" => Some(Self::PreauthorizeEstimateThenSettle),
            _ => None,
        }
    }
}

/// One effector-budget row (OF-277 §3.3 schema, ratified names).
///
/// `limit` units: `sends`/`rate` count gate-admitted effector dispatches;
/// `spend` is the connector's DECLARED denomination (M8 resolution
/// 2026-07-10): ISO-4217 currencies in minor units, provider units
/// (credits/tokens/requests) as opaque integers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EffectorBudget {
    pub dimension: EffectorBudgetDimension,
    /// Optional narrowing; matched against the normalized effect channel.
    pub channel_class: Option<String>,
    pub limit: u64,
    /// Required iff `dimension == Spend`: a 3-ASCII-uppercase ISO-4217 code or
    /// a connector-declared provider-unit token.
    pub unit: Option<String>,
    pub window: EffectorBudgetWindow,
    pub on_exhaust: EffectorBudgetOnExhaust,
    /// Spend only; `None` ⇒ `SettleOnly`.
    pub reserve_policy: Option<EffectorBudgetReservePolicy>,
}

impl EffectorBudget {
    /// Sends-dimension row.
    #[must_use]
    pub fn sends(
        limit: u64,
        window: EffectorBudgetWindow,
        on_exhaust: EffectorBudgetOnExhaust,
    ) -> Self {
        Self {
            dimension: EffectorBudgetDimension::Sends,
            channel_class: None,
            limit,
            unit: None,
            window,
            on_exhaust,
            reserve_policy: None,
        }
    }

    /// Rate-dimension row: rolling window, refuse on exhaust.
    #[must_use]
    pub fn rate(limit: u64, duration_s: u64) -> Self {
        Self {
            dimension: EffectorBudgetDimension::Rate,
            channel_class: None,
            limit,
            unit: None,
            window: EffectorBudgetWindow::Rolling { duration_s },
            on_exhaust: EffectorBudgetOnExhaust::Refuse,
            reserve_policy: None,
        }
    }

    /// Spend-dimension row (settle-only reserve policy).
    #[must_use]
    pub fn spend(
        limit: u64,
        unit: &str,
        window: EffectorBudgetWindow,
        on_exhaust: EffectorBudgetOnExhaust,
    ) -> Self {
        Self {
            dimension: EffectorBudgetDimension::Spend,
            channel_class: None,
            limit,
            unit: Some(unit.to_owned()),
            window,
            on_exhaust,
            reserve_policy: None,
        }
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

/// Canonicalizes an ordinary outbound connector/channel key (duplicate of the
/// private `outbound.rs::normalize_key` on the shared string space).
///
/// An already-canonical per-grant connector spelling is the one exception:
/// storage must retain an admitted server identity, so `'-'` and `'_'` remain
/// distinct. Preserving that exact string does not classify an ordinary
/// lookalike or confer authority; only typed [`ScopedCapabilityProvenance`] does.
#[must_use]
pub(crate) fn normalize_connector_key(value: &str) -> String {
    if canonical_scoped_capability_connector_parts(value).is_some() {
        return value.to_owned();
    }
    value.trim().to_ascii_lowercase().replace('-', "_")
}

/// The reserved compiled-entry tag for a capability-only `never key` rule
/// (ONE-1885).
///
/// An ordinary channel beginning with `"capability-key:"` is not a canonical
/// per-grant connector shape, so `normalize_connector_key` rewrites that
/// prefix's `'-'` to `'_'`. No ordinary entry can therefore begin with this
/// tag. The two rule modes stay STRUCTURALLY disjoint: nothing has to guess a
/// rule's mode from its shape.
pub(super) const CAPABILITY_NEVER_ENTRY_TAG: &str = "capability-key:";

/// The reserved compiled-entry tag for the exact ordinary channel of a typed
/// scoped-MCP call (ONE-1885). The ordinary normalized entry is retained
/// alongside this private form.
///
/// Like the capability tag, this prefix is UNREACHABLE for an ordinary entry:
/// an ordinary channel is stored normalized, and normalization rewrites `'-'`
/// to `'_'` everywhere except an already-canonical `mcp:{server}:grant:{id}`
/// connector — which begins with `"mcp:"`, not with this tag. The three rule
/// modes therefore stay STRUCTURALLY disjoint and nothing has to guess a rule's
/// mode from its shape.
pub(super) const SCOPED_CHANNEL_NEVER_ENTRY_TAG: &str = "scoped-channel:";

/// The ONE safe canonical scoped-server segment rule (ONE-1885).
///
/// Every scoped creation seam — the scoped grant constructor, the persisted
/// grant scope encode/decode/validate, the scoped-call admission path, the
/// per-grant capability-key producer, and the charter capability-key compiler —
/// asks exactly this function. Admission accepts only an already-canonical,
/// non-empty ASCII `[a-z0-9_.-]` segment. It never trims, folds case, or rewrites
/// `'-'` to `'_'`; those bytes name distinct server identities. A colon,
/// whitespace, wildcard/glob punctuation, non-ASCII byte, or any other spelling
/// outside that alphabet has no scoped capability identity.
#[must_use]
pub(crate) fn canonical_scoped_server_segment(server: &str) -> Option<String> {
    if server.is_empty()
        || !server.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || byte == b'_'
                || byte == b'.'
                || byte == b'-'
        })
    {
        return None;
    }
    Some(server.to_owned())
}

/// Parses only the canonical storage spelling of a per-grant connector. This
/// shape check preserves identity bytes in connector-key storage; it does not
/// confer capability authority on an ordinary lookalike.
fn canonical_scoped_capability_connector_parts(text: &str) -> Option<(&str, EntityId)> {
    let mut parts = text.split(':');
    let (Some("mcp"), Some(server), Some("grant"), Some(grant_hex), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return None;
    };
    canonical_scoped_server_segment(server)?;
    let grant_id = EntityId::from_hex(grant_hex).ok()?;
    (grant_id.to_hex() == grant_hex).then_some((server, grant_id))
}

/// The one typed per-grant scoped capability identity (ONE-1885).
///
/// This value IS the capability authority: it exists only where a live scoped
/// grant, its principal, its scoped call, a safe canonical server, and the real
/// engine-produced key identity have all been admitted. Nothing derives it from
/// connector text, an `mcp:*:grant:*` spelling, a tool/server string, or a
/// caller assertion — an ordinary connector that merely LOOKS like a capability
/// key never carries one, and a charter's capability rules are consulted only
/// against a value of this type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ScopedCapabilityProvenance {
    grant_id: EntityId,
    server: String,
    connector: String,
}

impl ScopedCapabilityProvenance {
    /// Mints the identity for one verified grant on one server. `None` when the
    /// server is not a safe canonical segment: an unsafe server has no
    /// capability key at all, so no key is minted from it.
    #[must_use]
    pub(crate) fn mint(server: &str, grant_id: &EntityId) -> Option<Self> {
        let server = canonical_scoped_server_segment(server)?;
        let connector = format!("mcp:{server}:grant:{}", grant_id.to_hex());
        Some(Self {
            grant_id: *grant_id,
            server,
            connector,
        })
    }

    /// Rebuilds the identity from persisted parts, fail-closed: the stored
    /// server must already be the canonical segment and the stored connector
    /// must be EXACTLY what [`Self::mint`] produces for that pair. A malformed
    /// or mismatched durable value therefore yields no capability at all.
    #[must_use]
    pub(crate) fn from_persisted_parts(
        grant_id: &EntityId,
        server: &str,
        connector: &str,
    ) -> Option<Self> {
        let minted = Self::mint(server, grant_id)?;
        (minted.server == server && minted.connector == connector).then_some(minted)
    }

    /// Reads one OWNER-AUTHORED capability-key spelling (the `never key`
    /// operand, and the stored entry that operand compiles into).
    ///
    /// This is charter grammar, not connector authority: it decides whether an
    /// owner named an identity the engine could actually produce, and its
    /// result is only ever compared against a minted identity. It is never
    /// applied to a connector string to manufacture a capability.
    #[must_use]
    pub(crate) fn parse_owner_capability_key(text: &str) -> Option<Self> {
        let (server, grant_id) = canonical_scoped_capability_connector_parts(text)?;
        let minted = Self::mint(server, &grant_id)?;
        (minted.connector == text).then_some(minted)
    }

    /// The exact engine-produced per-grant connector key.
    #[must_use]
    pub(crate) fn connector(&self) -> &str {
        &self.connector
    }

    /// The safe canonical scoped-server segment.
    #[must_use]
    pub(crate) fn server(&self) -> &str {
        &self.server
    }

    /// The grant this capability was minted for.
    #[must_use]
    pub(crate) const fn grant_id(&self) -> EntityId {
        self.grant_id
    }

    /// The ORDINARY channel this scoped dispatch also travels on
    /// (`mcp:{server}`), derived from the typed identity so gate admission and
    /// recovery read the same whole channel string with no text inference.
    #[must_use]
    pub(crate) fn ordinary_channel(&self) -> String {
        format!("mcp:{}", self.server)
    }
}

pub(super) fn validate_connector_token(connector: &str) -> Result<()> {
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
pub(super) fn validate_secret_ref(secret_ref: &str) -> Result<()> {
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

pub(super) fn validate_budget_row(budget: &EffectorBudget) -> Result<()> {
    if budget.limit == 0 {
        return Err(invalid_body("budget limit must be at least 1"));
    }
    match (budget.dimension, budget.unit.as_deref()) {
        (EffectorBudgetDimension::Spend, Some(unit)) => validate_spend_unit(unit)?,
        (EffectorBudgetDimension::Spend, None) => {
            return Err(invalid_body("spend rows require a unit"));
        }
        (_, Some(_)) => return Err(invalid_body("unit only allowed on spend rows")),
        (_, None) => {}
    }
    if budget.reserve_policy.is_some() && budget.dimension != EffectorBudgetDimension::Spend {
        return Err(invalid_body("reserve_policy only allowed on spend rows"));
    }
    match &budget.window {
        EffectorBudgetWindow::Rolling { duration_s } => {
            if *duration_s == 0 {
                return Err(invalid_body("rolling window duration must be at least 1s"));
            }
        }
        EffectorBudgetWindow::Calendar { tz, .. } => {
            if let Some(tz) = tz.as_deref()
                && tz != CALENDAR_TZ_UTC
            {
                return Err(invalid_body("calendar tz must be UTC"));
            }
        }
    }
    if let Some(channel_class) = budget.channel_class.as_deref() {
        if normalize_connector_key(channel_class).is_empty() {
            return Err(invalid_body("channel_class must not be blank"));
        }
        // Same stored-form == index-form invariant as the connector token:
        // row matching compares against the normalized effect channel, so a
        // non-canonical stored narrowing would never match any dispatch.
        if channel_class != normalize_connector_key(channel_class) {
            return Err(invalid_body("channel_class must be stored normalized"));
        }
    }
    Ok(())
}

pub(super) fn validate_suggested_budget_row(budget: &EffectorBudget) -> Result<()> {
    validate_budget_row(budget)?;
    if budget.dimension == EffectorBudgetDimension::Spend {
        return Err(invalid_body("suggested budget rows must be sends or rate"));
    }
    if budget.on_exhaust != EffectorBudgetOnExhaust::Refuse {
        return Err(invalid_body("suggested budget rows must refuse on exhaust"));
    }
    Ok(())
}

/// The connector-declared denomination (M8 resolution 2026-07-10): a
/// 3-ASCII-uppercase ISO-4217 code, or a provider-unit token
/// (`[a-z0-9_]{1,32}`). A 3-letter alphabetic unit is the ISO namespace and
/// must be uppercase — `"usd"` is a malformed currency, not a provider token.
pub(super) fn validate_spend_unit(unit: &str) -> Result<()> {
    let bytes = unit.as_bytes();
    if bytes.len() == 3 && bytes.iter().all(u8::is_ascii_alphabetic) {
        if bytes.iter().all(u8::is_ascii_uppercase) {
            return Ok(());
        }
        return Err(invalid_body("spend unit currency code must be uppercase"));
    }
    if !bytes.is_empty()
        && bytes.len() <= 32
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Ok(());
    }
    Err(invalid_body(
        "spend unit must be an ISO-4217 code or provider-unit token",
    ))
}

pub(super) fn validate_compiled_policy(compiled: &CompiledConnectorPolicy) -> Result<()> {
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

/// A compiled never-list entry MUST be one of the TWO disjoint canonical rules
/// the compiler emits, byte-for-byte (ONE-1885).
///
/// 1. A CAPABILITY-ONLY rule, `"capability-key:mcp:{server}:grant:{id}"`. It
///    names one exact real engine-produced per-grant capability identity and is
///    consulted only against a typed [`ScopedCapabilityProvenance`], never
///    against a connector string. It must parse back into an identity the
///    engine could actually mint (safe canonical server, real grant id), so a
///    partial wildcard (`"…:grant:*"`, `"mcp*:acme"`) or a truncated spelling
///    fails closed here instead of compiling into a rule nothing can honour.
/// 2. An ORDINARY `"{channel}:{verb}"` rule, whose channel is everything before
///    the LAST ':' and is matched as the WHOLE connector string. Colons inside
///    an ordinary channel are data (`"mcp:calendar:send"` prohibits `send` on
///    the whole `mcp:calendar` connector), so no ordinary connector is ever
///    truncated at its first colon or re-read as a capability.
///
/// The compiler preserves the ordinary channel operand byte-for-byte, including
/// `-`, `_`, and colons. Ordinary matching normalizes that rule channel against
/// the already-normalized connector key; typed scoped-MCP matching instead uses
/// an exact whole `mcp:{server}` comparison so `-` and `_` remain distinct.
/// Only blank or partial-wildcard channels are rejected so a corrupted charter
/// cannot silently fail open.
pub(super) fn validate_never_list_entry(entry: &str) -> Result<()> {
    if let Some(capability_key) = entry.strip_prefix(CAPABILITY_NEVER_ENTRY_TAG) {
        if ScopedCapabilityProvenance::parse_owner_capability_key(capability_key)
            .is_none_or(|capability| capability.connector() != capability_key)
        {
            return Err(invalid_body("never_list capability key invalid"));
        }
        return Ok(());
    }
    if let Some(exact_channel_entry) = entry.strip_prefix(SCOPED_CHANNEL_NEVER_ENTRY_TAG) {
        let Some((channel_part, verb)) = exact_channel_entry.rsplit_once(':') else {
            return Err(invalid_body("never_list scoped channel invalid"));
        };
        if !is_canonical_scoped_channel(channel_part) {
            return Err(invalid_body("never_list scoped channel invalid"));
        }
        return validate_never_list_verb(verb);
    }
    // The verb is the LAST segment; everything before it is the whole ordinary
    // channel. A first-colon split would read `"mcp:calendar:send"` as the
    // channel `"mcp"` and deny nothing the author named.
    let Some((channel_part, verb)) = entry.rsplit_once(':') else {
        return Err(invalid_body("never_list entry must be channel:verb"));
    };
    if channel_part != "*" {
        // A `'*'` anywhere else on the channel side is a partial wildcard: the
        // normalized ordinary matcher would otherwise deny nothing (fail-open).
        if channel_part.trim().is_empty() || channel_part.contains('*') {
            return Err(invalid_body("never_list entry channel invalid"));
        }
        // Ordinary entries are stored in the existing normalized form. The
        // compiler preserves the source spelling only in a private exact-scoped
        // entry, when the channel is a typed canonical `mcp:{server}` value.
        if channel_part != normalize_connector_key(channel_part) {
            return Err(invalid_body("never_list entry channel must be canonical"));
        }
    }
    validate_never_list_verb(verb)
}

fn validate_never_list_verb(verb: &str) -> Result<()> {
    if verb == "*" {
        return Ok(());
    }
    // `parse_charter_verb` LOWERCASES before validating, so it accepts a
    // non-canonical spelling like `"SEND"` (yielding `"send"`). Enforcement
    // compares the stored verb by EXACT string against the lowercased effect
    // verb, so the stored part must ALREADY equal its canonical output.
    match parse_charter_verb(verb) {
        Ok(canonical) if canonical == verb => Ok(()),
        Ok(_) => Err(invalid_body("never_list entry verb must be canonical")),
        Err(_) => Err(invalid_body("never_list entry verb invalid")),
    }
}

/// The ONE rule for the exact ordinary channel of a typed scoped-MCP call:
/// literal `"mcp:"` followed by a safe canonical server segment (ONE-1885).
///
/// The charter compiler emits the private tagged entry for exactly this shape
/// and this validator accepts exactly this shape, so emit and accept cannot
/// drift apart. Everything else — a mixed-case or wildcard server, an extra
/// colon, a non-ASCII or unsafe byte, an ordinary lookalike — has no typed
/// scoped channel and therefore never becomes a tagged entry.
pub(super) fn is_canonical_scoped_channel(channel: &str) -> bool {
    channel
        .strip_prefix("mcp:")
        .is_some_and(|server| canonical_scoped_server_segment(server).is_some())
}

pub(super) fn invalid_body(reason: &'static str) -> Error {
    Error::InvalidConnectorKeyBody(reason)
}
