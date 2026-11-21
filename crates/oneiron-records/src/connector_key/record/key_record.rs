//! Moved from `crates/oneiron/src/connector_key/record/key_record.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::connector_key::record::budgets::EffectorBudget;
use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::connector_key_status::ConnectorKeyStatus;

/// How one catalogued connector's calls are classified for effector
/// budgeting (ARCH-0054: *"the Send class applies to counterparty
/// communications only, and scoped-MCP tool calls are unbudgeted by
/// default"*).
///
/// The class describes the catalog as a whole; one dispatched call's budget
/// class also reads its tool's approved declaration (FIX 8688): on a
/// `CounterpartyComm` catalog a tool declared read-only is retrieval and
/// never debits `Sends`, and every other tool does.
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
    /// This exact approval act, including an identical reapproval that resets usage.
    pub approval_id: EntityId,
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
pub const CONNECTOR_KEY_NAME_MAX_LEN: usize = 128;

/// A custody reference is a NAME in SECRET-01's name space (ONE-1919), which
/// keeps names verbatim — so this deliberately does NOT normalize. It only
/// bounds the string and keeps it index-safe; whether the name RESOLVES is a
/// live-vault question the write doors answer inside their transaction.
pub fn validate_secret_ref(secret_ref: &str) -> Result<()> {
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

pub fn invalid_body(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidConnectorKeyBody(reason))
}

/// Protocol revisions are bounded transport tokens, not caller-authored prose.
pub fn validate_protocol_revision(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err(invalid_body("invalid negotiated protocol revision"));
    }
    Ok(())
}

/// The same maximum applies to both serialized snapshot and pending wrapper.
/// It is checked before write and before decode so a writer cannot persist an
/// otherwise valid key that its own reader refuses.
pub const MAX_CONNECTOR_MANIFEST_BYTES: usize = 4_194_304;

pub fn validate_manifest_json_size(value: &impl serde::Serialize) -> Result<()> {
    if serde_json::to_vec(value)
        .map_err(|_| invalid_body("manifest serialization failed"))?
        .len()
        > MAX_CONNECTOR_MANIFEST_BYTES
    {
        return Err(invalid_body("resolved manifest exceeds aggregate bound"));
    }
    Ok(())
}
