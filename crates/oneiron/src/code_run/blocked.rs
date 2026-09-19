//! Witnessed, reference-addressed self-reports. Only the closed category can
//! drive routing; the detail is a terminal escaped, untrusted leaf.

use crate::{EntityId, Error, Result, Vault};
use serde::{Deserialize, Serialize};

pub(crate) const BLOCKED_REPORT_MESSAGE_TYPE: &str = "executor.report_blocked";

const PREFIX: &str = "oneiron:report_blocked:v1:";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedCategory {
    Tool,
    Permission,
    Context,
    Environment,
}
impl BlockedCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tool => "tool",
            Self::Permission => "permission",
            Self::Context => "context",
            Self::Environment => "environment",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockedReceipt {
    pub category: BlockedCategory,
    /// Escaped canonical leaf; never executable, never a routing selector.
    pub untrusted_detail: String,
}
impl BlockedReceipt {
    pub fn new(category: BlockedCategory, raw_detail: &str) -> Result<Self> {
        Ok(Self {
            category,
            untrusted_detail: crate::self_heal::untrusted_text::canonical_untrusted_detail(
                raw_detail,
            )?,
        })
    }
    pub(crate) fn content(&self) -> Result<String> {
        crate::self_heal::untrusted_text::validate_untrusted_detail(&self.untrusted_detail)?;
        Ok(format!(
            "{PREFIX}{}",
            serde_json::to_string(self)
                .map_err(|_| Error::InvalidConfig("blocked receipt encoding".into()))?
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfReportBlockedCall {
    pub category: BlockedCategory,
    pub detail: String,
    pub(crate) order: u32,
    pub(crate) occurred_at: u64,
}
impl SelfReportBlockedCall {
    pub fn new(category: BlockedCategory, detail: impl Into<String>) -> Self {
        Self {
            category,
            detail: detail.into(),
            order: 0,
            occurred_at: 0,
        }
    }
    pub(crate) fn stamped(mut self, order: u32, occurred_at: u64) -> Self {
        self.order = order;
        self.occurred_at = occurred_at;
        self
    }
}

/// Decode only a live canonical witnessed MESSAGE carrying this receipt
/// schema. Ordinary speech and malformed refs are not blocked reports.
pub fn read_blocked_receipt(vault: &Vault, id: &EntityId) -> Result<Option<BlockedReceipt>> {
    let Some(raw) = vault.get_raw(id)? else {
        return Ok(None);
    };
    let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != crate::registry::ENTITY_TYPE_MESSAGE
        || raw.len() <= crate::batch::ENTITY_METADATA_HEADER_LEN
    {
        return Ok(None);
    }
    let body = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
    if crate::gate::validate_canonical_witness_message_body(body).is_err() {
        return Ok(None);
    }
    let value: rmpv::Value = match rmpv::decode::read_value(&mut std::io::Cursor::new(body)) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let Some(entries) = value.as_map() else {
        return Ok(None);
    };
    let field = |name: &str| {
        entries
            .iter()
            .find(|(k, _)| k.as_str() == Some(name))
            .map(|(_, v)| v)
    };
    if field("author").and_then(rmpv::Value::as_str) != Some("companion")
        || field("type").and_then(rmpv::Value::as_str) != Some(BLOCKED_REPORT_MESSAGE_TYPE)
    {
        return Ok(None);
    }
    let Some(text) = entries
        .iter()
        .find(|(k, _)| k.as_str() == Some("content"))
        .and_then(|(_, v)| v.as_str())
    else {
        return Ok(None);
    };
    let Some(json) = text.strip_prefix(PREFIX) else {
        return Ok(None);
    };
    let receipt: BlockedReceipt = match serde_json::from_str(json) {
        Ok(receipt) => receipt,
        Err(_) => return Ok(None),
    };
    if receipt.content().is_err() {
        return Ok(None);
    }
    Ok(Some(receipt))
}
