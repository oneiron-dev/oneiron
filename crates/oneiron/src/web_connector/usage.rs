//! One usage row per web call: provider, tool, key source, latency and cost.
//! A row never holds the query, the URL or the results.
use serde::{Deserialize, Serialize};

use super::{WebProvider, WebTool};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// One row per web call. Key: the call's time in ms + a fresh id16, so a read
/// walks them newest first.
const USAGE: SideTable<(u64, EntityId), WebConnectorUsage, Named> =
    SideTable::new(&side_table::WEB_CONNECTOR_USAGE);

/// Rows one read returns when its caller names no count.
pub const USAGE_READ_DEFAULT_LIMIT: u32 = 100;
/// The most rows one read returns.
pub const USAGE_READ_MAX_LIMIT: u32 = 1_000;

/// Whose key a call ran on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebKeySource {
    /// The deploy's backend key: our cash.
    Backend,
    /// The user's own key, from custody.
    User,
    /// A hub connector's key.
    Hub,
}

/// Where a row's cost came from (Engine call on FIX 8689, 10-26 22:19).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebCostBasis {
    /// The provider reported it in its response.
    Actual,
    /// The provider's declared price for the tool.
    Estimated,
    /// No price is known: measured and shown, never refused.
    Unpriced,
}

/// How a call ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WebCallOutcome {
    /// Answered, with this many results (1 for a fetched page).
    Ok { results: u32 },
    /// Failed, with its reason code.
    Failed { reason: String },
    /// A hub connector's call that waits (held, pending delivery or awaiting
    /// input); its own row in the connector-call ledger settles it.
    Waiting { reason: String },
}

/// One web call's usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WebConnectorUsage {
    pub at_ms: u64,
    pub tool: WebTool,
    pub provider: WebProvider,
    pub key: WebKeySource,
    /// The installed connector a hub key forwarded the call to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hub_connector: Option<String>,
    pub latency_ms: u64,
    /// `None` when unpriced.
    pub cost_micro_usd: Option<u64>,
    pub cost_basis: WebCostBasis,
    /// The provider's own id for the request, when its response names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_request_id: Option<String>,
    pub outcome: WebCallOutcome,
}

/// `vault.connectors.web.usage`'s input.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebConnectorUsageRead {
    /// Only rows at or after this time (ms).
    #[serde(default)]
    pub since_ms: Option<u64>,
    /// At most [`USAGE_READ_MAX_LIMIT`]; [`USAGE_READ_DEFAULT_LIMIT`] when absent.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// The rows a usage read returns, newest first, with their summed known cost.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WebConnectorUsagePage {
    pub rows: Vec<WebConnectorUsage>,
    /// The summed cost of the returned rows that carry one.
    pub total_cost_micro_usd: u64,
    /// How many returned rows are unpriced.
    pub unpriced: u32,
}

impl Vault {
    /// Records one web call's usage row.
    pub fn record_web_connector_usage(&self, usage: &WebConnectorUsage) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        USAGE.put(
            &self.store,
            &mut txn,
            &(usage.at_ms, EntityId::now()),
            usage,
        )?;
        txn.commit()?;
        Ok(())
    }

    /// The web calls' usage rows under the owner proof, newest first.
    pub fn web_connector_usage_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        read: &WebConnectorUsageRead,
    ) -> Result<WebConnectorUsagePage> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let limit = read
            .limit
            .unwrap_or(USAGE_READ_DEFAULT_LIMIT)
            .clamp(1, USAGE_READ_MAX_LIMIT) as usize;
        let since = read.since_ms.unwrap_or(0);
        let mut page = WebConnectorUsagePage::default();
        for row in USAGE.iter_rev_from(&self.store, &txn, &[])? {
            let ((at_ms, _), usage) = row?;
            if at_ms < since || page.rows.len() >= limit {
                break;
            }
            match usage.cost_micro_usd {
                Some(cost) => {
                    page.total_cost_micro_usd = page.total_cost_micro_usd.saturating_add(cost);
                }
                None => page.unpriced = page.unpriced.saturating_add(1),
            }
            page.rows.push(usage);
        }
        Ok(page)
    }
}
