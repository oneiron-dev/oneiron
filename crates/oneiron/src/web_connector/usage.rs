//! One usage row per web call: provider, tool, key source, latency and cost.
//! A row never holds the query, the URL or the results.
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// One row per web call. Key: the call's time in ms + a fresh id16, so a read
/// walks them newest first.
const USAGE: SideTable<(u64, EntityId), WebConnectorUsage, Named> =
    SideTable::new(&side_table::WEB_CONNECTOR_USAGE);

pub use crate::settings::web_connector::{
    USAGE_READ_DEFAULT_LIMIT, USAGE_READ_MAX_LIMIT, WebCallOutcome, WebConnectorUsage,
    WebConnectorUsagePage, WebConnectorUsageRead, WebCostBasis, WebKeySource,
};

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
