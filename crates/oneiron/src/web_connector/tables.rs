//! The side tables `web_connector` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// The owner's web connector switch (FIX 11598): which provider serves `connector.web.*`, on
    /// whose key. Absent means Tavily on the deploy's backend key. Key: ().
    WEB_CONNECTOR_SETTING: VaultMeta b"web_connector:setting:v1" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One usage row per web connector call: provider, tool, key source, latency, cost and the
    /// provider's request id; never the query, URL or results. Key: u64 BE (ms) + id16.
    WEB_CONNECTOR_USAGE: VaultMeta b"web_connector:usage:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
