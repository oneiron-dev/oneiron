//! The side table `mcp_task` keeps: each row declares one, and the crate's build script places it
//! in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One MCP task handle (L1-03): the actor it answers, the record it wraps, its creation time,
    /// retention and cancel request. Key: blake3 hash32 of the handle id.
    MCP_TASK: VaultMeta b"mcp.task.v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
}
