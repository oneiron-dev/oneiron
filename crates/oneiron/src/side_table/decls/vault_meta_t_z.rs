// Declared `vault_meta` tables whose prefix starts with `t` to `z`, in prefix order.

side_tables! {
    /// Retired consult fan-out policy carrier; the policy manifest now governs.
    /// Declared so bytes written by older engines stay owned. Key: ().
    TASK_FANOUT_POLICY: VaultMeta b"tasks/fanout_policy/v1" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Weave digest of one reader. Key: reader kind byte + id16 + u64be.
    WEAVE_DIGEST: VaultMeta b"weave:digest:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Empty lens-rerender intent after erasure. Key: the full saved digest key.
    WEAVE_DIGEST_RERENDER: VaultMeta b"weave:digest_rerender:v1:" Raw
        [restore: content] [family: structure] [tier: canonical];
    /// Source-to-digest invalidation index. Key: source id16 ‖ digest key.
    WEAVE_DIGEST_SOURCE: VaultMeta b"weave:digest_source:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The newest live lens of one reader. Key: reader kind byte + id16.
    WEAVE_LIVE: VaultMeta b"weave:live:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A workflow leaf's custodied tool transcript pointer and exact settled state. Key: id16 (attempt).
    WORKFLOW_TOOL_CHECKPOINT: VaultMeta b"workflow:tool_checkpoint:v1:" Named Authored
        [refs: &[&[Field("content")], &[Field("retained")]]]
        [accepts: crate::agent_dispatch::workflow_tool_checkpoint_accepts_masked]
        [restore: content] [family: owner WorkflowTool] [tier: canonical]
        => crate::agent_dispatch::erase_workflow_tool_actor_in_txn;
}
