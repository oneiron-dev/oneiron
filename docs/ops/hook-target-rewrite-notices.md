# Hook target rewrite notices on MCP

The vault owner's hooks may rewrite a restrictive action's target. The row's
existing validation and caller-bound execution checks still apply. This does
not add pinned consent or erasure exceptions.

For a direct MCP agent-verb call that ran successfully, the reply carries any
existing target-rewrite or ignored-rewrite notes in
`structuredContent.meta.hook_notice`. The canonical JSON text in `content`
carries the same notice. The verb's typed `output` is unchanged.

If a post hook returns a typed stop after the row ran, its existing `isError`
tool result carries `meta.hook_notice` and an additional text block. Other
post-chain transport errors carry `error.data.hook_notice`. The original stop
or error is unchanged. A row that failed before its post chain keeps its
existing error behavior.

The existing destination-release checks apply to the notice as well as the
rest of the reply. A held reply does not release its target-change text.

This notice is call-scoped. It contains the verb and the existing change notes,
clipped at the owner notice's existing detail limit. It adds no caller or
invocation identifier, table, receipt, or durable recipient. Existing owner
inbox notices are unchanged.

This covers direct MCP replies only. It does not add caller notice delivery to
raw HTTP success bodies, native calls, or code-mode verb results. Those paths
remain separate work; their typed result shapes are not wrapped by this change.
