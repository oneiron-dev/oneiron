# Code-run target-rewrite notices

A hook may rewrite the target of a take-away action. The executing door still
checks the rewritten call under the caller's authority. This mechanism adds no
pinned target exceptions or extra admission checks.

## MCP code-mode calls

For a successful SDK verb call through the MCP code-mode door, its hook notice
travels beside the native answer's output and source rows. The `execute_code`
reply returns the notices in `meta.hook_notices`, an array collected before the
step list is paged. A call to `finish()` does not hide this metadata. The normal
MCP text content includes the same structured reply.

The JavaScript verb keeps returning its original output. There is no
`hook_notice` property inside that output, and arrays and primitive results are
not wrapped. The guest, typed host import and console stream do not change.

Notice detail uses the same device-release rules as direct MCP notices. Unknown
short refs or held detail produce the existing `{"details_on_device":true}`
placeholder instead of a string. Allowed notice refs join the final answer's
source rows after act narrowing, so the run's existing release, replay and
erasure paths retain them. The replay record keeps the notice with the answer;
replay does not rerun the verb just to recreate the notice.

## Scope and deployment

This path covers successful calls through the MCP code-mode verb door. It does
not add notices to HTTP success bodies, other native verb-door implementations,
or code-mode error and stopped-call paths.

Update the engine and server together. The guest WIT, JavaScript bootstrap and
component artifacts do not change for this host-side path.
