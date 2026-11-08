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

A saved native hook completion that supplied a positive notice also keeps the
existing content-free summary beside its recorded code-mode denial. Both saved
results and saved errors use this path. The original denial kind, code and
reason codes stay unchanged, as does the refusal seen by JavaScript. The same
`meta.hook_notices` collector returns this summary without rerunning the hook.
Absent metadata remains unknown.

An ordinary MCP code-mode refusal that supplied a hook notice keeps the same
content-free summary beside its original code when recorded as a denial. The
notice comes from that same error, not from its code. A refusal with no supplied
notice remains unknown. Typed hook stops and provider retry errors keep their
existing paths. This slice does not cover paths that replace the denial with a
consent wait.

This path covers successful calls through the MCP code-mode verb door, the
saved native hook completions described above, and ordinary MCP refusals with
a supplied notice. It does not add notices to HTTP success bodies, other native
verb-door implementations, or errors without a supplied notice source.

Update the engine and server together. The guest WIT, JavaScript bootstrap and
component artifacts do not change for this host-side path.
