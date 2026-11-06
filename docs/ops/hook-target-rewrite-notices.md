# Hook target rewrite notices

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

A native saved pre-hook completion that supplied a positive notice also sends
the existing content-free notice in `error.data.hook_notice`, beside its original
typed stop. The adapter reads the notice already retained in that same stop.
Absent metadata is unknown. A fresh detailed notice takes precedence, and an
absent fresh notice does not erase a supplied saved notice. This does not rerun
the call or turn a completed stop into a successful response.

Embedded short refs in a notice are resolved before its detail is released.
Allowed detail adds those dependencies to the final reply's replay provenance,
after the action's own result narrowing. Unresolved refs or a held notice use
`{"details_on_device": true}` in `meta.hook_notice` instead of the text; a typed
stop's additional text block states that same content-free value. The original
typed output and error are unchanged. Existing destination-release checks
still apply to the rest of the reply.

This notice is call-scoped. It contains the verb and the existing change notes,
clipped at the owner notice's existing detail limit. It adds no caller or
invocation identifier, table, receipt, or durable recipient. Existing owner
inbox notices are unchanged.

The detailed notices above cover direct MCP replies. Code-mode replies carry
notices in their existing MCP metadata; see [code-run hook notices](code-run-hook-notices.md).
Neither path changes the verb's typed result shape.

## HTTP facade replies

Generated HTTP host/server doors with an explicit pre/post hook chain carry a
content-free notice in `x-oneiron-hook-notice` when a take-away hook changed
arguments or had a proposed change ignored. Ordinary core-invoke doors carry
the same notice from the hook chain that actually ran inside the engine,
without invoking hooks a second time. The header contains no verb,
target, argument, caller or invocation detail. MCP's detailed notices are
unchanged. The HTTP JSON body keeps its original shape, including arrays and
primitive results.

When one of these calls receives a pre-hook result and then fails, the same header
carries its content-free notice beside the original error or post-hook stop.
The error's status, typed body, receipt and retry behavior stay unchanged. A
live duplicate waiting on that refusal receives the notice beside the existing
refusal recheck; the refusal does not become a successful replay release or a
new durable failed-call record. A source that supplied no metadata remains
unknown.

The HTTP SDK returns the original `Response`; read the notice through
`response.headers.get("x-oneiron-hook-notice")`. The CORS exposure list includes
this header. Connected Rust clients expose `last_hook_notice()`, Python clients
expose `last_hook_notice()`, and native TypeScript clients expose
`lastHookNotice()`. These getters return the notice string or none/null beside
the typed result. A clone starts with none. The next facade call clears the
notice before serialization or sending, including when that call fails before
reaching the server. Server-backed in-process clients use the same path;
vault-direct handles return none.

A saved HTTP/chat reply keeps only its original result and a boolean notice
flag in its private replay record, never in the public result body. Fresh and
replayed replies send the same content-free notice. The result's dependency
rows, destination release, program feedback and erasure owners are unchanged;
a notice cannot make an otherwise valid result disappear. Session-only calls
may carry the notice without adding a durable receipt or notice record.

When a facade pre-chain receives a native saved completion, it forwards that
completion's supplied positive notice beside the original typed stop or error.
It reads the notice already retained with that same stop; it does not run the
call again or turn the stop into a successful response.

A core call reading a drained call's saved completion returns the original
result or error and any notice metadata its source supplied. Non-room native drains
keep the actual hook-chain bit for both outcomes. Credential facade drains
keep a positive notice flag beside the result or error; an absent flag does
not certify that no arguments changed. Credential MCP and managed-owner MCP
drains keep a positive flag from the same hook chain's existing notice,
including a supplied error notice. A receipt failure does not discard an
already supplied positive notice. Missing metadata remains unknown, not a
claim that the arguments stayed unchanged. Room-turn calls through the
notice-aware facade and native drain paths keep the same hook-chain metadata;
a turn that could not open supplies none. These are separate from a saved HTTP reply, which already
keeps the notice flag described above. Saved metadata never grants authority
to run a call.

This HTTP slice does not cover other unsupported completion sources or room-turn
callers, action-wrapper routes, custody-spool routes, non-facade calls, or errors
before a notice source was supplied. Other completion adapters outside the
notice-aware core and facade pre-chain paths are not covered by this slice.
It adds no notice to those
paths. The wider caller-notice
row remains partial. Deploy matching engine/server and native SDK binaries;
no guest artifact change is needed.
