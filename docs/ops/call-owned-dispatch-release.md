# Call-owned dispatch release

`RunAdmission::with_send_guard` binds a credential-liveness check to that handle.
Cloning or overlaying the handle preserves the check. Adding another check conjoins
it with the existing one. Ordinary handles have no check.

`RunAdmission::gate` retains the same check on its `GatedBackend`, outside shared
`RunInner`, the budget lease, wire data and dispatch identity. A false check returns
`FatalLlmError::Auth`. The gate keeps its existing permit, work-context, pending
receipt and settlement order.

For a guarded handle the gate calls
`SingleRouteBackend::generate_bound_released` or `stream_bound_released` with the
same bound request digest and a borrowed `DispatchRelease`. Without a check it
calls the original bound method. The additive defaults check at dispatch entry
and then call the existing bound method.

An entry check does not cover later waits or sends. A backend that waits for a
worker, a connection or a key must carry the same release to its actual send. A
fresh physical retry or plain resend must recheck it. These checks supplement,
and do not replace, the backend's existing admission and authorization checks.

The carrier alone does not activate a private decision producer, prove all
configured transports check every send, or authorize a caller from configuration.
A private producer still needs the actual caller authorization and the same
vault's live credential check. Existing unguarded behavior remains unchanged.

## OpenAI-compatible adapter

The adapter's released bound calls forward the same borrowed callback through
`OpenAiCompatTransport::execute_released` or `stream_released`. Their defaults
check entry only. `OpenAiCompatTransportError::Release` retains the original
`LlmError`; it is not converted into a provider failure or a not-sent I/O fault.
The transport error supports `PartialEq`, not `Eq`.

The server's `OpenAiHttp` overrides both methods. Its buffered JSON call and
lazy SSE start use the released HTTP helpers. Those helpers recheck before each
reqwest send attempt, including a fresh-connection retry and a plain resend after
a compressed request is refused. Existing reply parsing, model binding, launch
ties and inference evidence stay on the same path. Unguarded calls still use
the original HTTP helpers.

The managed EXL3 transport also carries the same release through buffered and
streamed generation. It checks after worker, session, connection and writer
readiness waits, inside the first SCM_RIGHTS send attempt. A session-refusal plain
retry keeps the same check. A failed check retains its original model error,
separate from socket I/O faults. Its HTTP fallback preserves the launch tie and
uses the same released HTTP path.

The native session `Fork` sends the full conversation before `generate`. Its
released path now carries the same borrowed callback and budget lease through
session selection, connection and writer readiness to that first descriptor
write. A release failure returns the original `LlmError`; it does not evict the
session or fall back to an ordinary generate. A worker refusal or socket fault
keeps the existing session invalidation and plain fallback. Unguarded calls keep
the original session send path.

Foreground session setup also carries that release through Create, resident
Restore, snapshot Import and the restored checkpoint's publication. Metadata
frames without descriptors use the same nonblocking first-write check, after
writer readiness, with no ancillary descriptor. Snapshot input uses the same
check with its descriptor. Ordinary sends without a release keep their existing
path and validation.

A snapshot restore releases its device hold before returning any import result.
A release failure then uses the existing cleanup for whether its newly created
session owns the snapshot pin, before returning the original error. It does not
retire a valid snapshot or turn that error into cold fallback. Existing resident
sessions are not evicted merely because a call's release failed. Ordinary cold
restores retain their existing cleanup, retirement and fallback behavior.

This is still not all session traffic. Background Prepare owns a separate task
and conversation; it cannot borrow a foreground call's callback. Its owned
authorization and lifetime remain separate engineering work. These changes do
not complete private-send coverage or activate a private producer. Other
configured backends need their own native qualification; a LocalVision seat name
does not prove it uses the in-process local runtime.
