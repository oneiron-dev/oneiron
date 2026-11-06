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
