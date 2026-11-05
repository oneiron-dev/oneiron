# Workflow replay capsule binding

Saved-workflow steps stage the admitted request and keep an owned, call-local
capture handle. After `generate_recorded_while` returns, that handle finalizes
only its staged capsule with the returned `ModelCallBinding`. The answering
rung may complete on another thread. No thread-local note or model-name lookup
is needed for this workflow path.

A `self.use` conversation captures its first actual request after requester
craft refresh. Only that first call's answer finalizes the capsule. Later tool
rounds still return their final binding for the workflow's existing outcome and
model-call record; that binding is not attached to the initial request. A failed
call leaves an unfinalized capsule. Capture and finalization failures do not
fail live work. The existing capsule writer still rejects erased actors and
keeps an already finalized binding.

Contribution forks and strict shadow calls admit the captured model through the
current native route, then restore the capsule's frozen route prompt on that
call-local, one-picked-rung ladder. This also handles an owner fallback whose
prompt differs from the model's current standalone prompt. It changes no live
configuration or fallback behavior. Strict shadow calls still require equality
of the full captured route pin, including the restored prompt digest.

This does not repair the general executor's thread-local answering-rung capture
or add a binding to the `LlmBackend` response. Other replay callers that still
compare the current prompt are unchanged. Callable/result/verb-read exposure
tracking is also separate work. No guest, image, artifact pin, deployment,
configuration, default or cap changes are needed for this source change.

## Windows native stack floor

The Windows callable path now reads the current thread's stack limits through
`GetCurrentThreadStackLimits`. It applies the same existing 1 MiB native stack
floor as Linux, Android and Apple. The Windows dependency only enables
`Win32_System_Threading` on the existing `windows-sys` version. The other
platform implementations and the unsupported-platform fallback are unchanged.
No Windows compile, VM run or stack-overflow execution is claimed.
