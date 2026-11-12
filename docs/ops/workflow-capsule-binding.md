# Workflow replay capsule binding

Saved-workflow steps stage the admitted request and keep an owned, call-local
capture handle. After `generate_recorded_while` returns, that handle finalizes
only its staged capsule with the returned `ModelCallBinding`. The answering
rung may complete on another thread. No thread-local note or model-name lookup
is needed for this workflow path. Executor steps still name their answering
rung on the calling thread. Both paths finalize through the one capsule writer.

A `self.use` conversation captures its first actual request after requester
craft refresh. Only that first call's answer finalizes the capsule. Later tool
rounds still return their final binding for the workflow's existing outcome and
model-call record; that binding is not attached to the initial request. A failed
call leaves an unfinalized capsule. Capture and finalization failures do not
fail live work. The existing capsule writer still rejects erased actors and
keeps an already finalized binding.

Durable tool continuations keep the existing `capture_completed` cursor. A
resumed tool tail does not stage or finalize a later round as its initial call.
After the first successful answer, the exact returned binding finalizes the
owned handle before that existing cursor is saved as completed. Checkpoint,
hook-wait and retry records otherwise keep their current behavior.

The capsule also keeps the role whose admission sent the call (FIX 6359). A
workflow passes its call's chat role to its handle. An executor step's host
notes the role that actually admitted the call: the browser role when its
admission took the call, else the chat role. A capture with no noted role is
never finalized.

The capsule writer keeps the answering rung's route prompt as a masked body
the run owns, admitted through the side-row wall (FIX 6255). The capsule names
that body by ref, with the digest of the prompt as sent. A prompt the wall
refuses is withheld: no copy is kept.

Contribution forks, strict shadow calls and code-fix exact replays use one
replay path. Each admits the captured model through the current native route
of the role that admitted the captured call (FIX 6359), and of no other role,
and selects the rung that answered the capsule: the one picked rung of that
model, served at the captured locality (`for_replay_binding`). A ladder with no
such rung is no replay (`no_exact_rung` for a shadow call). A captured call that
ran wider than the role's route went out on the owner's standing quota fallback
(`use_fallback`) for one of the route's offers. Its replay re-reads that choice
at replay time: it is admitted while the owner's fallback still names the model
at that locality, and refused once the owner has turned it off or named another
(`fallback_no_longer_allowed` for a shadow call). The selected rung's
configured prompt must match the stored digest; otherwise the replay is refused
(`route_prompt_moved`). An owner fallback whose prompt differs from the model's
current standalone prompt is therefore not replayed. The replay then reads the
stored prompt through the admitted reader and sends it on that call only, in
place of the configured prompt. A prompt that does not read sends nothing; a
code-fix job latches `PromptUnavailable`. A replayed answer finalizes no
capsule. It changes no live configuration or fallback behavior. Strict shadow
calls still require equality of the full captured route pin, including its
prompt digest.

This does not add a binding to the `LlmBackend` response. Callable/result/
verb-read exposure tracking is separate work. No guest, image, artifact pin,
deployment, configuration, default or cap changes are needed for this source
change.

## Native callable stack

On x86_64/aarch64 Unix and Windows, a nested callable that reaches the existing
1 MiB native stack floor runs on an extra 2 MiB stack segment on the same OS
thread. The segment size is twice the floor: one floor for the callable's frames
and one left below them. `stacker` tracks the active segment, restores the
original stack before returning, and resumes a panic only after that restore.
The host and runtime stay borrowed; neither gains a `Send` bound or a new thread.

Other targets retain their original native stack-bounds readers and
`skills_call_stack_floor` result. Callable admission, the configured nest-depth
question, cancellation and result recording are unchanged. Each nested runtime
still owns its guest worker and store; this change does not account their memory
or the extra native stack against the result-body pool.
No platform compile, VM run or stack-overflow execution is claimed here.
