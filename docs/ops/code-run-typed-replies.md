# Large typed code-run replies

The executor spills large settled task-ask replies, world-privacy replies,
inference-default replies and task wait-set replies without program feedback
before recording their bridge call. It uses the existing reply-size threshold
and sweeping result sink. The replay row and guest receive the same typed
stored-reply card, with its original source kind, taint, facets and result name.
The full guest JSON remains readable through the existing result tools.

A small reply or a host without result storage keeps its original typed value.
A wait set with nonempty `program_steps` also keeps its original typed value:
those diagnostics have a separate release projection. Such a wait still uses
the existing guest spill when needed. No feedback is dropped or made empty to
qualify a wait set for pre-record spilling.

The new wait-set carrier keeps the original `TasksWaitSet` effect check. It
uses the existing stored-reply shadow pool and occurrence lifetime; card text
is not authority or a replacement for the native stored occurrence. No guest
protocol, configuration or artifact change is required. This is a slice of
FIX 449, not completion of every typed outcome or the full result-memory work.
