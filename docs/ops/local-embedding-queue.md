# Local embedding queue

The in-process `local` provider uses `Turns` in
`crates/oneiron-server/src/embedder/local/mod.rs`. Other providers and the
sidecar queue are unchanged.

One forward runs at a time. A query holds its turn for its whole call. A bulk
forward drops and re-takes its turn at each layer, re-enrolling at the tail.
On a GPU it finishes the running layer with `synchronize()` before yielding.

Within each class, waiters take the turn first-in first-out in mutex enrollment
order. There is no global arrival ordering across classes. The class rule is
unchanged: queries run first; after `QUERY_STREAK` (4) queries in a row while a
bulk forward waits, the next waiting bulk forward runs one layer.

The running bulk forward yields at the next layer boundary. Calls ahead in the
queue can still run first; there is no bound on a call's total wait. This
ordering adds no queue bound, cancellation, timeout, refusal, or user/model
setting. It preserves the existing one-forward serialization and layer hook.
It does not add memory admission or preemption.
