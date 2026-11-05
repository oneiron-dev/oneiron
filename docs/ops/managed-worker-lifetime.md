# Managed worker lifetime

The model supervisor owns the configured worker as a direct child. Its exit
status comes only from that child. Health, activity, leases, native draining and
the existing stop grace do not come from a guardian process.

On Linux the existing parent-death signal is SIGTERM. On macOS, the real
`oneiron` and `oneiron-server` CLI entrypoints also start a private guardian from
the same executable. Before Tokio is created in either private child role, the
worker bootstrap receives the original program, arguments, environment and
working directory. It executes that program only after the guardian has joined
its process group and armed an actual original-server-parent exit notification.
No separate guardian executable, PATH entry, worker rebuild or configuration
setting is needed. An embedded or unregistered library host keeps direct launch.

The guardian signals its own membership-anchored group with SIGTERM when the
server process exits. Closing a control socket or dropping the server's Tokio
runtime is not treated as proof of process death. The guardian retains the
kernel parent-exit notification through that interval. The configured worker's
inherited signal disposition and mask are not changed.

A guardian that exits while the server lives is replaced for the same worker
first. Only an actual failed rearm invokes the existing managed stop/grace path
and normal supervisor relaunch. Guardian status never substitutes for worker
status. There is no new timer, restart delay, cap or admission policy.

## Stop during a join

A guardian is first spawned in its own private group. The controller obtains its
actual child handle before acquiring a worker-group pin and authorizing the one
self-join. The pin holds the worker unreaped until that join has finished, or the
controller has killed and reaped that joining guardian. Every signal still
checks actual worker exit under the same short lock as the worker's wait poll.

On macOS, abort and the signal phase of terminate can therefore wait for an
outstanding private guardian join to be independently killed and reaped before
sending the original worker-group signal. They never wait for worker exit while
holding that pin. A guardian blocked before its initial exec holds no worker pin
and does not delay worker stop. A normally armed guardian has no join pin and is
not removed before the worker's original TERM/KILL signal.

## Qualified failure cases

The controller is the sole waiter for its private standard-library child. If
that ownership contract is broken, such as by an external reaper, a failed wait
is UNKNOWN: it is not a terminal receipt or permission to signal a cached PID.
The actual child handle and any outstanding pin are retained until server
process exit. Worker stop can remain pending in that exceptional case. There is
no forced unpin, fabricated status or claim that every error is hang-free.

A stopped guardian cannot process its parent-exit event until it resumes.
Combined guardian loss and server death during rearm are not claimed to have
Linux's direct parent-death guarantee. This mechanism does not add adoption of a
worker after its parent has died, and it does not prove a bound on every
externally stopped or kernel-failed process.
