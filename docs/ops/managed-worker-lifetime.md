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

## Replacement cleanup across serving-runtime restarts

Each replacement owns a separate process-lifetime thread and Tokio runtime. It
retires the original worker, stops that worker's device admission only when no
worker still uses it, then starts the managed replacement or completes the
external worker's probe. Replacements remain parallel. Dropping the serving
runtime does not abandon this cleanup or cancel its wait for the original worker.

If the thread or its runtime cannot start, the process worker host retains the
same replacement job. A later configuration or worker-launch permission call
retries it. There is no retry timer, new deadline or extra admission policy.
The serving host still notifies each vault's drafter host when workers change.

## Restart for a vault's own drafter

A vault's drafter binding (FIX 14976) restarts a managed EXL3 worker through
the same row replacement as a changed config row. A new supervisor takes the
row, and its launch loads the vault's private load set as the draft. The
predecessor drains and stops through the existing managed stop and grace
path. Then the new worker starts and qualifies. There is no new timer,
restart delay, cap or admission policy. Calls that arrive during the restart
wait for the new worker, as they do after a config change. The new worker
reloads the target and starts with an empty cache.

Only a process that launches the worker for its own one vault restarts it
for a drafter. An external worker is never restarted for one. The hosted row
stays the configured row. If the same config is configured again, the
replacement stays. If the config changes, the row is replaced with the stock
draft, and the vault's drafter host applies the binding again.

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

## Native EXL3 channel identity

On Linux and macOS, a managed EXL3 channel checks the kernel peer UID and PID
against the actual direct child held by that launch's supervisor. Reaping and
terminal publication share the short custody lock used by this check. A copied
PID, socket path, worker name or launch manifest alone is not the proof. The
check holds no lock across a connection or reply wait.

Before a generation or session operation sends any input body or descriptor,
the same connected channel reads a `hello` and checks its launch-manifest digest,
wire model and expected backend epoch. Qualification also checks its channel
before sending its fixed input. Session create, fork, import, export, commit and
drop use the captured launch context. A retiring session keeps its original
context; it does not look up a replacement worker by name. Content-free activity
and drain controls retain their existing UID check.

On Linux and macOS this check is what makes a managed EXL3 worker's native
channel an on-device transport (I2-LOCAL): its models get an on-device offer
whose backend holds the routes captured when the runtime was built and no HTTP
sender, so a call it cannot send natively is not sent. The provider's own
offer is unchanged: native when the current launch has a socket, HTTP
otherwise, an OwnServer route either way. A call takes the on-device offer
only when its route is on device; it never falls back to HTTP. The on-device
offer keeps the provider offer's payer, key custody and rates, so charging is
unchanged: free work (a local payer, no key) stays free, and a paid
provider's call is charged to its payer under its run's budget line, as its
own-server call is. A local-payer keyless provider at locality `third_party`
gets no on-device offer, because on device its paid calls would turn free.
The reranker keeps its HTTP route, so the device-only reranking guard still
sends it a device-only row empty. Other Unix targets retain their existing
transport semantics: no PID check, no on-device offer.
