# Managed HOST legal-copy channel

The native managed-process launcher can hand the engine an additional Unix
listener with `--host-legal-listen-fd` and `--host-legal-uid`. The arguments are
an optional pair. With neither argument, startup and serving stay unchanged.
They are not settings-file fields, environment settings, HTTP routes, owner
verbs or agent verbs. This handoff is not a vault-VM vsock transport.

## Launcher ownership

The manager binds the listener before spawning the tenant engine. It owns the
private directory, socket pathname and cleanup. The directory must remain in
the HOST namespace, not a tenant-owned vault or run directory. The UID is the
actual manager identity, distinct from the engine's effective UID. Passing a
number in argv does not prove filesystem privacy or install a HOST store.
The matching manager must implement those requirements and consume the native
capture protocol; this engine startup port alone is not that manager.

The descriptor must be distinct from the HTTP listener in `HYPNOS_LISTEN_FD`,
the ready and credential pipes, the custody-anchor credential pipe, and both
restore pipes. Startup checks aliases before consuming any of those inputs.
It takes the legal descriptor once, clears the resolved handoff before managed
arguments are cloned, and sets close-on-exec before starting child programs.
The engine never binds, unlinks or changes permissions on the manager's path.

## Native admission and serving

The listener stays uniquely owned across fallible startup. Only after the
vault's open or restore gates does `HostLegalChannel::from_listener` validate
the actual AF_UNIX pathname socket, socket inode owner, listening state and
HOST/tenant UID separation. Native accept checks the kernel credentials of
that same accepted connection against the pinned HOST UID. An ordinary owner
credential or a request field cannot construct an admitted connection.

The legal service starts before the ready byte, after the cold restore's
verification notification. The listener accepts asynchronously; each native
collector runs on the managed blocking executor with the same opened vault.
The native collector, not the startup adapter, owns capture framing, source
and order checks, encryption, custody, source-writer lifetime and the exact
durable HOST acknowledgment. A successful socket accept is not a stored-copy
receipt or proof of a complete legal-hold replacement.

## Stop and failed startup

The service is retained with the managed startup handles. On shutdown or a
later startup error it stops accepting, sets the native cancellation flag and
shuts down **all** accepted sockets before joining **any** collector. Every
blocking collector is joined before the vault can close. This drain precedes
control-task joins. A gate or message collector reads one LMDB read snapshot
and holds no writer, so no control request waits on a collector to write.

Collector and listener failures are logged. Denied peers, interrupted accepts
and aborted connections leave the listener running. Another accept I/O error
drains and ends only the optional legal service; ordinary tenant serving
continues, and the HOST manager observes a closed channel rather than a custody
receipt. No automatic retry timer is added. Listener identity checks occur
after vault/restore gates, so a bad handoff can open the vault before startup
fails. These failures never become successful capture receipts.

The existing managed teardown keeps the original startup
error primary, continues cleanup after a stop-notification error and preserves
the normal stop/serve/telemetry result order. There is no new timer, capacity
policy, compatibility reader or detached collector. Existing in-place legal
holds, customer holds, spill handling and ordinary tenant serving are not
removed by this startup port.
