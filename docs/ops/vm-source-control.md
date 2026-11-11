# Original-engine source control in a vault VM

This is the native supplier for a live restore source. It does not activate
VM-source restore in Hypnos, select a source, or change the Cloud engine pin.
A caller still owns the source actor generation, freeze, whole-family read,
placement fence, final confirm, and the stream through the restore input.

## Native owner

The root bootstrap prepares `/run/oneiron-source-control/owner.sock` before
starting its engine. After `start_engine` returns its actual `Child`, it opens
a kernel pidfd while that child is still unreaped. The same guard is retained
through the existing Open or Restore supervision. It is dropped before the
existing companion and leftover-process cleanup.

The guest engine publishes its selected ctl socket to that root-owned Unix
socket. The bootstrap accepts the registration only from its pidfd-owned
child, using kernel peer credentials. It keeps the first binding and checks
the connected ctl peer again before and after each source exchange. A PID
from Ping, a helper PID, or a copied path is not this witness.

The root directory is created new, root-owned, mode 0711. The registration
socket is mode 0666 so the dropped-UID engine can connect; it cannot replace
entries in the root-owned directory. A pre-existing directory is not adopted.
The source owner removes only its own socket and directory on exit.

## Source transport

`VaultVm::source_ctl` connects to `VM_SOURCE_CTL_PORT`, port **1023**. Linux
AF_VSOCK reserves ports below 1024 to `CAP_NET_BIND_SERVICE`. An ordinary vault
UID therefore cannot impersonate this root listener if source setup fails.
The ordinary `VM_CTL_PORT` bridge is unchanged.

A connection first receives one JSON-line `VmSourceEngine` hello with
`vault` and the bootstrap's actual `engine_pid`. It then carries exactly one
existing `prepare_reap`, `host_order_holds`, or `reap_abort` request and its
unchanged response line. The existing ctl line bound applies. The hello is
not a credential or an actor-generation certificate. The host must associate
it with the same VM boot, original child, and source actor it selected.

The pidfd and synchronous owner-closing flag are checked around the ctl
exchange. Child exit or owner drop cancels all pending source connections.
Caller EOF cancels its pending relay. No source connection silently redials
a replacement engine. The source actor, not this relay, owns preparation and
abort ordering; the relay does not invent another prepare ledger or
terminate the VMM.

## Unavailable proof

Source setup and registration are not readiness gates. A missing pidfd,
unavailable listener, missing registration, wrong peer, child exit, owner
drop, malformed exchange, or disconnected source proves no family. Ordinary
VM control, Open, and Restore keep their existing behavior. Hypnos must keep
its ordinary Unknown restore path until its actual source coordinator adopts
and verifies this supplier. No runtime, privacy, full-row completion, or
Cloud pin activation is established by the native source alone.
