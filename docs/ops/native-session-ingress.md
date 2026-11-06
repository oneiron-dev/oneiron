# Native session loopback ingress

On Linux, `GuestSession::connect_loopback` and
`NativeFenceGuard::connect_loopback` open a fresh stream to an exact
`SocketAddr` in that fence's virtual loopback registry. The caller must hold
the actual session or trusted native-fence guard. The address is canonicalized
like a guest dial, including IPv4-mapped IPv6. It must name an existing
loopback listener in that same session. This opens no kernel INET listener,
public port, host-network route, or connection to another session.

The caller supplies its cancellation predicate. A full backlog waits in the
same ordered ticket line as guest connects, using the existing wake cadence.
Cancellation or session end answers `EINTR`; a closed or absent listener
answers `ECONNREFUSED`. Host-floor back-pressure is returned unchanged. No
new backlog, timeout, retry, or descriptor limit is added.

Both pair descriptors are admitted on the relay's existing host floor before
the pair is created. The queued end uses the ordinary guest accept reservation
and installation path. Its charge ends when that host descriptor is closed
or transferred into the guest. The returned `LoopbackConnection` keeps the
host peer's charge. `into_parts` transfers the `UnixStream` and its
`HostNetPermit` together; an async adapter must keep that permit until its
stream closes. As with a guest dial, closing the host peer does not withdraw
a connection that is already queued or accepted.

This is a trusted local primitive, not app port admission or a public preview
endpoint. Callers still own declared-port selection, session lifetime, and
existing owner/invite/share and revocation handling. The stdio fields of
`SessionTransport` are unchanged. On Linux its existing `SessionLease` exposes
the same independent stream capability after `GuestSession::into_transport`.
Backends without that capability answer `Unsupported`; they do not silently
reuse stdio or fall back to host TCP.

## Native Firecracker sessions

A native OCI session's lease connects to its own retained jail directory's
base `vsock.sock`, sends `CONNECT 55\n`, and reads exactly the VMM's
`OK <host-port>\n` line before sending the session request. Ports 52 (stdio),
53 (control) and 54 (egress) retain their original roles. Trusted guest PID 1
binds port 55 before spawning the native command. It admits only host CID 2
and the same session's existing 32-byte bridge token, then calls the same
`NativeFenceGuard::connect_loopback` registry and ticket path. This token
identifies the private session channel; it is not an engine read key or grant.

Firecracker treats a host Unix-socket EOF as shutdown of both vsock directions.
The separate ingress channel therefore frames each direction: a big-endian
32-bit length precedes each data chunk (at most 32 KiB); zero means directional
EOF; `u32::MAX` means full close. A write-half-close leaves the reverse stream
open. A full close or session cancellation closes both. These are transport
frame values, not a total byte allowance or a new policy limit. IO checks
session/caller cancellation at the existing loopback 250 ms cadence; no
opening deadline is added.

Before creating any host socket, the original relay floor admits the three
host descriptors and two bridge workers. The returned stream retains its
one-descriptor permit. The bridge retains the other two descriptors' and both
workers' permit until both workers finish. A lease drop clears the original
session-alive flag; pending connects and active workers observe it and close
their sockets. Guest workers are inside the VM, not host-floor worker claims.
The guest fence stays held across command exit and stdout drain until the
host ends VM custody, as before.

This source requires a matching rebuilt guest binary/rootfs and updated
artifact/release pins when adopted. It does not rebuild or deploy them,
change the kernel bytes, repin an older recipe, or change the generic guest
protocol version. An older guest image without port 55 does not gain this
capability merely because the host source changed. Source qualification is
not a compiler, boot, runtime or end-to-end certificate.
