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
reuse stdio or fall back to host TCP. A Firecracker host still needs a separate
host-to-guest stream transport and matching guest integration; its keepalive
and Fetch channels do not implement this ingress API.
