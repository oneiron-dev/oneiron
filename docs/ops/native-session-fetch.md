# Native-session Fetch transport

A native command in a no-NIC microVM can send an HTTP Fetch through the
session's existing host relay. PID 1 sets `ONEIRON_NATIVE_EGRESS_SOCKET` to
`/run/oneiron-native/egress.sock`. This is a transport address, not a credential.
The directory belongs to PID 1. The command cannot replace its socket.

The caller sends one `oneiron_container::HttpRequest` as JSON, preceded by its
four-byte big-endian byte length. The fields are `url`, `method`, `headers`
(name/value pairs), `body` (byte values), and `follow_redirects`. PID 1 accepts
only this Fetch body. It does not accept arbitrary relay commands or refusal
receipts. It wraps the request in the existing `RelayRequest::Fetch` and sends
it over the existing vsock egress port 54. No network interface, new syscall,
inherited descriptor number, or extra vsock port is introduced.

The host uses the session's original `EgressRelay::fetch`. Its policy, receipts,
and host resource floor still apply. Ordinary native socket traffic, fence
proofs, control port 53, and stdin/stdout are unchanged. A caller supplies its
own credentials and holder proofs when the destination requires them; PID 1
and the host transport supply none. An artifact backend with `NoEngineEgress`
still refuses Fetch. This transport alone does not authorize an artifact app
or bind an app credential to its staged code.

The reply is the existing length-prefixed JSON `RelayReply`. Nonzero `errno`
is a transport refusal; `floor`, when present, names the original host floor.
On success, `bytes` contains JSON for `oneiron_container::HttpResponse`: `url`,
`status`, byte-valued `headers`, and byte-valued `body`. An HTTP error status
is still a successful transport exchange. Both directions use the existing
relay-frame bound; a response whose encoded frame exceeds it ends the channel.
Each connection serves one request and then closes.

`examples/native-session-fetch/fetch.py` is a standard-library Python caller.
Run it **inside the native session**, supplying the request on stdin. It prints
the decoded HTTP response as JSON. It does not mint or obtain credentials.

PID 1 creates the socket before spawning the fenced command and starts its
accept loop before reporting native readiness. Each connection owns its guest
IO worker and channel. A parse, relay, or write error closes that connection.
A worker that cannot start also closes its client. These are guest-only threads:
`native::run` returns directly to the PID-1 entry point when the child ends,
and the host session lease tears down the owned VM. There is no host daemon or
persistent socket left by this listener. This source contract is not a VM boot
or runtime validation result.
