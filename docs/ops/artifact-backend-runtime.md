# Published artifact backends over HTTP/1 stdio

**Source implementation, not a deployment or runtime proof.** The native
Firecracker path transfers the projected directory bytes before starting the
command. It verifies their digest and mounts them read-only inside the guest.
Host and guest must be deployed together with the matching native protocol.
The contract below describes the source, not a completed deployment.

A host can run a published code artifact on its artifact-only listener. This
initial runtime is one isolated guest per HTTP request. The host supplies no
engine credential or engine-action grant. Ordinary computation and HTTP serving
do not require such a grant.

## Host execution profile

Set an explicit `[artifact_backend]` section in the served configuration file.
There are no image or resource defaults, and this section does not reuse
`[browser]`. Ordinary serve, embedded serve through `build_server`, and managed
serve pass the same profile to their server. The explicit `max_concurrent_sessions` host budget
covers staging, running and cleanup together. A request owns its permit until
the native process is reaped and both dedicated IO workers have joined.
The workers do not occupy Tokio blocking-pool slots needed for native cleanup.
An embedder constructing a server
directly can use the fallible `SyncServer::with_artifact_backend`.

The following values are an example, not defaults or a provisioned image:

```toml
[artifact_backend]
runtime = "/usr/bin/podman"
image = "example/app-runtime@sha256:0000000000000000000000000000000000000000000000000000000000000000"
uid = 10001
gid = 10001
memory_mib = 512
cpu_millis = 1000
pids = 64
tmpfs_mib = 64
bridge_buffer_bytes = 16384
max_concurrent_sessions = 8
```

The host provisions the runtime, pinned image and native fence launcher. The
native untrusted-session selector keeps its existing backend selection and
isolation requirements. No VM, image installation or deployment happens when
this source is changed. An absent profile leaves existing static serving
unchanged.

## App contract and address

Publish an Artifact-class code snapshot containing `oneiron.backend.json`:

```json
{
  "transport": "http1_stdio",
  "command": ["/usr/bin/python3", "/app/backend.py"]
}
```

The command runs **inside the configured guest image**, not on the host. Its
stdin receives one HTTP/1 request. Its stdout must contain the HTTP/1 response;
application logs belong on stderr. It can stream its response. This is an inetd
contract, not an adapter for an arbitrary process listening on a TCP port.
The guest sees admitted regular-file projections under read-only `/app`.
Executable bits are retained; snapshot symlink metadata is not recreated as
host symlinks. Writable temporary storage is the native guest's bounded tmpfs.

On KVM hosts the existing selector still chooses Firecracker. The host makes a
private archive from every caller-selected read-only directory. Descendant host
symlinks are copied as link metadata, never followed to collect host bytes. The
archive's length and BLAKE3 digest, plus the explicit uid/gid, travel in the small
native Start frame; file bytes follow separately on the same channel. The digest
is part of the session's argument receipt. The guest verifies the entire stream
before mounting files or starting the fenced command.

The guest uses an OverlayFS view of its pinned image to create arbitrary mount
destinations, then makes that root read-only again. The original system mounts
and writable scratch remain separate. Source directories are bind-mounted
read-only, nosuid and nodev. Archive extraction and the overlay upper tree share
the configured tmpfs budget; no additional file-count or bundle-size default is
introduced. The ordinary component guest keeps its existing identity defaults;
native sessions use the caller's actual non-root uid and gid. The native fence
includes `/app` in its read/execute-only Landlock paths; it grants no write
access to the code mount.

On the artifact listener, use `/_apps/<artifact>/`. The native `_t/<token>` and
`_s/<selector-kind>/<selector-value>` URL positions work after the artifact id,
just as on `/a/`. Entry URLs redirect to the canonical selector form. Query
selectors are consumed by the router; other query parameters reach the app.
App documents should use relative resource URLs; response bodies are not
rewritten. App-produced redirects resolve within the admitted app root,
including absolute Location values. They cannot redirect a fetch into another
artifact on the shared origin. External navigation can use an explicit link
in the app document instead.
The guest sees only its application-relative request target and a fixed
`Host: artifact.invalid`, never the reader's link capability path. Requests
can use any HTTP method, and their original bodies are streamed, not collected
under a new body-size cap.

These new routes exist only on the artifact-only listener. They are not API
routes. Existing `/a/` URLs, static headers, method handling and CSP are unchanged.
A configured app host (`<app>--<vault>.<domain>` or the managed
`<app>.<vault_id>.artifact.invalid` authority) selects the same backend from
its root URL. Redirects, cookie paths and CSP keep that browser-visible root,
including the native token and selector, rather than the internal route alias.
The hostname selects the vault and artifact; it grants no read or engine action.

With no execution profile, app hosts keep their static behavior. With a profile
but no admitted backend manifest, GET and HEAD fall back to the same static
reader, redirect, tier, projection, ETag, cache and CSP handling before any guest
starts or private headers are removed. Other methods remain unavailable on a
static app. A malformed manifest or staging error remains an error, not a static
fallback. Vault hosts (`<vault>.<domain>/<artifact>/…`), local `/a/` routes and
the API listener keep their existing behavior. Local `/_apps/` remains
backend-only; it does not become another static route.

## Authority and process lifetime

One read transaction admits the actual pointer, its target Scope, selector and
reader tier. It uses the same taint/stale policy, quarantined-path exclusion,
repo-mark projections, masked byte reader and output hashes as static serving.
The runtime mounts only those projected bytes in a fresh host-owned scratch
child. It does not mount an owner's checkout or a private preview process.
The snapshot's paths are validated before any filesystem write. The scratch
parent remains private on the host; only the readable child enters the guest.

No owner/read Authorization, binding proof, engine headers, forwarding
attestation, incoming host cookie or link capability is passed to the guest.
Server-set application cookies can round-trip across per-request guests. The
host stores each cookie under `oneiron_app_<hash>_<guest-name>`, where the full
BLAKE3 hash is domain-separated over the validated serving authority (host and
port, ASCII-lowercased) and admitted canonical app root (including its selector
and any link-token path). Including the port keeps local listeners separate even
though browser cookie domains do not distinguish ports. Only names in that exact namespace are
unwrapped into the guest request. All incoming host cookies are still removed;
app cookie values are ordinary client input, never engine credentials or grants.

Guest cookie paths are relative to the app root. The host rebases an explicit
`Path` inside that root, or uses the original request's application-relative
RFC default path when `Path` is absent or invalid. It removes `Domain`, so the
browser cookie is host-only. It preserves separate `Set-Cookie` headers, their
order, expiry/deletion values, Secure, HttpOnly, SameSite, Partitioned and other
attributes. The same name/path rewrite handles deletion. Valid browser-reserved
names such as `__Host-session` are supported by enforcing their original
Secure/HttpOnly/explicit-root/no-Domain requirements before wrapping the name;
none is silently downgraded for plain HTTP. Browser acceptance and retention
still follow its normal cookie rules. No cookie jar, expiry timer or size/count
limit is added on the host.

This is a server `Set-Cookie`/`Cookie` transport, not a transparent rewrite of
`document.cookie`. JavaScript sees the stored names, and direct browser cookie
APIs or DOM storage do not gain per-app origin isolation on this shared listener.
An application's cookies do not authenticate engine actions. Hop-by-hop headers
are rebuilt. Backend responses are no-store and use a path-scoped
connect/form CSP for this app, with no frames or workers. This does not relax
the API-origin or static-artifact policies.

The response body owns the native session lease. The two blocking IO bridges
own only its pipes. Completion, error, request cancellation or response drop
aborts the HTTP connection, drops the native lease off the async worker, and
joins the pipe workers before removing scratch. Native lease drop supplies
process stop/reap. In the native VM the stdout copier is joined and its output
half is closed after draining. Guest PID 1 keeps the existing fence and control
heartbeats alive until the host lease stops the VM; a command exit does not kill
pending response bytes. No new timeout substitutes for that custody.

## The app's own engine actions

A native app uses `ONEIRON_NATIVE_EGRESS_SOCKET` with the Fetch framing in
[native-session-fetch.md](native-session-fetch.md). For this artifact runtime,
only relative `POST /v1/core/actions/{verb}` calls reach the engine. The request
body is the existing action request (`args`, `idempotencyKey`, optional
`liveRun`), encoded as the Fetch body's byte values. Authorization and holder
proof headers must be the app's own. Other URLs and ordinary network socket or
datagram operations remain unavailable. Redirect following opens no second URL.

The host retains the exact pointer, fork hash and physical code-artifact record
id from the same read transaction that projected the staged files. No later
head lookup or guest-supplied source label selects this identity. The native
binding middleware admits the caller's proof once. The normal CoreAuth path
then checks a verified Agent credential whose full native app principal matches
that staged artifact, fork and code-artifact record. This identity match grants
nothing: the ordinary current-grant, action scope, gate, invocation, read-key,
Memory, room, off-record session and receipt paths still judge the call.

The adapter runs the original action router and returns its HTTP status, raw
headers, body and call-receipt stamp. Inner facade calls reuse the admitted
headers and extensions, not another proof-consuming admission. No owner
attestation, browser credential, host-root identity, fake connection address or
new Memory is supplied. A native request with no proven connection retains the
ordinary off-device/unknown destination; it does not become local merely
because the relay runs in the host process. A zero-action credential still has
no action scope. Ordinary zero-grant computation and HTTP serving continue.

The ordinary API body codec decodes the request after binding admission and
before the staged identity check and action readers. It also negotiates JSON
reply compression. The original wire observer counts the call under its own
caller, and the ordinary connection-receipt wrapper keeps its existing path
selection; the action handler still supplies its own receipt stamp. Action
idempotency remains the request body's `idempotencyKey`, not a second header-key
cache. All codec, receipt and telemetry policies are the existing API policies.
The existing `limits.request_body_bytes` setting and its refusal-naming
middleware also apply. The adapter chooses no separate body limit.

## Remaining work and evidence limits

The separate artifact-backend pairing API creates an app's own principal and
one-use holder pairing with empty action scope. The runtime does not inject or
redeem that credential. The explicit owner grant and backend-slip APIs can issue
its own scoped capability, bound to the app's public holder key. The app must
hold its own key and present its own credential and proof. An app label,
snapshot hash, reader federation grant or owner credential is not that authority.
There is no permissive network egress proxy in this runtime.

Persistent/declared-port applications, direct browser cookie and DOM-storage
isolation, automatic cloud app-host dispatch and an end-to-end runtime proof of
grant-bearing engine calls remain work under OF-356.
This implementation does not claim that the whole published-backend row is
complete. Static source inspection and formatting are not runtime, isolation
or compiler evidence. Publication still needs the Engine's passing production
compile train. No tests are written, compiled or run under the decree.
