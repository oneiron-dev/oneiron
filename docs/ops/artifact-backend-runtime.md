# Published artifact backends over HTTP/1 stdio

**Source implementation, not a deployment or runtime proof.** The native
Firecracker path transfers the projected directory bytes before starting the
command. It verifies their digest and mounts them read-only inside the guest.
Host and guest must be deployed together with the matching native protocol.
The contract below describes the source, not a completed deployment.

A host can run a published code artifact on its artifact-only listener. This
initial runtime is one isolated guest per HTTP request. It holds no engine
credential and has no engine-action grants. Ordinary computation and HTTP
serving do not require such a grant.

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
Configured cloud subdomain rewriting continues to serve its existing static
paths. A cloud edge must explicitly forward this new backend route to the
artifact listener with a local authority outside the configured artifact
domains. The existing public/internal subdomain rewrite is static-only;
automatic app-subdomain backend selection is not part of this slice.

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
This first per-request transport does not forward cookies or accept app
Set-Cookie responses. Application-cookie namespace/path isolation remains
separate work; it must not reuse host authentication cookies. Hop-by-hop
headers are rebuilt. Backend responses are no-store and use a path-scoped
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

## Remaining work and evidence limits

The separate artifact-backend pairing API creates an app's own principal and
one-use holder pairing with empty action scope. This zero-action runtime does
not inject or redeem that credential. Later owner Ask grants need a real
scoped capability issuance and dispatcher join; an app label, snapshot hash,
reader federation grant or owner credential is not that authority. There is
no permissive egress proxy in this runtime.

Persistent/declared-port applications, application cookies, automatic cloud
app-host dispatch and grant-bearing engine calls remain work under OF-356.
This implementation does not claim that the whole published-backend row is
complete. Static source inspection and formatting are not runtime, isolation
or compiler evidence. Publication still needs the Engine's passing production
compile train. No tests are written, compiled or run under the decree.
