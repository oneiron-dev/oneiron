# Owner vault-key lock

`POST /v1/owner/vault-key/lock` uses the same owner authentication and proof as
the other `/v1/owner/vault-key` routes. It has no request body.

The door calls the existing async vault lock on this running server's vault
handle. Snapshot admission closes, the attached runtime is asked to release
its state under the existing release bound, then this handle's key is dropped.
The sealed snapshot catalog and wraps are not deleted. Unlock remains at
`POST /v1/owner/vault-key/unlock`.

The response is the native snapshot lock receipt:

- `closed_generation`: the snapshot admission generation that closed.
- `bound_ms`: the existing runtime release bound plus its margin, or `null`
  when no runtime is attached.
- `release`: the runtime's answer, or `null` with no runtime attached. The
  answer includes released count, aborted worker incarnations, timeout and
  elapsed time, and host-copy counts at the start and at its answer.

A timeout or nonzero `host_copies_left` remains visible; an HTTP success does
not turn it into a successful full release. The receipt describes this lock
operation, not a promise that no later owner action unlocked the handle.
The route adds no timeout, worker policy or automatic unlock.
