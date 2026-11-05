# Organ mesh input destinations

An organ router tries its local host first. If that host cannot run the call,
it tries the owner's mesh nodes in roster order. With no usable node, the call
keeps its existing waiting state and records the reasons.

## Vault inputs

Before it reads or stages a vault input for a mesh node, the router:

1. Dials the node and checks that it offers the requested organ and verb.
2. Resolves the connection's authenticated endpoint key through
   `Vault::mesh_peer_machine` for the organ ALPN.
3. Reads the metadata for each exact artifact version. The native metadata
   reader validates its persisted `blob.version` claim.
4. Passes every artifact and version claim to `Vault::release_hold_for`, toward
   the connection's machine proof.

Every input must pass before any input body is materialized for that node. A
native release hold skips that candidate and records its content-free reason.
The router tries the next node, or waits if none can take the call.

The router materializes inputs once, after the first permitted offer, and keeps
that copy across candidate attempts. It checks all input destinations again for
each candidate before sending. The caller's original secret sight still selects
each input copy. Local execution is unchanged.

The grant roster and an organ offer are not world-recipient proofs. An unproved
endpoint uses the native judge's unknown-destination behavior; this change does
not require a new machine profile or reject Everywhere rows on that basis.

## Scope

The check uses current native row/world placement. It adds no artifact-world
field and infers no world from a hash, media type, organ name, or user label.
Version metadata, the release verdict, and the body read use their existing
native snapshots; this is not a new atomic snapshot spanning those operations.

Arguments, typed bodies, and caller-lent bytes do not gain a new placement
carrier. Their existing caller-side admission is unchanged. Mesh grants,
secret masking, input hashes, resource admission, deadlines, receipts, output
landing, and wait-row storage are unchanged.

## Release

Rebuild the engine and its organ-host consumer at an authorized release. No
protocol version, client schema, configuration, or data migration changes.
