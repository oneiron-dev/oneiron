# Published-app backend pairing

`POST /v1/owner/artifacts/backend-pairing` gives a published app its own
fresh principal and a one-use pairing link. The caller must be the authenticated
vault owner. A host issuer alone cannot call it as the owner.

Request:

```json
{
  "artifact": "the-code-artifact-project-id",
  "fork_hash": "the-64-character-export-fork-hash",
  "lifetime_secs": 3600,
  "comm": "parent"
}
```

All four fields are required. `comm` is the owner's explicit communication
ceiling (`parent`, `subtree`, `project`, or `vault`), not permission to send.
`lifetime_secs` takes the normal pairing lifetime policy; this endpoint adds
no lifetime default. The selected snapshot must belong to this artifact and
have class `Artifact`, not `Codebase`.

The response has `artifact`, `fork_hash`, `code_artifact_ref`, `principal_ref`,
and the normal `link` (`code`, expiry, checkpoint pin, and communication ceiling).
Treat the one-use link as a secret. Give it to this app, not to a public page.
The app generates its own binding key and redeems the link through
`POST /v1/core/pairing/redeem`, using `principal_ref` as its holder. The existing
pairing transcript and holder-proof rules apply. No owner key is handed to the
app.

Each successful bootstrap creates a fresh actor; it does not adopt or revoke a
named agent's existing identity or grants. The actor's native body records the
artifact, fork hash and code-artifact id selected in that same write. Those
fields and the fresh random name derive its principal id. They identify the
app; they grant no action or read.

The owner is checked in the actor writer and again in the pairing-link writer.
If issuing the link fails after actor creation, an actor row can remain, but no
credential or grant is issued.

The paired slip has an explicitly empty engine-action verb scope. This call
creates no agent ceiling, policy grant, reader federation grant, or proxy
connector admission. The owner recorded on the link is not its holder.
The signed communication ceiling does not add a verb.

## Explicit owner grants

The owner can name this `principal_ref` as `agent` in the existing
`vault.agents.grants.mint` door. The native grant writer recognizes this live
app PERSON by its complete stored descriptor and derived id, not by an app
label or an arbitrary PERSON row. It keeps the same owner revalidation, exact
six-axis `authority_scope`, explicit verb list, expiry, optional repo bounds,
signed authority act and FEDERATION_GRANT row. The ordinary consent registry
and `vault.agents.grants.revoke` own that row. There is no second app grant
store, automatic grant, agent-definition ceiling or new approval step.

The empty-verb bootstrap slip stays empty. A grant row does not widen it: a
caller also needs an owner-issued credential whose own scope admits the call.
The normal credential and dispatcher checks still apply. This identity/grant
join does not pass a holder key, slip or grant into a backend guest, and does
not provide the guest's native action transport.

This is the identity bootstrap and owner-grant join for FIX1116 / OF-356, not backend deployment.
It starts no process, changes no publication pointer or audience, and exposes
no private preview. An app can compute and serve without engine-action grants.
The pinned-code process/request lifecycle on the artifact origin and the
explicit owner-Ask grant join remain separate work. This endpoint does not
claim that either has run.
