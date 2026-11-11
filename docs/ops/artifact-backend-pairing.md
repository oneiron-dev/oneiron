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
named agent's existing identity or grants. The owner is checked in the actor
writer and again in the pairing-link writer. If issuing the link fails after
actor creation, an actor row can remain, but no credential or grant is issued.

The paired slip has an explicitly empty engine-action verb scope. This call
creates no agent ceiling, policy grant, reader federation grant, or proxy
connector admission. The owner recorded on the link is not its holder.
The signed communication ceiling does not add a verb.

This is the identity bootstrap for FIX1116 / OF-356, not backend deployment.
It starts no process, changes no publication pointer or audience, and exposes
no private preview. An app can compute and serve without engine-action grants.
The pinned-code process/request lifecycle on the artifact origin and the
explicit owner-Ask grant join remain separate work. This endpoint does not
claim that either has run.
