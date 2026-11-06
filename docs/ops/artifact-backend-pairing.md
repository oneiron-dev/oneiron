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

The native principal-standing check also recognizes this exact live app
PERSON as class `agent`, unless it is archived. It then requires the same
single live owner grant that names that principal and the work's exact verb,
under the same snapshot, clock, owner and pact rules as other agent work.
It does not union grants or use the human PERSON branch. This makes the
native standing primitive available to work that already calls it; the
standing check itself does not enqueue an app callback.

The empty-verb bootstrap slip stays empty. A grant row does not widen it.
The owner explicitly issues a separate credential through
`POST /v1/owner/artifacts/backend-slip`:

```json
{
  "grant_ref": "the-owner-agent-access-grant-id",
  "holder_key": "the-apps-64-character-public-ed25519-key-hex",
  "expires_at": 1794000000,
  "comm": "parent"
}
```

All fields are required. `expires_at` is an absolute Unix second chosen by the
owner, later than the vault's current instant. The key is the app's public
binding key; the app keeps its private key. This is a new explicit owner act,
not an upgrade of the bootstrap or a requirement to find an earlier slip.
The response has `token`, `principal_ref`, `grant_ref` and `expires_at`. Treat
`token` as a credential and give it only to the app whose key it binds. Use
it with the normal holder proof; possession of the token alone is not proof.

A Rust app can use `oneiron_remote::replace_paired_slip(&credential, &token)`
to keep its own existing connection key while adopting this separately issued
slip. The returned value is again one private `v2.cred.` credential. This only
formats the credential: it issues no token or grant, reads no authority from
the token and does not widen the bootstrap. The normal server checks still
verify the new slip's signature, holder, binding key and exact live grant.

The native `Vault::mint_artifact_backend_slip` checks the owner and host issuer,
then selects exactly that existing live owner-agent Access grant and its native
app principal in the same writer that signs and logs the slip. Its signed
six-axis scope is the selected grant's exact scope, and its class is `agent`.
It creates no grant, combines no grants and adds no verbs. The grant must still
confer under the native clock, owner, withdrawal and pact rules. Personal-vault
residence grants use the same native path as shared-vault grants.

Each normal slip liveness check rechecks the exact grant. Current-scope checks
reject a cached proof that exceeds a narrowed grant, and proof-backed read keys
meet the current scope in their own snapshot. Expiry, withdrawal, an archived
app or a lapsed native grant ends its standing even if the token's own expiry
is later. No extra credential lifetime cap is added.

The normal credential and dispatcher checks still apply. This issuer does not
pass a holder key, slip or grant into a backend guest. The artifact runtime's
native Fetch relay carries the app's own signed requests to `/v1/core/actions`;
it does not supply the app's private key or credential. The request must name
the app PERSON for the exact staged artifact, fork and code-artifact source.
The app remains responsible for obtaining and holding its own key and token.

The same Fetch relay accepts `POST /v1/core/pairing/redeem` for this app's
bootstrap. The app receives its one-use link through its own channel, generates
its own key and sends the normal signed redemption body. Before redemption,
the runtime checks that `holder_ref` is the app PERSON for the exact staged
artifact, fork and code-artifact source. The ordinary redemption handler still
checks the one-use code, possession signature, pin and holder. Its reply returns
the empty-verb bootstrap credential to the requesting app; it neither mints an
owner grant nor upgrades that credential. This opens no owner endpoint,
arbitrary HTTP origin or slip-renewal endpoint. The owner-grant token is still
delivered to this app through its own channel after the explicit owner act.
No engine-owned private key, key storage or persistence across backend sessions
is supplied by this door.

For an app using the Rust client, `oneiron_remote::PreparedPairing::new(link)`
prepares the existing signed redemption without sending HTTP. Keep the returned
value inside the app. Its `binding_key()` is the nonsecret public key the owner
can later name when issuing the explicit grant-bound slip. Serialize
`request_body()` as JSON and send it through the native Fetch relay to
`/v1/core/pairing/redeem`, without an Authorization bearer. Handle a non-success
HTTP response before calling `finish(reply_body)`. That consumes the prepared
value, checks the original checkpoint pin and returns the ordinary
`(origin, credential, pin, comm)` tuple. The credential contains the app's private
connection key and must stay one secret. This client neither logs it nor stores
it on disk. The direct-HTTP `OneironClient::pair` and `pair_pinned` paths use the
same preparation and reply validation; the prepared value is for callers that
provide their own transport. It does not turn the facade client into the guest's
action transport or supply persistence across backend sessions.

An app that already retains its own private Ed25519 connection seed can use
`PreparedPairing::from_seed(link, seed)` instead. The same link, signed transcript,
checkpoint-pin check and reply decoder apply. The fresh-key `new` path is
unchanged. The seed is the app's secret, not permission: the explicit owner grant
and current-grant checks still decide every engine action. Generate and retain it
through the app's own private channel, never in its published source, cookies,
browser state, request body or logs. Supplying a retained key does not supply a
storage backend, persist guest tmpfs, recover a spent pairing link or change the
one-use redemption rule. The app remains responsible for retaining the resulting
credential as well as receiving any separately owner-issued grant slip.

If the app restores an ordinary paired credential, call
`oneiron_remote::paired_binding_key(&credential)` to recover its nonsecret public
binding key for the owner's later slip issuance. A bare bearer returns `None`;
malformed paired credentials keep the ordinary parser error. The helper uses the
native key parser and derives only the public key. It sends nothing and verifies
no grant, slip or identity; never send the private credential to the owner.

After adopting the app's separately issued grant slip, use
`oneiron_remote::prepare_app_action(&credential, verb, &action_body)` to prepare
an existing `InProcessRequest` for the native Fetch relay. Its method, relative
path, credential-bearing headers and body belong only to that relay. The body
is the original action JSON: `args`, `idempotencyKey`, and optional `liveRun`,
not a facade verb input. The caller chooses its idempotency key; this helper
adds no `Idempotency-Key` header or header cache. Prepare a fresh request for
each send, including a retry with the same body idempotency key, so the native
holder proof gets a fresh nonce. This function reuses the ordinary credential
header builder and JSON encoding. It sends nothing, installs no credential,
and changes no staged-app, grant, scope or dispatch check. The app handles the
Fetch response through its own transport.

This is the identity bootstrap and owner-grant join for FIX1116 / OF-356, not backend deployment.
It starts no process, changes no publication pointer or audience, and exposes
no private preview. An app can compute and serve without engine-action grants.
The pinned-code process/request lifecycle on the artifact origin and the
explicit owner-Ask grant join remain separate work. This endpoint does not
claim that either has run.
