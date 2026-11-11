# Requested bundle publication: existing-generation grants

An asked publisher can carry the home's latest generation even when it has no
reader or in-object publication capsule. It uses a separately offered
`world_keys::SealedPublicationGrant`, not a plaintext outer key or a pad-admission
grant.

## Native flow

1. On the existing bundle upkeep tick, a current proved owner machine asks the
   home for pending publication grants. The native grantee selector supplies the
   exact request/executor under its current recipient key.
2. An old reader fetches both actual objects through the ordinary machine read
   path. `Vault::seal_bundle_publication_grant` must open both with its own
   capsules, verify the native bodies, bundle publisher and matching generation,
   then sign the exact request, executor, issuer, recipient-key digest and both
   sealed grant envelopes. Merely keeping ciphertext does not let a home issue it.
3. The home checks that the generation is kept and the native pair is admitted
   under its current authority in the same writer as the offer. The uploader's
   socket does not supply issuer authority.
4. The asked executor first uses the existing reader/in-object paths. Only a
   typed missing capsule triggers `publicationGet` for that exact generation and
   request. The home derives the executor from the socket proof and rechecks the
   current request and pair admission. Actual use again checks native admission,
   OpenPolicy, both object AEADs and the bundle publisher. No world key is granted.
5. The same pair is passed to assembly. The existing slot, turn, attempt,
   reconciliation, commit and enactment path remains in charge of publication.

An offer that does not open the current objects is invalidated by its proved
executor. The home removes only the exact tried offer, not a concurrent
replacement. This permits a fresh pair after an in-place pad rewrite. If no
reader can issue a usable pair, the request stays pending as before. Grant
upkeep failures do not stop the pre-existing pad-admission or erase work.

## Storage and wire

The existing raw `SYNC_RESIDENCE_BUNDLE_ACCESS` table has a separate
`p:<generation>:<request>:<executor>` key family. Values are strict native signed
pair bytes. Existing `q:` admission and `g:` pad-grant rows and parsers are
unchanged. Pair rows are removed with their generation in its retiring writer.
The existing table remains LIVE and checkpoint-Unclassified; it is not a new
owner payload, new table, restore getter, authority record or plaintext escrow.

The existing `residence.bundle.access` RPC adds four tagged JSON operations:
`publicationPending`, `publicationOffer`, `publicationGet` and
`publicationInvalidate`. Write operations use the existing write scope. Deploy
matching engine/server code when releasing this transport. There is no new
configuration, numeric cap, timeout, timer, crypto purpose or migration.

This describes the implemented native path. A passing production compile and
runtime delivery are separate evidence; source inspection alone proves neither.
