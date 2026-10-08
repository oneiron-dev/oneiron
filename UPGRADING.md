# Upgrading

Oneiron is pre-release. These notes cover API and index changes for development
builds. See [MIGRATIONS.md](./MIGRATIONS.md) for storage-format decision history.

## Server authentication

Production HTTP authentication now uses a logged capability slip in the
`Authorization: Bearer` header and a holder proof in `x-oneiron-binding`.
The configured `auth_secret` is issuer key material, not a bearer credential.
Sending it verbatim, or sending an old string-claim token, does not authenticate.

Protected legacy `/api/*` routes and `/v1/usage/*` routes require an owner-grade
credential. This means a verified, unrestricted top-scope slip. A holder identity
alone does not narrow it. Scoped, organization-bound, or caveated credentials do
not meet that bar, even if they can call a corresponding `/v1/core/*` route.
`/api/health` remains public.

Scoped credentials are checked against the scopes and access rules of the
`/v1/core/*` and `/v1/companion/*` routes they call. Move scoped callers of legacy
routes to the corresponding scoped route where one exists. The former
`/v1/consumer/*` billing routes are no longer part of the engine; host applications
own wallet and billing policy.

## Rebuilding text indexes

`ANALYZER_VERSION = "v3"` adds the portable emoji lane. Version `v2` added Han
language routing. These changes affect analyzer-manifest hashes. Text indexes
built with an older manifest must be rebuilt rather than searched with a different
analyzer.

1. Start from the vault's normal `VaultConfig`, retaining its storage and vector
   settings. Set `skip_text_index_manifest_check = true` for recovery.
2. Open the existing vault path with `Vault::open` or `Vault::open_owned`.
   `Vault::open_existing` refuses this bypass. On a populated index, text reads
   and writes remain unavailable until the index is cleared.
3. Run `vault.maintain().clear_text_index().run()?`. This clears the text index,
   not entities, vectors, or edges.
4. Close the vault and reopen it with the normal manifest check enabled.
5. Reindex the documents through the application's indexing pipeline.

The bypass is for recovery only. Do not leave it enabled in normal use.
