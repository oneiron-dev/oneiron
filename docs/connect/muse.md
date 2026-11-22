# Connect Muse to your vault

Muse reaches your vault as a remote MCP server through a custom connector and
signs in with OAuth 2.1 (PKCE and dynamic client registration). Nothing is
installed on your side. Never paste a token, slip or key into a Muse chat: the
sign-in below is the only credential Muse needs, and the vault holds the rest.

What Muse sends is taken from service reports, not from a contract Meta
publishes; the vault's sign-in is the same standard route every app uses.

## Before you start

Your vault must be served at a public https address, and that address must be
its OAuth identity. Start `oneiron serve` with
`--oauth-resource-indicator https://<vault-host>` (or set
`oauth_resource_indicator` in its config): an https origin with no path. A
vault without it answers 404 on every OAuth route, so no app can sign in.

## Add the connector

1. In Muse, add a custom connector with the MCP URL
   `https://<vault-host>/mcp`.
2. Start the sign-in. Muse registers itself with your vault and opens your
   vault's sign-in page. The page shows a six-character match code.
3. Answer the ask in your Oneiron inbox. It names the app, the tier it asked
   for and the same match code. Check that the codes match, then allow it and
   pick the tier:
   - `read`: it reads, and writes nothing;
   - `propose`: it reads, and each write waits for your review (the tier an
     app gets when it asks for none);
   - `full`: its writes take effect at once.

   You may also bind it to one world: it then reads and writes in that world
   alone. Over MCP or the SDK the answer is `vault.oauth.authorization.answer`
   with `request_ref`, `allow`, `tier` and `world_ref`.
4. The sign-in page sends Muse back with its code, and Muse trades it for its
   tokens. It then lists your vault's tools and calls them under the grant you
   allowed. Its tokens refresh on their own.

## Stop it

Your answer is an agent grant in `vault.consent.registry`. Revoke it there
(`vault.consent.revoke` with its `grant_ref`), and Muse's next call is
refused. Connecting again needs a new sign-in and your new answer.

## Notes

- Each connection is its own agent with its own grant. Two Muse connections
  are two agents, and the name "Muse" grants nothing by itself.
- `crates/oneiron-server/tests/oauth_named_client_acceptance.rs` runs Muse's
  client profile against a served vault in CI. A run with a live Muse account
  is your own act and is not part of CI.
