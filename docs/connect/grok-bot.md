# Connect Grok Bot to your vault

Grok Bot reaches your vault as a remote MCP server and signs in with OAuth.
Nothing is installed on your side. Never paste a token, slip or key into a
Grok chat: the sign-in below is the only credential Grok Bot needs, and the
vault holds the rest.

## Before you start

Your vault must be served at a public https address, and that address must be
its OAuth identity. Start `oneiron serve` with
`--oauth-resource-indicator https://<vault-host>` (or set
`oauth_resource_indicator` in its config): an https origin with no path. A
vault without it answers 404 on every OAuth route, so no app can sign in.

## Add the server

1. In Grok Bot, add a custom MCP server with the URL
   `https://<vault-host>/mcp`. Grok Bot does not carry custom servers over
   from elsewhere, so add it in each Grok Bot setup.
2. Start the sign-in. Grok Bot registers itself with your vault (OAuth
   dynamic client registration) and opens your vault's sign-in page. The page
   shows a six-character match code.
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
4. The sign-in page sends Grok Bot back with its code, and Grok Bot trades it
   for its tokens. It then lists your vault's tools and calls them under the
   grant you allowed. Its tokens refresh on their own.

## Stop it

Your answer is an agent grant in `vault.consent.registry`. Revoke it there
(`vault.consent.revoke` with its `grant_ref`), and Grok Bot's next call is
refused. Connecting again needs a new sign-in and your new answer.

## Notes

- Grok Bot registers three callback addresses, among them
  `cursor://anysphere.cursor-mcp/oauth/callback`. The vault admits that one
  address by its exact string. Every other private-use address whose scheme
  has no `.` in it stays refused.
- Grok Bot sends no `MCP-Protocol-Version` header on later calls. The vault
  serves those calls.
- `crates/oneiron-server/tests/oauth_named_client_acceptance.rs` runs Grok
  Bot's client profile against a served vault in CI. A run with a live Grok
  Bot account is your own act and is not part of CI.
