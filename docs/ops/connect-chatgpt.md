# Connect ChatGPT to your vault (developer mode)

ChatGPT on the web can add a remote MCP server as a custom plugin. A
self-hosted vault can be that server: ChatGPT calls the vault's MCP endpoint
over HTTPS, and signs in through the vault's own OAuth 2.1 server, which asks
you, the owner, before it lets ChatGPT in.

This is a plugin for your own ChatGPT account. It is not an app in ChatGPT's
directory: nothing is listed or reviewed by OpenAI, and nobody else can
install it. A listed app needs a hosted endpoint and OpenAI's review; Oneiron
has neither yet.

The steps below follow the vault's code and OpenAI's page "Connect a custom
MCP server" (platform.openai.com/docs/guides/developer-mode, read on
2026-11-14). The whole flow has not yet been tried against ChatGPT;
[Limits](#limits) lists what the vault requires of a client.

## 1. Give the vault a public https origin

ChatGPT reaches the vault from OpenAI's servers, so the vault needs a public
https address. TLS ends at a reverse proxy in front of `oneiron serve`.

- Set that origin as `oauth_resource_indicator`: a top-level key in the config
  `serve` reads, `--oauth-resource-indicator` or
  `ONEIRON_OAUTH_RESOURCE_INDICATOR`. Give the origin alone, such as
  `https://vault.example.com`, with no path. Without it, or with a value that is
  not an https origin, every OAuth route answers 404.
- The server needs its `auth_secret` (`ONEIRON_AUTH_SECRET`), as for every
  agent credential. Without it, sign-in answers `temporarily_unavailable`.

The vault then serves its OAuth metadata at
`/.well-known/oauth-protected-resource` (and `.../mcp`) and
`/.well-known/oauth-authorization-server`, client registration at
`/oauth/register`, sign-in at `/oauth/authorize`, and tokens at
`/oauth/token` and `/oauth/revoke`. The protected resource is
`https://vault.example.com/mcp`; one sign-in reaches both MCP endpoints,
`/mcp` and `/mcp/tool-first`.

## 2. Add the plugin in ChatGPT

In ChatGPT on the web, open Plugins, select the plus button, then **Add
custom MCP server**. Name it, and enter the server URL
`https://vault.example.com/mcp/tool-first`: that endpoint lists one tool per
verb. Choose **OAuth** as the authentication. ChatGPT registers itself with
the vault, by dynamic registration or by a client ID metadata document; the
vault accepts both, for public clients with PKCE. Confirm the risk warning
and create the plugin.

## 3. Allow the sign-in

ChatGPT opens the vault's sign-in page. It names the app, its host, the tier
it asks for and a six-character match code. Your inbox gets an ask with the
same code: check that the codes match, then allow or deny. The page moves on
by itself once you answer.

The tier comes from the OAuth scope ChatGPT asks for (as for
[`oneiron token agent`](connect-an-agent.md#1-mint-the-agents-credential)):

- `read`: it only reads.
- `propose`: its writes wait for your review. This is the tier when ChatGPT
  names no scope.
- `full`: its writes land at once, through the same write gate as yours.

An allow makes ChatGPT an agent of its own, with an agent grant of that tier.
Its access token lasts an hour, and its refresh token 30 days; each refresh
replaces both.

## What ChatGPT sees

`tools/list` gives each tool the standard MCP tool annotations of its verb's
act class:

| tool | annotations |
|---|---|
| a read verb, `setup_oneiron`, `read_result` | `readOnlyHint: true` |
| a write an undo restores (`reversible_work`) | `readOnlyHint: false`, `destructiveHint: false` |
| a delete (of items or the whole vault), an erase, a member removal | `readOnlyHint: false`, `destructiveHint: true` |
| a send under a delegated identity, a legal send | `readOnlyHint: false`, `openWorldHint: true` |
| any other act class | `readOnlyHint: false` |
| an `unstated` verb, `execute_code`, `invoke_action` | none |

ChatGPT treats a tool without `readOnlyHint` as a write action and asks you
to confirm each call, so a read verb runs without asking and every other
tool asks. The hints never widen what ChatGPT may do: the vault checks every
call against its grant.

## Revoke

The connection is an agent grant in your consent registry
(`vault.consent.registry`), with its own revoke. You can also revoke it with
`POST /v1/owner/agent-grants/revoke` and its `grant_ref`, or the verb
`vault.agents.grants.revoke`. Revoking ends every token it holds at once.
Lapsed sign-ins and tokens are swept hourly
([housekeeping](owner-actions.md#housekeeping)).

## Limits

What the vault requires of a client, from its code. ChatGPT's side of each
has not been checked.

- Streamable HTTP over POST. A GET answers 405: the vault opens no SSE stream
  and keeps no session.
- PKCE with S256, as a public client (no client secret).
- The `resource` parameter at sign-in, naming the protected resource
  `https://vault.example.com/mcp` for either endpoint; a sign-in without it,
  or with another value, is refused with `invalid_target`.
- A scope of `read`, `propose` or `full`, or none.
- A request that carries a browser `Origin` must come from an origin in
  `allowed_origins` or the vault's own. A server-side call carries none.
