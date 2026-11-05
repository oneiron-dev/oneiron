# Sign in with ChatGPT authorize plans

`oneiron seat login-plan` builds a sign-in plan. For the `sign_in_with_chatgpt`
route, its `authorize_url` uses OpenAI's public open-source client flow at
`https://auth.openai.com/api/accounts/authorize`. Printing that URL is not a
completed login. The command does not open a browser, start a callback listener,
exchange a code, validate an ID token, or write a local token store.

The current vendor contract is [OpenAI's sign-in guide](https://developers.openai.com/siwc/token-sharing-open-source/sign-in).
Do not reuse a Codex CLI client id or a Codex login store as an SIWC API session.
The Codex app-server seat is a separate route.

## Request fields

Supply all six required SIWC flags together:

| Flag | Caller responsibility |
| --- | --- |
| `--siwc-client-id` | `dynamic_agent_client` for initial registration; the issued client id for later sign-ins to that ChatGPT account. |
| `--siwc-redirect-uri` | The exact HTTP loopback callback URI on `127.0.0.1`, including the selected port. |
| `--siwc-verifier` | A fresh RFC 7636 verifier for this attempt; only its S256 challenge is printed. |
| `--siwc-state` | Fresh random state retained by the caller and checked on return. |
| `--siwc-nonce` | A fresh OIDC nonce retained for later ID-token validation. |
| `--siwc-agent-host-id` | A stable identifier for this host, reused on that host's later sign-ins. |

Initial registration also requires `--siwc-agent-name-hint`, with the app's actual
name used consistently across installations. It is sent only with
`dynamic_agent_client`; issued-client reauthorization omits the name hint.
The initial callback supplies the issued client id to save and reuse. Never use
`dynamic_agent_client` as the identity for code exchange.

`--siwc-scope` overrides the scope string. Without it, the plan requests the
vendor's direct-token scope:
`openid profile email offline_access resource.invoke chatgpt.tokens.use.direct`.
The resource is `https://api.openai.com/v1`. Requested scopes are not granted
permissions, and a printed plan is not proof of plan access.

The caller starts its loopback listener before opening the URL. Keep the registered
scheme, host and path unchanged across sign-ins; only the loopback port may vary.
Within an attempt, the eventual code exchange must use exactly the authorize
request's URI. Do not substitute `localhost`. This URL builder neither starts that
listener nor proves that state, nonce, verifier or host id were generated or kept
correctly by the caller. It adds no callback-path policy of its own.

## Credential custody and remaining work

The plan carries no access token, refresh token or ID-token hint. Seat settings
still name a local login store or endpoint credential by handle; the control plane
never receives vendor login tokens. Existing seat placement, hosted-plan approval
and dry-seat policies are unchanged.

The separate [`oneiron seat siwc-login` command](siwc-local-login.md) implements
the local callback, code exchange, ID-token verification and protected record.
That runbook also describes the configured Responses model consumer and rotating
refresh, explicit local clearing and renewable-session revocation. An authorize
plan alone must not be presented
as any of those operations, or as a working authenticated inference session.
No existing executor or dispatcher is replaced by the URL-plan command.
