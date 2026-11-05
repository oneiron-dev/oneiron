# Local Sign in with ChatGPT

`oneiron seat siwc-login` starts an explicit authorization attempt on the runtime
where you invoke it. Run it on your own machine or self-hosted runtime. It does
not open a browser, inject a credential into an official CLI, or make an inference
request.

Pass all four inputs:

```sh
oneiron seat siwc-login \
  --credential-file /your/private/config/chatgpt-account.json \
  --host-id-file /your/private/config/chatgpt-host.json \
  --callback-uri http://127.0.0.1:0/auth/callback \
  --agent-name 'Your app name'
```

The parent directories must already exist. Put both files outside vaults,
repositories and synced directories. These are caller-selected filesystem paths;
the command cannot infer that a path is outside every sync service. The credential
file contains secrets. Never print, commit or ingest it.

The command binds its callback listener before printing the authorization URL.
Open that URL in your system browser. Port `0` selects an available loopback port.
Keep the callback scheme, host and path unchanged on later sign-ins; only the port
may change. Use the same actual app name across installations. This command does
not add an ID-token hint to the printed URL.

Use a separate credential file for each account registration. Reuse the host-ID
file across this host's registrations. It is created atomically once, and its
random identifier is a host label, not account identity or authority. A per-file
lock prevents two commands from replacing the same registration at once.

Each attempt generates fresh state, nonce and a 32-byte random PKCE verifier.
The command checks the callback state before using either a code or an OAuth
error. First registration exchanges the callback-issued client ID, never
`dynamic_agent_client`. Reauthorization retains the selected client ID and rejects
a different callback ID or a different verified account subject.

The command exchanges the code once against OpenAI's official token endpoint,
using the original verifier, exact redirect URI and Responses resource. On a
refused exchange, start a fresh sign-in; the command never retries the code.
The ID token must verify against OpenAI's published signing keys, with the
expected issuer, issued-client audience, expiry, nonce and authorized party.
The local record is replaced only after verification succeeds. A failed or
cancelled attempt leaves the previous credentials unchanged.

The record keeps the issued client ID, verified identity, host and registered
callback, access/refresh/ID tokens, returned scopes and expiry data. Files use the
existing protected-credential writer (owner-only mode and native ACL checks,
atomic replacement). Tokens are not printed or placed in a vault, control-plane
record, or environment by this command. Ctrl-C cancels a pending callback,
exchange or verification; a cancelled verifier cannot publish credentials later.

A successful identity sign-in is not permission to spend the ChatGPT plan. The
command reports whether the **returned** scopes include
`chatgpt.tokens.use.direct`. It may save a valid identity grant without that scope.
A file path, account label, client ID or host ID alone proves no such permission.

This command does not yet connect the saved record to a served Responses backend,
refresh credentials or revoke a registration. Those remain separate engineering
work. Do not configure the saved token as an environment key or vault secret to
work around that gap. Existing seat placement and plan-budget rules still apply
when an inference consumer is connected.

The vendor contract is documented at
<https://developers.openai.com/siwc/token-sharing-open-source/sign-in>.
The fixed issuer/JWKS/token endpoints match OpenAI's published
<https://auth.openai.com/.well-known/openid-configuration>.
