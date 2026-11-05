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

The record keeps the issued client ID, verified identity, original nonce, host and
registered callback, access/refresh/ID tokens, returned scopes and expiry data. Files use the
existing protected-credential writer (owner-only mode and native ACL checks,
atomic replacement). Tokens are not printed or placed in a vault, control-plane
record, or environment by this command. Ctrl-C cancels a pending callback,
exchange or verification; a cancelled verifier cannot publish credentials later.

A successful identity sign-in is not permission to spend the ChatGPT plan. The
command reports whether the **returned** scopes include
`chatgpt.tokens.use.direct`. It may save a valid identity grant without that scope.
A file path, account label, client ID or host ID alone proves no such permission.

## Serve a configured Responses model

The saved record can supply a normal `[models]` provider. Select the record, not
its token. For example, replace `YOUR_MODEL` with a model your plan serves:

```toml
[models.providers.chatgpt]
kind = "openai-compat"
base_url = "https://api.openai.com/v1"

[models.providers.chatgpt.siwc]
credential_file = "/your/private/config/chatgpt-account.json"

[models.roles.generative_reasoner]
model = "chatgpt:YOUR_MODEL"
```

An absolute path makes the selection independent of the process's working
directory. A relative path is resolved once against the runtime's working
directory when the provider is built. The record must already exist. The backend
binds the saved issuer, subject, issued client and host at construction. Each
physical send reopens the protected record and checks that same registration,
the returned direct-plan scope, access-token expiry and the selected token. A
changed registration needs a model-runtime rebuild; a same-registration sign-in
can supply later calls. Removing the file prevents later sends. Requests already
sent are not revoked by removing the file.

The actual startup vault supplies the hosting posture. Existing P4 rules apply:
a hosted runtime requires actual OpenAI hosted-plan approval, represented by
`openai_hosted_plan_approved = true` in the `siwc` table. It is absent/false until
that approval exists. A local file does not prove self-hosted placement or vendor
approval. Embedded callers of `ModelRuntime::build` and `build_with_keys` must
supply their actual `HostingPrivacyPosture` explicitly.

Calls use the existing model ladders, run admission and budget settlement. This
new selection defaults to `customer_seat` funding and T1 credential custody, not
local/keyless or broker-isolated T0 custody. An explicit provider payer setting
still applies. The offer's `siwc-file:` binding is only a locator; it is not an
account or authority proof. Tokens never enter provider config, public request
headers, a vault, or the control plane.

Both buffered and streaming calls send the full native Responses turn over HTTPS
with `stream=true` and `store=false`. There is no WebSocket create frame, chained
previous-response ID or chat fallback with the subscription token. The native
codec retains tool calls/results, images, JSON controls, usage and supported
reasoning replay. Audio this codec cannot represent is refused without sending;
existing non-SIWC chat/audio providers are unchanged. Reranking, embedding and
media ports do not consume this new credential selection.

Before opening a Responses call, the backend refreshes an expired access token
using the saved issued client ID and refresh token at the official token endpoint.
The existing provider `timeout_secs` bounds the whole refresh HTTP request,
including its response body; the normal provider default remains unchanged.
Same-backend callers share a refresh; the per-record lock also serializes it with
local sign-in. Another process holding that lock can make an expired-token call
fail; a later call rereads the record. A returned rotating refresh token replaces
the old one atomically with the access token. If the response omits a refresh token
or unchanged scopes, the previous values remain. An explicitly returned empty
scope does not keep the old direct-plan permission.

A returned ID token must verify its signature, issuer, issued-client audience,
expiry and authorized party, and keep the same account subject. Its nonce, when
present, must match the original sign-in nonce. No ID token in a refresh response
means the prior verified identity remains; it is not a new identity assertion.
`earliest_refresh_at` stays opaque vendor data: this backend does not guess its
units or use it to schedule early refreshes.

Cancellation drops the pending refresh and cannot publish from a detached
verifier. A failed or cancelled exchange may still have rotated the remote grant;
there is no automatic retry or claim that the vendor rolled it back. Sign in again
if that grant is no longer valid. Do not configure a saved token as an environment
key or vault secret to work around a failed refresh.

Registration revocation and full official-seat Dreamer execution remain separate
engineering work.

The vendor contract is documented at
<https://developers.openai.com/siwc/token-sharing-open-source/sign-in>.
The fixed issuer/JWKS/token endpoints match OpenAI's published
<https://auth.openai.com/.well-known/openid-configuration>.
