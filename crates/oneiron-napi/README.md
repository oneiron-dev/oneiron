# Raw Node-API shared invitation integration

These APIs are exported by the raw `oneiron-napi` addon and wrapped by the
high-level `Oneiron` class in `packages/oneiron` (`acceptSharedInvitationHttps`,
`retrySharedInvitationHttps`, `bootstrapSharedEnv`, `retainSharedEnv`).
`NativeClient` is available in every addon build. `NativeEngine` and
`NativeSharedBootstrapOutcome` require the opt-in `engine` Cargo feature.
The feature remains off by default.

## Accept on the connected HTTPS home

Call `NativeClient.connect(url, key)` with the accepting invitee's credential,
then `client.acceptSharedInvitationHttps(request)`. The request uses the native
wire shape:

- `vault_id`: a decimal string, including for small ids;
- `invitation`: the invitation token;
- `expires_at`: the required credential expiry, a safe JavaScript integer.

A pending call throws the complete native `MemoryError` as JSON in the error's
message. Pass that serialized refusal and the same request to
`client.retrySharedInvitationHttps(pending, request)`, or pass the refusal's
original JSON text and the same request to
`client.retrySharedInvitationHttpsJson(pendingJson, request)` to keep full
integers parsing only in Rust. The native retry uses the refusal's own
invocation. The ordinary verb and generic retry are unchanged.

Both methods return `NativeSharedAcceptance`, which holds the original opaque
HTTPS acceptance. A decoded receipt cannot construct that value. It provides:

- `homeUrl()` and `acceptanceUrl()`;
- `requestJson()`: the original request as JSON text;
- `replyJson()`: the complete original receipt and member credential as JSON text;
- `memberClient()`: a new remote `NativeClient` under the accepted credential.

Readers and member-client construction do not consume the acceptance. Its reply
remains readable if member-client creation or a later bootstrap fails. The JSON
readers return strings to preserve all native integers. Parsing them with ordinary
`JSON.parse` can round integers beyond JavaScript's safe range. Treat the reply as
credential-bearing data; do not log it.

## Bootstrap and explicitly retain

On a started `NativeEngine`, call
`engine.bootstrapSharedEnv(acceptance, entry, dimensions, configFile)`. Pass the
original `NativeSharedAcceptance`, not its JSON readers. Omit optional dimensions
and config file with `undefined`, as with the existing native methods.

The entry is the native `SharedEnvConfig` shape: `path`, `vault_id`, `member`,
`home_url`, and `credential_file`. Use the decimal-string form of `vault_id` to
preserve the full native range. `home_url` is the shared home's `ws` or `wss`
`/ws` endpoint. The credential file must already hold the accepting invitee's
credential. The target resolves from this entry's path, never the personal vault.

Setup or task failures throw immediately. Once import answers, the returned
`NativeSharedBootstrapOutcome` keeps the original import result and the native
publication flag independently:

- `committed()` returns that flag, even when a later step failed;
- `vaultPath()` returns the actual imported path or throws the inner error;
- `errorJson()` returns the complete inner native `MemoryError` as JSON text, or
  `null` when import succeeded or failed with another error type. A `null` error
  reader alone is therefore not a success signal.

Native `MemoryError` payloads are preserved before any other engine error is
projected. No failed import returns an empty or fabricated successful path.

Bootstrap changes the live registry but does not persist the entry in the host
configuration. To retain it for the next start, explicitly call
`engine.retainSharedEnv(entry)` with the same entry. This invokes the native
config-file upsert and leaves the running registry unchanged. A host without a
config file cannot retain there; a managed engine's supervisor remains its writer.
