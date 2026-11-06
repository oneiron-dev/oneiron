# Gmail custody grants and access-token refresh

The Gmail read and send HTTP wires accept a bare access token or a stored JSON
`access_token` through the existing admitted credential door. A usable access
credential is always presented first.

When those bytes cannot produce a bearer header, a stored Google grant containing
`refresh_token`, `client_id`, and an optional `client_secret` can provide a fresh
access token. The wire uses its existing blocking client and Google's fixed token
endpoint through the shared pack-setup exchange implementation. The exchange and
Gmail call both stay inside the already-admitted custody callback, after its
write transaction has been released. The fresh token uses the existing zeroizing
wrapper and is not saved. Its sensitive bearer header stays inside that callback.

For inbox reads, an actual HTTP 401 from a list or metadata GET can use that same
stored grant to refresh the access header and repeat the same GET. The current
header is shared across the rest of that page, so a metadata refresh does not
restart the list or change its cursor. If the credential has no refresh metadata,
the original 401 is reported. An exchange failure reports `gmail_refresh_failed`.
The repeated GET uses the original response handling. Transport errors, other
HTTP statuses and unreadable JSON do not trigger refresh or another request.

For sends, only an actual HTTP 401 from Google's fixed `messages.send` endpoint
can refresh the injected grant and repeat the same POST once. The raw message
and thread id are unchanged, and the successful send's metadata lookup uses the
refreshed header. Missing refresh metadata keeps the original 401; a refresh
failure reports `gmail_refresh_failed`. The repeated POST uses the original
response handling. No transport error, other status, unreadable response or
missing message id triggers another send.

Google's [Gmail error guide](https://developers.google.com/workspace/gmail/api/guides/handle-errors)
describes 401 as an invalid access token and directs clients to refresh it.
[Bearer-token error handling](https://www.rfc-editor.org/rfc/rfc6750#section-3.1)
allows obtaining a new token and retrying the rejected request. Google's
[official authorized HTTP client](https://github.com/googleapis/google-cloud-python/blob/b86536f91caa7ff2ea5a37b943444111959422c1/packages/google-auth-httplib2/google_auth_httplib2.py#L229-L256)
refreshes after a 401 and repeats the same URI, method and body, including the
POST used by its Gmail send sample. This wire permits only one such continuation.
This is not a retry of an uncertain delivery or a claim that sends are idempotent.

Read/send scopes, consent, credential admission, output receipts and send-result
precedence are unchanged. Uncertain sends are never retried by this path.

These are runtime slices of FIX 1054 / OF-374; the full row remains partial.
The host's browser sign-in and state/redirect handling remain external. There
is no new OAuth client registry, credential store, configuration, timer or
operating limit.
