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

Read/send scopes, consent, credential admission, output receipts and send-result
precedence are unchanged. No extra Gmail POST retry is introduced. A failed or
uncertain send is not retried by this path.

These are runtime slices of FIX 1054 / OF-374; the full row remains partial.
Authorization-code exchange and refresh after a send's expired-access-token
response remain open. There is no new OAuth client registry, credential store,
configuration, timer or operating limit.
