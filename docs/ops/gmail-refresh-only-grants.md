# Gmail refresh-only custody grants

The Gmail read and send HTTP wires accept a bare access token or a stored JSON
`access_token` through the existing admitted credential door. Those usable access
credentials keep their original behavior.

When those bytes cannot produce a bearer header, a stored Google grant containing
`refresh_token`, `client_id`, and an optional `client_secret` can provide a fresh
access token. The wire uses its existing blocking client and Google's fixed token
endpoint through the shared pack-setup exchange implementation. The exchange and
Gmail call both stay inside the already-admitted custody callback, after its
write transaction has been released. The fresh token uses the existing zeroizing wrapper and is not saved. Its
sensitive bearer header stays inside that callback.

Read/send scopes, consent, credential admission, output receipts and send-result
precedence are unchanged. No extra Gmail POST retry is introduced. A failed or
uncertain send is not retried by this path.

This is only the refresh-only runtime slice of FIX 1054 / OF-374. An existing
access token is still presented as before even when its JSON also carries refresh
fields. Expired-access-token detection/401 refresh and authorization-code exchange
are not implemented here. There is no new OAuth client registry, credential store,
configuration, timer or operating limit.
