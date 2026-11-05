# Native mail credential check through `self.use`

`self.use` accepts `native_mail.jmap` with empty arguments:

```json
{"handle":"sc12","operation":"native_mail.jmap","arguments":{}}
```

The operation uses the Stalwart placement installed on this open vault by
`oneiron-server` from its `[native_mail]` configuration. An embedded host can
install the same placement with `Vault::install_served_transports` and
`ServedTransports::with_native_mail`. Without that placement the operation
cannot reach a mail server.

The credential is the record named by the caller's handle, not the native
mail pack's configured credential. Its binding must grant `read` for
`connector:native_mail`; the current custody floor and door policy still
apply. Run-found records use the existing run-seat door. A secret grant for
this operation redeems at the send, at its pinned generation.

The check performs authenticated JMAP discovery and the existing configured
domain read. It does not provision a mailbox, poll mail, send mail, bind a
secret or reveal its value. It accepts the same whole `Basic ...` or
`Bearer ...` Authorization header, or bare bearer token, as the native mail
pack's connection check.

The result has `account`, `provider_account` and `scopes`, like the other
provider-check operations. No evidence digest is returned. Both successful
results and failure text are cleared of the released credential inside the
T0 door. The ordinary `self.use` intent and linked outcome retain the actual
presented record and generation, including when the provider check fails.
A door refusal records no presentation.

FIX 2615 remains partial for the separate broker and webhook operations.
