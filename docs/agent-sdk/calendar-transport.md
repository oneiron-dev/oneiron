# Calendar invite and CalDAV host doors

All calls are typed SDK/MCP verbs and `POST /v1/core/facade/<verb>` routes.
OpenAPI publishes the engine request and response schemas. Setup, observation,
pull, own-calendar write and kill require the same owner proof as the other
owner host doors. `calendar.invite` acts as its own caller through the existing
outbound gate, UID/SEQUENCE admission and intent ledger.

## Invites

`calendar.invite` takes the existing `CalendarInviteSurfaceInput`:

```json
{"method":"REQUEST","uid":"meeting@example.test","sequence":0,"ics_blob_ref":"<blob-id>#v1","recipient":"person@example.test"}
```

`method` is `REQUEST` or `CANCEL` (the existing engine wire spelling, not a new
lowercase alias). `mention` is optional. The result is `OutboundIntentReceipt`:
intent reference, schedule/dedupe outcome, gate outcome and gate decision.
The blob must contain this UID, SEQUENCE, METHOD, organizer and recipient.
No request flag supplies consent, identity or hygiene. A scheduled receipt is
not a claim of delivery. Inspect the normal send receipts for delivery.

The engine checks live agreement/grant and primary-calendar-domain evidence.
The first request uses sequence zero; updates and cancellation preserve the UID
and strictly advance its sequence. Retries coalesce through the existing ledger.

## Host iMIP sender

`calendar.imip.configure` accepts `{endpoint, secret_ref}` and returns the saved
configuration. `calendar.imip.get` takes `{}` and returns it or `null`.
Credentials are stored through the existing secret custody doors. Give the
credential a read binding for effector `calendar.imip`.

The installed endpoint is an HTTP mail submission service supplied by the host,
not an engine email provider. The served connector-send worker POSTs a complete
RFC 5322 MIME message as `message/rfc822`, with its frozen calendar part, a stable
Message-ID and an `Idempotency-Key` for the logical send. The From address is the
identity selected by the engine, never an address from setup. A 2xx acknowledges
acceptance for delivery. The service must dedupe the key if it retries mail
submission internally. An uncertain HTTP outcome is marked possibly delivered;
the engine's existing ledger decides whether another attempt is lawful.

The stored credential is a complete `Basic ...` or `Bearer ...` Authorization
header, or a bare bearer token. No credential is stored in an endpoint URL.

## CalDAV

`calendar.connector.configure` accepts:

```json
{"config":{"seat_ref":"work","secret_ref":"caldav-work","system":"caldav-work","calendar_ref":"Personal","cadence_jitter_min_seconds":300,"cadence_jitter_max_seconds":900},"endpoint":"https://dav.example.test/"}
```

The config is the engine's existing `CalendarConnectorSeatConfig`. This host
supports its CalDAV provider. Give the credential a read binding for effector
`calendar.caldav:<seat_ref>`. Store an app-password credential as a complete
Basic Authorization header. `calendar_ref` selects the exact collection href,
absolute collection URL or DAV display name found by principal/home discovery.
An identical setup is idempotent; a different configuration uses a new seat ref.

- `calendar.connector.get({seat_ref})` returns the installed endpoint, seat
  config, real cursor, kill-switch state and last sync observation, or `null`.
- `calendar.connector.pull({seat_ref})` calls the existing connector sync. Its
  `CalendarSyncOutcome` is `Killed`, or `Reenqueued` with `next_cursor`,
  `next_not_before`, `applied`, `acknowledged`, `source_absences` and
  `status_cancellations`. The cursor is saved, not supplied by the caller.
- `calendar.connector.write({seat_ref,event_ref})` writes a readable EVENT
  through the existing durable write outbox. The result is `RemoteWriteReceipt`
  with href, ETag, UID, sequence and content hash. No raw ICS or claimed provider
  receipt enters this door. New resources use If-None-Match; updates require
  If-Match. A precondition failure reconciles and refuses, never overwrites.
- `calendar.connector.kill({seat_ref,reason_ref})` stops the seat and returns its
  retained state. It erases no EVENT, passport or outbox evidence.

The wire performs real DAV discovery, sync-collection REPORTs, resource GETs and
conditional PUTs. Imported data still passes the engine import gate; transport
success grants no claim approval. Echoes are acknowledged by the engine's
existing passport law without semantic writes or invite sends.

Pull is callable explicitly. The engine also enqueues its normal next-poll
attempt; the served CalDAV attempt consumer is a separate outstanding host
wiring item, recorded on the fix list. No automatic-polling claim is made here.

## Transport bounds

These new HTTP clients use a five-second connection deadline and a thirty-second
request deadline, with no proxy or redirects. DAV replies are limited to 16 MiB.
Endpoints must use HTTPS, or HTTP on loopback, without URL credentials, queries
or fragments. DAV hrefs must stay on the installed origin. No engine scheduling,
consent or calendar-policy default was changed.
