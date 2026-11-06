# APNs alert delivery

The served outbound sink handles `apns/push` through Apple's HTTP/2 API.
It consumes the original frozen intent and the normal typed content loader.
The common actor, Grant, Gate, budget, window and intent-ledger path still runs
before transport. An APNs acceptance is not handset delivery or a read receipt.

## Configure the app, not its key bytes

Register the Apple P-256 `.p8` key with the existing owner secret door in T0
custody. Allow the `apns.push` effector through the normal secret-use policy.
Keep the immutable SECRET record id, not an alias that could name another row.
The provider key, its Team ID, Key ID, topic and environment must be the actual
Apple account's values. No account, entitlement or Grant is inferred from them.

```toml
[[apns.applications]]
id = "phone"
team_id = "<Apple Team ID>"
key_id = "<Apple Key ID>"
topic = "com.example.reader"
environment = "production" # or explicitly "sandbox"
signing_key_ref = "<immutable SECRET record id>"
```

After rotating an Apple key, update both the stored `.p8` and the configured
Apple Key ID (and Team ID if it changed), then restart the matching host with
that configuration. Rotating a SECRET value does not invent new issuer metadata.

The section is file-only. No section means no configured APNs applications;
Slack, LINE, Telegram and native mail keep their existing behavior. App ids
must be unique. The public config has no private key or cached bearer token.
The standard production and sandbox hosts are selected by the explicit
`environment`. Existing provider endpoint overrides are unchanged.

## Register a device through the existing identity lifecycle

The APNs registration is an ordinary self-held `ChannelIdentity`, not another
registry or a new table. Use `ApnsDeviceAddress::address()` to form its complete
opaque address:

```rust
use oneiron::outbound::{ApnsDeviceAddress, ApnsEnvironment};

let address = ApnsDeviceAddress {
    application: "phone".into(),
    environment: ApnsEnvironment::Production,
    topic: "com.example.reader".into(),
    device_token: device_token_from_the_app,
}.address()?;
```

For clients without the Rust helper, the address is `apns-address:` followed by
unpadded Base64URL of UTF-8 JSON, with these fields in this order:
`application`, `environment`, `topic`, `device_token`. Environment is
`production` or `sandbox`; the token is nonempty even-length lowercase hex.
No fixed token length is assumed. Whitespace, alternative JSON field orders
and uppercase token encodings are not canonical addresses.

The complete encoded address, including the `apns-address:` prefix, must fit
ChannelIdentity's existing 512-byte `address_or_handle` bound. The Rust helper
reports an address that exceeds that bound before provisioning. Use short app
labels such as `phone`; the encoded size also depends on the topic and token,
so an app-id length alone does not determine whether the address fits.

1. Call the existing owner-bound `vault.channel_identities.provision` with
   `channel: "apns"`, that `address_or_handle`, `shape: "dedicated_address"`,
   the normal explicit binding, and manual fulfillment.
2. Complete the existing owner-bound `vault.channel_identities.fulfill` for
   that identity. This is the owner's manual registration act, not a claim
   that Apple has verified the device token. Provision alone is still pending.
   The normal lifecycle Gate and its receipts keep their existing behavior.
3. Use `ApnsDeviceAddress::target(identity_ref)`, equivalently
   `apns-device:<identity_ref>`, as the outbound intent's target.

The identity assignment key keeps the complete address immutable. A new token,
application, topic or environment needs a new address/identity, not a mutable
alias behind an admitted send. The sender reads that same identity id on each
attempt and requires its live `apns` registration. An attempt whose registration
read sees release/close makes no provider call. This adds no cancellation of
already admitted, in-flight sends; their ordinary uncertainty remains. No
provider error silently deletes the registration.
The row is destination data. It does not supply the send actor, consent, a
sender identity or permission to use the provider key.

## What goes on the wire

The normal typed outbound `content_ref` supplies `aps.alert`. An effective
APNs interruption-level from execute-time delivery-window policy is preserved;
`time_sensitive` uses Apple's wire spelling `time-sensitive`. There is no new
agent-supplied raw payload or arbitrary text argument at send time. This slice
sends text alerts, not badge/sound, background, VoIP or arbitrary custom payloads.

Every request enters the live T0 secret door again. A key revoked or suspended
before that admission cannot use an old session. Existing secret scope and custody
admission remain in force. P-256 PKCS8 PEM is signed with ES256; the JWT uses
Apple's Key ID, Team ID and Unix issued-at timestamp. Private key bytes and the
transient JWT remain inside the current secret-door callback.

Each configured app/topic/environment has its own HTTP/2 connection pool.
Key rotation starts a fresh pool. Only the public issued-at timestamp and key
fingerprint are retained with it: deterministic RFC6979 signing recreates the
same JWT inside each live door until the 20-minute refresh point. No bearer
credential is retained between calls. This follows Apple's requirement to
refresh no more often than every 20 minutes on one connection and at least
every 60 minutes; it is not an admission wait or a new outbound retry timer.
This describes the adapter's retained state, not complete allocator or network
buffer erasure. The existing connect and request timeouts are unchanged.

APNs `200` becomes `DeliveredToChannel`, with its returned `apns-id` when
present, or an explicitly acceptance-only label. Definite connection refusal
is not started. A later no-reply is possible delivery and keeps the common
ledger's uncertainty handling. Provider `429` uses the existing rate-limit
wait with the actual `Retry-After`. Other provider failures keep their HTTP
status and available reason/id/timestamp fields; APNs timestamps retain their
provider units. No new body cap, backoff, fallback sender or worker was added.

## Rollout and boundaries

Matching engine/server code and an explicitly configured app are required.
The owner registers the key and device through existing doors. No guest, VM,
kel/bel change or automatic deployment is part of this source change.
APNs/voice FIX1468/11894 is not wholly closed: voice remains separate, and
badge/sound/custom payload and app-side registration transport are not built
by this alert sender.

Protocol references:
- https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns
- https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns
