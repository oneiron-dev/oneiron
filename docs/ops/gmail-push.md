# Gmail push

New Gmail mail can arrive within seconds instead of at the host's next 300 s
pass (ARCH-0063 #mail-import: "watch plus `history.list`, with a periodic
reconcile behind it"). Gmail publishes a notice to a Pub/Sub topic on each
change to a watched mailbox. A push subscription delivers it to this host's
hook. The hook reads the mailbox it names and steps that source at once.

The topic and the subscription belong to the owner, in their own Google
Cloud project. Oneiron runs no topic of its own.

## Set it up

In the Google Cloud project whose OAuth client the mailbox connected with:

1. Create a topic, for example `projects/<project>/topics/gmail`.
2. Give `gmail-api-push@system.gserviceaccount.com` the role Pub/Sub
   Publisher on that topic. Gmail publishes as that account.
3. Create a service account for the subscription, for example
   `gmail-push@<project>.iam.gserviceaccount.com`.
4. Create a push subscription on the topic:
   - endpoint `https://<this host>/v1/hooks/gmail/push`;
   - authentication on, with that service account and an audience (by
     default the endpoint URL).
5. Name all three in the host's config file and restart `serve`:

```toml
[gmail_push]
topic = "projects/<project>/topics/gmail"
audience = "https://<this host>/v1/hooks/gmail/push"
service_account = "gmail-push@<project>.iam.gserviceaccount.com"
# jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"   # Google's, when absent
```

`serve` refuses to start on a topic that is not `projects/<p>/topics/<t>`, an
empty audience, a service account that is not an email, or a `jwks_uri` that
is neither `https://` nor `file://`.

## What the host does

- **Channels.** Each 300 s pass opens a channel (Gmail's `users.watch` on the
  topic) for each Active Gmail mailbox. It renews the channel daily: Google
  closes one after 7 days. When the host drops `[gmail_push]` or changes the
  topic, the pass closes the channel (`users.stop`) or moves it. When a
  mailbox is paused or disconnected, its credential reads nothing, so the
  pass lets its channel go without a call. Google closes it within its week,
  and its notices wake nothing. Each open, renewal and close is charged
  within the source's quota windows ([Gmail import pacing](gmail-quota-pacing.md)).
- **The hook.** `POST /v1/hooks/gmail/push` is keyless. Google's OIDC token
  on each delivery is the authentication. The token must be RS256, signed by
  a key of `jwks_uri`, issued by `accounts.google.com`, for `audience`, and
  name `service_account` as a verified email. Any other request answers 401
  and wakes nothing. A signed delivery always answers 204, so Pub/Sub does
  not deliver it again. That holds for a mailbox this vault does not hold and
  for a body the hook cannot read.
- **The wake.** A notice names a mailbox and its new history id, never mail.
  The hook wakes each Active mailbox of that address whose stored anchor is
  older, unless the source is resting out of quota. The mail worker steps
  each woken source at once, as the vault's local owner. A notice that comes
  while a step runs leaves one more wake.
- **The reconcile.** The 300 s pass still steps every source from its
  committed anchor. A dropped notice is read there.

Without `[gmail_push]` the hook is not served (404), no mailbox is watched,
and new mail waits for the pass.
