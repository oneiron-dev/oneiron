---
name: oneiron-native-mail-setup
description: Walk the owner through connecting their agent's own mail, from the permissions to a checked connection to this host's mail server.
---

# Set up native mail

Use this skill when the owner wants their agent to have its own email
addresses on a domain they control, or when the native mail pack shows a
setup step that is not done. Read the setup from the pack's own setup session
and its cards; never guess a step the session already shows as done. Setup
grants nothing by itself, and the pack stays a Candidate until its check
passes.

## What the owner needs

- A mail server this host runs: Stalwart 0.16 or later, serving one domain
  the owner controls. The host's `[native_mail]` config names its JMAP session
  URL, the domain and the domain's id on the server. A host without that
  section cannot pass the check.
- The domain's MX, SPF, DKIM and DMARC records pointed at the server. The
  host owns those records and the server's keys; setup changes none of them.
- An API key or app password for the server's administrator account.

## Steps

1. Review the permissions first. Show the permission card: each row says what
   the agent can do with its mail and what could go wrong. Ask the owner to
   allow each one. Each permission they allow gets its own Gate receipt.
2. Store the server credential through the owner secrets form, under the name
   the card shows, bound for read to connector:native_mail. Store the whole
   Authorization header (`Basic ...` or `Bearer ...`), or a bare bearer token.
   Never ask for the value in chat, never repeat it back, and never write it
   into a note or a card.
3. Check the connection. The check signs in to the server's JMAP session with
   the stored credential, confirms it offers mail and submission, and reads
   the domain: it must be enabled, exactly the configured name, with no
   catch-all address and no other tenant. It sends no mail and changes no DNS.

## When the check fails

- "this host has no [native_mail] server configured": the host's config has
  no `[native_mail]` section. Whoever runs the host adds it and restarts.
- "the mail server refused the check": the credential is wrong or lacks the
  administrator's rights, the session URL is wrong, or the domain is disabled,
  has a catch-all address or belongs to another tenant. Fix it on the server,
  then check again.
